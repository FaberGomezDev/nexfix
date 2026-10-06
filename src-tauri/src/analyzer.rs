//! Disk space analyzer: parallel directory walk that builds a compact tree of
//! folders (files are only aggregated), plus the largest files and a
//! breakdown by extension.

use std::borrow::Cow;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use rayon::prelude::*;
use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::fswalk::read_dir_fast;
use crate::util::{display_path, filetime_to_unix, long_path};

pub const NO_PARENT: u32 = u32::MAX;
const TOP_FILES: usize = 300;
const LIST_FILES: usize = 400;

pub struct Node {
    pub name: Box<str>,
    pub parent: u32,
    pub children: Vec<u32>,
    pub size: u64,
    pub files: u64,
    pub dirs: u64,
    pub own_size: u64,
    pub own_files: u64,
    pub mtime: u64,
    pub denied: bool,
    /// Virtual container layers the directory walker deliberately skips.
    pub skipped: bool,
}

pub struct Scan {
    pub root: PathBuf,
    pub nodes: Vec<Node>,
    pub top_files: Vec<FileDto>,
    pub exts: Vec<ExtStat>,
    pub errors: u64,
    pub elapsed_ms: u64,
    pub method: &'static str,
}

#[derive(Default)]
pub struct Progress {
    pub files: AtomicU64,
    pub dirs: AtomicU64,
    pub bytes: AtomicU64,
    pub errors: AtomicU64,
    pub current: Mutex<String>,
    pub cancel: AtomicBool,
}

#[derive(Clone, Serialize)]
pub struct FileDto {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub mtime: i64,
}

#[derive(Clone, Serialize)]
pub struct ExtStat {
    pub ext: String,
    pub size: u64,
    pub count: u64,
}

#[derive(Clone, Serialize)]
pub struct NodeDto {
    pub id: u32,
    pub name: String,
    pub size: u64,
    pub files: u64,
    pub dirs: u64,
    pub mtime: i64,
    pub denied: bool,
    pub skipped: bool,
}

#[derive(Serialize)]
pub struct Crumb {
    pub id: u32,
    pub name: String,
}

#[derive(Serialize)]
pub struct Listing {
    pub node: NodeDto,
    pub path: String,
    pub crumbs: Vec<Crumb>,
    pub dirs: Vec<NodeDto>,
    pub files: Vec<FileDto>,
    pub files_more: u64,
    pub files_more_size: u64,
}

#[derive(Clone, Serialize)]
pub struct ScanSummary {
    pub id: u32,
    pub root: NodeDto,
    pub path: String,
    pub errors: u64,
    pub elapsed_ms: u64,
    pub method: String,
}

#[derive(Clone, Serialize)]
struct ProgressEvent {
    id: u32,
    files: u64,
    dirs: u64,
    bytes: u64,
    errors: u64,
    current: String,
}

#[derive(Clone, Serialize)]
struct DoneEvent {
    id: u32,
    ok: bool,
    error: Option<String>,
    summary: Option<ScanSummary>,
}

struct Tmp {
    name: Box<str>,
    size: u64,
    files: u64,
    dirs: u64,
    own_size: u64,
    own_files: u64,
    mtime: u64,
    denied: bool,
    skipped: bool,
    children: Vec<Tmp>,
}

struct Ctx<'a> {
    p: &'a Progress,
    skip: Vec<String>,
    top: Mutex<BinaryHeap<Reverse<(u64, PathBuf, u64)>>>,
    top_min: AtomicU64,
    exts: Mutex<HashMap<String, (u64, u64)>>,
}

impl Ctx<'_> {
    fn offer_top(&self, path: PathBuf, size: u64, mtime: u64) {
        let mut heap = self.top.lock();
        heap.push(Reverse((size, path, mtime)));
        if heap.len() > TOP_FILES {
            heap.pop();
            if let Some(Reverse((min, _, _))) = heap.peek() {
                self.top_min.store(*min, Relaxed);
            }
        }
    }
}

/// Lower-case extension, borrowed from the name whenever possible (hot path).
fn ext_of(name: &OsStr) -> Cow<'_, str> {
    let s = name.to_string_lossy();
    let Some(i) = s.rfind('.') else { return Cow::Borrowed("") };
    if i == 0 || s.len() - i > 12 {
        return Cow::Borrowed("");
    }
    match s {
        Cow::Borrowed(b) => {
            let ext = &b[i + 1..];
            if ext.bytes().any(|c| c.is_ascii_uppercase()) {
                Cow::Owned(ext.to_ascii_lowercase())
            } else {
                Cow::Borrowed(ext)
            }
        }
        Cow::Owned(o) => Cow::Owned(o[i + 1..].to_ascii_lowercase()),
    }
}

/// Folders made of virtual container layers (Windows Sandbox, Docker for
/// Windows): enumerating them is extremely slow and they are mostly hard
/// links to files already counted elsewhere.
fn skip_list() -> Vec<String> {
    let mut v = Vec::new();
    if let Some(pd) = crate::util::env_path("ProgramData") {
        for sub in [r"Microsoft\Windows\Containers\Layers", r"Microsoft\Windows\Containers\BaseImages"] {
            v.push(display_path(&pd.join(sub)).to_lowercase());
        }
    }
    v
}

fn scan_dir(ctx: &Ctx, path: PathBuf, name: Box<str>, mtime: u64) -> Tmp {
    let mut t = Tmp {
        name,
        size: 0,
        files: 0,
        dirs: 0,
        own_size: 0,
        own_files: 0,
        mtime,
        denied: false,
        skipped: false,
        children: Vec::new(),
    };
    if ctx.p.cancel.load(Relaxed) {
        return t;
    }
    if (t.name.eq_ignore_ascii_case("Layers") || t.name.eq_ignore_ascii_case("BaseImages"))
        && ctx.skip.contains(&display_path(&path).to_lowercase())
    {
        t.skipped = true;
        return t;
    }

    let mut subdirs: Vec<(PathBuf, Box<str>, u64)> = Vec::new();
    let mut exts: HashMap<String, (u64, u64)> = HashMap::new();
    let res = read_dir_fast(&path, |e| {
        if e.is_dir() {
            if !e.is_link() {
                subdirs.push((path.join(&e.name), e.name_lossy().into_boxed_str(), e.mtime));
            }
        } else {
            t.own_size += e.size;
            t.own_files += 1;
            let ext = ext_of(&e.name);
            match exts.get_mut(ext.as_ref()) {
                Some(s) => {
                    s.0 += e.size;
                    s.1 += 1;
                }
                None => {
                    exts.insert(ext.into_owned(), (e.size, 1));
                }
            }
            if e.size > ctx.top_min.load(Relaxed) {
                ctx.offer_top(path.join(&e.name), e.size, e.mtime);
            }
        }
    });
    if res.is_err() {
        t.denied = true;
        ctx.p.errors.fetch_add(1, Relaxed);
    }

    if !exts.is_empty() {
        let mut global = ctx.exts.lock();
        for (k, (s, c)) in exts {
            let g = global.entry(k).or_insert((0, 0));
            g.0 += s;
            g.1 += c;
        }
    }

    ctx.p.files.fetch_add(t.own_files, Relaxed);
    ctx.p.bytes.fetch_add(t.own_size, Relaxed);
    let d = ctx.p.dirs.fetch_add(1, Relaxed);
    if d % 97 == 0 {
        if let Some(mut cur) = ctx.p.current.try_lock() {
            *cur = display_path(&path);
        }
    }

    t.children = subdirs
        .into_par_iter()
        .map(|(p, n, m)| scan_dir(ctx, p, n, m))
        .collect();

    t.size = t.own_size;
    t.files = t.own_files;
    t.dirs = t.children.len() as u64;
    for c in &t.children {
        t.size += c.size;
        t.files += c.files;
        t.dirs += c.dirs;
    }
    t
}

fn flatten(t: Tmp, parent: u32, nodes: &mut Vec<Node>) -> u32 {
    let id = nodes.len() as u32;
    nodes.push(Node {
        name: t.name,
        parent,
        children: Vec::new(),
        size: t.size,
        files: t.files,
        dirs: t.dirs,
        own_size: t.own_size,
        own_files: t.own_files,
        mtime: t.mtime,
        denied: t.denied,
        skipped: t.skipped,
    });
    let mut kids = t.children;
    kids.sort_unstable_by(|a, b| b.size.cmp(&a.size));
    let ids: Vec<u32> = kids.into_iter().map(|k| flatten(k, id, nodes)).collect();
    nodes[id as usize].children = ids;
    id
}

/// `C:\` style volume roots → drive letter.
fn volume_letter(root: &Path) -> Option<char> {
    let s = display_path(root);
    let s = s.trim_end_matches('\\');
    let mut chars = s.chars();
    let letter = chars.next()?;
    (s.len() == 2 && letter.is_ascii_alphabetic() && chars.next() == Some(':')).then(|| letter.to_ascii_uppercase())
}

/// Whole NTFS volumes are read straight from the MFT when running as
/// administrator; everything else uses the parallel directory walker.
pub fn run_scan(root: PathBuf, progress: &Progress) -> Result<Scan, String> {
    if let Some(letter) = volume_letter(&root) {
        if crate::elevation::is_elevated() {
            match crate::mft::scan_volume(letter, progress) {
                Ok(scan) => return Ok(scan),
                Err(e) if progress.cancel.load(Relaxed) => return Err(e),
                Err(_) => {
                    progress.files.store(0, Relaxed);
                    progress.bytes.store(0, Relaxed);
                    progress.dirs.store(0, Relaxed);
                }
            }
        }
    }
    walk_scan(root, progress)
}

fn walk_scan(root: PathBuf, progress: &Progress) -> Result<Scan, String> {
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads((threads * 2).clamp(4, 48))
        .stack_size(8 << 20)
        .thread_name(|i| format!("nexfix-scan-{i}"))
        .build()
        .map_err(|e| e.to_string())?;

    let start = Instant::now();
    let ctx = Ctx {
        p: progress,
        skip: skip_list(),
        top: Mutex::new(BinaryHeap::with_capacity(TOP_FILES + 1)),
        top_min: AtomicU64::new(0),
        exts: Mutex::new(HashMap::new()),
    };
    let root_name: Box<str> = display_path(&root).into_boxed_str();
    let tmp = pool.install(|| scan_dir(&ctx, root.clone(), root_name, 0));
    if progress.cancel.load(Relaxed) {
        return Err("Análisis cancelado".into());
    }

    let mut nodes = Vec::with_capacity(progress.dirs.load(Relaxed) as usize + 1);
    flatten(tmp, NO_PARENT, &mut nodes);

    let top_files = ctx
        .top
        .into_inner()
        .into_sorted_vec()
        .into_iter()
        .map(|Reverse((size, path, mtime))| FileDto {
            name: path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
            path: display_path(&path),
            size,
            mtime: filetime_to_unix(mtime),
        })
        .collect();

    let mut exts: Vec<ExtStat> = ctx
        .exts
        .into_inner()
        .into_iter()
        .map(|(ext, (size, count))| ExtStat { ext, size, count })
        .collect();
    exts.sort_unstable_by(|a, b| b.size.cmp(&a.size));
    exts.truncate(80);

    Ok(Scan {
        root,
        nodes,
        top_files,
        exts,
        errors: progress.errors.load(Relaxed),
        elapsed_ms: start.elapsed().as_millis() as u64,
        method: "walk",
    })
}

/// Runs a scan on a background thread, streaming progress events.
pub fn spawn_scan(
    app: AppHandle,
    id: u32,
    root: PathBuf,
    progress: Arc<Progress>,
    store: impl FnOnce(Scan) -> ScanSummary + Send + 'static,
) {
    let done = Arc::new(AtomicBool::new(false));
    {
        let app = app.clone();
        let progress = progress.clone();
        let done = done.clone();
        std::thread::spawn(move || {
            while !done.load(Relaxed) {
                let _ = app.emit(
                    "analyzer://progress",
                    ProgressEvent {
                        id,
                        files: progress.files.load(Relaxed),
                        dirs: progress.dirs.load(Relaxed),
                        bytes: progress.bytes.load(Relaxed),
                        errors: progress.errors.load(Relaxed),
                        current: progress.current.lock().clone(),
                    },
                );
                std::thread::sleep(Duration::from_millis(140));
            }
        });
    }
    std::thread::spawn(move || {
        let result = run_scan(root, &progress);
        done.store(true, Relaxed);
        let event = match result {
            Ok(scan) => DoneEvent { id, ok: true, error: None, summary: Some(store(scan)) },
            Err(e) => DoneEvent { id, ok: false, error: Some(e), summary: None },
        };
        let _ = app.emit("analyzer://done", event);
    });
}

impl Scan {
    pub fn dto(&self, id: u32) -> NodeDto {
        let n = &self.nodes[id as usize];
        NodeDto {
            id,
            name: n.name.to_string(),
            size: n.size,
            files: n.files,
            dirs: n.dirs,
            mtime: filetime_to_unix(n.mtime),
            denied: n.denied,
            skipped: n.skipped,
        }
    }

    pub fn summary(&self, id: u32) -> ScanSummary {
        ScanSummary {
            id,
            root: self.dto(0),
            path: display_path(&self.root),
            errors: self.errors,
            elapsed_ms: self.elapsed_ms,
            method: self.method.to_string(),
        }
    }

    pub fn node_path(&self, id: u32) -> PathBuf {
        let mut names = Vec::new();
        let mut cur = id;
        while cur != 0 && cur != NO_PARENT {
            let n = &self.nodes[cur as usize];
            names.push(n.name.as_ref());
            cur = n.parent;
        }
        let mut p = self.root.clone();
        for name in names.into_iter().rev() {
            p.push(name);
        }
        p
    }

    pub fn listing(&self, id: u32) -> Result<Listing, String> {
        let node = self.nodes.get(id as usize).ok_or("Carpeta no encontrada")?;
        let path = self.node_path(id);

        let mut crumbs = Vec::new();
        let mut cur = id;
        while cur != NO_PARENT {
            let n = &self.nodes[cur as usize];
            crumbs.push(Crumb { id: cur, name: n.name.to_string() });
            cur = n.parent;
        }
        crumbs.reverse();

        let dirs = node.children.iter().map(|&c| self.dto(c)).collect();

        let mut files = Vec::new();
        let _ = read_dir_fast(&path, |e| {
            if !e.is_dir() {
                files.push((e.size, e.mtime, e.name_lossy()));
            }
        });
        files.sort_unstable_by(|a, b| b.0.cmp(&a.0));
        let mut files_more = 0;
        let mut files_more_size = 0;
        if files.len() > LIST_FILES {
            for f in &files[LIST_FILES..] {
                files_more += 1;
                files_more_size += f.0;
            }
            files.truncate(LIST_FILES);
        }
        let base = display_path(&path);
        let files = files
            .into_iter()
            .map(|(size, mtime, name)| FileDto {
                path: join_display(&base, &name),
                name,
                size,
                mtime: filetime_to_unix(mtime),
            })
            .collect();

        Ok(Listing {
            node: self.dto(id),
            path: base,
            crumbs,
            dirs,
            files,
            files_more,
            files_more_size,
        })
    }

    /// Locates the folder node for an absolute path inside this scan.
    pub fn find_node(&self, path: &Path) -> Option<u32> {
        let root = display_path(&self.root);
        let root_l = root.trim_end_matches('\\').to_lowercase();
        let p = display_path(path);
        let p_l = p.trim_end_matches('\\').to_lowercase();
        if p_l == root_l {
            return Some(0);
        }
        let prefix = format!("{root_l}\\");
        if !p_l.starts_with(&prefix) {
            return None;
        }
        let rel = &p.trim_end_matches('\\')[prefix.len()..];
        let mut cur = 0u32;
        for part in rel.split('\\').filter(|s| !s.is_empty()) {
            cur = *self.nodes[cur as usize].children.iter().find(|&&c| {
                let n = &self.nodes[c as usize].name;
                n.as_ref() == part || n.eq_ignore_ascii_case(part)
            })?;
        }
        Some(cur)
    }

    fn subtract_up(&mut self, mut id: u32, size: u64, files: u64, dirs: u64) {
        while id != NO_PARENT {
            let n = &mut self.nodes[id as usize];
            n.size = n.size.saturating_sub(size);
            n.files = n.files.saturating_sub(files);
            n.dirs = n.dirs.saturating_sub(dirs);
            id = n.parent;
        }
    }

    pub fn dir_size(&self, path: &Path) -> Option<u64> {
        self.find_node(path).map(|id| self.nodes[id as usize].size)
    }

    /// Updates the tree after a folder was removed from disk.
    pub fn remove_dir(&mut self, path: &Path) {
        let Some(id) = self.find_node(path) else { return };
        if id == 0 {
            return;
        }
        let (size, files, dirs, parent) = {
            let n = &self.nodes[id as usize];
            (n.size, n.files, n.dirs, n.parent)
        };
        self.nodes[parent as usize].children.retain(|&c| c != id);
        self.subtract_up(parent, size, files, dirs + 1);
        let prefix = format!("{}\\", display_path(path).to_lowercase());
        self.top_files.retain(|f| !f.path.to_lowercase().starts_with(&prefix));
    }

    /// Updates the tree after a file was removed from disk.
    pub fn remove_file(&mut self, path: &Path, size: u64) {
        if let Some(parent) = path.parent().and_then(|p| self.find_node(p)) {
            let n = &mut self.nodes[parent as usize];
            n.own_size = n.own_size.saturating_sub(size);
            n.own_files = n.own_files.saturating_sub(1);
            self.subtract_up(parent, size, 1, 0);
        }
        let p = display_path(path).to_lowercase();
        self.top_files.retain(|f| f.path.to_lowercase() != p);
    }
}

fn join_display(base: &str, name: &str) -> String {
    if base.ends_with('\\') {
        format!("{base}{name}")
    } else {
        format!("{base}\\{name}")
    }
}

#[derive(Serialize, Default)]
pub struct DeleteReport {
    pub deleted: u32,
    pub freed: u64,
    pub failed: Vec<DeleteFailure>,
}

#[derive(Serialize)]
pub struct DeleteFailure {
    pub path: String,
    pub error: String,
}

pub fn remove_file_force(path: &Path) -> std::io::Result<()> {
    let lp = long_path(path);
    match std::fs::remove_file(&lp) {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            if let Ok(md) = std::fs::symlink_metadata(&lp) {
                let mut perms = md.permissions();
                if perms.readonly() {
                    #[allow(clippy::permissions_set_readonly_false)]
                    perms.set_readonly(false);
                    std::fs::set_permissions(&lp, perms)?;
                    return std::fs::remove_file(&lp);
                }
            }
            Err(e)
        }
        other => other,
    }
}

pub fn io_error_es(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => "Acceso denegado o archivo en uso".into(),
        std::io::ErrorKind::NotFound => "Ya no existe".into(),
        _ => e.to_string(),
    }
}

/// Deletes user-selected paths (optionally to the Recycle Bin) and keeps the
/// scan tree in sync. Must run on a thread without COM initialized (the
/// `trash` crate initializes it as STA).
pub fn delete_paths(scan: Option<Arc<RwLock<Scan>>>, paths: Vec<String>, to_recycle: bool) -> DeleteReport {
    let mut report = DeleteReport::default();
    for raw in paths {
        let path = PathBuf::from(&raw);
        if let Err(e) = crate::safety::check_deletable(&path) {
            report.failed.push(DeleteFailure { path: raw, error: e });
            continue;
        }
        let md = match std::fs::symlink_metadata(long_path(&path)) {
            Ok(m) => m,
            Err(e) => {
                report.failed.push(DeleteFailure { path: raw, error: io_error_es(&e) });
                continue;
            }
        };
        let is_dir = md.is_dir();
        let size = if is_dir {
            scan.as_ref().and_then(|s| s.read().dir_size(&path)).unwrap_or(0)
        } else {
            md.len()
        };

        let result = if to_recycle {
            trash::delete(&path).map_err(|e| e.to_string())
        } else if is_dir {
            std::fs::remove_dir_all(long_path(&path)).map_err(|e| io_error_es(&e))
        } else {
            remove_file_force(&path).map_err(|e| io_error_es(&e))
        };

        match result {
            Ok(()) => {
                report.deleted += 1;
                report.freed += size;
                if let Some(s) = &scan {
                    let mut s = s.write();
                    if is_dir {
                        s.remove_dir(&path);
                    } else {
                        s.remove_file(&path, size);
                    }
                }
            }
            Err(e) => {
                // A folder may be partially removed; reflect what is really left.
                if is_dir && !to_recycle && path.exists() {
                    if let Some(s) = &scan {
                        let p = Progress::default();
                        if let Ok(rest) = run_scan(path.clone(), &p) {
                            let left = rest.nodes[0].size;
                            let mut s = s.write();
                            if let Some(id) = s.find_node(&path) {
                                let removed = s.nodes[id as usize].size.saturating_sub(left);
                                report.freed += removed;
                                s.subtract_up(id, removed, 0, 0);
                            }
                        }
                    }
                }
                report.failed.push(DeleteFailure { path: raw, error: e });
            }
        }
    }
    report
}

#[doc(hidden)]
pub fn walk_only(root: PathBuf, progress: &Progress) -> Result<Scan, String> {
    walk_scan(root, progress)
}
