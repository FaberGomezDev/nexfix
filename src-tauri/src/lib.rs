mod analyzer;
mod cleaner;
#[cfg(dev)]
mod devserver;
mod elevation;
mod fswalk;
mod gpu;
mod maintenance;
mod mft;
mod nvme;
mod quarantine;
mod safety;
mod security;
mod sign;
mod startup;
mod storage;
mod system;
mod tweaks;
mod util;
mod wmiq;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use analyzer::{DeleteReport, ExtStat, FileDto, Listing, Progress, Scan};
use cleaner::{CategoryResult, CleanReport, JunkData};

#[derive(Default)]
struct AppState {
    live: Mutex<Option<sysinfo::System>>,
    /// Persistent GPU counters for live stats (tried once; None if unavailable).
    gpu: Mutex<(bool, Option<gpu::GpuQuery>)>,
    scans: Mutex<HashMap<u32, Arc<RwLock<Scan>>>>,
    scan_progress: Mutex<HashMap<u32, Arc<Progress>>>,
    next_scan: AtomicU32,
    junk: Mutex<HashMap<String, JunkData>>,
    tasks: maintenance::Running,
    /// Findings of the last security scan (with their fix steps).
    security: Mutex<Vec<security::Finding>>,
}

type Res<T> = Result<T, String>;

/// Runs blocking work off the main thread (WMI/COM must not touch the UI thread).
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Res<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())
}

/// Runs work on a brand-new OS thread: required for Recycle Bin (COM STA) calls.
async fn fresh_thread<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Res<T> {
    let (tx, rx) = tauri::async_runtime::channel(1);
    std::thread::spawn(move || {
        let _ = tx.blocking_send(f());
    });
    let mut rx = rx;
    rx.recv().await.ok_or_else(|| "La operación se interrumpió".to_string())
}

// ---------- System ----------

#[tauri::command]
fn is_admin() -> bool {
    elevation::is_elevated()
}

#[tauri::command]
fn relaunch_admin(app: AppHandle) -> Res<()> {
    elevation::relaunch_as_admin()?;
    app.exit(0);
    Ok(())
}

#[tauri::command]
async fn system_info() -> Res<system::SystemInfo> {
    blocking(|| system::system_info(elevation::is_elevated())).await
}

#[tauri::command]
async fn live_stats(state: State<'_, AppState>) -> Res<system::LiveStats> {
    let gpu = {
        let mut g = state.gpu.lock();
        if !g.0 {
            *g = (true, gpu::GpuQuery::open());
        }
        g.1.as_ref().map(|q| q.sample())
    };
    let mut guard = state.live.lock();
    let sys = guard.get_or_insert_with(system::new_live_system);
    Ok(system::live_stats(sys, gpu.as_ref()))
}

#[tauri::command]
async fn storage_info() -> Res<storage::StorageInfo> {
    blocking(|| storage::storage_info(elevation::is_elevated())).await
}

// ---------- Junk cleaner ----------

#[tauri::command]
async fn junk_scan(state: State<'_, AppState>) -> Res<Vec<CategoryResult>> {
    let (list, data) = blocking(cleaner::scan_all).await?;
    *state.junk.lock() = data;
    Ok(list)
}

#[derive(Clone, Serialize)]
struct CleanProgress {
    category: String,
    done: usize,
    total: usize,
    freed: u64,
}

#[tauri::command]
async fn junk_clean(
    app: AppHandle,
    state: State<'_, AppState>,
    ids: Vec<String>,
    excluded: Vec<String>,
    included: Vec<String>,
) -> Res<CleanReport> {
    let selected: Vec<(String, JunkData)> = {
        let mut junk = state.junk.lock();
        ids.into_iter().filter_map(|id| junk.remove(&id).map(|d| (id, d))).collect()
    };
    if selected.is_empty() {
        return Err("Analiza primero y selecciona al menos una categoría".into());
    }
    let excluded: HashSet<String> = excluded.into_iter().map(|p| p.to_lowercase()).collect();
    let included: HashSet<String> = included.into_iter().map(|p| p.to_lowercase()).collect();
    fresh_thread(move || {
        cleaner::clean(selected, &excluded, &included, |id, done, total, freed| {
            let _ = app.emit(
                "cleaner://progress",
                CleanProgress { category: id.to_string(), done, total, freed },
            );
        })
    })
    .await
}

// ---------- Space analyzer ----------

#[tauri::command]
fn analyzer_start(app: AppHandle, state: State<'_, AppState>, path: String) -> Res<u32> {
    let root = PathBuf::from(path.replace('/', "\\"));
    if !root.is_dir() {
        return Err("La ruta no es una carpeta válida".into());
    }
    let id = state.next_scan.fetch_add(1, Ordering::Relaxed) + 1;

    // Only one scan lives at a time: free the memory of previous ones.
    for (_, p) in state.scan_progress.lock().drain() {
        p.cancel.store(true, Ordering::Relaxed);
    }
    state.scans.lock().clear();

    let progress = Arc::new(Progress::default());
    state.scan_progress.lock().insert(id, progress.clone());

    let handle = app.clone();
    analyzer::spawn_scan(app, id, root, progress, move |scan| {
        let summary = scan.summary(0);
        let summary = analyzer::ScanSummary { id, ..summary };
        let st = handle.state::<AppState>();
        st.scan_progress.lock().remove(&id);
        st.scans.lock().insert(id, Arc::new(RwLock::new(scan)));
        summary
    });
    Ok(id)
}

#[tauri::command]
fn analyzer_cancel(state: State<'_, AppState>, id: u32) {
    if let Some(p) = state.scan_progress.lock().get(&id) {
        p.cancel.store(true, Ordering::Relaxed);
    }
}

fn get_scan(state: &AppState, id: u32) -> Res<Arc<RwLock<Scan>>> {
    state.scans.lock().get(&id).cloned().ok_or_else(|| "El análisis ya no está disponible".into())
}

#[tauri::command]
async fn analyzer_list(state: State<'_, AppState>, id: u32, node: u32) -> Res<Listing> {
    let scan = get_scan(&state, id)?;
    blocking(move || scan.read().listing(node)).await?
}

#[tauri::command]
fn analyzer_top_files(state: State<'_, AppState>, id: u32) -> Res<Vec<FileDto>> {
    Ok(get_scan(&state, id)?.read().top_files.clone())
}

#[tauri::command]
fn analyzer_extensions(state: State<'_, AppState>, id: u32) -> Res<Vec<ExtStat>> {
    Ok(get_scan(&state, id)?.read().exts.clone())
}

#[tauri::command]
fn analyzer_summary(state: State<'_, AppState>, id: u32) -> Res<analyzer::ScanSummary> {
    let scan = get_scan(&state, id)?;
    let s = scan.read();
    Ok(analyzer::ScanSummary { id, ..s.summary(0) })
}

#[tauri::command]
async fn delete_paths(
    state: State<'_, AppState>,
    scan_id: Option<u32>,
    paths: Vec<String>,
    to_recycle: bool,
) -> Res<DeleteReport> {
    let scan = scan_id.and_then(|id| get_scan(&state, id).ok());
    fresh_thread(move || analyzer::delete_paths(scan, paths, to_recycle)).await
}

#[tauri::command]
fn reveal_in_explorer(path: String) -> Res<()> {
    let p = PathBuf::from(&path);
    let mut cmd = std::process::Command::new("explorer.exe");
    if p.is_dir() {
        cmd.arg(&p);
    } else {
        cmd.arg(format!("/select,{}", p.display()));
    }
    cmd.spawn().map(|_| ()).map_err(|e| e.to_string())
}

// ---------- Maintenance ----------

#[tauri::command]
fn maintenance_tasks() -> Vec<maintenance::TaskDef> {
    maintenance::tasks()
}

#[tauri::command]
fn task_run(app: AppHandle, state: State<'_, AppState>, id: String, drive: Option<String>) -> Res<()> {
    let def = maintenance::tasks().into_iter().find(|t| t.id == id).ok_or("Tarea desconocida")?;
    if def.admin && !elevation::is_elevated() {
        return Err("Esta tarea necesita permisos de administrador".into());
    }
    maintenance::run_task(app, state.tasks.clone(), id, drive)
}

#[tauri::command]
fn task_cancel(state: State<'_, AppState>, id: String) -> Res<()> {
    maintenance::cancel_task(&state.tasks, &id)
}

// ---------- Security ----------

#[tauri::command]
async fn security_scan(state: State<'_, AppState>) -> Res<security::SecurityReport> {
    let report = blocking(|| security::scan(elevation::is_elevated(), &quarantine::ignored())).await?;
    *state.security.lock() = report.findings.clone();
    Ok(report)
}

#[tauri::command]
async fn security_fix(state: State<'_, AppState>, ids: Vec<String>) -> Res<quarantine::FixReport> {
    let selected: Vec<security::Finding> = {
        let all = state.security.lock();
        ids.iter().filter_map(|id| all.iter().find(|f| &f.id == id).cloned()).collect()
    };
    if selected.is_empty() {
        return Err("Analiza primero y selecciona al menos una amenaza".into());
    }
    let report = blocking(move || quarantine::fix(selected)).await?;
    state.security.lock().retain(|f| !report.items.iter().any(|i| i.ok && i.id == f.id));
    Ok(report)
}

#[tauri::command]
async fn security_ignore(key: String, ignored: bool) -> Res<()> {
    blocking(move || quarantine::set_ignored(&key, ignored)).await?
}

#[tauri::command]
async fn quarantine_list() -> Res<Vec<quarantine::QEntry>> {
    blocking(quarantine::list).await
}

#[tauri::command]
async fn quarantine_restore(id: String) -> Res<String> {
    blocking(move || quarantine::restore(&id)).await?
}

#[tauri::command]
async fn quarantine_delete(id: String) -> Res<()> {
    blocking(move || quarantine::delete(&id)).await?
}

#[tauri::command]
async fn defender_scan_file(path: String) -> Res<quarantine::DefenderScan> {
    blocking(move || quarantine::defender_scan_file(&path)).await?
}

#[tauri::command]
fn open_windows_security() -> Res<()> {
    std::process::Command::new("explorer.exe")
        .arg("windowsdefender://threat/")
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// ---------- Tweaks & startup ----------

#[tauri::command]
async fn tweaks_get() -> Res<tweaks::Tweaks> {
    blocking(|| tweaks::get_tweaks(elevation::is_elevated())).await
}

#[tauri::command]
async fn tweak_set(name: String, enabled: bool) -> Res<()> {
    blocking(move || tweaks::set_tweak(&name, enabled)).await?
}

#[tauri::command]
async fn power_plan_set(guid: String) -> Res<()> {
    blocking(move || tweaks::set_power_plan(&guid)).await?
}

#[tauri::command]
async fn power_plan_add_ultimate() -> Res<()> {
    blocking(tweaks::add_ultimate_plan).await?
}

#[tauri::command]
async fn startup_list() -> Res<Vec<startup::StartupItem>> {
    blocking(startup::list).await
}

#[tauri::command]
async fn startup_set(id: String, enabled: bool) -> Res<()> {
    blocking(move || startup::set_enabled(&id, enabled)).await?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let context = tauri::generate_context!();
    // `cargo run` builds in dev mode but does not start Vite like `pnpm tauri dev`.
    #[cfg(dev)]
    let mut dev_server = devserver::ensure(context.config().build.dev_url.as_ref());

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            is_admin,
            relaunch_admin,
            system_info,
            live_stats,
            storage_info,
            junk_scan,
            junk_clean,
            analyzer_start,
            analyzer_cancel,
            analyzer_list,
            analyzer_top_files,
            analyzer_extensions,
            analyzer_summary,
            delete_paths,
            reveal_in_explorer,
            maintenance_tasks,
            task_run,
            task_cancel,
            tweaks_get,
            tweak_set,
            power_plan_set,
            power_plan_add_ultimate,
            startup_list,
            startup_set,
            security_scan,
            security_fix,
            security_ignore,
            quarantine_list,
            quarantine_restore,
            quarantine_delete,
            defender_scan_file,
            open_windows_security,
        ])
        .build(context)
        .expect("error al iniciar NexFix")
        .run(move |_app, _event| {
            #[cfg(dev)]
            if let tauri::RunEvent::Exit = _event {
                dev_server.stop();
            }
        });
}

/// Diagnostics entry point used by `cargo run --example probe`.
#[doc(hidden)]
pub fn probe_json(what: &str, arg: &str) -> String {
    let admin = elevation::is_elevated();
    let t = std::time::Instant::now();
    let json = match what {
        "system" => serde_json::to_string_pretty(&system::system_info(admin)),
        "storage" => serde_json::to_string_pretty(&storage::storage_info(admin)),
        "tweaks" => serde_json::to_string_pretty(&tweaks::get_tweaks(admin)),
        "startup" => serde_json::to_string_pretty(&startup::list()),
        "security" => {
            let r = security::scan(admin, &quarantine::ignored());
            serde_json::to_string_pretty(&serde_json::json!({
                "findings": r.findings, "resources": r.resources, "cpu": r.cpu_total, "gpu": r.gpu_total,
                "av": r.av, "disk": r.disk, "checked": r.checked, "ms": r.elapsed_ms,
            }))
        }
        "quarantine" => serde_json::to_string_pretty(&quarantine::list()),
        "live" => {
            let mut s = system::new_live_system();
            let q = gpu::GpuQuery::open();
            std::thread::sleep(std::time::Duration::from_millis(1000));
            let g = q.as_ref().map(|q| q.sample());
            serde_json::to_string_pretty(&system::live_stats(&mut s, g.as_ref()))
        }
        "junk" => {
            let (list, _) = cleaner::scan_all();
            let brief: Vec<_> = list
                .iter()
                .map(|c| serde_json::json!({"id": c.id, "found": c.found, "denied": c.denied, "size": c.size, "count": c.count}))
                .collect();
            serde_json::to_string_pretty(&brief)
        }
        "mftdiag" => Ok(mft::diag(arg.chars().next().unwrap_or('C'))),
        "mftdiag2" => Ok(mft::diag2(arg.chars().next().unwrap_or('C'))),
        "mft" => {
            let p = Progress::default();
            let letter = arg.chars().next().unwrap_or('C');
            match mft::scan_volume(letter, &p) {
                Ok(s) => serde_json::to_string_pretty(&serde_json::json!({
                    "root": s.dto(0), "nodes": s.nodes.len(), "ms": s.elapsed_ms,
                    "top": s.top_files.iter().take(5).collect::<Vec<_>>(),
                    "exts": s.exts.iter().take(5).collect::<Vec<_>>(),
                    "listing_dirs": s.listing(0).map(|l| l.dirs.into_iter().take(8).map(|d| (d.name, d.size)).collect::<Vec<_>>()).unwrap_or_default(),
                })),
                Err(e) => Ok(format!("MFT error: {e}")),
            }
        }
        "scan" | "walk" => {
            let p = Progress::default();
            let r = if what == "walk" { analyzer::walk_only(PathBuf::from(arg), &p) } else { analyzer::run_scan(PathBuf::from(arg), &p) };
            match r {
                Ok(s) => serde_json::to_string_pretty(&serde_json::json!({
                    "root": s.dto(0), "nodes": s.nodes.len(), "errors": s.errors, "ms": s.elapsed_ms, "method": s.method,
                    "top": s.top_files.iter().take(5).collect::<Vec<_>>(),
                    "exts": s.exts.iter().take(8).collect::<Vec<_>>(),
                    "listing_dirs": s.listing(0).map(|l| l.dirs.into_iter().take(6).map(|d| (d.name, d.size)).collect::<Vec<_>>()).unwrap_or_default(),
                })),
                Err(e) => Ok(e),
            }
        }
        _ => Ok("unknown".into()),
    };
    format!("{}\n-- {} ms, admin={admin}", json.unwrap_or_else(|e| e.to_string()), t.elapsed().as_millis())
}
