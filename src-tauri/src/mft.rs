//! Whole-volume scan by reading the NTFS Master File Table directly (the
//! technique used by WizTree / Everything). Millions of files in seconds,
//! and hard links are counted once. Requires administrator rights; callers
//! fall back to the directory walker otherwise.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::fs::File;
use std::os::windows::fs::FileExt;
use std::path::PathBuf;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::mpsc;
use std::time::Instant;

use crate::analyzer::{ExtStat, FileDto, Node, Progress, Scan, NO_PARENT};
use crate::util::filetime_to_unix;

const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
const ROOT_RECORD: u32 = 5;
const CHUNK: usize = 8 << 20;
const TOP_FILES: usize = 300;

const K_IN_USE: u8 = 1;
const K_DIR: u8 = 2;
const K_NAMED: u8 = 4;

fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn rd64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Page-aligned buffer (required by unbuffered volume reads).
struct AlignedBuf {
    ptr: *mut u8,
    len: usize,
}
unsafe impl Send for AlignedBuf {}
impl AlignedBuf {
    fn new(len: usize) -> Self {
        let layout = std::alloc::Layout::from_size_align(len, 4096).unwrap();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "sin memoria");
        Self { ptr, len }
    }
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}
impl Drop for AlignedBuf {
    fn drop(&mut self) {
        let layout = std::alloc::Layout::from_size_align(self.len, 4096).unwrap();
        unsafe { std::alloc::dealloc(self.ptr, layout) };
    }
}

struct Geometry {
    cluster: u64,
    record: usize,
    mft_offset: u64,
}

fn open_volume(letter: char) -> Result<File, String> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let path = crate::util::wide(&format!(r"\\.\{letter}:"));
    let h = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(format!("abrir volumen: {}", std::io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_handle(h as _) })
}

fn read_geometry(vol: &File) -> Result<Geometry, String> {
    let mut boot = AlignedBuf::new(4096);
    vol.seek_read(boot.as_mut(), 0).map_err(|e| e.to_string())?;
    let b = boot.as_mut();
    if &b[3..11] != b"NTFS    " {
        return Err("La unidad no es NTFS".into());
    }
    let sector = rd16(b, 0x0B) as u64;
    let cluster = sector * b[0x0D] as u64;
    let mft_lcn = rd64(b, 0x30);
    let cpr = b[0x40] as i8;
    let record = if cpr < 0 { 1usize << (-cpr) as u32 } else { cpr as usize * cluster as usize };
    if cluster == 0 || !(512..=65536).contains(&record) {
        return Err("Geometría NTFS no reconocida".into());
    }
    Ok(Geometry { cluster, record, mft_offset: mft_lcn * cluster })
}

/// Applies the multi-sector "update sequence" fixups. Returns false if torn.
fn fixup(rec: &mut [u8]) -> bool {
    let usa_off = rd16(rec, 4) as usize;
    let usa_count = rd16(rec, 6) as usize;
    if usa_count < 2 || usa_off + usa_count * 2 > rec.len() {
        return false;
    }
    let seq = rd16(rec, usa_off);
    for i in 1..usa_count {
        let pos = i * 512 - 2;
        if pos + 2 > rec.len() {
            break;
        }
        if rd16(rec, pos) != seq {
            return false;
        }
        rec[pos] = rec[usa_off + i * 2];
        rec[pos + 1] = rec[usa_off + i * 2 + 1];
    }
    true
}

/// Decodes the data runs of a non-resident attribute into (lcn, clusters).
/// Sparse runs come back with `lcn = None`.
fn data_runs(b: &[u8], mut o: usize, end: usize) -> Vec<(Option<u64>, u64)> {
    let mut runs = Vec::new();
    let mut lcn: i64 = 0;
    while o < end {
        let h = b[o];
        if h == 0 {
            break;
        }
        let ln = (h & 0x0F) as usize;
        let on = (h >> 4) as usize;
        o += 1;
        if o + ln + on > end || ln == 0 || ln > 8 || on > 8 {
            break;
        }
        let mut len = 0u64;
        for i in 0..ln {
            len |= (b[o + i] as u64) << (8 * i);
        }
        o += ln;
        if on == 0 {
            runs.push((None, len));
        } else {
            let mut off = 0i64;
            for i in 0..on {
                off |= (b[o + i] as i64) << (8 * i);
            }
            let shift = 64 - 8 * on as u32;
            off = (off << shift) >> shift;
            lcn += off;
            runs.push((Some(lcn as u64), len));
        }
        o += on;
    }
    runs
}

type Runs = Vec<(Option<u64>, u64)>;

/// One `$DATA` segment of a non-resident attribute: (starting VCN, size if first, runs).
fn data_segments(rec: &[u8], want_name_len: u8) -> (Vec<(u64, Option<u64>, Runs)>, Option<(bool, usize, usize)>) {
    let mut segs = Vec::new();
    let mut attr_list = None;
    let used = (rd32(rec, 0x18) as usize).min(rec.len());
    let mut off = rd16(rec, 0x14) as usize;
    while off + 16 <= used {
        let typ = rd32(rec, off);
        let len = rd32(rec, off + 4) as usize;
        if typ == 0xFFFF_FFFF || len < 16 || off + len > used {
            break;
        }
        let nonres = rec[off + 8] == 1;
        if typ == 0x20 {
            attr_list = Some((nonres, off, len));
        }
        if typ == 0x80 && rec[off + 9] == want_name_len && nonres {
            let start_vcn = rd64(rec, off + 0x10);
            let size = (start_vcn == 0).then(|| rd64(rec, off + 0x30));
            let runs_off = off + rd16(rec, off + 0x20) as usize;
            segs.push((start_vcn, size, data_runs(rec, runs_off, off + len)));
        }
        off += len;
    }
    (segs, attr_list)
}

/// Byte offset on the volume of a position inside a run-mapped stream.
fn map_offset(runs: &Runs, cluster: u64, pos: u64) -> Option<u64> {
    let mut vcn_start = 0u64;
    let vcn = pos / cluster;
    for (lcn, len) in runs {
        if vcn < vcn_start + len {
            return lcn.map(|l| (l + vcn - vcn_start) * cluster + pos % cluster);
        }
        vcn_start += len;
    }
    None
}

fn read_bytes(vol: &File, at: u64, len: usize) -> Result<Vec<u8>, String> {
    let aligned = at & !4095;
    let pad = (at - aligned) as usize;
    let total = (pad + len).div_ceil(4096) * 4096;
    let mut buf = AlignedBuf::new(total);
    vol.seek_read(buf.as_mut(), aligned).map_err(|e| e.to_string())?;
    Ok(buf.as_mut()[pad..pad + len].to_vec())
}

/// Extents of the $MFT stream and its total size. Handles a fragmented MFT
/// whose `$DATA` mapping continues in extension records ($ATTRIBUTE_LIST).
fn mft_extents(vol: &File, g: &Geometry) -> Result<(Runs, u64), String> {
    let mut rec0 = read_bytes(vol, g.mft_offset, g.record)?;
    if &rec0[0..4] != b"FILE" || !fixup(&mut rec0) {
        return Err("Registro $MFT dañado".into());
    }
    let (mut segs, attr_list) = data_segments(&rec0, 0);
    let first = segs.iter().find(|s| s.0 == 0).ok_or("No se encontró $DATA de $MFT")?;
    let size = first.1.unwrap_or(0);
    let base_runs = first.2.clone();

    if let Some((nonres, off, len)) = attr_list {
        let list: Vec<u8> = if !nonres {
            let v = off + rd16(&rec0, off + 0x14) as usize;
            let vl = rd32(&rec0, off + 0x10) as usize;
            rec0.get(v..v + vl).ok_or("Lista de atributos inválida")?.to_vec()
        } else {
            let real = rd64(&rec0, off + 0x30) as usize;
            let runs = data_runs(&rec0, off + rd16(&rec0, off + 0x20) as usize, off + len);
            let mut out = Vec::with_capacity(real);
            for (lcn, clusters) in runs {
                let Some(lcn) = lcn else { break };
                out.extend(read_bytes(vol, lcn * g.cluster, (clusters * g.cluster) as usize)?);
            }
            out.truncate(real);
            out
        };
        let mut o = 0usize;
        let mut seen = std::collections::HashSet::new();
        while o + 0x1A <= list.len() {
            let typ = rd32(&list, o);
            let elen = rd16(&list, o + 4) as usize;
            if elen == 0 {
                break;
            }
            let name_len = list[o + 6];
            let recno = rd64(&list, o + 0x10) & 0xFFFF_FFFF_FFFF;
            if typ == 0x80 && name_len == 0 && recno != 0 && seen.insert(recno) {
                let pos = recno * g.record as u64;
                let at = map_offset(&base_runs, g.cluster, pos).ok_or("Registro de extensión fuera de alcance")?;
                let mut ext = read_bytes(vol, at, g.record)?;
                if &ext[0..4] == b"FILE" && fixup(&mut ext) {
                    segs.extend(data_segments(&ext, 0).0);
                }
            }
            o += elen;
        }
    }

    segs.sort_by_key(|s| s.0);
    segs.dedup_by_key(|s| s.0);
    let runs: Runs = segs.into_iter().flat_map(|s| s.2).collect();
    let covered: u64 = runs.iter().map(|r| r.1).sum::<u64>() * g.cluster;
    if covered < size {
        return Err(format!("Mapa de la MFT incompleto ({covered} de {size} bytes)"));
    }
    Ok((runs, size))
}

struct Parsed {
    kind: Vec<u8>,
    parent: Vec<u32>,
    size: Vec<u64>,
    ext: Vec<u16>,
    dir_names: HashMap<u32, (Box<str>, u64)>,
    ext_names: Vec<String>,
    ext_ids: HashMap<String, u16>,
    top: BinaryHeap<Reverse<(u64, u32, String, u64)>>,
    top_min: u64,
    /// Names found in extension records: classified once every base record is known.
    pending: Vec<(u32, String, u64)>,
}

impl Parsed {
    fn new(total: usize) -> Self {
        Self {
            kind: vec![0; total],
            parent: vec![u32::MAX; total],
            size: vec![0; total],
            ext: vec![0; total],
            dir_names: HashMap::new(),
            ext_names: Vec::new(),
            ext_ids: HashMap::new(),
            top: BinaryHeap::with_capacity(TOP_FILES + 1),
            top_min: 0,
            pending: Vec::new(),
        }
    }

    fn ensure(&mut self, rec: usize) {
        if rec >= self.kind.len() {
            let n = (rec + 1).max(self.kind.len() + self.kind.len() / 8);
            self.kind.resize(n, 0);
            self.parent.resize(n, u32::MAX);
            self.size.resize(n, 0);
            self.ext.resize(n, 0);
        }
    }

    /// One FILE_LAYOUT_ENTRY (with its name, stream and extra-info entries).
    fn layout_entry(&mut self, b: &[u8], e: usize) {
        let attrs = rd32(b, e + 12);
        let rec = (rd64(b, e + 16) & 0xFFFF_FFFF_FFFF) as usize;
        if rec >= u32::MAX as usize - 1 {
            return;
        }
        self.ensure(rec);
        let is_dir = attrs & 0x10 != 0;

        let mut name: Option<(u64, String)> = None;
        let mut no = rd32(b, e + 24) as usize;
        let mut at = e + no;
        while no != 0 && at + 24 <= b.len() {
            let flags = rd32(b, at + 4);
            let len = rd32(b, at + 16) as usize;
            if at + 24 + len > b.len() {
                break;
            }
            let primary = flags & 1 != 0;
            if flags & 2 == 0 || primary {
                if name.is_none() || primary {
                    let units: Vec<u16> = (0..len / 2).map(|i| rd16(b, at + 24 + i * 2)).collect();
                    name = Some((rd64(b, at + 8) & 0xFFFF_FFFF_FFFF, String::from_utf16_lossy(&units)));
                }
                if primary {
                    break;
                }
            }
            no = rd32(b, at) as usize;
            at += no;
        }

        let mut size = 0u64;
        let mut so = rd32(b, e + 28) as usize;
        let mut st = e + so;
        while so != 0 && st + 48 <= b.len() {
            let typ = rd32(b, st + 36);
            let id_len = rd32(b, st + 44) as usize;
            let main = id_len == 0
                || (id_len == 14 && st + 48 + 14 <= b.len() && {
                    let units: Vec<u16> = (0..7).map(|i| rd16(b, st + 48 + i * 2)).collect();
                    String::from_utf16_lossy(&units) == "::$DATA"
                });
            if typ == 0x80 && main {
                size = rd64(b, st + 24);
            }
            so = rd32(b, st + 4) as usize;
            st += so;
        }

        let xo = rd32(b, e + 32) as usize;
        let mtime = if xo != 0 && e + xo + 24 <= b.len() { rd64(b, e + xo + 16) } else { 0 };

        let Some((parent, fname)) = name else { return };
        self.kind[rec] = K_IN_USE | K_NAMED | if is_dir { K_DIR } else { 0 };
        self.parent[rec] = parent.min(u32::MAX as u64 - 1) as u32;
        if !is_dir {
            self.size[rec] = size;
        }
        self.classify(rec as u32, fname, mtime);
    }

    fn ext_id(&mut self, name: &str) -> u16 {
        let ext = match name.rfind('.') {
            Some(i) if i > 0 && name.len() - i <= 12 => name[i + 1..].to_ascii_lowercase(),
            _ => String::new(),
        };
        if let Some(&id) = self.ext_ids.get(&ext) {
            return id;
        }
        if self.ext_names.len() >= u16::MAX as usize {
            return 0;
        }
        let id = self.ext_names.len() as u16;
        self.ext_names.push(ext.clone());
        self.ext_ids.insert(ext, id);
        id
    }

    fn parse(&mut self, rec: &mut [u8], no: u32) {
        self.parse_with(rec, no, true);
    }

    /// `apply_fixup` is false for records returned by FSCTL_GET_NTFS_FILE_RECORD
    /// (already resolved by NTFS).
    fn parse_with(&mut self, rec: &mut [u8], no: u32, apply_fixup: bool) {
        if &rec[0..4] != b"FILE" || (apply_fixup && !fixup(rec)) {
            return;
        }
        let flags = rd16(rec, 0x16);
        if flags & 1 == 0 {
            return;
        }
        let base = rd64(rec, 0x20) & 0xFFFF_FFFF_FFFF;
        let target = if base == 0 { no } else { base as u32 };
        if target as usize >= self.kind.len() {
            return;
        }
        if base == 0 {
            self.kind[no as usize] |= K_IN_USE | if flags & 2 != 0 { K_DIR } else { 0 };
        }

        let used = (rd32(rec, 0x18) as usize).min(rec.len());
        let mut off = rd16(rec, 0x14) as usize;
        let mut mtime = 0u64;
        let mut name: Option<(u64, usize, usize, u8)> = None;
        let mut size: Option<u64> = None;
        while off + 16 <= used {
            let typ = rd32(rec, off);
            let len = rd32(rec, off + 4) as usize;
            if typ == 0xFFFF_FFFF || len < 16 || off + len > used {
                break;
            }
            let nonres = rec[off + 8];
            let attr_name_len = rec[off + 9];
            match typ {
                0x10 if nonres == 0 => {
                    let v = off + rd16(rec, off + 0x14) as usize;
                    if v + 16 <= off + len {
                        mtime = rd64(rec, v + 8);
                    }
                }
                0x30 if nonres == 0 => {
                    let v = off + rd16(rec, off + 0x14) as usize;
                    if v + 0x42 <= off + len {
                        let nlen = rec[v + 0x40] as usize;
                        let ns = rec[v + 0x41];
                        let better = match name {
                            None => true,
                            Some((_, _, _, cur)) => cur == 0 && ns != 0,
                        };
                        if ns != 2 && better && v + 0x42 + nlen * 2 <= off + len {
                            name = Some((rd64(rec, v) & 0xFFFF_FFFF_FFFF, v + 0x42, nlen, ns));
                        }
                    }
                }
                0x80 if attr_name_len == 0 => {
                    if nonres == 0 {
                        size = Some(rd32(rec, off + 0x10) as u64);
                    } else if rd64(rec, off + 0x10) == 0 {
                        size = Some(rd64(rec, off + 0x30));
                    }
                }
                _ => {}
            }
            off += len;
        }

        let t = target as usize;
        if let Some(s) = size {
            self.size[t] = s;
        }
        let Some((parent, noff, nlen, _)) = name else { return };
        if self.kind[t] & K_NAMED != 0 {
            return;
        }
        self.kind[t] |= K_NAMED;
        self.parent[t] = parent.min(u32::MAX as u64 - 1) as u32;

        let units: Vec<u16> = (0..nlen).map(|i| rd16(rec, noff + i * 2)).collect();
        let fname = String::from_utf16_lossy(&units);
        if base != 0 {
            // The base record may not have been read yet.
            self.pending.push((target, fname, mtime));
        } else {
            self.classify(target, fname, mtime);
        }
    }

    fn classify(&mut self, rec: u32, fname: String, mtime: u64) {
        let t = rec as usize;
        if self.kind[t] & K_DIR != 0 {
            self.dir_names.insert(rec, (fname.into_boxed_str(), mtime));
            return;
        }
        self.ext[t] = self.ext_id(&fname);
        let s = self.size[t];
        if s > self.top_min {
            self.top.push(Reverse((s, rec, fname, mtime)));
            if self.top.len() > TOP_FILES {
                self.top.pop();
                if let Some(Reverse((m, ..))) = self.top.peek() {
                    self.top_min = *m;
                }
            }
        }
    }

    fn finalize(&mut self) {
        for (rec, name, mtime) in std::mem::take(&mut self.pending) {
            self.classify(rec, name, mtime);
        }
    }
}

/// Strategy 1: read the $MFT clusters straight from the volume (fastest).
fn scan_raw(letter: char, progress: &Progress) -> Result<Parsed, String> {
    let vol = open_volume(letter)?;
    let g = read_geometry(&vol).map_err(|e| format!("sector de arranque: {e}"))?;
    let (runs, mft_size) = mft_extents(&vol, &g).map_err(|e| format!("mapa de la MFT: {e}"))?;
    let total = (mft_size / g.record as u64) as usize;
    *progress.current.lock() = format!("Leyendo la MFT de {letter}: ({total} registros)");

    let mut p = Parsed::new(total);

    // Reader thread → parser pipeline with recycled aligned buffers.
    let (full_tx, full_rx) = mpsc::sync_channel::<(AlignedBuf, usize, u64)>(2);
    let (free_tx, free_rx) = mpsc::channel::<AlignedBuf>();
    for _ in 0..3 {
        let _ = free_tx.send(AlignedBuf::new(CHUNK));
    }
    let cluster = g.cluster;
    let record = g.record as u64;
    let reader = std::thread::spawn(move || -> Result<(), String> {
        let mut stream_pos = 0u64;
        for (lcn, clusters) in runs {
            let mut remaining = clusters * cluster;
            let Some(lcn) = lcn else {
                stream_pos += remaining;
                continue;
            };
            let mut disk = lcn * cluster;
            while remaining > 0 {
                let mut buf = free_rx.recv().map_err(|_| "cancelado".to_string())?;
                let n = remaining.min(CHUNK as u64) as usize;
                vol.seek_read(&mut buf.as_mut()[..n], disk).map_err(|e| e.to_string())?;
                if full_tx.send((buf, n, stream_pos)).is_err() {
                    return Ok(());
                }
                disk += n as u64;
                stream_pos += n as u64;
                remaining -= n as u64;
            }
        }
        Ok(())
    });

    let mut carry: Vec<u8> = Vec::new();
    let mut carry_pos = 0u64;
    let mut seen = 0u64;
    for (mut buf, n, pos) in full_rx {
        if progress.cancel.load(Relaxed) {
            break;
        }
        let data = &mut buf.as_mut()[..n];
        let mut i = 0usize;
        if !carry.is_empty() && carry_pos + carry.len() as u64 == pos {
            let need = record as usize - carry.len();
            if need <= n {
                carry.extend_from_slice(&data[..need]);
                let no = (carry_pos / record) as u32;
                if (no as usize) < total {
                    p.parse(&mut carry, no);
                }
                i = need;
            }
        }
        carry.clear();
        let mut abs = pos + i as u64;
        // Realign to a record boundary of the stream.
        let misalign = (abs % record) as usize;
        if misalign != 0 {
            let skip = record as usize - misalign;
            i += skip;
            abs += skip as u64;
        }
        while i + record as usize <= n {
            let no = (abs / record) as usize;
            if no >= total {
                break;
            }
            p.parse(&mut data[i..i + record as usize], no as u32);
            i += record as usize;
            abs += record;
        }
        if i < n {
            carry.extend_from_slice(&data[i..n]);
            carry_pos = abs;
        }
        seen += n as u64;
        progress.bytes.store(seen, Relaxed);
        progress.files.store(seen / record, Relaxed);
        let _ = free_tx.send(buf);
    }
    drop(free_tx);
    reader.join().map_err(|_| "Fallo en la lectura de la MFT".to_string())??;
    if progress.cancel.load(Relaxed) {
        return Err("Análisis cancelado".into());
    }
    Ok(p)
}

const FSCTL_GET_NTFS_VOLUME_DATA: u32 = 0x0009_0064;
const FSCTL_QUERY_FILE_LAYOUT: u32 = 0x0009_0277;
const QFL_RESTART: u32 = 0x1;
const QFL_INCLUDE_NAMES: u32 = 0x2;
const QFL_INCLUDE_STREAMS: u32 = 0x4;
const QFL_INCLUDE_EXTRA_INFO: u32 = 0x10;
const QFL_INCLUDE_STREAMS_WITH_NO_CLUSTERS: u32 = 0x20;
const ERROR_HANDLE_EOF: i32 = 38;

fn ioctl(vol: &File, code: u32, input: &[u8], output: &mut [u8]) -> std::io::Result<u32> {
    use std::os::windows::io::AsRawHandle;
    let mut got = 0u32;
    let ok = unsafe {
        windows_sys::Win32::System::IO::DeviceIoControl(
            vol.as_raw_handle() as _,
            code,
            input.as_ptr() as _,
            input.len() as u32,
            output.as_mut_ptr() as _,
            output.len() as u32,
            &mut got,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(got)
    }
}

/// Strategy 2: let NTFS enumerate its own MFT with `FSCTL_QUERY_FILE_LAYOUT`
/// (works where raw volume reads are blocked).
fn scan_layout(letter: char, progress: &Progress) -> Result<Parsed, String> {
    let vol = open_volume(letter)?;
    let mut vd = [0u8; 128];
    ioctl(&vol, FSCTL_GET_NTFS_VOLUME_DATA, &[], &mut vd).map_err(|e| format!("datos NTFS: {e}"))?;
    let rec_size = rd32(&vd, 0x30).max(512) as u64;
    let total = (rd64(&vd, 0x38) / rec_size) as usize + 1;
    *progress.current.lock() = format!("Leyendo la MFT de {letter}: ({total} registros)");
    let mut p = Parsed::new(total);

    let mut input = [0u8; 32];
    let mut out = vec![0u8; 8 << 20];
    let mut first = true;
    let mut entries = 0u64;
    loop {
        if progress.cancel.load(Relaxed) {
            return Err("Análisis cancelado".into());
        }
        let flags = QFL_INCLUDE_NAMES
            | QFL_INCLUDE_STREAMS
            | QFL_INCLUDE_EXTRA_INFO
            | QFL_INCLUDE_STREAMS_WITH_NO_CLUSTERS
            | if first { QFL_RESTART } else { 0 };
        input[4..8].copy_from_slice(&flags.to_le_bytes());
        first = false;
        let got = match ioctl(&vol, FSCTL_QUERY_FILE_LAYOUT, &input, &mut out) {
            Ok(n) => n as usize,
            Err(e) if e.raw_os_error() == Some(ERROR_HANDLE_EOF) => break,
            Err(e) => return Err(format!("FILE_LAYOUT: {e}")),
        };
        if got < 16 {
            break;
        }
        let count = rd32(&out, 0);
        let mut off = rd32(&out, 4) as usize;
        for _ in 0..count {
            if off == 0 || off + 40 > got {
                break;
            }
            p.layout_entry(&out[..got], off);
            entries += 1;
            let next = rd32(&out, off + 4) as usize;
            if next == 0 {
                break;
            }
            off += next;
        }
        progress.files.store(entries, Relaxed);
    }
    Ok(p)
}

pub fn scan_volume(letter: char, progress: &Progress) -> Result<Scan, String> {
    let start = Instant::now();
    let parsed = match scan_raw(letter, progress) {
        Ok(p) => p,
        Err(raw) => {
            if progress.cancel.load(Relaxed) {
                return Err(raw);
            }
            progress.files.store(0, Relaxed);
            progress.bytes.store(0, Relaxed);
            scan_layout(letter, progress).map_err(|e| format!("lectura directa: {raw} · {e}"))?
        }
    };
    *progress.current.lock() = "Construyendo árbol de carpetas…".into();
    let mut parsed = parsed;
    parsed.finalize();
    build_scan(parsed, letter, start)
}

fn build_scan(p: Parsed, letter: char, start: Instant) -> Result<Scan, String> {
    let n = p.kind.len();
    let is_dir = |r: usize| p.kind[r] & (K_IN_USE | K_DIR) == (K_IN_USE | K_DIR);

    // Files → their folder's own totals, plus extension stats.
    let mut own_size = vec![0u64; n];
    let mut own_files = vec![0u32; n];
    let mut ext_stats = vec![(0u64, 0u64); p.ext_names.len().max(1)];
    for r in 0..n {
        let k = p.kind[r];
        if k & K_IN_USE == 0 || k & K_DIR != 0 || k & K_NAMED == 0 {
            continue;
        }
        let par = p.parent[r] as usize;
        if par >= n || !is_dir(par) {
            continue;
        }
        own_size[par] += p.size[r];
        own_files[par] += 1;
        let e = &mut ext_stats[p.ext[r] as usize];
        e.0 += p.size[r];
        e.1 += 1;
    }

    // Folder tree as first-child / next-sibling links.
    let mut first_child = vec![u32::MAX; n];
    let mut next_sib = vec![u32::MAX; n];
    let root = ROOT_RECORD as usize;
    if root >= n || !is_dir(root) {
        return Err("No se encontró la carpeta raíz en la MFT".into());
    }
    for r in 0..n {
        if r == root || !is_dir(r) {
            continue;
        }
        let par = p.parent[r] as usize;
        if par >= n || par == r || !is_dir(par) {
            continue;
        }
        next_sib[r] = first_child[par];
        first_child[par] = r as u32;
    }

    // Post-order totals (iterative to survive deep trees).
    let mut tot_size = own_size.clone();
    let mut tot_files: Vec<u64> = own_files.iter().map(|&f| f as u64).collect();
    let mut tot_dirs = vec![0u64; n];
    let mut order = Vec::new();
    let mut visited = vec![false; n];
    let mut stack = vec![root];
    visited[root] = true;
    while let Some(d) = stack.pop() {
        order.push(d);
        let mut c = first_child[d];
        while c != u32::MAX {
            let ci = c as usize;
            if !visited[ci] {
                visited[ci] = true;
                stack.push(ci);
            }
            c = next_sib[ci];
        }
    }
    for &d in order.iter().rev() {
        if d == root {
            continue;
        }
        let par = p.parent[d] as usize;
        tot_size[par] += tot_size[d];
        tot_files[par] += tot_files[d];
        tot_dirs[par] += tot_dirs[d] + 1;
    }

    // Arena in BFS order with children sorted by size.
    let root_path = PathBuf::from(format!("{letter}:\\"));
    let mut nodes: Vec<Node> = Vec::with_capacity(order.len());
    let mut rec_of: Vec<usize> = Vec::with_capacity(order.len());
    nodes.push(Node {
        name: format!("{letter}:\\").into_boxed_str(),
        parent: NO_PARENT,
        children: Vec::new(),
        size: tot_size[root],
        files: tot_files[root],
        dirs: tot_dirs[root],
        own_size: own_size[root],
        own_files: own_files[root] as u64,
        mtime: 0,
        denied: false,
        skipped: false,
    });
    rec_of.push(root);
    let mut q = 0usize;
    while q < nodes.len() {
        let rec = rec_of[q];
        let mut kids = Vec::new();
        let mut c = first_child[rec];
        while c != u32::MAX {
            if visited[c as usize] {
                kids.push(c as usize);
            }
            c = next_sib[c as usize];
        }
        kids.sort_unstable_by(|a, b| tot_size[*b].cmp(&tot_size[*a]));
        let mut ids = Vec::with_capacity(kids.len());
        for k in kids {
            let id = nodes.len() as u32;
            let (name, mtime) = p
                .dir_names
                .get(&(k as u32))
                .map(|(n, m)| (n.clone(), *m))
                .unwrap_or_else(|| (format!("#{k}").into_boxed_str(), 0));
            nodes.push(Node {
                name,
                parent: q as u32,
                children: Vec::new(),
                size: tot_size[k],
                files: tot_files[k],
                dirs: tot_dirs[k],
                own_size: own_size[k],
                own_files: own_files[k] as u64,
                mtime,
                denied: false,
                skipped: false,
            });
            rec_of.push(k);
            ids.push(id);
        }
        nodes[q].children = ids;
        q += 1;
    }

    // Paths for the largest files, rebuilt from folder names.
    let dir_path = |mut r: usize| -> Option<String> {
        let mut parts = Vec::new();
        let mut guard = 0;
        while r != root {
            let (name, _) = p.dir_names.get(&(r as u32))?;
            parts.push(name.as_ref());
            r = p.parent[r] as usize;
            guard += 1;
            if guard > 4096 || r >= n {
                return None;
            }
        }
        parts.reverse();
        Some(format!("{letter}:\\{}", parts.join("\\")))
    };
    let top_files = p
        .top
        .into_sorted_vec()
        .into_iter()
        .filter_map(|Reverse((size, rec, name, mtime))| {
            let par = p.parent[rec as usize] as usize;
            let base = dir_path(par)?;
            let path = if base.ends_with('\\') { format!("{base}{name}") } else { format!("{base}\\{name}") };
            Some(FileDto { name, path, size, mtime: filetime_to_unix(mtime) })
        })
        .collect();

    let mut exts: Vec<ExtStat> = ext_stats
        .into_iter()
        .enumerate()
        .filter(|(_, (_, c))| *c > 0)
        .map(|(i, (size, count))| ExtStat { ext: p.ext_names.get(i).cloned().unwrap_or_default(), size, count })
        .collect();
    exts.sort_unstable_by(|a, b| b.size.cmp(&a.size));
    exts.truncate(80);

    Ok(Scan {
        root: root_path,
        nodes,
        top_files,
        exts,
        errors: 0,
        elapsed_ms: start.elapsed().as_millis() as u64,
        method: "mft",
    })
}

#[doc(hidden)]
pub fn diag(letter: char) -> String {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, SetFilePointerEx, FILE_BEGIN, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    let mut out = String::new();
    let path = crate::util::wide(&format!(r"\\.\{letter}:"));
    for (label, flags) in [("nobuf", FILE_FLAG_NO_BUFFERING), ("buffered", 0u32)] {
        let h = unsafe {
            CreateFileW(path.as_ptr(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(), OPEN_EXISTING, flags, std::ptr::null_mut())
        };
        if h == INVALID_HANDLE_VALUE {
            out += &format!("{label}: open err {}\n", std::io::Error::last_os_error());
            continue;
        }
        for size in [512usize, 4096] {
            let mut buf = AlignedBuf::new(4096);
            let mut got = 0u32;
            let ok = unsafe {
                SetFilePointerEx(h, 0, std::ptr::null_mut(), FILE_BEGIN);
                ReadFile(h, buf.ptr, size as u32, &mut got, std::ptr::null_mut())
            };
            let e = std::io::Error::last_os_error();
            out += &format!("{label} ReadFile {size}: ok={ok} got={got} sig={:?} err={e}\n", String::from_utf8_lossy(&buf.as_mut()[3..11]));
        }
        let f = unsafe { <File as std::os::windows::io::FromRawHandle>::from_raw_handle(h as _) };
        let mut buf = AlignedBuf::new(4096);
        out += &format!("{label} seek_read: {:?}\n", f.seek_read(buf.as_mut(), 0).map_err(|e| e.to_string()));
        let mut vd = [0u8; 128];
        let mut got = 0u32;
        let ok = unsafe {
            DeviceIoControl(f.as_raw_handle() as _, 0x0009_0064, std::ptr::null(), 0, vd.as_mut_ptr() as _, 128, &mut got, std::ptr::null_mut())
        };
        out += &format!("{label} FSCTL_GET_NTFS_VOLUME_DATA ok={ok} got={got} err={} bpc={} rec={} mftlcn={} mftvalid={}\n",
            std::io::Error::last_os_error(), rd32(&vd, 0x2C), rd32(&vd, 0x30), rd64(&vd, 0x40), rd64(&vd, 0x38));
    }
    out
}

#[doc(hidden)]
pub fn diag2(letter: char) -> String {
    let mut out = String::new();
    let vol = match open_volume(letter) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // 1) FILE_LAYOUT with minimal flags
    for flags in [QFL_RESTART | QFL_INCLUDE_NAMES, QFL_RESTART] {
        let mut input = [0u8; 32];
        input[4..8].copy_from_slice(&flags.to_le_bytes());
        let mut o = vec![0u8; 1 << 20];
        let r = ioctl(&vol, FSCTL_QUERY_FILE_LAYOUT, &input, &mut o);
        out += &format!("FILE_LAYOUT flags={flags:#x}: {:?} count={}\n", r.as_ref().map_err(|e| e.to_string()), rd32(&o, 0));
    }
    // 2) ENUM_USN_DATA
    {
        let mut input = [0u8; 24];
        input[16..24].copy_from_slice(&i64::MAX.to_le_bytes());
        let mut o = vec![0u8; 1 << 16];
        let r = ioctl(&vol, 0x0009_00B3, &input, &mut o);
        out += &format!("ENUM_USN_DATA: {:?}\n", r.map_err(|e| e.to_string()));
    }
    // 3) GET_NTFS_FILE_RECORD on a sample, parsed with the raw parser
    let mut vd = [0u8; 128];
    let _ = ioctl(&vol, FSCTL_GET_NTFS_VOLUME_DATA, &[], &mut vd);
    let total = (rd64(&vd, 0x38) / rd32(&vd, 0x30).max(512) as u64) as usize;
    let mut p = Parsed::new(total);
    let mut ok_reads = 0;
    let mut fix_fail = 0;
    let mut first_err = None;
    let mut no: u64 = total as u64 - 1;
    let t = Instant::now();
    loop {
        let mut o = vec![0u8; 12 + 4096];
        match ioctl(&vol, 0x0009_0068, &no.to_le_bytes(), &mut o) {
            Ok(_) => {
                let got_no = rd64(&o, 0) & 0xFFFF_FFFF_FFFF;
                let len = rd32(&o, 8) as usize;
                let mut rec = o[12..12 + len.min(4096)].to_vec();
                ok_reads += 1;
                let before = p.kind[got_no as usize];
                p.parse_with(&mut rec, got_no as u32, false);
                if p.kind[got_no as usize] == before {
                    fix_fail += 1;
                }
                if got_no == 0 {
                    break;
                }
                no = got_no - 1;
            }
            Err(e) => {
                first_err.get_or_insert(e.to_string());
                if no == 0 {
                    break;
                }
                no -= 1;
            }
        }
        if t.elapsed().as_secs() > 400 {
            break;
        }
    }
    let dirs = p.kind.iter().filter(|k| **k & K_DIR != 0).count();
    let named = p.kind.iter().filter(|k| **k & K_NAMED != 0).count();
    out += &format!(
        "GET_NTFS_FILE_RECORD: reads={ok_reads} unparsed={fix_fail} err={first_err:?} in {} ms; dirs={dirs} named={named} root_name={:?}\n",
        t.elapsed().as_millis(),
        p.dir_names.get(&5).map(|d| d.0.to_string())
    );
    let mut sample: Vec<_> = p.dir_names.iter().take(8).map(|(k, v)| format!("{k}:{}<-{}", v.0, p.parent[*k as usize])).collect();
    sample.sort();
    out += &format!("sample dirs: {sample:?}\n");
    let big: Vec<_> = p.top.iter().take(5).map(|r| format!("{} {}", r.0 .2, r.0 .0)).collect();
    out += &format!("top files sample: {big:?}\n");
    p.finalize();
    match build_scan(p, letter, t) {
        Ok(scan) => {
            let root = &scan.nodes[0];
            out += &format!("TREE: size={} files={} dirs={} nodes={}\n", root.size, root.files, root.dirs, scan.nodes.len());
            for &c in root.children.iter().take(8) {
                let n = &scan.nodes[c as usize];
                out += &format!("  {} = {} ({} files)\n", n.name, n.size, n.files);
            }
            for f in scan.top_files.iter().take(5) {
                out += &format!("  top: {} {}\n", f.size, f.path);
            }
            for e in scan.exts.iter().take(5) {
                out += &format!("  ext: {} {} ({})\n", e.ext, e.size, e.count);
            }
        }
        Err(e) => out += &format!("build_scan error: {e}\n"),
    }
    out
}

