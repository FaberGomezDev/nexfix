//! Remediation of security findings: closes processes, moves files into a
//! restorable quarantine, removes persistence (keeping backups) and stores
//! the user's ignore list. Nothing here runs until the user confirms.
//!
//! Two stores: elevated runs write to `%ProgramData%\NexFix\Cuarentena`
//! (entries are trusted only if owned by Administrators/SYSTEM, so malware
//! running as the user cannot plant a "backup" for an elevated restore);
//! standard runs write to `%LOCALAPPDATA%\NexFix\Cuarentena` and can only
//! restore into the user's own profile and HKCU.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ};
use winreg::{RegKey, RegValue};

use crate::analyzer::{io_error_es, remove_file_force};
use crate::security::{hosts_path, norm, ExclKind, Finding, FixStep, Places};
use crate::util::{decode_console, display_path, env_path, hidden_command, long_path, now_unix, wide};

static LOCK: Mutex<()> = Mutex::new(());
static COUNTER: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Store {
    User,
    Admin,
}

fn store_dir(store: Store) -> Option<PathBuf> {
    match store {
        Store::User => env_path("LOCALAPPDATA").map(|p| p.join(r"NexFix\Cuarentena")),
        Store::Admin => env_path("ProgramData").map(|p| p.join(r"NexFix\Cuarentena")),
    }
}

fn current_store() -> Store {
    if crate::elevation::is_elevated() { Store::Admin } else { Store::User }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct QEntry {
    pub id: String,
    /// "file" | "reg" | "task" | "service" | "exclusion" | "hosts"
    pub kind: String,
    /// Title of the finding that produced it.
    pub title: String,
    /// What it was: path, registry value, task name...
    pub original: String,
    pub stored: Option<String>,
    pub size: u64,
    pub date: i64,
    #[serde(default)]
    pub data: serde_json::Value,
    /// Lives in the administrator store (restoring needs admin).
    #[serde(default)]
    pub admin: bool,
}

fn index_path(store: Store) -> Option<PathBuf> {
    store_dir(store).map(|d| d.join("indice.json"))
}

fn load(store: Store) -> Vec<QEntry> {
    let Some(path) = index_path(store) else { return Vec::new() };
    if !path.exists() || (store == Store::Admin && !crate::safety::owned_by_admins(&path)) {
        return Vec::new();
    }
    let mut v: Vec<QEntry> = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    for e in &mut v {
        e.admin = store == Store::Admin;
    }
    v
}

fn save(store: Store, entries: &[QEntry]) -> Result<(), String> {
    let path = index_path(store).ok_or("No se encontró la carpeta de datos")?;
    let tmp = path.with_extension("tmp");
    let data = serde_json::to_vec_pretty(entries).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, data).map_err(|e| format!("No se pudo guardar la cuarentena: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("No se pudo guardar la cuarentena: {e}"))
}

fn ensure_dir(store: Store) -> Result<PathBuf, String> {
    let dir = store_dir(store).ok_or("No se encontró la carpeta de datos")?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("No se pudo crear la carpeta de cuarentena: {e}"))?;
    Ok(dir)
}

fn new_id(store: Store) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed) % 1000;
    format!("{}{}{n:03}", if store == Store::Admin { "a" } else { "u" }, now_unix())
}

fn push(store: Store, entry: QEntry) -> Result<(), String> {
    let _g = LOCK.lock();
    let mut v = load(store);
    v.push(entry);
    save(store, &v)
}

pub fn list() -> Vec<QEntry> {
    let _g = LOCK.lock();
    let mut v = load(Store::User);
    v.extend(load(Store::Admin));
    v.sort_by(|a, b| b.date.cmp(&a.date));
    v
}

// ---------- Ignore list ----------

#[derive(Serialize, Deserialize, Default)]
struct Prefs {
    #[serde(default)]
    ignored: Vec<String>,
}

fn prefs_path() -> Option<PathBuf> {
    env_path("LOCALAPPDATA").map(|p| p.join(r"NexFix\seguridad.json"))
}

fn load_prefs() -> Prefs {
    prefs_path()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

pub fn ignored() -> HashSet<String> {
    load_prefs().ignored.into_iter().collect()
}

pub fn set_ignored(key: &str, ignore: bool) -> Result<(), String> {
    let _g = LOCK.lock();
    let mut prefs = load_prefs();
    prefs.ignored.retain(|k| k != key);
    if ignore {
        prefs.ignored.push(key.to_string());
    }
    let path = prefs_path().ok_or("No se encontró la carpeta de datos")?;
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let data = serde_json::to_vec_pretty(&prefs).map_err(|e| e.to_string())?;
    std::fs::write(path, data).map_err(|e| format!("No se pudo guardar la preferencia: {e}"))
}

// ---------- Fix ----------

#[derive(Serialize)]
pub struct StepResult {
    pub text: String,
    pub ok: bool,
    pub message: String,
}

#[derive(Serialize)]
pub struct FixItem {
    pub id: String,
    pub title: String,
    pub ok: bool,
    pub steps: Vec<StepResult>,
}

#[derive(Serialize, Default)]
pub struct FixReport {
    pub items: Vec<FixItem>,
    pub fixed: usize,
    pub failed: usize,
    pub reboot: bool,
    pub freed: u64,
}

struct Ctx {
    store: Store,
    elevated: bool,
    places: Places,
    /// Files already moved in this run (a miner can appear as a process and
    /// as a startup entry).
    done: HashSet<String>,
    reboot: bool,
    freed: u64,
}

const ADMIN_NEEDED: &str = "Necesita permisos de administrador: reinicia NexFix como administrador";

fn image_path(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

fn pids_with_exe(target: &str) -> Vec<u32> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing().with_exe(UpdateKind::Always));
    sys.processes()
        .iter()
        .filter(|(_, p)| p.exe().is_some_and(|e| norm(e) == target))
        .map(|(pid, _)| pid.as_u32())
        .collect()
}

/// Critical Windows processes: killing them crashes or locks the session.
fn is_critical(places: &Places, path: &str) -> bool {
    let p = path.to_lowercase();
    let name = p.rsplit('\\').next().unwrap_or("").trim_end_matches(".exe").to_string();
    p.starts_with(&format!("{}\\", places.windir))
        && matches!(name.as_str(), "csrss" | "wininit" | "smss" | "lsass" | "services" | "winlogon" | "lsaiso" | "dwm" | "svchost" | "fontdrvhost" | "sihost")
}

fn terminate(pid: u32) -> Result<bool, String> {
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, pid);
        if h.is_null() {
            let e = std::io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(87) => Ok(false), // Already gone.
                Some(5) => Err(ADMIN_NEEDED.into()),
                _ => Err(e.to_string()),
            };
        }
        let ok = TerminateProcess(h, 1);
        let err = std::io::Error::last_os_error();
        if ok != 0 {
            WaitForSingleObject(h, 3000);
        }
        CloseHandle(h);
        if ok != 0 {
            Ok(true)
        } else if err.raw_os_error() == Some(5) {
            Err(ADMIN_NEEDED.into())
        } else {
            Err(err.to_string())
        }
    }
}

fn kill(ctx: &Ctx, pids: &[u32], exe: Option<&Path>) -> Result<String, String> {
    let target = exe.map(norm);
    let me = std::process::id();
    let mut killed = 0;
    let mut first_err = None;
    // Watchdog pairs relaunch each other: sweep a few times.
    for round in 0..3 {
        let mut victims: Vec<u32> = if round == 0 { pids.to_vec() } else { Vec::new() };
        if let Some(t) = &target {
            victims.extend(pids_with_exe(t));
        }
        victims.sort_unstable();
        victims.dedup();
        victims.retain(|&p| p > 4 && p != me);
        if victims.is_empty() {
            break;
        }
        let mut any = false;
        for pid in victims {
            let current = image_path(pid);
            if let (Some(cur), Some(t)) = (&current, &target) {
                if norm(Path::new(cur)) != *t {
                    continue; // The PID now belongs to another program.
                }
            }
            if current.as_deref().is_some_and(|c| is_critical(&ctx.places, c)) {
                first_err.get_or_insert_with(|| "Es un proceso crítico de Windows: usa el análisis sin conexión de Microsoft Defender".to_string());
                continue;
            }
            match terminate(pid) {
                Ok(true) => {
                    killed += 1;
                    any = true;
                }
                Ok(false) => {}
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        if !any {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
    match (killed, first_err) {
        (0, Some(e)) => Err(e),
        (0, None) => Ok("No se estaba ejecutando".into()),
        (n, _) => Ok(if n == 1 { "Proceso cerrado".into() } else { format!("{n} procesos cerrados") }),
    }
}

fn move_file(src: &Path, dest: &Path) -> std::io::Result<()> {
    let (s, d) = (long_path(src), long_path(dest));
    let mut last = None;
    for _ in 0..8 {
        match std::fs::rename(&s, &d) {
            Ok(()) => return Ok(()),
            // ERROR_NOT_SAME_DEVICE: copy and delete instead.
            Err(e) if e.raw_os_error() == Some(17) => {
                std::fs::copy(&s, &d)?;
                return remove_file_force(src).inspect_err(|_| {
                    let _ = std::fs::remove_file(&d);
                });
            }
            Err(e) => {
                last = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("error desconocido")))
}

/// A renamed file keeps its old owner and ACL, so whoever could write it
/// before still could. In the administrator store, reset it to the folder's
/// inherited ACL and make Administrators the owner.
fn lock_down(path: &Path) {
    let _ = hidden_command("icacls.exe").arg(path).args(["/reset", "/C", "/Q"]).output();
    let _ = hidden_command("icacls.exe").arg(path).args(["/setowner", "*S-1-5-32-544", "/C", "/Q"]).output();
}

fn quarantine(ctx: &mut Ctx, path: &Path, title: &str) -> Result<String, String> {
    let real = crate::safety::real_path(path);
    let key = norm(&real);
    if ctx.done.contains(&key) {
        return Ok("Ya se movió a la cuarentena".into());
    }
    let md = std::fs::symlink_metadata(long_path(&real)).map_err(|_| "El archivo ya no existe".to_string())?;
    crate::safety::check_security_target(&real)?;
    let sig = crate::sign::verify(&real);
    if sig.by_microsoft() {
        return Err("Está firmado por Microsoft: NexFix no lo mueve. Si crees que es malicioso, usa Microsoft Defender.".into());
    }
    let dir = ensure_dir(ctx.store)?;
    let id = new_id(ctx.store);
    let stored = format!("{id}.cuarentena");
    match move_file(&real, &dir.join(&stored)) {
        Ok(()) => {
            if ctx.store == Store::Admin {
                lock_down(&dir.join(&stored));
            }
            ctx.done.insert(key);
            push(
                ctx.store,
                QEntry {
                    id,
                    kind: "file".into(),
                    title: title.into(),
                    original: display_path(&real),
                    stored: Some(stored),
                    size: md.len(),
                    date: now_unix(),
                    data: json!({ "signer": sig.signer }),
                    admin: ctx.store == Store::Admin,
                },
            )?;
            Ok("Movido a la cuarentena".into())
        }
        Err(e) => {
            // Still locked (e.g. a driver or a protected process): delete on reboot.
            if ctx.elevated && unsafe { MoveFileExW(wide(&real).as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) } != 0 {
                ctx.done.insert(key);
                ctx.reboot = true;
                return Ok("Está en uso: se eliminará al reiniciar el PC (no se podrá restaurar)".into());
            }
            Err(if e.kind() == std::io::ErrorKind::PermissionDenied && !ctx.elevated { ADMIN_NEEDED.into() } else { io_error_es(&e) })
        }
    }
}

fn hive(machine: bool) -> RegKey {
    RegKey::predef(if machine { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER })
}

fn reg_string(value: &str, expand: bool) -> RegValue<'static> {
    let mut bytes: Vec<u8> = value.encode_utf16().chain(std::iter::once(0)).flat_map(|u| u.to_le_bytes()).collect();
    bytes.shrink_to_fit();
    RegValue { bytes: bytes.into(), vtype: if expand { REG_EXPAND_SZ } else { REG_SZ } }
}

fn reg_change(ctx: &Ctx, machine: bool, subkey: &str, name: &str, new: Option<&str>, title: &str) -> Result<String, String> {
    let key = hive(machine)
        .open_subkey_with_flags(subkey, KEY_READ | KEY_SET_VALUE | KEY_WOW64_64KEY)
        .map_err(|e| if e.kind() == std::io::ErrorKind::PermissionDenied { ADMIN_NEEDED.to_string() } else { e.to_string() })?;
    let old = key.get_raw_value(name).ok();
    let (old_str, old_type) = match &old {
        Some(v) => (Some(v.to_string()), if matches!(v.vtype, REG_EXPAND_SZ) { "expand" } else { "sz" }),
        None => (None, "absent"),
    };
    let res = match new {
        None => key.delete_value(name),
        Some(v) => key.set_raw_value(name, &reg_string(v, old_type == "expand")),
    };
    res.map_err(|e| if e.kind() == std::io::ErrorKind::PermissionDenied { ADMIN_NEEDED.to_string() } else { e.to_string() })?;
    let store = if machine { Store::Admin } else { ctx.store };
    ensure_dir(store)?;
    push(
        store,
        QEntry {
            id: new_id(store),
            kind: "reg".into(),
            title: title.into(),
            original: format!(r"{}\{subkey}\{name}", if machine { "HKLM" } else { "HKCU" }),
            stored: None,
            size: 0,
            date: now_unix(),
            data: json!({ "machine": machine, "subkey": subkey, "name": name, "old": old_str, "type": old_type }),
            admin: store == Store::Admin,
        },
    )?;
    Ok(if new.is_none() { "Entrada quitada".into() } else { "Valor restablecido".into() })
}

fn delete_task(ctx: &Ctx, name: &str, xml: &Path, title: &str) -> Result<String, String> {
    if !ctx.elevated {
        return Err(ADMIN_NEEDED.into());
    }
    let dir = ensure_dir(Store::Admin)?;
    let id = new_id(Store::Admin);
    let stored = format!("{id}.xml");
    std::fs::copy(long_path(xml), dir.join(&stored)).map_err(|e| format!("No se pudo copiar la tarea: {}", io_error_es(&e)))?;
    let out = hidden_command("schtasks.exe")
        .args(["/Delete", "/TN", name, "/F"])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        let _ = std::fs::remove_file(dir.join(&stored));
        let msg = decode_console(&out.stderr);
        return Err(msg.trim().lines().next().unwrap_or("schtasks devolvió un error").to_string());
    }
    push(
        Store::Admin,
        QEntry {
            id,
            kind: "task".into(),
            title: title.into(),
            original: name.into(),
            stored: Some(stored),
            size: 0,
            date: now_unix(),
            data: json!({ "name": name }),
            admin: true,
        },
    )?;
    Ok("Tarea eliminada".into())
}

fn disable_service(ctx: &Ctx, name: &str, title: &str) -> Result<String, String> {
    if !ctx.elevated {
        return Err(ADMIN_NEEDED.into());
    }
    let key = hive(true)
        .open_subkey_with_flags(format!(r"SYSTEM\CurrentControlSet\Services\{name}"), KEY_READ | KEY_SET_VALUE)
        .map_err(|e| format!("No se pudo abrir el servicio: {e}"))?;
    let old: u32 = key.get_value("Start").unwrap_or(3);
    key.set_value("Start", &4u32).map_err(|e| format!("No se pudo deshabilitar: {e}"))?;
    let _ = hidden_command("sc.exe").args(["stop", name]).output();
    ensure_dir(Store::Admin)?;
    push(
        Store::Admin,
        QEntry {
            id: new_id(Store::Admin),
            kind: "service".into(),
            title: title.into(),
            original: name.into(),
            stored: None,
            size: 0,
            date: now_unix(),
            data: json!({ "name": name, "start": old }),
            admin: true,
        },
    )?;
    Ok("Servicio detenido y deshabilitado".into())
}

/// Runs a fixed PowerShell script; the only variable input travels in the
/// NEXFIX_ARG environment variable, never inside the script text.
fn powershell(script: &str, arg: &str) -> Result<(), String> {
    let out = hidden_command("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
        .env("NEXFIX_ARG", arg)
        .output()
        .map_err(|e| format!("No se pudo ejecutar PowerShell: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = decode_console(&out.stderr);
    Err(err.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("PowerShell devolvió un error").to_string())
}

fn exclusion_param(kind: ExclKind) -> &'static str {
    match kind {
        ExclKind::Path => "-ExclusionPath",
        ExclKind::Process => "-ExclusionProcess",
        ExclKind::Extension => "-ExclusionExtension",
    }
}

fn remove_exclusion(ctx: &Ctx, kind: ExclKind, value: &str, title: &str) -> Result<String, String> {
    if !ctx.elevated {
        return Err(ADMIN_NEEDED.into());
    }
    powershell(&format!("Remove-MpPreference {} $env:NEXFIX_ARG -ErrorAction Stop", exclusion_param(kind)), value)?;
    ensure_dir(Store::Admin)?;
    push(
        Store::Admin,
        QEntry {
            id: new_id(Store::Admin),
            kind: "exclusion".into(),
            title: title.into(),
            original: value.into(),
            stored: None,
            size: 0,
            date: now_unix(),
            data: json!({ "kind": kind }),
            admin: true,
        },
    )?;
    Ok("Exclusión quitada".into())
}

fn remove_wmi(ctx: &Ctx, name: &str) -> Result<String, String> {
    if !ctx.elevated {
        return Err(ADMIN_NEEDED.into());
    }
    const SCRIPT: &str = "$n = $env:NEXFIX_ARG; $ns = 'root/subscription'; \
        Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | \
          Where-Object { $_.Consumer.Name -eq $n } | ForEach-Object { \
            $f = $_.Filter.Name; Remove-CimInstance -InputObject $_; \
            Get-CimInstance -Namespace $ns -ClassName __EventFilter | Where-Object Name -eq $f | Remove-CimInstance }; \
        foreach ($c in 'CommandLineEventConsumer','ActiveScriptEventConsumer') { \
          Get-CimInstance -Namespace $ns -ClassName $c -ErrorAction SilentlyContinue | Where-Object Name -eq $n | Remove-CimInstance }";
    powershell(SCRIPT, name)?;
    Ok("Suscripción WMI eliminada".into())
}

fn comment_hosts(ctx: &Ctx, lines: &[String], title: &str) -> Result<String, String> {
    if !ctx.elevated {
        return Err(ADMIN_NEEDED.into());
    }
    let path = hosts_path(&ctx.places);
    let bytes = std::fs::read(&path).map_err(|e| io_error_es(&e))?;
    let dir = ensure_dir(Store::Admin)?;
    let id = new_id(Store::Admin);
    let stored = format!("{id}.hosts");
    std::fs::write(dir.join(&stored), &bytes).map_err(|e| io_error_es(&e))?;

    let bad: HashSet<&str> = lines.iter().map(|l| l.trim()).collect();
    let text = String::from_utf8_lossy(&bytes);
    let mut changed = 0;
    let out: Vec<String> = text
        .lines()
        .map(|l| {
            let l = l.trim_end_matches('\r');
            if bad.contains(l.trim()) {
                changed += 1;
                format!("# [NexFix] {l}")
            } else {
                l.to_string()
            }
        })
        .collect();
    let md = std::fs::metadata(&path).map_err(|e| io_error_es(&e))?;
    let readonly = md.permissions().readonly();
    if readonly {
        let mut p = md.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        p.set_readonly(false);
        let _ = std::fs::set_permissions(&path, p);
    }
    let result = std::fs::write(&path, out.join("\r\n") + "\r\n").map_err(|e| io_error_es(&e));
    if readonly {
        if let Ok(md) = std::fs::metadata(&path) {
            let mut p = md.permissions();
            p.set_readonly(true);
            let _ = std::fs::set_permissions(&path, p);
        }
    }
    if let Err(e) = result {
        let _ = std::fs::remove_file(dir.join(&stored));
        return Err(e);
    }
    push(
        Store::Admin,
        QEntry {
            id,
            kind: "hosts".into(),
            title: title.into(),
            original: display_path(&path),
            stored: Some(stored),
            size: bytes.len() as u64,
            date: now_unix(),
            data: json!({ "lines": changed }),
            admin: true,
        },
    )?;
    let _ = hidden_command("ipconfig.exe").arg("/flushdns").output();
    Ok(format!("{changed} líneas desactivadas"))
}

fn delete_files(ctx: &mut Ctx, paths: &[PathBuf]) -> Result<String, String> {
    let mut deleted = 0u64;
    let mut freed = 0u64;
    let mut first_err = None;
    for p in paths {
        if let Err(e) = crate::safety::check_security_target(p) {
            first_err.get_or_insert(e);
            continue;
        }
        let real = crate::safety::real_path(p);
        let size = std::fs::symlink_metadata(long_path(&real)).map(|m| m.len()).unwrap_or(0);
        match remove_file_force(&real) {
            Ok(()) => {
                deleted += 1;
                freed += size;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                first_err.get_or_insert_with(|| {
                    if e.kind() == std::io::ErrorKind::PermissionDenied && !ctx.elevated { ADMIN_NEEDED.into() } else { io_error_es(&e) }
                });
            }
        }
    }
    ctx.freed += freed;
    match (deleted, first_err) {
        (0, Some(e)) => Err(e),
        (n, _) => Ok(format!("{n} archivos eliminados ({:.1} MB)", freed as f64 / 1_048_576.0)),
    }
}

fn run_step(ctx: &mut Ctx, step: &FixStep, title: &str) -> Result<String, String> {
    match step {
        FixStep::Kill { pids, exe } => kill(ctx, pids, exe.as_deref()),
        FixStep::Quarantine { path } => quarantine(ctx, path, title),
        FixStep::DeleteRegValue { machine, subkey, name } => reg_change(ctx, *machine, subkey, name, None, title),
        FixStep::SetRegValue { machine, subkey, name, value } => reg_change(ctx, *machine, subkey, name, Some(value), title),
        FixStep::DeleteTask { name, xml } => delete_task(ctx, name, xml, title),
        FixStep::DisableService { name } => disable_service(ctx, name, title),
        FixStep::RemoveWmi { name } => remove_wmi(ctx, name),
        FixStep::RemoveExclusion { kind, value } => remove_exclusion(ctx, *kind, value, title),
        FixStep::CommentHosts { lines } => comment_hosts(ctx, lines, title),
        FixStep::DeleteFiles { paths } => delete_files(ctx, paths),
    }
}

/// Applies the fix plan of each finding, in order. A failed step does not
/// stop the rest (killing may fail while removing the startup entry works).
pub fn fix(findings: Vec<Finding>) -> FixReport {
    let elevated = crate::elevation::is_elevated();
    let mut ctx = Ctx {
        store: current_store(),
        elevated,
        places: Places::new(),
        done: HashSet::new(),
        reboot: false,
        freed: 0,
    };
    let mut report = FixReport::default();
    for f in findings {
        let mut steps = Vec::new();
        for step in &f.steps {
            let (ok, message) = match run_step(&mut ctx, step, &f.title) {
                Ok(m) => (true, m),
                Err(e) => (false, e),
            };
            steps.push(StepResult { text: step.describe(), ok, message });
        }
        let ok = !steps.is_empty() && steps.iter().all(|s| s.ok);
        if ok {
            report.fixed += 1;
        } else {
            report.failed += 1;
        }
        report.items.push(FixItem { id: f.id, title: f.title, ok, steps });
    }
    report.reboot = ctx.reboot;
    report.freed = ctx.freed;
    report
}

// ---------- Restore / delete ----------

const RESTORABLE_KEYS: &[&str] = &[
    r"software\microsoft\windows\currentversion\run",
    r"software\wow6432node\microsoft\windows\currentversion\run",
    r"software\microsoft\windows\currentversion\policies\explorer\run",
    r"software\microsoft\windows nt\currentversion\winlogon",
    r"software\microsoft\windows nt\currentversion\image file execution options\",
    r"software\microsoft\windows nt\currentversion\windows",
];

fn take_entry(id: &str) -> Result<(Store, QEntry), String> {
    let store = if id.starts_with('a') { Store::Admin } else { Store::User };
    let entry = load(store).into_iter().find(|e| e.id == id).ok_or("Ya no está en la cuarentena")?;
    Ok((store, entry))
}

fn drop_entry(store: Store, id: &str) -> Result<(), String> {
    let mut v = load(store);
    if let Some(pos) = v.iter().position(|e| e.id == id) {
        let e = v.remove(pos);
        if let (Some(stored), Some(dir)) = (&e.stored, store_dir(store)) {
            let _ = remove_file_force(&dir.join(stored));
        }
        save(store, &v)?;
    }
    Ok(())
}

pub fn restore(id: &str) -> Result<String, String> {
    let _g = LOCK.lock();
    let elevated = crate::elevation::is_elevated();
    let (store, e) = take_entry(id)?;
    if store == Store::Admin && !elevated {
        return Err(ADMIN_NEEDED.into());
    }
    // The user store is writable by anything running as the user: it can
    // only ever hold files and HKCU values, never system-level changes.
    if store == Store::User && !matches!(e.kind.as_str(), "file" | "reg") {
        return Err("Copia de seguridad no válida".into());
    }
    let dir = store_dir(store).ok_or("No se encontró la carpeta de cuarentena")?;
    let stored = e.stored.as_ref().map(|s| dir.join(s));
    if let Some(s) = &stored {
        if store == Store::Admin && !crate::safety::owned_by_admins(s) {
            return Err("La copia de seguridad no es de confianza (no la creó un administrador)".into());
        }
    }
    let str_of = |k: &str| e.data.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let msg = match e.kind.as_str() {
        "file" => {
            let src = stored.ok_or("Falta el archivo en la cuarentena")?;
            let dest = PathBuf::from(&e.original);
            if store == Store::User && elevated && !crate::safety::inside_profile(&dest) {
                return Err("Este archivo solo se puede restaurar sin permisos de administrador".into());
            }
            if dest.exists() {
                return Err("Ya existe un archivo en la ruta original".into());
            }
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(long_path(parent)).map_err(|err| io_error_es(&err))?;
            }
            move_file(&src, &dest).map_err(|err| io_error_es(&err))?;
            // Take the permissions of its original folder again.
            let _ = hidden_command("icacls.exe").arg(&dest).args(["/reset", "/C", "/Q"]).output();
            "Archivo restaurado".to_string()
        }
        "reg" => {
            let machine = e.data.get("machine").and_then(|v| v.as_bool()).unwrap_or(true);
            let subkey = str_of("subkey");
            let name = str_of("name");
            if machine && store != Store::Admin {
                return Err("Copia de seguridad no válida".into());
            }
            let sl = subkey.to_lowercase();
            if !RESTORABLE_KEYS.iter().any(|k| sl == k.trim_end_matches('\\') || sl.starts_with(k) || sl.starts_with(&format!("{k}\\"))) {
                return Err("Clave de registro no permitida".into());
            }
            let key = hive(machine)
                .open_subkey_with_flags(&subkey, KEY_SET_VALUE | KEY_WOW64_64KEY)
                .map_err(|err| if err.kind() == std::io::ErrorKind::PermissionDenied { ADMIN_NEEDED.to_string() } else { err.to_string() })?;
            match (e.data.get("old").and_then(|v| v.as_str()), str_of("type").as_str()) {
                (Some(old), t) => key.set_raw_value(&name, &reg_string(old, t == "expand")),
                (None, _) => key.delete_value(&name),
            }
            .map_err(|err| err.to_string())?;
            "Valor del registro restaurado".to_string()
        }
        "task" => {
            let xml = stored.ok_or("Falta la copia de la tarea")?;
            let out = hidden_command("schtasks.exe")
                .args(["/Create", "/TN", &e.original, "/XML"])
                .arg(&xml)
                .arg("/F")
                .output()
                .map_err(|err| err.to_string())?;
            if !out.status.success() {
                return Err(decode_console(&out.stderr).trim().lines().next().unwrap_or("schtasks devolvió un error").to_string());
            }
            "Tarea restaurada".to_string()
        }
        "service" => {
            let start = e.data.get("start").and_then(|v| v.as_u64()).unwrap_or(3).min(4) as u32;
            let name = str_of("name");
            if name.is_empty() || name.contains(['\\', '/']) {
                return Err("Copia de seguridad no válida".into());
            }
            hive(true)
                .open_subkey_with_flags(format!(r"SYSTEM\CurrentControlSet\Services\{name}"), KEY_SET_VALUE)
                .and_then(|k| k.set_value("Start", &start))
                .map_err(|err| err.to_string())?;
            "Servicio restaurado (se iniciará al reiniciar)".to_string()
        }
        "exclusion" => {
            let kind: ExclKind = serde_json::from_value(e.data.get("kind").cloned().unwrap_or_default()).map_err(|_| "Copia de seguridad no válida")?;
            powershell(&format!("Add-MpPreference {} $env:NEXFIX_ARG -ErrorAction Stop", exclusion_param(kind)), &e.original)?;
            "Exclusión restaurada".to_string()
        }
        "hosts" => {
            let backup = stored.ok_or("Falta la copia del archivo hosts")?;
            let bytes = std::fs::read(&backup).map_err(|err| io_error_es(&err))?;
            std::fs::write(hosts_path(&Places::new()), bytes).map_err(|err| io_error_es(&err))?;
            "Archivo hosts restaurado".to_string()
        }
        _ => return Err("Tipo de elemento desconocido".into()),
    };
    // A restored file left the folder already; drop the entry (and any backup copy).
    if e.kind == "file" {
        let mut v = load(store);
        v.retain(|x| x.id != e.id);
        save(store, &v)?;
    } else {
        drop_entry(store, &e.id)?;
    }
    Ok(msg)
}

pub fn delete(id: &str) -> Result<(), String> {
    let _g = LOCK.lock();
    let (store, _) = take_entry(id)?;
    if store == Store::Admin && !crate::elevation::is_elevated() {
        return Err(ADMIN_NEEDED.into());
    }
    drop_entry(store, id)
}

// ---------- Microsoft Defender ----------

#[derive(Serialize)]
pub struct DefenderScan {
    pub threat: bool,
    pub summary: String,
    pub output: String,
}

/// Scans one file with Microsoft Defender (report only, no remediation).
pub fn defender_scan_file(path: &str) -> Result<DefenderScan, String> {
    let exe = crate::maintenance::mpcmdrun().ok_or("No se encontró Microsoft Defender (MpCmdRun.exe)")?;
    let p = PathBuf::from(path);
    if !long_path(&p).exists() {
        return Err("El archivo ya no existe".into());
    }
    let out = hidden_command(&exe.to_string_lossy())
        .args(["-Scan", "-ScanType", "3", "-File"])
        .arg(&p)
        .arg("-DisableRemediation")
        .output()
        .map_err(|e| format!("No se pudo ejecutar Microsoft Defender: {e}"))?;
    let mut output = decode_console(&out.stdout);
    output.push_str(&decode_console(&out.stderr));
    let code = out.status.code().unwrap_or(-1);
    let (threat, summary) = match code {
        0 => (false, "Microsoft Defender no encontró amenazas en este archivo".to_string()),
        2 => (true, "Microsoft Defender detectó una amenaza en este archivo".to_string()),
        _ => (false, format!("Microsoft Defender no pudo analizarlo (código {code}). ¿Está activo o en modo pasivo por otro antivirus?")),
    };
    Ok(DefenderScan { threat, summary, output: output.trim().to_string() })
}
