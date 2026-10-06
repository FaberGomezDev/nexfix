//! Guard rails for user-initiated deletions in the space analyzer: system
//! folders and the roots of well-known folders can never be removed.

use std::path::{Component, Path, PathBuf};

use crate::util::env_path;

fn norm(p: &Path) -> String {
    crate::util::display_path(p)
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

fn protected_roots() -> Vec<PathBuf> {
    let mut v = Vec::new();
    for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PUBLIC", "OneDrive"] {
        if let Some(p) = env_path(var) {
            v.push(p);
        }
    }
    if let Some(home) = env_path("USERPROFILE") {
        for sub in ["Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music", "AppData", "Saved Games"] {
            v.push(home.join(sub));
        }
        if let Some(parent) = home.parent() {
            v.push(parent.to_path_buf());
        }
    }
    v
}

const ROOT_SYSTEM_ENTRIES: &[&str] = &[
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
    "dumpstack.log.tmp",
    "dumpstack.log",
    "system volume information",
    "$recycle.bin",
    "recovery",
    "boot",
    "efi",
    "bootmgr",
    "$windows.~bt",
    "$windows.~ws",
    "$winreagent",
];

pub fn check_deletable(path: &Path) -> Result<(), String> {
    let n = norm(path);
    if !path.is_absolute() {
        return Err("Ruta no válida".into());
    }

    // Drive roots like "c:".
    let parts: Vec<_> = Path::new(&n)
        .components()
        .filter(|c| !matches!(c, Component::RootDir | Component::Prefix(_)))
        .collect();
    if parts.is_empty() {
        return Err("No se puede eliminar la raíz de una unidad".into());
    }

    if let Some(win) = env_path("SystemRoot").or_else(|| env_path("windir")) {
        let w = norm(&win);
        if n == w || n.starts_with(&format!("{w}\\")) {
            return Err("La carpeta de Windows está protegida".into());
        }
    }

    if let Some(pd) = env_path("ProgramData") {
        let c = format!("{}\\microsoft\\windows\\containers", norm(&pd));
        if n == c || n.starts_with(&format!("{c}\\")) {
            return Err("Capas de Windows Sandbox/contenedores: no se borran a mano. Desactiva Windows Sandbox en Mantenimiento".into());
        }
    }

    if parts.len() == 1 {
        let name = parts[0].as_os_str().to_string_lossy().to_lowercase();
        if ROOT_SYSTEM_ENTRIES.contains(&name.as_str()) {
            return Err("Elemento del sistema protegido".into());
        }
    }

    for root in protected_roots() {
        if n == norm(&root) {
            return Err("Esta carpeta del sistema/usuario está protegida (puedes borrar su contenido)".into());
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        let e = norm(&exe);
        if e == n || e.starts_with(&format!("{n}\\")) {
            return Err("No puedes eliminar NexFix mientras se ejecuta".into());
        }
    }
    Ok(())
}

/// Resolves junctions/symlinks so a user-made link cannot redirect an
/// elevated operation into a protected folder.
pub fn real_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(crate::util::long_path(path))
        .map(|p| PathBuf::from(crate::util::display_path(&p)))
        .unwrap_or_else(|_| path.to_path_buf())
}

fn windows_temp() -> Option<String> {
    env_path("SystemRoot").or_else(|| env_path("windir")).map(|w| format!("{}\\temp\\", norm(&w)))
}

/// Files the security module may move to quarantine or delete as junk:
/// like `check_deletable`, but `Windows\Temp` is allowed (malware and the
/// CAB bug live there) and only files qualify.
pub fn check_security_target(path: &Path) -> Result<(), String> {
    let real = real_path(path);
    let n = norm(&real);
    if real.is_dir() {
        return Err("Solo se actúa sobre archivos, no carpetas".into());
    }
    if windows_temp().is_some_and(|t| n.starts_with(&t)) {
        return Ok(());
    }
    check_deletable(&real).map_err(|e| {
        if e.contains("Windows") {
            "Está dentro de la carpeta de Windows: NexFix no lo toca. Usa el análisis sin conexión de Microsoft Defender.".into()
        } else {
            e
        }
    })
}

/// True when the file or folder is owned by Administrators or SYSTEM, so a
/// standard user (or malware running as one) cannot have planted it.
pub fn owned_by_admins(path: &Path) -> bool {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };
    let w = crate::util::wide(path);
    let mut owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let err = unsafe {
        GetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if err != 0 || owner.is_null() {
        return false;
    }
    let ok = unsafe { IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0 || IsWellKnownSid(owner, WinLocalSystemSid) != 0 };
    unsafe { LocalFree(sd) };
    ok
}

/// Destinations an elevated NexFix may restore user-level backups to: only
/// inside the user's own profile (after resolving links).
pub fn inside_profile(path: &Path) -> bool {
    let Some(home) = env_path("USERPROFILE") else { return false };
    let parent = path.parent().map(real_path).unwrap_or_default();
    let h = norm(&home);
    let p = norm(&parent);
    p == h || p.starts_with(&format!("{h}\\"))
}
