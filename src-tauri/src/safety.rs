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
