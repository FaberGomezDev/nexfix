//! Startup programs (Run keys and Startup folders) with the same
//! enable/disable mechanism Task Manager uses (`StartupApproved`).

use std::path::PathBuf;

use serde::Serialize;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_BINARY};
use winreg::{RegKey, RegValue};

use crate::util::{env_path, now_unix};

const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";

#[derive(Serialize, Clone)]
pub struct StartupItem {
    pub id: String,
    pub name: String,
    pub command: String,
    pub source: String,
    pub machine: bool,
    pub enabled: bool,
}

struct Source {
    key: &'static str,
    machine: bool,
    run_path: Option<&'static str>,
    folder: Option<PathBuf>,
    approved_sub: &'static str,
    label: &'static str,
}

fn sources() -> Vec<Source> {
    let mut v = vec![
        Source {
            key: "hkcu_run",
            machine: false,
            run_path: Some(r"Software\Microsoft\Windows\CurrentVersion\Run"),
            folder: None,
            approved_sub: "Run",
            label: "Registro (usuario)",
        },
        Source {
            key: "hklm_run",
            machine: true,
            run_path: Some(r"Software\Microsoft\Windows\CurrentVersion\Run"),
            folder: None,
            approved_sub: "Run",
            label: "Registro (todos los usuarios)",
        },
        Source {
            key: "hklm_run32",
            machine: true,
            run_path: Some(r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            folder: None,
            approved_sub: "Run32",
            label: "Registro 32 bits",
        },
    ];
    if let Some(appdata) = env_path("APPDATA") {
        v.push(Source {
            key: "user_folder",
            machine: false,
            run_path: None,
            folder: Some(appdata.join(r"Microsoft\Windows\Start Menu\Programs\Startup")),
            approved_sub: "StartupFolder",
            label: "Carpeta Inicio (usuario)",
        });
    }
    if let Some(pd) = env_path("ProgramData") {
        v.push(Source {
            key: "common_folder",
            machine: true,
            run_path: None,
            folder: Some(pd.join(r"Microsoft\Windows\Start Menu\Programs\StartUp")),
            approved_sub: "StartupFolder",
            label: "Carpeta Inicio (todos)",
        });
    }
    v
}

/// Where a startup item lives, for the security scan's removal steps.
pub enum Location {
    Registry { machine: bool, subkey: &'static str, name: String },
    File(PathBuf),
}

pub fn location(id: &str) -> Option<Location> {
    let (key_id, name) = id.split_once('|')?;
    let src = sources().into_iter().find(|s| s.key == key_id)?;
    match (src.run_path, src.folder) {
        (Some(subkey), _) => Some(Location::Registry { machine: src.machine, subkey, name: name.to_string() }),
        (None, Some(folder)) => Some(Location::File(folder.join(name))),
        _ => None,
    }
}

fn root(machine: bool) -> RegKey {
    RegKey::predef(if machine { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER })
}

fn is_enabled(machine: bool, approved_sub: &str, name: &str) -> bool {
    let Ok(key) = root(machine).open_subkey_with_flags(format!(r"{APPROVED}\{approved_sub}"), KEY_READ | KEY_WOW64_64KEY)
    else {
        return true;
    };
    match key.get_raw_value(name) {
        // First byte: 0x02/0x06 enabled, 0x03/0x07 disabled.
        Ok(v) if !v.bytes.is_empty() => v.bytes[0] & 1 == 0,
        _ => true,
    }
}

fn pretty_name(raw: &str) -> String {
    raw.strip_suffix(".lnk").unwrap_or(raw).to_string()
}

pub fn list() -> Vec<StartupItem> {
    let mut items = Vec::new();
    for src in sources() {
        if let Some(run) = src.run_path {
            let Ok(key) = root(src.machine).open_subkey_with_flags(run, KEY_READ | KEY_WOW64_64KEY) else { continue };
            for (name, value) in key.enum_values().flatten() {
                if name.is_empty() {
                    continue;
                }
                let command = value.to_string().trim_matches('"').to_string();
                items.push(StartupItem {
                    id: format!("{}|{}", src.key, name),
                    enabled: is_enabled(src.machine, src.approved_sub, &name),
                    name: pretty_name(&name),
                    command,
                    source: src.label.to_string(),
                    machine: src.machine,
                });
            }
        } else if let Some(folder) = &src.folder {
            let Ok(entries) = std::fs::read_dir(folder) else { continue };
            for e in entries.flatten() {
                let file = e.file_name().to_string_lossy().to_string();
                if file.eq_ignore_ascii_case("desktop.ini") {
                    continue;
                }
                items.push(StartupItem {
                    id: format!("{}|{}", src.key, file),
                    enabled: is_enabled(src.machine, src.approved_sub, &file),
                    name: pretty_name(&file),
                    command: e.path().to_string_lossy().to_string(),
                    source: src.label.to_string(),
                    machine: src.machine,
                });
            }
        }
    }
    items.sort_by_key(|i| i.name.to_lowercase());
    items
}

pub fn set_enabled(id: &str, enabled: bool) -> Result<(), String> {
    let (key_id, name) = id.split_once('|').ok_or("Elemento no válido")?;
    let src = sources().into_iter().find(|s| s.key == key_id).ok_or("Origen no válido")?;
    let (key, _) = root(src.machine)
        .create_subkey_with_flags(format!(r"{APPROVED}\{}", src.approved_sub), KEY_SET_VALUE | KEY_WOW64_64KEY)
        .map_err(|_| {
            if src.machine {
                "Este programa es de todo el equipo: reinicia NexFix como administrador".to_string()
            } else {
                "No se pudo abrir la configuración de inicio".to_string()
            }
        })?;

    let mut bytes = vec![0u8; 12];
    if enabled {
        bytes[0] = 0x02;
    } else {
        bytes[0] = 0x03;
        // FILETIME of when it was disabled, like Task Manager writes.
        let ft = (now_unix() as u64) * 10_000_000 + 116_444_736_000_000_000;
        bytes[4..12].copy_from_slice(&ft.to_le_bytes());
    }
    key.set_raw_value(name, &RegValue { bytes: bytes.into(), vtype: REG_BINARY })
        .map_err(|e| e.to_string())
}
