//! Built-in Windows maintenance tools (defrag/TRIM, chkdsk, SFC, DISM...)
//! run as hidden child processes with their output streamed to the UI.
//! Commands are fixed here; the UI can only pick a task id and a drive letter.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::sync::Arc;

use parking_lot::Mutex;
use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::util::{decode_bytes, hidden_command, looks_utf16};

#[derive(Serialize, Clone)]
pub struct TaskDef {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub admin: bool,
    pub needs_drive: bool,
    pub duration: &'static str,
    pub category: &'static str,
}

pub fn tasks() -> Vec<TaskDef> {
    vec![
        TaskDef {
            id: "optimize",
            name: "Optimizar unidad",
            description: "Ejecuta TRIM en SSD/NVMe o desfragmenta discos duros. Windows elige el método correcto según el tipo de disco.",
            admin: true,
            needs_drive: true,
            duration: "1-5 min (SSD) · más en HDD",
            category: "Disco",
        },
        TaskDef {
            id: "retrim",
            name: "Forzar ReTrim (SSD/M.2)",
            description: "Informa al SSD de todos los bloques libres para mantener su velocidad de escritura. Nunca desfragmenta.",
            admin: true,
            needs_drive: true,
            duration: "< 1 min",
            category: "Disco",
        },
        TaskDef {
            id: "chkdsk",
            name: "Comprobar errores del sistema de archivos",
            description: "chkdsk /scan: revisa el volumen en línea, sin reiniciar ni bloquear la unidad.",
            admin: true,
            needs_drive: true,
            duration: "1-10 min",
            category: "Disco",
        },
        TaskDef {
            id: "sfc",
            name: "Reparar archivos del sistema (SFC)",
            description: "sfc /scannow: verifica y repara archivos protegidos de Windows dañados.",
            admin: true,
            needs_drive: false,
            duration: "5-20 min",
            category: "Windows",
        },
        TaskDef {
            id: "dism_restore",
            name: "Reparar imagen de Windows (DISM)",
            description: "DISM /RestoreHealth: repara el almacén de componentes que usa SFC. Ejecútalo antes de SFC si SFC no puede reparar.",
            admin: true,
            needs_drive: false,
            duration: "10-30 min",
            category: "Windows",
        },
        TaskDef {
            id: "dism_analyze",
            name: "Analizar almacén de componentes",
            description: "Indica cuánto espacio ocupa WinSxS y si conviene limpiarlo.",
            admin: true,
            needs_drive: false,
            duration: "1-3 min",
            category: "Windows",
        },
        TaskDef {
            id: "dism_cleanup",
            name: "Limpiar componentes antiguos (WinSxS)",
            description: "Elimina versiones viejas de componentes reemplazadas por actualizaciones. Libera espacio de forma segura.",
            admin: true,
            needs_drive: false,
            duration: "5-15 min",
            category: "Windows",
        },
        TaskDef {
            id: "sandbox_off",
            name: "Desactivar Windows Sandbox (capas de contenedores)",
            description: "Quita la característica «Espacio aislado de Windows». Es la forma correcta de liberar ProgramData\\Microsoft\\Windows\\Containers: no borres esas carpetas a mano. Se puede volver a activar en «Características de Windows». Requiere reiniciar.",
            admin: true,
            needs_drive: false,
            duration: "1-3 min",
            category: "Windows",
        },
        TaskDef {
            id: "defender_quick",
            name: "Análisis rápido de Microsoft Defender",
            description: "Revisa la memoria, los procesos en ejecución y los lugares donde se esconde el malware (inicio, carpetas del sistema).",
            admin: true,
            needs_drive: false,
            duration: "2-10 min",
            category: "Seguridad",
        },
        TaskDef {
            id: "defender_full",
            name: "Análisis completo de Microsoft Defender",
            description: "Analiza todos los archivos de todas las unidades. Úsalo si sospechas de malware; puedes seguir usando el PC.",
            admin: true,
            needs_drive: false,
            duration: "30 min - varias horas",
            category: "Seguridad",
        },
        TaskDef {
            id: "defender_update",
            name: "Actualizar firmas de Microsoft Defender",
            description: "Descarga las últimas definiciones de amenazas antes de analizar.",
            admin: true,
            needs_drive: false,
            duration: "< 1 min",
            category: "Seguridad",
        },
        TaskDef {
            id: "defender_offline",
            name: "Análisis sin conexión de Microsoft Defender",
            description: "Reinicia el PC y analiza antes de que arranque Windows: elimina malware que se protege mientras Windows está en marcha (rootkits, mineros persistentes). Guarda tu trabajo antes: el reinicio es inmediato.",
            admin: true,
            needs_drive: false,
            duration: "~15 min (con reinicio)",
            category: "Seguridad",
        },
        TaskDef {
            id: "flush_dns",
            name: "Vaciar caché DNS",
            description: "Soluciona problemas de conexión a servidores de juegos tras cambios de IP o DNS.",
            admin: false,
            needs_drive: false,
            duration: "Instantáneo",
            category: "Red",
        },
    ]
}

/// Newest `MpCmdRun.exe`: the platform folder in ProgramData is updated by
/// Defender itself; Program Files keeps the version shipped with Windows.
pub fn mpcmdrun() -> Option<PathBuf> {
    let platform = crate::util::env_path("ProgramData")?.join(r"Microsoft\Windows Defender\Platform");
    let mut best: Option<(Vec<u64>, PathBuf)> = None;
    if let Ok(dirs) = std::fs::read_dir(&platform) {
        for d in dirs.flatten() {
            let exe = d.path().join("MpCmdRun.exe");
            if !exe.is_file() {
                continue;
            }
            let name = d.file_name().to_string_lossy().to_string();
            let ver: Vec<u64> = name.split(['.', '-']).map(|p| p.parse().unwrap_or(0)).collect();
            if best.as_ref().is_none_or(|(b, _)| ver > *b) {
                best = Some((ver, exe));
            }
        }
    }
    best.map(|(_, p)| p).or_else(|| {
        let exe = crate::util::env_path("ProgramFiles")?.join(r"Windows Defender\MpCmdRun.exe");
        exe.is_file().then_some(exe)
    })
}

fn command_for(id: &str, drive: Option<&str>) -> Result<(String, Vec<String>), String> {
    let d = || -> Result<String, String> {
        let d = drive.ok_or("Selecciona una unidad")?;
        let c = d.trim_end_matches(['\\', ':']).to_uppercase();
        if c.len() == 1 && c.chars().all(|ch| ch.is_ascii_uppercase()) {
            Ok(format!("{c}:"))
        } else {
            Err("Unidad no válida".into())
        }
    };
    let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    Ok(match id {
        "optimize" => ("defrag.exe".into(), [vec![d()?], v(&["/O", "/U", "/V"])].concat()),
        "retrim" => ("defrag.exe".into(), [vec![d()?], v(&["/L", "/U", "/V"])].concat()),
        "chkdsk" => ("chkdsk.exe".into(), [vec![d()?], v(&["/scan"])].concat()),
        "sfc" => ("sfc.exe".into(), v(&["/scannow"])),
        "dism_restore" => ("DISM.exe".into(), v(&["/Online", "/Cleanup-Image", "/RestoreHealth"])),
        "dism_analyze" => ("DISM.exe".into(), v(&["/Online", "/Cleanup-Image", "/AnalyzeComponentStore"])),
        "dism_cleanup" => ("DISM.exe".into(), v(&["/Online", "/Cleanup-Image", "/StartComponentCleanup"])),
        "flush_dns" => ("ipconfig.exe".into(), v(&["/flushdns"])),
        "sandbox_off" => (
            "DISM.exe".into(),
            v(&["/Online", "/Disable-Feature", "/FeatureName:Containers-DisposableClientVM", "/NoRestart"]),
        ),
        "defender_quick" | "defender_full" | "defender_update" => {
            let exe = mpcmdrun().ok_or("No se encontró Microsoft Defender (MpCmdRun.exe)")?;
            let args = match id {
                "defender_quick" => v(&["-Scan", "-ScanType", "1"]),
                "defender_full" => v(&["-Scan", "-ScanType", "2"]),
                _ => v(&["-SignatureUpdate"]),
            };
            (exe.to_string_lossy().into_owned(), args)
        }
        "defender_offline" => (
            "powershell.exe".into(),
            v(&["-NoProfile", "-NonInteractive", "-Command", "Start-MpWDOScan"]),
        ),
        _ => return Err("Tarea desconocida".into()),
    })
}

#[derive(Clone, Serialize)]
struct OutputEvent {
    task: String,
    line: String,
    /// The line ended in `\r`: a progress update that replaces the previous one.
    replace: bool,
}

#[derive(Clone, Serialize)]
struct DoneEvent {
    task: String,
    code: Option<i32>,
    success: bool,
    cancelled: bool,
}

pub type Running = Arc<Mutex<HashMap<String, Arc<Mutex<Child>>>>>;

/// Streams a pipe, splitting on `\r` and `\n` and decoding UTF-16 or OEM text.
fn pump(mut reader: impl Read, app: AppHandle, task: String) {
    let mut buf = [0u8; 4096];
    let mut pending: Vec<u8> = Vec::new();
    let mut utf16: Option<bool> = None;
    let emit = |bytes: &[u8], is16: bool, replace: bool| {
        let line = if is16 {
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .filter(|&u| u != 0xFEFF)
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            decode_bytes(bytes)
        };
        let line = line.trim_end().to_string();
        if !line.trim().is_empty() {
            let _ = app.emit("task://output", OutputEvent { task: task.clone(), line, replace });
        }
    };

    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        pending.extend_from_slice(&buf[..n]);
        let is16 = *utf16.get_or_insert_with(|| looks_utf16(&pending));
        let step = if is16 { 2 } else { 1 };
        let mut start = 0;
        let mut i = 0;
        while i + step <= pending.len() {
            let c = if is16 {
                u16::from_le_bytes([pending[i], pending[i + 1]])
            } else {
                pending[i] as u16
            };
            if c == b'\r' as u16 && i + step == pending.len() {
                // Wait for the next chunk to know whether this is CRLF.
                break;
            }
            if c == b'\n' as u16 || c == b'\r' as u16 {
                let next_is_lf = c == b'\r' as u16 && {
                    let j = i + step;
                    j + step <= pending.len()
                        && (if is16 { u16::from_le_bytes([pending[j], pending[j + 1]]) } else { pending[j] as u16 })
                            == b'\n' as u16
                };
                let replace = c == b'\r' as u16 && !next_is_lf;
                emit(&pending[start..i], is16, replace);
                i += step;
                if next_is_lf {
                    i += step;
                }
                start = i;
                continue;
            }
            i += step;
        }
        pending.drain(..start);
    }
    if !pending.is_empty() {
        let is16 = utf16.unwrap_or(false);
        emit(&pending, is16, false);
    }
}

pub fn run_task(app: AppHandle, running: Running, id: String, drive: Option<String>) -> Result<(), String> {
    if running.lock().contains_key(&id) {
        return Err("La tarea ya se está ejecutando".into());
    }
    let (program, args) = command_for(&id, drive.as_deref())?;
    let mut child = hidden_command(&program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("No se pudo iniciar {program}: {e}"))?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let child = Arc::new(Mutex::new(child));
    running.lock().insert(id.clone(), child.clone());

    let _ = app.emit(
        "task://output",
        OutputEvent { task: id.clone(), line: format!("> {} {}", program, args.join(" ")), replace: false },
    );

    let mut pumps = Vec::new();
    if let Some(out) = stdout {
        let (a, t) = (app.clone(), id.clone());
        pumps.push(std::thread::spawn(move || pump(out, a, t)));
    }
    if let Some(err) = stderr {
        let (a, t) = (app.clone(), id.clone());
        pumps.push(std::thread::spawn(move || pump(err, a, t)));
    }

    std::thread::spawn(move || {
        for p in pumps {
            let _ = p.join();
        }
        let status = loop {
            if let Ok(Some(st)) = child.lock().try_wait() {
                break Some(st);
            }
            if !running.lock().contains_key(&id) {
                let _ = child.lock().wait();
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        };
        let cancelled = running.lock().remove(&id).is_none();
        let code = status.and_then(|s| s.code());
        let _ = app.emit(
            "task://done",
            DoneEvent { task: id, code, success: code == Some(0), cancelled },
        );
    });
    Ok(())
}

pub fn cancel_task(running: &Running, id: &str) -> Result<(), String> {
    let child = running.lock().remove(id).ok_or("La tarea no está en ejecución")?;
    let result = child.lock().kill().map_err(|e| e.to_string());
    result
}
