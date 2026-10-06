//! Junk cleaner: well-known temporary/cache locations grouped in categories.
//! Scanning only measures; nothing is removed until the user picks what to clean.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use rayon::prelude::*;
use serde::Serialize;
use windows_sys::Win32::UI::Shell::{
    SHEmptyRecycleBinW, SHQueryRecycleBinW, SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI, SHERB_NOSOUND,
    SHQUERYRBINFO,
};

use crate::analyzer::{io_error_es, remove_file_force};
use crate::fswalk::read_dir_fast;
use crate::util::{display_path, env_path, filetime_to_unix, long_path, now_unix, system_drive};

#[derive(Clone, Copy, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Safe,
    Moderate,
    Caution,
}

#[derive(Clone, Copy, PartialEq)]
enum Special {
    None,
    RecycleBin,
}

struct Category {
    id: &'static str,
    name: &'static str,
    group: &'static str,
    description: &'static str,
    risk: Risk,
    default_on: bool,
    admin: bool,
    min_age_hours: u64,
    recycle: bool,
    /// Only files the user ticks one by one are removed (personal folders).
    explicit: bool,
    special: Special,
    /// (base folder, glob suffix). An empty suffix means the base itself.
    targets: Vec<(PathBuf, &'static str)>,
}

#[derive(Clone)]
pub struct JunkFile {
    pub path: PathBuf,
    pub size: u64,
    pub mtime: u64,
}

#[derive(Default)]
pub struct JunkData {
    pub files: Vec<JunkFile>,
    /// Sub-folders in post-order (deepest first) so empty ones can be pruned.
    pub dirs: Vec<PathBuf>,
    pub recycle: bool,
    pub explicit: bool,
    pub special_recycle_bin: bool,
}

#[derive(Serialize)]
pub struct JunkItem {
    pub path: String,
    pub size: u64,
    pub mtime: i64,
}

#[derive(Serialize)]
pub struct CategoryResult {
    pub id: String,
    pub name: String,
    pub group: String,
    pub description: String,
    pub risk: Risk,
    pub default_on: bool,
    pub admin: bool,
    pub found: bool,
    pub denied: bool,
    pub size: u64,
    pub count: u64,
    pub min_age_hours: u64,
    pub recycle: bool,
    pub explicit: bool,
    pub top: Vec<JunkItem>,
}

#[derive(Serialize, Default)]
pub struct CleanReport {
    pub freed: u64,
    pub deleted: u64,
    pub failed: u64,
    pub categories: Vec<CategoryClean>,
}

#[derive(Serialize)]
pub struct CategoryClean {
    pub id: String,
    pub freed: u64,
    pub deleted: u64,
    pub failed: u64,
    pub sample_error: Option<String>,
}

fn steam_root() -> Option<PathBuf> {
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let key = hkcu.open_subkey(r"Software\Valve\Steam").ok()?;
    let path: String = key.get_value("SteamPath").ok()?;
    let p = PathBuf::from(path.replace('/', "\\"));
    p.exists().then_some(p)
}

fn steam_libraries(root: &Path) -> Vec<PathBuf> {
    let mut libs = vec![root.to_path_buf()];
    if let Ok(vdf) = std::fs::read_to_string(root.join(r"steamapps\libraryfolders.vdf")) {
        for line in vdf.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("\"path\"") {
                let v = rest.trim().trim_matches('"').replace("\\\\", "\\");
                let p = PathBuf::from(v);
                if p.exists() && !libs.iter().any(|l| l.to_string_lossy().eq_ignore_ascii_case(&p.to_string_lossy())) {
                    libs.push(p);
                }
            }
        }
    }
    libs
}

fn categories() -> Vec<Category> {
    let local = env_path("LOCALAPPDATA").unwrap_or_default();
    let roaming = env_path("APPDATA").unwrap_or_default();
    let temp = env_path("TEMP").unwrap_or_else(|| local.join("Temp"));
    let windir = env_path("SystemRoot").unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let progdata = env_path("ProgramData").unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let home = env_path("USERPROFILE").unwrap_or_default();
    let local_low = home.join(r"AppData\LocalLow");
    let sysdrive = PathBuf::from(format!("{}\\", system_drive()));

    let chromium = |base: PathBuf| -> Vec<(PathBuf, &'static str)> {
        vec![
            (base.clone(), r"*\Cache"),
            (base.clone(), r"*\Code Cache"),
            (base.clone(), r"*\GPUCache"),
            (base.clone(), r"*\DawnGraphiteCache"),
            (base.clone(), r"*\DawnWebGPUCache"),
            (base.clone(), "ShaderCache"),
            (base, "GrShaderCache"),
        ]
    };

    let mut steam_targets = Vec::new();
    let mut steam_shader = Vec::new();
    if let Some(root) = steam_root() {
        steam_targets.push((root.clone(), r"appcache\httpcache"));
        steam_targets.push((root.clone(), "logs"));
        steam_targets.push((root.clone(), "dumps"));
        for lib in steam_libraries(&root) {
            steam_shader.push((lib, r"steamapps\shadercache"));
        }
    }
    steam_targets.push((local.clone(), r"Steam\htmlcache"));

    let c = |id, name, group, description, risk, default_on, admin, targets| Category {
        id,
        name,
        group,
        description,
        risk,
        default_on,
        admin,
        min_age_hours: 0,
        recycle: false,
        explicit: false,
        special: Special::None,
        targets,
    };

    let mut list = vec![
        Category {
            min_age_hours: 24,
            ..c("user_temp", "Archivos temporales del usuario", "Sistema",
                "Restos que dejan instaladores y programas en %TEMP%. Solo se borran los que tienen más de 24 h.",
                Risk::Safe, true, false, vec![(temp, "")])
        },
        Category {
            min_age_hours: 24,
            ..c("win_temp", "Temporales de Windows", "Sistema",
                "Archivos temporales del sistema en Windows\\Temp (más de 24 h).",
                Risk::Safe, true, true, vec![(windir.clone(), "Temp")])
        },
        c("wu_cache", "Caché de Windows Update", "Sistema",
            "Paquetes de actualizaciones ya instaladas. Windows los vuelve a descargar si los necesita.",
            Risk::Safe, true, true, vec![(windir.clone(), r"SoftwareDistribution\Download")]),
        c("delivery_opt", "Optimización de distribución", "Sistema",
            "Caché que Windows usa para compartir actualizaciones con otros PCs.",
            Risk::Safe, true, true,
            vec![(windir.clone(), r"ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache")]),
        c("thumbnails", "Caché de miniaturas", "Sistema",
            "Miniaturas del Explorador. Se regeneran solas al abrir carpetas.",
            Risk::Safe, true, false, vec![(local.clone(), r"Microsoft\Windows\Explorer\thumbcache_*.db")]),
        c("wer", "Informes de errores de Windows", "Sistema",
            "Reportes de fallos de programas que ya se enviaron o no sirven.",
            Risk::Safe, true, false,
            vec![
                (local.clone(), r"Microsoft\Windows\WER"),
                (progdata.clone(), r"Microsoft\Windows\WER\ReportArchive"),
                (progdata.clone(), r"Microsoft\Windows\WER\ReportQueue"),
                (progdata.clone(), r"Microsoft\Windows\WER\Temp"),
            ]),
        c("crash_dumps", "Volcados de memoria", "Sistema",
            "Archivos .dmp de cuelgues y pantallazos azules. Solo sirven si vas a diagnosticar un BSOD.",
            Risk::Safe, true, true,
            vec![
                (local.clone(), "CrashDumps"),
                (windir.clone(), "Minidump"),
                (windir.clone(), "MEMORY.DMP"),
                (windir.clone(), "LiveKernelReports"),
            ]),
        Category {
            min_age_hours: 24,
            ..c("win_logs", "Registros de Windows", "Sistema",
                "Logs de CBS, DISM y del instalador de Windows.",
                Risk::Safe, true, true,
                vec![
                    (windir.clone(), r"Logs\CBS\*.log"),
                    (windir.clone(), r"Logs\CBS\*.cab"),
                    (windir.clone(), r"Logs\DISM\*.log"),
                    (windir.clone(), r"Logs\MoSetup\*.log"),
                    (windir.clone(), r"Panther\*.log"),
                ])
        },
        Category {
            special: Special::RecycleBin,
            ..c("recycle_bin", "Papelera de reciclaje", "Sistema",
                "Archivos que ya eliminaste. Vaciarla es definitivo: revisa antes que no haya nada importante.",
                Risk::Moderate, false, false, vec![])
        },
        c("driver_installers", "Instaladores de drivers extraídos", "Juegos y GPU",
            "Carpetas C:\\AMD y C:\\NVIDIA y descargas antiguas de drivers. Ya están instalados; suelen ocupar varios GB.",
            Risk::Safe, true, false,
            vec![
                (sysdrive.clone(), "AMD"),
                (sysdrive.clone(), "NVIDIA"),
                (progdata.clone(), r"NVIDIA Corporation\Downloader"),
            ]),
        c("dx_shader", "Caché de sombreadores DirectX", "Juegos y GPU",
            "Shaders compilados. Se regeneran, pero los juegos pueden dar tirones las primeras partidas. Recomendado tras actualizar drivers.",
            Risk::Moderate, false, false, vec![(local.clone(), "D3DSCache")]),
        c("nvidia_shader", "Caché de sombreadores NVIDIA", "Juegos y GPU",
            "Cachés DX/GL/Vulkan del driver NVIDIA. Bórrala si tienes artefactos o tras cambiar de driver.",
            Risk::Moderate, false, false,
            vec![
                (local.clone(), r"NVIDIA\DXCache"),
                (local.clone(), r"NVIDIA\GLCache"),
                (local.clone(), r"NVIDIA Corporation\NV_Cache"),
                (local_low.clone(), r"NVIDIA\PerDriverVersion\DXCache"),
                (local_low.clone(), r"NVIDIA\PerDriverVersion\GLCache"),
                (progdata.clone(), r"NVIDIA Corporation\NV_Cache"),
            ]),
        c("amd_shader", "Caché de sombreadores AMD", "Juegos y GPU",
            "Cachés DX/Vulkan/GL del driver AMD Radeon. Bórrala tras cambiar de driver o si hay problemas gráficos.",
            Risk::Moderate, false, false,
            vec![
                (local.clone(), r"AMD\DxCache"),
                (local.clone(), r"AMD\DxcCache"),
                (local.clone(), r"AMD\GLCache"),
                (local.clone(), r"AMD\VkCache"),
                (local_low.clone(), r"AMD\DxCache"),
                (local_low.clone(), r"AMD\DxcCache"),
                (local_low.clone(), r"AMD\VkCache"),
            ]),
        c("steam_shader", "Steam: caché de sombreadores", "Juegos y GPU",
            "Shaders precompilados de tus juegos de Steam. Steam los vuelve a descargar o compilar.",
            Risk::Moderate, false, false, steam_shader),
        c("steam_web", "Steam: caché web, logs y dumps", "Juegos y GPU",
            "Caché del navegador interno de Steam, registros y volcados de errores.",
            Risk::Safe, true, false, steam_targets),
        c("epic", "Epic Games: caché y logs", "Juegos y GPU",
            "Caché web y registros del launcher de Epic Games.",
            Risk::Safe, true, false,
            vec![
                (local.clone(), r"EpicGamesLauncher\Saved\webcache*"),
                (local.clone(), r"EpicGamesLauncher\Saved\Logs"),
            ]),
        c("discord", "Discord: caché", "Juegos y GPU",
            "Imágenes y datos en caché de Discord. No borra mensajes ni ajustes.",
            Risk::Safe, true, false,
            vec![
                (roaming.clone(), r"discord\Cache"),
                (roaming.clone(), r"discord\Code Cache"),
                (roaming.clone(), r"discord\GPUCache"),
            ]),
        c("chrome", "Google Chrome: caché", "Navegadores",
            "Caché de páginas, código y GPU. No borra contraseñas, historial ni sesiones.",
            Risk::Safe, true, false, chromium(local.join(r"Google\Chrome\User Data"))),
        c("edge", "Microsoft Edge: caché", "Navegadores",
            "Caché de páginas, código y GPU. No borra contraseñas, historial ni sesiones.",
            Risk::Safe, true, false, chromium(local.join(r"Microsoft\Edge\User Data"))),
        c("brave", "Brave: caché", "Navegadores",
            "Caché de páginas, código y GPU. No borra contraseñas, historial ni sesiones.",
            Risk::Safe, true, false, chromium(local.join(r"BraveSoftware\Brave-Browser\User Data"))),
        c("opera", "Opera / Opera GX: caché", "Navegadores",
            "Caché de páginas y GPU de Opera y Opera GX.",
            Risk::Safe, true, false,
            vec![
                (local.clone(), r"Opera Software\Opera Stable\Cache"),
                (local.clone(), r"Opera Software\Opera Stable\*\Cache"),
                (local.clone(), r"Opera Software\Opera GX Stable\Cache"),
                (local.clone(), r"Opera Software\Opera GX Stable\*\Cache"),
                (roaming.clone(), r"Opera Software\Opera GX Stable\GPUCache"),
                (roaming.clone(), r"Opera Software\Opera Stable\GPUCache"),
            ]),
        c("firefox", "Firefox: caché", "Navegadores",
            "Caché de páginas de Firefox. No borra contraseñas ni historial.",
            Risk::Safe, true, false, vec![(local.clone(), r"Mozilla\Firefox\Profiles\*\cache2")]),
        c("npm_cache", "Caché de npm", "Desarrollo",
            "Paquetes descargados por npm. Se vuelven a descargar al instalar.",
            Risk::Safe, false, false, vec![(local.clone(), r"npm-cache\_cacache")]),
        c("pip_cache", "Caché de pip", "Desarrollo",
            "Paquetes de Python descargados por pip.",
            Risk::Safe, false, false, vec![(local.clone(), r"pip\Cache")]),
        c("yarn_cache", "Caché de Yarn", "Desarrollo",
            "Paquetes descargados por Yarn.",
            Risk::Safe, false, false, vec![(local.clone(), r"Yarn\Cache")]),
        Category {
            recycle: true,
            explicit: true,
            ..c("downloads", "Carpeta Descargas", "Personal",
                "Tus descargas. NexFix nunca las selecciona solo: revisa la lista y marca lo que quieras. Se envían a la Papelera.",
                Risk::Caution, false, false, vec![(home.join("Downloads"), "")])
        },
    ];
    list.retain(|c| c.special == Special::RecycleBin || !c.targets.is_empty());
    list
}

fn resolve_targets(targets: &[(PathBuf, &'static str)]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for (base, suffix) in targets {
        if base.as_os_str().is_empty() {
            continue;
        }
        if suffix.is_empty() {
            out.push(base.clone());
        } else if suffix.contains('*') {
            let pattern = format!("{}\\{}", glob::Pattern::escape(&base.to_string_lossy()), suffix);
            if let Ok(paths) = glob::glob(&pattern) {
                out.extend(paths.flatten());
            }
        } else {
            out.push(base.join(suffix));
        }
    }
    out
}

fn collect_dir(dir: &Path, cutoff: u64, data: &mut JunkData, denied: &mut bool) {
    let mut subdirs = Vec::new();
    let res = read_dir_fast(dir, |e| {
        if e.is_dir() {
            if !e.is_link() {
                subdirs.push(dir.join(&e.name));
            }
        } else if cutoff == 0 || e.mtime < cutoff {
            data.files.push(JunkFile { path: dir.join(&e.name), size: e.size, mtime: e.mtime });
        }
    });
    if let Err(e) = res {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            *denied = true;
        }
        return;
    }
    for sub in subdirs {
        collect_dir(&sub, cutoff, data, denied);
        data.dirs.push(sub);
    }
}

fn recycle_bin_info() -> (u64, u64) {
    let mut info = SHQUERYRBINFO {
        cbSize: std::mem::size_of::<SHQUERYRBINFO>() as u32,
        i64Size: 0,
        i64NumItems: 0,
    };
    let hr = unsafe { SHQueryRecycleBinW(std::ptr::null(), &mut info) };
    if hr < 0 {
        return (0, 0);
    }
    (info.i64Size.max(0) as u64, info.i64NumItems.max(0) as u64)
}

fn scan_category(cat: &Category) -> (CategoryResult, JunkData) {
    let mut data = JunkData { recycle: cat.recycle, explicit: cat.explicit, ..Default::default() };
    let mut found = false;
    let mut denied = false;
    let (size, count);

    if cat.special == Special::RecycleBin {
        data.special_recycle_bin = true;
        (size, count) = recycle_bin_info();
        found = true;
    } else {
        let cutoff = if cat.min_age_hours > 0 {
            let now_ticks = (now_unix() as u64) * 10_000_000 + 116_444_736_000_000_000;
            now_ticks.saturating_sub(cat.min_age_hours * 3600 * 10_000_000)
        } else {
            0
        };
        for target in resolve_targets(&cat.targets) {
            let lp = long_path(&target);
            match std::fs::symlink_metadata(&lp) {
                Ok(md) if md.is_dir() => {
                    found = true;
                    collect_dir(&target, cutoff, &mut data, &mut denied);
                }
                Ok(md) => {
                    found = true;
                    let mtime = md
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() * 10_000_000 + 116_444_736_000_000_000)
                        .unwrap_or(0);
                    if cutoff == 0 || mtime < cutoff {
                        data.files.push(JunkFile { path: target.clone(), size: md.len(), mtime });
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    found = true;
                    denied = true;
                }
                Err(_) => {}
            }
        }
        data.files.sort_unstable_by(|a, b| b.size.cmp(&a.size));
        size = data.files.iter().map(|f| f.size).sum();
        count = data.files.len() as u64;
    }

    let top_n = if cat.explicit { 400 } else { 80 };
    let top = data
        .files
        .iter()
        .take(top_n)
        .map(|f| JunkItem { path: display_path(&f.path), size: f.size, mtime: filetime_to_unix(f.mtime) })
        .collect();

    (
        CategoryResult {
            id: cat.id.to_string(),
            name: cat.name.to_string(),
            group: cat.group.to_string(),
            description: cat.description.to_string(),
            risk: cat.risk,
            default_on: cat.default_on,
            admin: cat.admin,
            found,
            denied,
            size,
            count,
            min_age_hours: cat.min_age_hours,
            recycle: cat.recycle,
            explicit: cat.explicit,
            top,
        },
        data,
    )
}

pub fn scan_all() -> (Vec<CategoryResult>, HashMap<String, JunkData>) {
    let results: Vec<(CategoryResult, JunkData)> = categories().par_iter().map(scan_category).collect();
    let mut map = HashMap::new();
    let mut list = Vec::with_capacity(results.len());
    for (r, d) in results {
        map.insert(r.id.clone(), d);
        list.push(r);
    }
    (list, map)
}

/// Deletes the selected categories. `excluded` holds file paths the user
/// unticked; for `explicit` categories only the paths in `included` go.
/// Runs on a fresh thread so the Recycle Bin COM calls can initialize COM.
pub fn clean(
    selected: Vec<(String, JunkData)>,
    excluded: &HashSet<String>,
    included: &HashSet<String>,
    mut on_progress: impl FnMut(&str, usize, usize, u64),
) -> CleanReport {
    let mut report = CleanReport::default();
    let total = selected.len();
    for (i, (id, data)) in selected.into_iter().enumerate() {
        let mut cc = CategoryClean { id: id.clone(), freed: 0, deleted: 0, failed: 0, sample_error: None };

        if data.special_recycle_bin {
            let (size, count) = recycle_bin_info();
            let hr = unsafe {
                SHEmptyRecycleBinW(
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND,
                )
            };
            if hr >= 0 || count == 0 {
                cc.freed = size;
                cc.deleted = count;
            } else {
                cc.failed = count.max(1);
                cc.sample_error = Some(format!("No se pudo vaciar la papelera (0x{hr:08X})"));
            }
        } else {
            let files: Vec<&JunkFile> = data
                .files
                .iter()
                .filter(|f| {
                    let key = display_path(&f.path).to_lowercase();
                    if data.explicit {
                        included.contains(&key)
                    } else {
                        !excluded.contains(&key)
                    }
                })
                .collect();

            if data.recycle {
                for f in files {
                    match trash::delete(&f.path) {
                        Ok(()) => {
                            cc.deleted += 1;
                            cc.freed += f.size;
                        }
                        Err(e) => {
                            cc.failed += 1;
                            cc.sample_error.get_or_insert_with(|| e.to_string());
                        }
                    }
                }
            } else {
                let freed = AtomicU64::new(0);
                let deleted = AtomicU64::new(0);
                let failed = AtomicU64::new(0);
                let sample = parking_lot::Mutex::new(None::<String>);
                files.par_iter().for_each(|f| match remove_file_force(&f.path) {
                    Ok(()) => {
                        deleted.fetch_add(1, Relaxed);
                        freed.fetch_add(f.size, Relaxed);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        failed.fetch_add(1, Relaxed);
                        let mut s = sample.lock();
                        if s.is_none() {
                            *s = Some(io_error_es(&e));
                        }
                    }
                });
                cc.freed = freed.into_inner();
                cc.deleted = deleted.into_inner();
                cc.failed = failed.into_inner();
                cc.sample_error = sample.into_inner();
                for d in &data.dirs {
                    let _ = std::fs::remove_dir(long_path(d));
                }
            }
        }

        report.freed += cc.freed;
        report.deleted += cc.deleted;
        report.failed += cc.failed;
        on_progress(&id, i + 1, total, report.freed);
        report.categories.push(cc);
    }
    report
}
