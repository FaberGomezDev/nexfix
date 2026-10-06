//! Gaming-related Windows settings: power plan, Game Mode, Game DVR, HAGS,
//! mouse acceleration, hibernation and Storage Sense. Every change is
//! reversible and only happens when the user flips a switch.

use serde::Serialize;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    SystemParametersInfoW, SPIF_SENDCHANGE, SPIF_UPDATEINIFILE, SPI_GETMOUSE, SPI_SETMOUSE,
};
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE};
use winreg::RegKey;

use crate::util::run_capture;

pub const ULTIMATE_PLAN: &str = "e9a42b02-d5df-448d-aa00-03f14749eb61";

#[derive(Serialize, Clone)]
pub struct PowerPlan {
    pub guid: String,
    pub name: String,
    pub active: bool,
}

#[derive(Serialize, Clone)]
pub struct Tweaks {
    pub power_plans: Vec<PowerPlan>,
    pub game_mode: bool,
    pub game_dvr: bool,
    pub hags: Option<bool>,
    pub mouse_accel: bool,
    pub hibernation: bool,
    pub hiberfil_size: u64,
    pub storage_sense: bool,
    pub is_admin: bool,
}

fn is_guid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() }
        })
}

pub fn power_plans() -> Vec<PowerPlan> {
    let Ok(out) = run_capture("powercfg.exe", &["/list"]) else { return Vec::new() };
    let mut plans = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        // "GUID del plan de energía: 381b4222-...  (Equilibrado) *"
        let Some(guid) = line.split_whitespace().find(|t| is_guid(t)).map(|t| t.to_lowercase()) else {
            continue;
        };
        let name = match (line.find('('), line.rfind(')')) {
            (Some(a), Some(b)) if b > a => line[a + 1..b].to_string(),
            _ => guid.clone(),
        };
        plans.push(PowerPlan { guid, name, active: line.ends_with('*') });
    }
    plans
}

pub fn set_power_plan(guid: &str) -> Result<(), String> {
    if !is_guid(guid) {
        return Err("Plan no válido".into());
    }
    run_capture("powercfg.exe", &["/setactive", guid]).map(|_| ())
}

/// Adds the hidden "Ultimate Performance" plan to the list.
pub fn add_ultimate_plan() -> Result<(), String> {
    run_capture("powercfg.exe", &["-duplicatescheme", ULTIMATE_PLAN]).map(|_| ())
}

fn read_dword(root: &RegKey, path: &str, name: &str) -> Option<u32> {
    root.open_subkey_with_flags(path, KEY_READ).ok()?.get_value::<u32, _>(name).ok()
}

fn write_dword(root: &RegKey, path: &str, name: &str, value: u32) -> Result<(), String> {
    let (key, _) = root.create_subkey(path).map_err(|e| e.to_string())?;
    key.set_value(name, &value).map_err(|e| e.to_string())
}

fn mouse_params() -> [i32; 3] {
    let mut p = [0i32; 3];
    unsafe { SystemParametersInfoW(SPI_GETMOUSE, 0, p.as_mut_ptr() as *mut core::ffi::c_void, 0) };
    p
}

pub fn get_tweaks(is_admin: bool) -> Tweaks {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    let game_mode = read_dword(&hkcu, r"Software\Microsoft\GameBar", "AutoGameModeEnabled").unwrap_or(1) != 0;
    let app_capture = read_dword(&hkcu, r"Software\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled").unwrap_or(0);
    let historical = read_dword(&hkcu, r"Software\Microsoft\Windows\CurrentVersion\GameDVR", "HistoricalCaptureEnabled").unwrap_or(0);
    let hags = read_dword(&hklm, r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode").map(|v| v == 2);
    let storage_sense = read_dword(&hkcu, r"Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy", "01").unwrap_or(0) == 1;
    let hiber = crate::storage::system_files().hiberfil;
    let hib_enabled = read_dword(&hklm, r"SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabled").map(|v| v != 0).unwrap_or(hiber > 0);

    Tweaks {
        power_plans: power_plans(),
        game_mode,
        game_dvr: app_capture == 1 || historical == 1,
        hags,
        mouse_accel: mouse_params()[2] != 0,
        hibernation: hib_enabled,
        hiberfil_size: hiber,
        storage_sense,
        is_admin,
    }
}

pub fn set_tweak(name: &str, enabled: bool) -> Result<(), String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match name {
        "game_mode" => {
            write_dword(&hkcu, r"Software\Microsoft\GameBar", "AutoGameModeEnabled", enabled as u32)?;
            write_dword(&hkcu, r"Software\Microsoft\GameBar", "AllowAutoGameMode", enabled as u32)
        }
        "game_dvr" => {
            let v = enabled as u32;
            write_dword(&hkcu, r"Software\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled", v)?;
            write_dword(&hkcu, r"System\GameConfigStore", "GameDVR_Enabled", v)?;
            if !enabled {
                write_dword(&hkcu, r"Software\Microsoft\Windows\CurrentVersion\GameDVR", "HistoricalCaptureEnabled", 0)?;
            }
            Ok(())
        }
        "hags" => {
            let key = hklm
                .open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", KEY_SET_VALUE)
                .map_err(|_| "Se necesitan permisos de administrador".to_string())?;
            key.set_value("HwSchMode", &(if enabled { 2u32 } else { 1u32 })).map_err(|e| e.to_string())
        }
        "mouse_accel" => {
            let mut p: [i32; 3] = if enabled { [6, 10, 1] } else { [0, 0, 0] };
            let ok = unsafe {
                SystemParametersInfoW(
                    SPI_SETMOUSE,
                    0,
                    p.as_mut_ptr() as *mut core::ffi::c_void,
                    SPIF_UPDATEINIFILE | SPIF_SENDCHANGE,
                )
            };
            if ok == 0 { Err("No se pudo cambiar la aceleración del ratón".into()) } else { Ok(()) }
        }
        "hibernation" => run_capture("powercfg.exe", &["/hibernate", if enabled { "on" } else { "off" }]).map(|_| ()),
        "storage_sense" => write_dword(
            &hkcu,
            r"Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy",
            "01",
            enabled as u32,
        ),
        _ => Err("Ajuste desconocido".into()),
    }
}
