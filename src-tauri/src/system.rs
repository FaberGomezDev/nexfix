//! Hardware inventory (CPU, RAM modules, GPUs, board, BIOS, displays) and
//! live usage (CPU, memory, heaviest processes).

use std::collections::HashMap;

use serde::Serialize;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
use windows_sys::Win32::Graphics::Gdi::{
    EnumDisplayDevicesW, EnumDisplaySettingsW, DEVMODEW, DISPLAY_DEVICEW, DISPLAY_DEVICE_ATTACHED_TO_DESKTOP,
    ENUM_CURRENT_SETTINGS,
};

use crate::util::{cim_date, from_wide};
use crate::wmiq::{self, s, u};

#[derive(Serialize, Clone)]
pub struct OsInfo {
    pub name: String,
    pub version: String,
    pub build: String,
    pub arch: String,
    pub hostname: String,
    pub install_date: Option<String>,
    pub uptime_secs: u64,
}

#[derive(Serialize, Clone)]
pub struct CpuInfo {
    pub name: String,
    pub vendor: String,
    pub cores: u64,
    pub threads: u64,
    pub max_mhz: u64,
    pub l2_kb: u64,
    pub l3_kb: u64,
    pub socket: String,
}

#[derive(Serialize, Clone)]
pub struct MemModule {
    pub capacity: u64,
    pub speed: u64,
    pub configured_speed: u64,
    pub manufacturer: String,
    pub part_number: String,
    pub locator: String,
    pub mem_type: String,
}

#[derive(Serialize, Clone)]
pub struct MemoryInfo {
    pub total: u64,
    pub modules: Vec<MemModule>,
    pub slots: u64,
}

#[derive(Serialize, Clone)]
pub struct GpuInfo {
    pub name: String,
    pub vendor: String,
    pub driver_version: String,
    pub driver_date: Option<String>,
    pub vram: u64,
    pub refresh_rate: u64,
    pub width: u64,
    pub height: u64,
    pub integrated: bool,
}

#[derive(Serialize, Clone)]
pub struct BoardInfo {
    pub manufacturer: String,
    pub product: String,
    pub bios_vendor: String,
    pub bios_version: String,
    pub bios_date: Option<String>,
    pub system_model: String,
}

#[derive(Serialize, Clone)]
pub struct DisplayInfo {
    pub name: String,
    pub adapter: String,
    pub width: u32,
    pub height: u32,
    pub current_hz: u32,
    pub max_hz: u32,
    pub primary: bool,
}

#[derive(Serialize, Clone)]
pub struct SystemInfo {
    pub os: OsInfo,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub gpus: Vec<GpuInfo>,
    pub board: BoardInfo,
    pub displays: Vec<DisplayInfo>,
    pub is_admin: bool,
}

#[derive(Serialize)]
pub struct ProcInfo {
    pub name: String,
    pub count: u32,
    pub memory: u64,
    pub cpu: f32,
    pub gpu: f32,
}

#[derive(Serialize)]
pub struct LiveStats {
    pub cpu_total: f32,
    pub per_core: Vec<f32>,
    pub cpu_mhz: u64,
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub process_count: usize,
    pub top_memory: Vec<ProcInfo>,
    pub top_cpu: Vec<ProcInfo>,
    pub top_gpu: Vec<ProcInfo>,
    /// Busiest GPU engine, 0-100 (None when the counters are unavailable).
    pub gpu_total: Option<f32>,
    pub uptime_secs: u64,
}

fn mem_type(code: u64) -> &'static str {
    match code {
        20 => "DDR",
        21 => "DDR2",
        24 => "DDR3",
        26 => "DDR4",
        27 => "LPDDR",
        28 => "LPDDR2",
        29 => "LPDDR3",
        30 => "LPDDR4",
        34 => "DDR5",
        35 => "LPDDR5",
        _ => "",
    }
}

fn gpu_vendor(name: &str) -> &'static str {
    let n = name.to_lowercase();
    if n.contains("nvidia") || n.contains("geforce") || n.contains("rtx") || n.contains("gtx") {
        "NVIDIA"
    } else if n.contains("amd") || n.contains("radeon") {
        "AMD"
    } else if n.contains("intel") || n.contains("arc") {
        "Intel"
    } else {
        ""
    }
}

fn is_integrated(name: &str) -> bool {
    let n = name.to_lowercase();
    n == "amd radeon(tm) graphics"
        || n.contains("radeon(tm) graphics")
        || n.contains("radeon graphics")
        || n.contains("uhd graphics")
        || n.contains("iris")
        || n.contains("hd graphics")
        || n.contains("vega 8")
        || n.contains("780m")
        || n.contains("680m")
        || n.contains("basic display")
        || n.contains("basic render")
}

/// Real VRAM from the display class registry key (WMI AdapterRAM caps at 4 GB).
fn vram_from_registry() -> Vec<(String, u64)> {
    let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    let mut out = Vec::new();
    let Ok(class) = hklm.open_subkey(r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}") else {
        return out;
    };
    for key in class.enum_keys().flatten() {
        if key.len() != 4 || !key.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(sub) = class.open_subkey(&key) else { continue };
        let desc: String = sub.get_value("DriverDesc").unwrap_or_default();
        let qw: Option<u64> = sub.get_value("HardwareInformation.qwMemorySize").ok();
        let mem = qw.or_else(|| {
            sub.get_raw_value("HardwareInformation.MemorySize").ok().and_then(|v| {
                let b = &v.bytes;
                match b.len() {
                    4 => Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64),
                    8 => Some(u64::from_le_bytes(b[..8].try_into().ok()?)),
                    _ => None,
                }
            })
        });
        if let Some(m) = mem {
            if !desc.is_empty() {
                out.push((desc, m));
            }
        }
    }
    out
}

pub fn displays() -> Vec<DisplayInfo> {
    let mut out = Vec::new();
    let mut i = 0u32;
    loop {
        let mut dd: DISPLAY_DEVICEW = unsafe { std::mem::zeroed() };
        dd.cb = std::mem::size_of::<DISPLAY_DEVICEW>() as u32;
        if unsafe { EnumDisplayDevicesW(std::ptr::null(), i, &mut dd, 0) } == 0 {
            break;
        }
        i += 1;
        if dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP == 0 {
            continue;
        }
        let dev_name = dd.DeviceName;
        let mut cur: DEVMODEW = unsafe { std::mem::zeroed() };
        cur.dmSize = std::mem::size_of::<DEVMODEW>() as u16;
        if unsafe { EnumDisplaySettingsW(dev_name.as_ptr(), ENUM_CURRENT_SETTINGS, &mut cur) } == 0 {
            continue;
        }
        let mut max_hz = cur.dmDisplayFrequency;
        let mut m = 0u32;
        loop {
            let mut mode: DEVMODEW = unsafe { std::mem::zeroed() };
            mode.dmSize = std::mem::size_of::<DEVMODEW>() as u16;
            if unsafe { EnumDisplaySettingsW(dev_name.as_ptr(), m, &mut mode) } == 0 {
                break;
            }
            m += 1;
            if mode.dmPelsWidth == cur.dmPelsWidth && mode.dmPelsHeight == cur.dmPelsHeight {
                max_hz = max_hz.max(mode.dmDisplayFrequency);
            }
        }

        let mut mon: DISPLAY_DEVICEW = unsafe { std::mem::zeroed() };
        mon.cb = std::mem::size_of::<DISPLAY_DEVICEW>() as u32;
        let monitor_name = if unsafe { EnumDisplayDevicesW(dev_name.as_ptr(), 0, &mut mon, 0) } != 0 {
            from_wide(&mon.DeviceString)
        } else {
            String::new()
        };

        out.push(DisplayInfo {
            name: if monitor_name.is_empty() { from_wide(&dev_name) } else { monitor_name },
            adapter: from_wide(&dd.DeviceString),
            width: cur.dmPelsWidth,
            height: cur.dmPelsHeight,
            current_hz: cur.dmDisplayFrequency,
            max_hz,
            primary: dd.StateFlags & 0x4 != 0,
        });
    }
    out
}

pub fn system_info(is_admin: bool) -> SystemInfo {
    let con = wmiq::connect(r"ROOT\CIMV2");
    let q = |sql: &str| con.as_ref().map(|c| wmiq::query(c, sql)).unwrap_or_default();

    let os_row = q("SELECT Caption, Version, BuildNumber, OSArchitecture, InstallDate FROM Win32_OperatingSystem")
        .into_iter()
        .next()
        .unwrap_or_default();
    let os = OsInfo {
        name: {
            let c = s(&os_row, "Caption");
            if c.is_empty() { System::long_os_version().unwrap_or_default() } else { c }
        },
        version: System::os_version().unwrap_or_else(|| s(&os_row, "Version")),
        build: s(&os_row, "BuildNumber"),
        arch: s(&os_row, "OSArchitecture"),
        hostname: System::host_name().unwrap_or_default(),
        install_date: cim_date(&s(&os_row, "InstallDate")),
        uptime_secs: System::uptime(),
    };

    let cpu_row = q("SELECT Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, L2CacheSize, L3CacheSize, SocketDesignation FROM Win32_Processor")
        .into_iter()
        .next()
        .unwrap_or_default();
    let threads = u(&cpu_row, "NumberOfLogicalProcessors");
    let cpu = CpuInfo {
        name: s(&cpu_row, "Name"),
        vendor: s(&cpu_row, "Manufacturer"),
        cores: {
            let c = u(&cpu_row, "NumberOfCores");
            if c > 0 { c } else { System::physical_core_count().unwrap_or(0) as u64 }
        },
        threads: if threads > 0 {
            threads
        } else {
            std::thread::available_parallelism().map(|n| n.get() as u64).unwrap_or(0)
        },
        max_mhz: u(&cpu_row, "MaxClockSpeed"),
        l2_kb: u(&cpu_row, "L2CacheSize"),
        l3_kb: u(&cpu_row, "L3CacheSize"),
        socket: s(&cpu_row, "SocketDesignation"),
    };

    let modules: Vec<MemModule> = q("SELECT Capacity, Speed, ConfiguredClockSpeed, Manufacturer, PartNumber, DeviceLocator, SMBIOSMemoryType FROM Win32_PhysicalMemory")
        .iter()
        .map(|r| MemModule {
            capacity: u(r, "Capacity"),
            speed: u(r, "Speed"),
            configured_speed: u(r, "ConfiguredClockSpeed"),
            manufacturer: s(r, "Manufacturer"),
            part_number: s(r, "PartNumber"),
            locator: s(r, "DeviceLocator"),
            mem_type: mem_type(u(r, "SMBIOSMemoryType")).to_string(),
        })
        .collect();
    let slots = q("SELECT MemoryDevices FROM Win32_PhysicalMemoryArray")
        .iter()
        .map(|r| u(r, "MemoryDevices"))
        .sum();
    let mut sys = System::new();
    sys.refresh_memory();
    let memory = MemoryInfo { total: sys.total_memory(), modules, slots };

    let vram = vram_from_registry();
    let mut gpus: Vec<GpuInfo> = q("SELECT Name, DriverVersion, DriverDate, AdapterRAM, CurrentRefreshRate, CurrentHorizontalResolution, CurrentVerticalResolution FROM Win32_VideoController")
        .iter()
        .map(|r| {
            let name = s(r, "Name");
            let reg = vram.iter().find(|(d, _)| d.eq_ignore_ascii_case(&name)).map(|(_, m)| *m);
            GpuInfo {
                vendor: gpu_vendor(&name).to_string(),
                integrated: is_integrated(&name),
                driver_version: s(r, "DriverVersion"),
                driver_date: cim_date(&s(r, "DriverDate")),
                vram: reg.unwrap_or_else(|| u(r, "AdapterRAM")),
                refresh_rate: u(r, "CurrentRefreshRate"),
                width: u(r, "CurrentHorizontalResolution"),
                height: u(r, "CurrentVerticalResolution"),
                name,
            }
        })
        .collect();
    gpus.sort_by(|a, b| a.integrated.cmp(&b.integrated).then(b.vram.cmp(&a.vram)));

    let bb = q("SELECT Manufacturer, Product FROM Win32_BaseBoard").into_iter().next().unwrap_or_default();
    let bios = q("SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS").into_iter().next().unwrap_or_default();
    let cs = q("SELECT Manufacturer, Model FROM Win32_ComputerSystem").into_iter().next().unwrap_or_default();
    let board = BoardInfo {
        manufacturer: s(&bb, "Manufacturer"),
        product: s(&bb, "Product"),
        bios_vendor: s(&bios, "Manufacturer"),
        bios_version: s(&bios, "SMBIOSBIOSVersion"),
        bios_date: cim_date(&s(&bios, "ReleaseDate")),
        system_model: format!("{} {}", s(&cs, "Manufacturer"), s(&cs, "Model")).trim().to_string(),
    };

    SystemInfo { os, cpu, memory, gpus, board, displays: displays(), is_admin }
}

pub fn new_live_system() -> System {
    let mut sys = System::new();
    sys.refresh_cpu_usage();
    sys.refresh_memory();
    sys
}

pub fn live_stats(sys: &mut System, gpu: Option<&crate::gpu::GpuSample>) -> LiveStats {
    sys.refresh_cpu_usage();
    sys.refresh_cpu_frequency();
    sys.refresh_memory();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_memory().with_cpu(),
    );

    let cores = sys.cpus().len().max(1) as f32;
    let mut groups: HashMap<String, ProcInfo> = HashMap::new();
    for (pid, p) in sys.processes() {
        let raw = p.name().to_string_lossy();
        let name = raw.strip_suffix(".exe").unwrap_or(&raw).to_string();
        if name.is_empty() || name == "System Idle Process" {
            continue;
        }
        let e = groups.entry(name.clone()).or_insert(ProcInfo { name, count: 0, memory: 0, cpu: 0.0, gpu: 0.0 });
        e.count += 1;
        e.memory += p.memory();
        e.cpu += p.cpu_usage() / cores;
        if let Some(g) = gpu.and_then(|g| g.procs.get(&pid.as_u32())) {
            e.gpu = e.gpu.max(g.usage);
        }
    }
    let process_count = sys.processes().len();
    let mut by_mem: Vec<ProcInfo> = groups.into_values().collect();
    by_mem.sort_unstable_by(|a, b| b.memory.cmp(&a.memory));
    let copy = |p: &ProcInfo| ProcInfo { name: p.name.clone(), count: p.count, memory: p.memory, cpu: p.cpu, gpu: p.gpu };
    let mut top_cpu: Vec<ProcInfo> = by_mem.iter().filter(|p| p.cpu > 0.05).map(copy).collect();
    top_cpu.sort_unstable_by(|a, b| b.cpu.total_cmp(&a.cpu));
    top_cpu.truncate(8);
    let mut top_gpu: Vec<ProcInfo> = by_mem.iter().filter(|p| p.gpu >= 0.5).map(copy).collect();
    top_gpu.sort_unstable_by(|a, b| b.gpu.total_cmp(&a.gpu));
    top_gpu.truncate(8);
    by_mem.truncate(10);

    LiveStats {
        cpu_total: sys.global_cpu_usage(),
        per_core: sys.cpus().iter().map(|c| c.cpu_usage()).collect(),
        cpu_mhz: sys.cpus().iter().map(|c| c.frequency()).max().unwrap_or(0),
        mem_total: sys.total_memory(),
        mem_used: sys.used_memory(),
        swap_total: sys.total_swap(),
        swap_used: sys.used_swap(),
        process_count,
        top_memory: by_mem,
        top_cpu,
        top_gpu,
        gpu_total: gpu.filter(|g| g.available).map(|g| g.total),
        uptime_secs: System::uptime(),
    }
}
