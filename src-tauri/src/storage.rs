//! Physical disks (model, bus, health, SMART), volumes and SSD-related
//! system state (TRIM, page/hibernation files).

use serde::Serialize;
use sysinfo::Disks;
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::fswalk::read_dir_fast;
use crate::nvme::{self, NvmeHealth};
use crate::util::{run_capture, system_drive, wide};
use crate::wmiq::{self, opt_u, s, u};

const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;

#[derive(Serialize, Clone, Default)]
pub struct Reliability {
    pub temperature: Option<u64>,
    pub temperature_max: Option<u64>,
    pub wear: Option<u64>,
    pub power_on_hours: Option<u64>,
    pub read_errors: Option<u64>,
    pub write_errors: Option<u64>,
}

#[derive(Serialize, Clone)]
pub struct PhysicalDisk {
    pub number: u32,
    pub model: String,
    pub serial: String,
    pub firmware: String,
    pub media: String,
    pub bus: String,
    pub is_nvme: bool,
    pub is_ssd: bool,
    pub size: u64,
    pub health: String,
    pub spindle_rpm: u64,
    pub nvme: Option<NvmeHealth>,
    pub nvme_error: Option<String>,
    pub reliability: Option<Reliability>,
    pub volumes: Vec<String>,
    pub vendor_tool: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct Volume {
    pub letter: String,
    pub label: String,
    pub fs: String,
    pub total: u64,
    pub free: u64,
    pub disk_number: Option<u32>,
    pub is_system: bool,
    pub removable: bool,
}

#[derive(Serialize, Clone, Default)]
pub struct SystemFiles {
    pub pagefile: u64,
    pub hiberfil: u64,
    pub swapfile: u64,
}

#[derive(Serialize, Clone)]
pub struct StorageInfo {
    pub disks: Vec<PhysicalDisk>,
    pub volumes: Vec<Volume>,
    pub trim_ntfs: Option<bool>,
    pub trim_refs: Option<bool>,
    pub system_files: SystemFiles,
    pub windows_old: bool,
    pub is_admin: bool,
}

fn bus_name(code: u64) -> &'static str {
    match code {
        1 => "SCSI",
        2 => "ATAPI",
        3 => "ATA",
        7 => "USB",
        8 => "RAID",
        9 => "iSCSI",
        10 => "SAS",
        11 => "SATA",
        12 => "SD",
        13 => "MMC",
        14 | 15 => "Virtual",
        16 => "Storage Spaces",
        17 => "NVMe",
        18 => "SCM",
        19 => "UFS",
        _ => "Desconocido",
    }
}

fn health_name(code: u64) -> &'static str {
    match code {
        0 => "healthy",
        1 => "warning",
        2 => "unhealthy",
        _ => "unknown",
    }
}

fn vendor_tool(model: &str) -> Option<String> {
    let m = model.to_lowercase();
    let tools: &[(&[&str], &str)] = &[
        (&["samsung"], "Samsung Magician"),
        (&["wdc", "wd_", "wd ", "western digital", "sandisk", "wd_black", "wds"], "WD Dashboard"),
        (&["crucial", "ct250", "ct500", "ct1000", "ct2000", "ct4000", "micron"], "Crucial Storage Executive"),
        (&["kingston", "snv", "skc", "sfyr"], "Kingston SSD Manager"),
        (&["seagate", "firecuda", "barracuda", "zp"], "Seagate SeaTools"),
        (&["intel", "solidigm"], "Solidigm Storage Tool"),
        (&["adata", "xpg"], "ADATA SSD ToolBox"),
        (&["corsair"], "Corsair iCUE / SSD Toolbox"),
        (&["sk hynix", "hynix", "hfm", "hfs"], "SK hynix Drive Manager"),
        (&["kioxia", "toshiba"], "KIOXIA SSD Utility"),
        (&["sabrent"], "Sabrent Rocket Control Panel"),
        (&["lexar"], "Lexar SSD Dash"),
        (&["teamgroup", "t-force", "tforce"], "T-FORCE SSD Toolbox"),
        (&["patriot", "viper"], "Patriot SSD Toolbox"),
        (&["msi", "spatium"], "MSI Center (SSD)"),
        (&["pny"], "PNY SSD Toolbox"),
        (&["hp ssd", "hp fx", "hp ex"], "HP SSD Toolbox"),
        (&["gigabyte", "aorus"], "GIGABYTE SSD Toolbox"),
    ];
    tools
        .iter()
        .find(|(keys, _)| keys.iter().any(|k| m.contains(k)))
        .map(|(_, t)| t.to_string())
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DiskExtent {
    disk_number: u32,
    starting_offset: i64,
    extent_length: i64,
}

#[repr(C)]
#[derive(Default)]
struct DiskExtents {
    count: u32,
    extents: [DiskExtent; 8],
}

/// Physical disk number that holds a drive letter (first extent).
fn volume_disk_number(letter: &str) -> Option<u32> {
    let path = wide(&format!(r"\\.\{letter}"));
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return None;
    }
    let mut ext = DiskExtents::default();
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            std::ptr::null(),
            0,
            &mut ext as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<DiskExtents>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    unsafe { CloseHandle(handle) };
    (ok != 0 && ext.count > 0).then_some(ext.extents[0].disk_number)
}

fn trim_status() -> (Option<bool>, Option<bool>) {
    let Ok(out) = run_capture("fsutil.exe", &["behavior", "query", "DisableDeleteNotify"]) else {
        return (None, None);
    };
    let mut ntfs = None;
    let mut refs = None;
    for line in out.lines() {
        let l = line.trim();
        let Some((key, value)) = l.split_once('=') else { continue };
        let digit = value.trim().chars().next().and_then(|c| c.to_digit(10));
        let Some(v) = digit else { continue };
        // DisableDeleteNotify = 0 means TRIM is enabled.
        if key.contains("NTFS") {
            ntfs = Some(v == 0);
        } else if key.contains("ReFS") {
            refs = Some(v == 0);
        }
    }
    (ntfs, refs)
}

pub fn system_files() -> SystemFiles {
    let mut sf = SystemFiles::default();
    let root = std::path::PathBuf::from(format!("{}\\", system_drive()));
    let _ = read_dir_fast(&root, |e| {
        match e.name_lossy().to_lowercase().as_str() {
            "pagefile.sys" => sf.pagefile = e.size,
            "hiberfil.sys" => sf.hiberfil = e.size,
            "swapfile.sys" => sf.swapfile = e.size,
            _ => {}
        }
    });
    sf
}

pub fn volumes() -> Vec<Volume> {
    let sys = system_drive().to_uppercase();
    let disks = Disks::new_with_refreshed_list();
    let mut vols: Vec<Volume> = disks
        .list()
        .iter()
        .filter_map(|d| {
            let mount = d.mount_point().to_string_lossy().to_string();
            let letter = mount.trim_end_matches('\\').to_uppercase();
            if letter.len() != 2 || !letter.ends_with(':') {
                return None;
            }
            Some(Volume {
                disk_number: volume_disk_number(&letter),
                is_system: letter == sys,
                label: d.name().to_string_lossy().to_string(),
                fs: d.file_system().to_string_lossy().to_string(),
                total: d.total_space(),
                free: d.available_space(),
                removable: d.is_removable(),
                letter,
            })
        })
        .collect();
    vols.sort_by(|a, b| a.letter.cmp(&b.letter));
    vols
}

pub fn storage_info(is_admin: bool) -> StorageInfo {
    let vols = volumes();
    let mut disks = Vec::new();

    if let Some(con) = wmiq::connect(r"ROOT\Microsoft\Windows\Storage") {
        let reliability = if is_admin {
            wmiq::query(&con, "SELECT * FROM MSFT_StorageReliabilityCounter")
        } else {
            Vec::new()
        };
        for row in wmiq::query(
            &con,
            "SELECT DeviceId, FriendlyName, Model, SerialNumber, FirmwareVersion, MediaType, BusType, HealthStatus, Size, SpindleSpeed FROM MSFT_PhysicalDisk",
        ) {
            let number: u32 = s(&row, "DeviceId").parse().unwrap_or(u32::MAX);
            let bus_code = u(&row, "BusType");
            let media_code = u(&row, "MediaType");
            let spindle = u(&row, "SpindleSpeed");
            let is_nvme = bus_code == 17;
            let is_ssd = media_code == 4 || is_nvme || (media_code == 0 && spindle == 0 && bus_code != 7);
            let media = match media_code {
                3 => "HDD",
                4 => "SSD",
                5 => "SCM",
                _ if is_nvme => "SSD",
                _ => "Desconocido",
            };
            let mut model = s(&row, "FriendlyName");
            if model.is_empty() {
                model = s(&row, "Model");
            }

            let rel = reliability
                .iter()
                .find(|r| s(r, "DeviceId") == number.to_string())
                .map(|r| Reliability {
                    temperature: opt_u(r, "Temperature").filter(|&t| t > 0),
                    temperature_max: opt_u(r, "TemperatureMax").filter(|&t| t > 0),
                    wear: opt_u(r, "Wear"),
                    power_on_hours: opt_u(r, "PowerOnHours"),
                    read_errors: opt_u(r, "ReadErrorsTotal"),
                    write_errors: opt_u(r, "WriteErrorsTotal"),
                });

            let (nvme_data, nvme_error) = if is_nvme && number != u32::MAX {
                if is_admin {
                    match nvme::read_health(number) {
                        Ok(h) => (Some(h), None),
                        Err(e) => (None, Some(e)),
                    }
                } else {
                    (None, Some("Reinicia NexFix como administrador para leer el SMART completo".into()))
                }
            } else {
                (None, None)
            };

            disks.push(PhysicalDisk {
                number,
                vendor_tool: vendor_tool(&model),
                serial: s(&row, "SerialNumber"),
                firmware: s(&row, "FirmwareVersion"),
                media: media.into(),
                bus: bus_name(bus_code).into(),
                is_nvme,
                is_ssd,
                size: u(&row, "Size"),
                health: health_name(u(&row, "HealthStatus")).into(),
                spindle_rpm: if spindle == u32::MAX as u64 { 0 } else { spindle },
                nvme: nvme_data,
                nvme_error,
                reliability: rel,
                volumes: vols
                    .iter()
                    .filter(|v| v.disk_number == Some(number))
                    .map(|v| v.letter.clone())
                    .collect(),
                model,
            });
        }
    }
    disks.sort_by_key(|d| d.number);

    let (trim_ntfs, trim_refs) = trim_status();
    let windows_old = std::path::Path::new(&format!("{}\\Windows.old", system_drive())).exists();

    StorageInfo {
        disks,
        volumes: vols,
        trim_ntfs,
        trim_refs,
        system_files: system_files(),
        windows_old,
        is_admin,
    }
}
