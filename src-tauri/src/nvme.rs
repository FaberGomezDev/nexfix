//! NVMe SMART / Health Information log (log page 0x02) read straight from the
//! drive through `IOCTL_STORAGE_QUERY_PROPERTY`, the same source tools like
//! CrystalDiskInfo use. Requires administrator rights.

use serde::Serialize;
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::util::wide;

const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
const STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY: u32 = 50;
const PROPERTY_STANDARD_QUERY: u32 = 0;
const PROTOCOL_TYPE_NVME: u32 = 3;
const NVME_DATA_TYPE_LOG_PAGE: u32 = 2;
const NVME_LOG_PAGE_HEALTH_INFO: u32 = 2;
const HEALTH_LOG_SIZE: usize = 512;

#[repr(C)]
#[derive(Clone, Copy)]
struct ProtocolSpecificData {
    protocol_type: u32,
    data_type: u32,
    request_value: u32,
    request_sub_value: u32,
    data_offset: u32,
    data_length: u32,
    fixed_return_data: u32,
    request_sub_value2: u32,
    request_sub_value3: u32,
    request_sub_value4: u32,
}

#[repr(C)]
struct QueryBuffer {
    property_id: u32,
    query_type: u32,
    spec: ProtocolSpecificData,
    data: [u8; HEALTH_LOG_SIZE],
}

#[derive(Serialize, Clone, Default)]
pub struct NvmeHealth {
    pub critical_warning: u8,
    pub temperature_c: i32,
    pub available_spare: u8,
    pub spare_threshold: u8,
    pub percentage_used: u8,
    pub data_read_bytes: u64,
    pub data_written_bytes: u64,
    pub power_cycles: u64,
    pub power_on_hours: u64,
    pub unsafe_shutdowns: u64,
    pub media_errors: u64,
    pub error_log_entries: u64,
    pub warning_temp_minutes: u32,
    pub critical_temp_minutes: u32,
    pub sensors_c: Vec<i32>,
}

fn u128_le(b: &[u8]) -> u128 {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[..16]);
    u128::from_le_bytes(a)
}

fn sat(v: u128) -> u64 {
    v.min(u64::MAX as u128) as u64
}

fn kelvin(k: u16) -> i32 {
    k as i32 - 273
}

pub fn read_health(disk_number: u32) -> Result<NvmeHealth, String> {
    let path = wide(&format!(r"\\.\PhysicalDrive{disk_number}"));
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err("Se necesitan permisos de administrador para leer el SMART del NVMe".into());
    }

    let mut buf = QueryBuffer {
        property_id: STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY,
        query_type: PROPERTY_STANDARD_QUERY,
        spec: ProtocolSpecificData {
            protocol_type: PROTOCOL_TYPE_NVME,
            data_type: NVME_DATA_TYPE_LOG_PAGE,
            request_value: NVME_LOG_PAGE_HEALTH_INFO,
            request_sub_value: 0,
            data_offset: std::mem::size_of::<ProtocolSpecificData>() as u32,
            data_length: HEALTH_LOG_SIZE as u32,
            fixed_return_data: 0,
            request_sub_value2: 0,
            request_sub_value3: 0,
            request_sub_value4: 0,
        },
        data: [0; HEALTH_LOG_SIZE],
    };
    let size = std::mem::size_of::<QueryBuffer>() as u32;
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &buf as *const _ as *const core::ffi::c_void,
            size,
            &mut buf as *mut _ as *mut core::ffi::c_void,
            size,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    let err = std::io::Error::last_os_error();
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        return Err(format!("El controlador no devolvió el registro SMART: {err}"));
    }

    // Output layout: STORAGE_PROTOCOL_DATA_DESCRIPTOR { Version, Size, ProtocolSpecificData }
    // followed by the log page at ProtocolSpecificData + DataOffset.
    let raw: &[u8] = unsafe {
        std::slice::from_raw_parts(&buf as *const _ as *const u8, size as usize)
    };
    let spec_start = 8usize;
    let data_offset = u32::from_le_bytes(raw[spec_start + 16..spec_start + 20].try_into().unwrap()) as usize;
    let data_length = u32::from_le_bytes(raw[spec_start + 20..spec_start + 24].try_into().unwrap()) as usize;
    let start = spec_start + data_offset;
    if data_length < HEALTH_LOG_SIZE || start + HEALTH_LOG_SIZE > raw.len() {
        return Err("Respuesta SMART NVMe incompleta".into());
    }
    let d = &raw[start..start + HEALTH_LOG_SIZE];

    // Data units are thousands of 512-byte sectors.
    let unit = 512_000u128;
    let mut sensors = Vec::new();
    for i in 0..8 {
        let k = u16::from_le_bytes([d[200 + i * 2], d[201 + i * 2]]);
        if k > 0 {
            sensors.push(kelvin(k));
        }
    }

    Ok(NvmeHealth {
        critical_warning: d[0],
        temperature_c: kelvin(u16::from_le_bytes([d[1], d[2]])),
        available_spare: d[3],
        spare_threshold: d[4],
        percentage_used: d[5],
        data_read_bytes: sat(u128_le(&d[32..48]).saturating_mul(unit)),
        data_written_bytes: sat(u128_le(&d[48..64]).saturating_mul(unit)),
        power_cycles: sat(u128_le(&d[112..128])),
        power_on_hours: sat(u128_le(&d[128..144])),
        unsafe_shutdowns: sat(u128_le(&d[144..160])),
        media_errors: sat(u128_le(&d[160..176])),
        error_log_entries: sat(u128_le(&d[176..192])),
        warning_temp_minutes: u32::from_le_bytes(d[192..196].try_into().unwrap()),
        critical_temp_minutes: u32::from_le_bytes(d[196..200].try_into().unwrap()),
        sensors_c: sensors,
    })
}
