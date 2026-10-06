//! Small helpers shared by every module: hidden process spawning, console
//! output decoding, wide strings and time conversions.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Globalization::{MultiByteToWideChar, CP_OEMCP};

pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// FILETIME ticks (100ns) between 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_DIFF: u64 = 116_444_736_000_000_000;

/// A `Command` that never flashes a console window.
pub fn hidden_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

/// Runs a short command and returns its decoded stdout (or stderr when stdout is empty).
pub fn run_capture(program: &str, args: &[&str]) -> Result<String, String> {
    let out = hidden_command(program)
        .args(args)
        .output()
        .map_err(|e| format!("No se pudo ejecutar {program}: {e}"))?;
    let mut text = decode_console(&out.stdout);
    if text.trim().is_empty() {
        text = decode_console(&out.stderr);
    }
    if !out.status.success() && text.trim().is_empty() {
        return Err(format!("{program} terminó con código {:?}", out.status.code()));
    }
    Ok(text)
}

/// Console tools write either UTF-16LE (sfc), UTF-8 or the OEM code page.
pub fn decode_console(bytes: &[u8]) -> String {
    if looks_utf16(bytes) {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .filter(|&u| u != 0xFEFF)
            .collect();
        return String::from_utf16_lossy(&units);
    }
    decode_bytes(bytes)
}

pub fn looks_utf16(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    if bytes[0] == 0xFF && bytes[1] == 0xFE {
        return true;
    }
    let odd = bytes.iter().skip(1).step_by(2).take(256);
    let total = odd.clone().count();
    let zeros = odd.filter(|&&b| b == 0).count();
    total > 0 && zeros * 10 >= total * 6
}

/// UTF-8 when valid, otherwise the console OEM code page (cp850 on Spanish Windows).
pub fn decode_bytes(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => oem_to_string(bytes),
    }
}

fn oem_to_string(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    unsafe {
        let len = MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), bytes.len() as i32, std::ptr::null_mut(), 0);
        if len <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let mut buf = vec![0u16; len as usize];
        MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), bytes.len() as i32, buf.as_mut_ptr(), len);
        String::from_utf16_lossy(&buf)
    }
}

/// NUL-terminated UTF-16 string for Win32 calls.
pub fn wide<S: AsRef<OsStr> + ?Sized>(s: &S) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Prefixes `\\?\` so Win32 APIs accept paths longer than MAX_PATH.
pub fn long_path(path: &Path) -> PathBuf {
    let s = path.as_os_str().to_string_lossy();
    if s.starts_with(r"\\?\") || s.starts_with(r"\\.\") {
        return path.to_path_buf();
    }
    let s = s.replace('/', "\\");
    if let Some(unc) = s.strip_prefix(r"\\") {
        PathBuf::from(format!(r"\\?\UNC\{unc}"))
    } else {
        PathBuf::from(format!(r"\\?\{s}"))
    }
}

/// Strips the `\\?\` prefix for display and for APIs that dislike it.
pub fn display_path(path: &Path) -> String {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        s.into_owned()
    }
}

pub fn filetime_to_unix(ticks: u64) -> i64 {
    if ticks <= FILETIME_UNIX_DIFF {
        return 0;
    }
    ((ticks - FILETIME_UNIX_DIFF) / 10_000_000) as i64
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).filter(|v| !v.is_empty()).map(PathBuf::from)
}

pub fn system_drive() -> String {
    std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string())
}

/// Converts a WMI CIM_DATETIME ("20240115000000.000000-000") into "2024-01-15".
pub fn cim_date(s: &str) -> Option<String> {
    let d = s.get(0..8)?;
    if !d.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(format!("{}-{}-{}", &d[0..4], &d[4..6], &d[6..8]))
}
