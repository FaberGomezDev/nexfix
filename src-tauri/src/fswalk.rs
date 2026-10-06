//! Fast directory enumeration using `FindFirstFileExW` with
//! `FindExInfoBasic` + `FIND_FIRST_EX_LARGE_FETCH`: it skips short names and
//! asks NTFS for big batches, noticeably faster than `std::fs::read_dir`.

use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::Path;

use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Storage::FileSystem::{
    FindClose, FindExInfoBasic, FindExSearchNameMatch, FindFirstFileExW, FindNextFileW,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FIND_FIRST_EX_LARGE_FETCH,
    WIN32_FIND_DATAW,
};

use crate::util::{long_path, wide};

pub struct RawEntry {
    pub name: OsString,
    pub attrs: u32,
    pub size: u64,
    /// Last write time in FILETIME ticks.
    pub mtime: u64,
    pub reparse_tag: u32,
}

impl RawEntry {
    pub fn is_dir(&self) -> bool {
        self.attrs & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    /// Junctions and symlinks: following them would double count or loop.
    pub fn is_link(&self) -> bool {
        self.attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 && self.reparse_tag & 0x2000_0000 != 0
    }

    pub fn name_lossy(&self) -> String {
        self.name.to_string_lossy().into_owned()
    }
}

/// Calls `f` for every entry of `dir` (without `.` and `..`).
pub fn read_dir_fast(dir: &Path, mut f: impl FnMut(RawEntry)) -> io::Result<()> {
    let mut pattern = long_path(dir).into_os_string();
    if !pattern.to_string_lossy().ends_with('\\') {
        pattern.push("\\");
    }
    pattern.push("*");
    let pattern = wide(&pattern);

    let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    let handle = unsafe {
        FindFirstFileExW(
            pattern.as_ptr(),
            FindExInfoBasic,
            &mut data as *mut _ as *mut core::ffi::c_void,
            FindExSearchNameMatch,
            std::ptr::null(),
            FIND_FIRST_EX_LARGE_FETCH,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }

    loop {
        let len = data.cFileName.iter().position(|&c| c == 0).unwrap_or(data.cFileName.len());
        let name = &data.cFileName[..len];
        let is_dot = name == [b'.' as u16] || name == [b'.' as u16, b'.' as u16];
        if !is_dot {
            f(RawEntry {
                name: OsString::from_wide(name),
                attrs: data.dwFileAttributes,
                size: ((data.nFileSizeHigh as u64) << 32) | data.nFileSizeLow as u64,
                mtime: ((data.ftLastWriteTime.dwHighDateTime as u64) << 32)
                    | data.ftLastWriteTime.dwLowDateTime as u64,
                reparse_tag: data.dwReserved0,
            });
        }
        if unsafe { FindNextFileW(handle, &mut data) } == 0 {
            break;
        }
    }
    unsafe { FindClose(handle) };
    Ok(())
}
