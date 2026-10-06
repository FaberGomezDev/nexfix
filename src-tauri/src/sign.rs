//! Authenticode verification (embedded signatures) plus the signer name, and
//! the version-resource strings of an executable. Used by the security scan
//! to tell trusted software from unknown binaries.

use std::path::Path;

use serde::Serialize;
use windows_sys::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
    WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};

use crate::util::{from_wide, wide};

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum SignState {
    /// Valid signature from a trusted chain.
    Trusted,
    /// No embedded signature.
    Unsigned,
    /// Signed, but the signature does not verify (tampered, expired, untrusted root…).
    Invalid,
    /// File missing or unreadable.
    Unknown,
}

#[derive(Serialize, Clone, Debug)]
pub struct Signature {
    pub state: SignState,
    pub signer: Option<String>,
}

impl Signature {
    pub fn trusted(&self) -> bool {
        self.state == SignState::Trusted
    }

    pub fn by_microsoft(&self) -> bool {
        self.trusted() && self.signer.as_deref().is_some_and(|s| s.starts_with("Microsoft"))
    }
}

/// Verifies the embedded Authenticode signature without touching the network
/// (no revocation checks, cached URLs only).
pub fn verify(path: &Path) -> Signature {
    if !path.is_file() {
        return Signature { state: SignState::Unknown, signer: None };
    }
    let wpath = wide(path);
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wpath.as_ptr(),
        hFile: std::ptr::null_mut(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous.pFile = &mut file;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(std::ptr::null_mut(), &mut action, &mut data as *mut _ as *mut core::ffi::c_void)
    };
    let signer = if data.hWVTStateData.is_null() { None } else { unsafe { signer_name(&data) } };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe { WinVerifyTrust(std::ptr::null_mut(), &mut action, &mut data as *mut _ as *mut core::ffi::c_void) };

    // TRUST_E_NOSIGNATURE and friends leave no signer behind; a signer with a
    // failing status means the signature exists but does not verify.
    let state = match (status, &signer) {
        (0, _) => SignState::Trusted,
        (_, None) => SignState::Unsigned,
        (_, Some(_)) => SignState::Invalid,
    };
    Signature { state, signer }
}

unsafe fn signer_name(data: &WINTRUST_DATA) -> Option<String> {
    let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
    if prov.is_null() {
        return None;
    }
    let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
    if sgnr.is_null() {
        return None;
    }
    let cert = WTHelperGetProvCertFromChain(sgnr, 0);
    if cert.is_null() || (*cert).pCert.is_null() {
        return None;
    }
    let mut buf = [0u16; 256];
    let n = CertGetNameStringW(
        (*cert).pCert,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        std::ptr::null(),
        buf.as_mut_ptr(),
        buf.len() as u32,
    );
    let name = if n > 1 { from_wide(&buf) } else { String::new() };
    (!name.trim().is_empty()).then(|| name.trim().to_string())
}

#[derive(Serialize, Clone, Default, Debug)]
pub struct VersionInfo {
    pub company: String,
    pub product: String,
    pub description: String,
    pub original_name: String,
}

/// Reads the version resource strings (first translation) of a PE file.
pub fn version_info(path: &Path) -> Option<VersionInfo> {
    let wpath = wide(path);
    let mut handle = 0u32;
    let size = unsafe { GetFileVersionInfoSizeW(wpath.as_ptr(), &mut handle) };
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    if unsafe { GetFileVersionInfoW(wpath.as_ptr(), 0, size, buf.as_mut_ptr() as *mut core::ffi::c_void) } == 0 {
        return None;
    }

    let query = |sub: &str| -> Option<(*mut core::ffi::c_void, u32)> {
        let w = wide(sub);
        let mut ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len = 0u32;
        let ok = unsafe { VerQueryValueW(buf.as_ptr() as *const core::ffi::c_void, w.as_ptr(), &mut ptr, &mut len) };
        (ok != 0 && !ptr.is_null() && len > 0).then_some((ptr, len))
    };

    let mut langs = Vec::new();
    if let Some((ptr, len)) = query(r"\VarFileInfo\Translation") {
        let pairs = unsafe { std::slice::from_raw_parts(ptr as *const u16, (len / 2) as usize) };
        for p in pairs.chunks_exact(2) {
            langs.push(format!("{:04x}{:04x}", p[0], p[1]));
        }
    }
    langs.extend(["040904b0".to_string(), "040904e4".to_string(), "0c0a04b0".to_string()]);

    let read = |name: &str| -> String {
        for lang in &langs {
            if let Some((ptr, len)) = query(&format!(r"\StringFileInfo\{lang}\{name}")) {
                let units = unsafe { std::slice::from_raw_parts(ptr as *const u16, len as usize) };
                let s = from_wide(units).trim().to_string();
                if !s.is_empty() {
                    return s;
                }
            }
        }
        String::new()
    };
    Some(VersionInfo {
        company: read("CompanyName"),
        product: read("ProductName"),
        description: read("FileDescription"),
        original_name: read("OriginalFilename"),
    })
}
