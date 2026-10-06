//! Security scan: crypto-miners hiding in the background (CPU/GPU), malware
//! persistence (Run keys, Startup folder, scheduled tasks, services, WMI,
//! Winlogon/IFEO hijacks), antivirus state and tampering (Defender
//! exclusions, hosts file) and what is filling the disk.
//!
//! Every finding carries a score built from explainable signals (shown to the
//! user as reasons) and the exact steps a fix would take. Scanning only
//! reports; nothing changes until the user picks findings (`quarantine.rs`).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rayon::prelude::*;
use serde::Serialize;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM, INVALID_FILE_ATTRIBUTES,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindow, GetWindowThreadProcessId, IsWindowVisible, GW_OWNER,
};
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
use winreg::RegKey;

use crate::fswalk::read_dir_fast;
use crate::gpu::{GpuQuery, GpuSample, ProcGpu};
use crate::sign::{self, SignState, Signature};
use crate::util::{cim_date, decode_console, display_path, env_path, filetime_to_unix, now_unix, system_drive, wide};
use crate::wmiq::{self, opt_u, s, u};

const MB: u64 = 1024 * 1024;
const GB: u64 = 1024 * MB;
const SAMPLE: Duration = Duration::from_millis(1600);
const RECENT_DAYS: u64 = 7;
/// Findings below this score are not shown (except orphan/info entries).
const SHOW_SCORE: i32 = 30;

// ---------- Public data ----------

#[derive(Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Medium,
    High,
    Critical,
}

fn level_for(score: i32) -> Level {
    match score {
        80.. => Level::Critical,
        50..=79 => Level::High,
        SHOW_SCORE..=49 => Level::Medium,
        _ => Level::Info,
    }
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Process,
    Startup,
    Task,
    Service,
    Wmi,
    Exclusion,
    Hosts,
    File,
    Defender,
}

/// One concrete change a fix performs. Executed by `quarantine::fix`.
#[derive(Clone, Debug)]
pub enum FixStep {
    /// Terminates these processes and any other instance of `exe`.
    Kill { pids: Vec<u32>, exe: Option<PathBuf> },
    /// Moves a file into NexFix's quarantine (restorable).
    Quarantine { path: PathBuf },
    /// Deletes a registry string value (backed up).
    DeleteRegValue { machine: bool, subkey: String, name: String },
    /// Overwrites a registry string value (old one backed up).
    SetRegValue { machine: bool, subkey: String, name: String, value: String },
    /// Deletes a scheduled task (its XML is backed up).
    DeleteTask { name: String, xml: PathBuf },
    /// Stops a service and sets it to Disabled (old start type backed up).
    DisableService { name: String },
    /// Removes a WMI event consumer and its bindings (not restorable).
    RemoveWmi { name: String },
    /// Removes a Microsoft Defender exclusion (restorable).
    RemoveExclusion { kind: ExclKind, value: String },
    /// Comments out lines of the hosts file (backed up).
    CommentHosts { lines: Vec<String> },
    /// Deletes files permanently (temporary junk).
    DeleteFiles { paths: Vec<PathBuf> },
}

impl FixStep {
    pub fn describe(&self) -> String {
        match self {
            FixStep::Kill { pids, exe } => match (pids.len(), exe) {
                (0, Some(e)) => format!("Cerrar {} si se está ejecutando", file_name(&e.to_string_lossy())),
                (1, _) => format!("Cerrar el proceso (PID {})", pids[0]),
                (n, _) => format!("Cerrar {n} procesos"),
            },
            FixStep::Quarantine { path } => format!("Mover a la cuarentena: {}", display_path(path)),
            FixStep::DeleteRegValue { machine, subkey, name } => {
                format!("Quitar «{name}» de {}\\{subkey} (se guarda copia)", if *machine { "HKLM" } else { "HKCU" })
            }
            FixStep::SetRegValue { name, value, .. } => format!("Restablecer «{name}» a «{value}» (se guarda copia)"),
            FixStep::DeleteTask { name, .. } => format!("Eliminar la tarea programada {name} (se guarda copia)"),
            FixStep::DisableService { name } => format!("Detener y deshabilitar el servicio «{name}»"),
            FixStep::RemoveWmi { name } => format!("Eliminar la suscripción WMI «{name}» (no se puede deshacer)"),
            FixStep::RemoveExclusion { kind, value } => format!("Quitar la exclusión de {}: {value}", kind.label()),
            FixStep::CommentHosts { lines } => format!("Desactivar {} líneas del archivo hosts (se guarda copia)", lines.len()),
            FixStep::DeleteFiles { paths } => match paths.len() {
                1 => format!("Eliminar {}", display_path(&paths[0])),
                n => format!("Eliminar {n} archivos"),
            },
        }
    }

    pub fn needs_admin(&self) -> bool {
        match self {
            FixStep::DeleteRegValue { machine, .. } | FixStep::SetRegValue { machine, .. } => *machine,
            FixStep::DeleteTask { .. }
            | FixStep::DisableService { .. }
            | FixStep::RemoveWmi { .. }
            | FixStep::RemoveExclusion { .. }
            | FixStep::CommentHosts { .. } => true,
            FixStep::DeleteFiles { paths } => paths.iter().any(|p| !p.starts_with(env_path("USERPROFILE").unwrap_or_default())),
            FixStep::Kill { .. } | FixStep::Quarantine { .. } => false,
        }
    }
}

#[derive(Serialize, serde::Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ExclKind {
    Path,
    Process,
    Extension,
}

impl ExclKind {
    pub fn label(&self) -> &'static str {
        match self {
            ExclKind::Path => "ruta",
            ExclKind::Process => "proceso",
            ExclKind::Extension => "extensión",
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct Finding {
    pub id: String,
    /// Stable key for the ignore list.
    pub key: String,
    pub kind: Kind,
    pub level: Level,
    pub score: i32,
    /// "mineria" | "malware" | "persistencia" | "proteccion" | "disco"
    pub category: &'static str,
    pub title: String,
    pub summary: String,
    pub reasons: Vec<String>,
    pub path: Option<String>,
    pub command: Option<String>,
    pub pids: Vec<u32>,
    pub signer: Option<String>,
    pub sign_state: Option<SignState>,
    pub cpu: Option<f32>,
    pub gpu: Option<f32>,
    pub vram: Option<u64>,
    pub write_rate: Option<u64>,
    pub size: Option<u64>,
    pub mtime: Option<i64>,
    /// What "Eliminar" will do, in order (empty: no automatic fix).
    pub plan: Vec<String>,
    pub needs_admin: bool,
    pub ignored: bool,
    #[serde(skip)]
    pub steps: Vec<FixStep>,
}

#[derive(Serialize, Clone)]
pub struct ProcRow {
    pub name: String,
    pub path: Option<String>,
    pub pids: Vec<u32>,
    pub cpu: f32,
    pub gpu: f32,
    pub compute: bool,
    pub vram: u64,
    pub memory: u64,
    pub write_rate: u64,
    pub written_total: u64,
    pub windowed: bool,
    pub signer: Option<String>,
    pub sign_state: Option<SignState>,
    pub flagged: bool,
}

#[derive(Serialize, Clone, Default)]
pub struct AvProduct {
    pub name: String,
    pub enabled: bool,
    pub up_to_date: bool,
    pub defender: bool,
}

#[derive(Serialize, Clone, Default)]
pub struct DefenderStatus {
    pub service: Option<bool>,
    pub antivirus: Option<bool>,
    pub realtime: Option<bool>,
    pub tamper: Option<bool>,
    pub mode: String,
    pub signature_age: Option<u64>,
    pub signature_date: Option<String>,
    pub quick_scan_age: Option<u64>,
    pub full_scan_age: Option<u64>,
}

#[derive(Serialize, Clone)]
pub struct Detection {
    pub name: String,
    pub severity: String,
    pub status: String,
    pub active: bool,
    pub resources: Vec<String>,
    pub date: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct Exclusion {
    pub kind: ExclKind,
    pub value: String,
    /// Set by group policy: Remove-MpPreference cannot remove it.
    pub policy: bool,
    pub risk: Option<String>,
}

#[derive(Serialize, Clone, Default)]
pub struct AvStatus {
    pub products: Vec<AvProduct>,
    pub defender: Option<DefenderStatus>,
    pub detections: Vec<Detection>,
    pub exclusions: Vec<Exclusion>,
    pub exclusions_readable: bool,
}

#[derive(Serialize, Clone)]
pub struct GrowthDir {
    pub path: String,
    pub bytes: u64,
    pub files: u64,
    pub note: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct BigFile {
    pub path: String,
    pub size: u64,
    pub mtime: i64,
    pub note: Option<String>,
    pub suspicious: bool,
}

#[derive(Serialize, Clone, Default)]
pub struct DiskActivity {
    pub days: u64,
    pub recent_bytes: u64,
    pub scanned_files: u64,
    pub growth: Vec<GrowthDir>,
    pub big_files: Vec<BigFile>,
}

#[derive(Serialize, Clone, Default)]
pub struct Checked {
    pub processes: usize,
    pub startup: usize,
    pub tasks: Option<usize>,
    pub services: usize,
    pub wmi: Option<usize>,
    pub hosts: bool,
}

#[derive(Serialize, Clone)]
pub struct SecurityReport {
    pub findings: Vec<Finding>,
    pub resources: Vec<ProcRow>,
    pub cpu_total: f32,
    pub gpu_total: Option<f32>,
    pub disk_write_rate: u64,
    pub av: AvStatus,
    pub disk: DiskActivity,
    pub checked: Checked,
    pub is_admin: bool,
    pub elapsed_ms: u64,
}

// ---------- Places & names ----------

pub fn norm(p: &Path) -> String {
    display_path(p).replace('/', "\\").trim_end_matches('\\').to_lowercase()
}

fn under(path: &str, dir: &str) -> bool {
    !dir.is_empty() && path.len() > dir.len() && path.starts_with(dir) && path.as_bytes()[dir.len()] == b'\\'
}

fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

/// Whether a path exists; "access denied" counts as existing (protected
/// folders such as WindowsApps must not look like deleted programs).
fn present(path: &str) -> bool {
    match std::fs::symlink_metadata(crate::util::long_path(Path::new(path))) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Lower-case file name without `.exe`.
fn stem(path: &str) -> String {
    let n = file_name(path).to_lowercase();
    n.strip_suffix(".exe").map(str::to_string).unwrap_or(n)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Loc {
    Windows,
    ProgramFiles,
    /// AppData, ProgramData, user folders: legitimate apps live here too.
    UserApps,
    /// Temp folders, Public, Recycle Bin, drive roots, odd Windows sub-folders.
    Suspicious,
    Other,
    Unknown,
}

pub struct Places {
    pub windir: String,
    windir_display: String,
    sysdrive: String,
    program_files: Vec<String>,
    programdata: String,
    users: String,
    public: String,
    temps: Vec<String>,
    own_exe: String,
}

impl Places {
    pub fn new() -> Self {
        let n = |p: Option<PathBuf>| p.map(|p| norm(&p)).unwrap_or_default();
        let win = env_path("SystemRoot").or_else(|| env_path("windir")).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        let windir = norm(&win);
        let sysdrive = system_drive().to_lowercase();
        let mut program_files: Vec<String> = ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
            .iter()
            .filter_map(|v| env_path(v))
            .map(|p| norm(&p))
            .collect();
        program_files.sort();
        program_files.dedup();
        let mut temps = vec![
            n(env_path("TEMP")),
            n(env_path("TMP")),
            n(env_path("LOCALAPPDATA").map(|p| p.join("Temp"))),
            format!("{windir}\\temp"),
        ];
        temps.retain(|t| !t.is_empty());
        temps.sort();
        temps.dedup();
        let home = n(env_path("USERPROFILE"));
        let users = home.rsplit_once('\\').map(|(a, _)| a.to_string()).unwrap_or_else(|| format!("{sysdrive}\\users"));
        Places {
            windir_display: display_path(&win).trim_end_matches('\\').to_string(),
            windir,
            program_files,
            programdata: n(env_path("ProgramData")),
            public: n(env_path("PUBLIC")),
            users,
            temps,
            own_exe: std::env::current_exe().map(|p| norm(&p)).unwrap_or_default(),
            sysdrive,
        }
    }

    fn classify(&self, p: &str) -> Loc {
        if p.is_empty() {
            return Loc::Unknown;
        }
        if self.temps.iter().any(|t| under(p, t)) || under(p, &self.public) || p.contains("\\$recycle.bin\\") {
            return Loc::Suspicious;
        }
        if under(p, &format!("{}\\perflogs", self.sysdrive)) {
            return Loc::Suspicious;
        }
        if let Some((parent, _)) = p.rsplit_once('\\') {
            if parent.len() <= 2 {
                return Loc::Suspicious; // A program straight in "C:\".
            }
        }
        if under(p, &self.windir) {
            const ODD: &[&str] = &[
                "fonts\\", "debug\\", "tasks\\", "tracing\\", "addins\\", "help\\", "media\\", "cursors\\",
                "system32\\tasks\\", "syswow64\\tasks\\", "system32\\spool\\drivers\\color\\",
                "registration\\crmlog\\", "system32\\com\\dmp\\",
            ];
            let rest = &p[self.windir.len() + 1..];
            return if ODD.iter().any(|d| rest.starts_with(d)) { Loc::Suspicious } else { Loc::Windows };
        }
        if self.program_files.iter().any(|d| under(p, d)) {
            return Loc::ProgramFiles;
        }
        if under(p, &self.programdata) || under(p, &self.users) {
            return Loc::UserApps;
        }
        Loc::Other
    }

    fn short(&self, p: &str) -> String {
        let shown = p.rsplit_once('\\').map(|(dir, _)| dir).unwrap_or(p);
        if self.temps.iter().any(|t| under(p, t)) {
            "una carpeta temporal".into()
        } else if under(p, &self.public) {
            "la carpeta Acceso público".into()
        } else if p.contains("\\$recycle.bin\\") {
            "la Papelera de reciclaje".into()
        } else {
            shown.to_string()
        }
    }

    /// Replaces %VAR% with its value and normalizes `\SystemRoot\`, `\??\`
    /// and bare `system32\…` paths (service image paths use them).
    fn expand(&self, raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        let mut rest = raw;
        while let Some(a) = rest.find('%') {
            let Some(b) = rest[a + 1..].find('%') else { break };
            let var = &rest[a + 1..a + 1 + b];
            out.push_str(&rest[..a]);
            match std::env::var(var) {
                Ok(v) if !var.is_empty() => out.push_str(&v),
                _ => out.push_str(&rest[a..a + b + 2]),
            }
            rest = &rest[a + b + 2..];
        }
        out.push_str(rest);
        let mut p = out.trim().to_string();
        if let Some(r) = p.strip_prefix(r"\??\") {
            p = r.to_string();
        }
        let lower = p.to_lowercase();
        if lower.starts_with(r"\systemroot\") {
            p = format!("{}{}", self.windir_display, &p[11..]);
        } else if lower.starts_with("system32\\") || lower.starts_with("syswow64\\") {
            p = format!("{}\\{}", self.windir_display, p);
        }
        p
    }

    /// Splits a command line into (executable, arguments), resolving
    /// unquoted paths with spaces and bare names in System32.
    fn split_command(&self, cmd: &str) -> (String, String) {
        let c = self.expand(cmd);
        let (exe, args) = if let Some(rest) = c.strip_prefix('"') {
            match rest.find('"') {
                Some(end) => (rest[..end].to_string(), rest[end + 1..].trim().to_string()),
                None => (rest.to_string(), String::new()),
            }
        } else {
            let parts: Vec<&str> = c.split(' ').collect();
            let mut found = None;
            for i in 1..=parts.len() {
                let cand = parts[..i].join(" ");
                if Path::new(&cand).is_file() || Path::new(&format!("{cand}.exe")).is_file() {
                    found = Some((cand, parts[i..].join(" ")));
                    break;
                }
            }
            found.unwrap_or_else(|| {
                let lower = c.to_lowercase();
                match lower.find(".exe") {
                    Some(i) => (c[..i + 4].to_string(), c[i + 4..].trim().to_string()),
                    None => match c.split_once(' ') {
                        Some((a, b)) => (a.to_string(), b.trim().to_string()),
                        None => (c.clone(), String::new()),
                    },
                }
            })
        };
        let exe = if !exe.contains('\\') && !exe.is_empty() {
            let name = if exe.to_lowercase().ends_with(".exe") { exe.clone() } else { format!("{exe}.exe") };
            [format!("{}\\System32\\{name}", self.windir_display), format!("{}\\{name}", self.windir_display)]
                .into_iter()
                .find(|p| Path::new(p).is_file())
                .unwrap_or(exe)
        } else {
            exe
        };
        (exe, args)
    }

    /// For script hosts and rundll32 the interesting file is the argument.
    fn payload(&self, exe: &str, args: &str) -> Option<String> {
        let host = stem(exe);
        let unq = |s: &str| s.trim().trim_matches('"').to_string();
        match host.as_str() {
            "rundll32" => {
                let first = args.trim_start_matches('"');
                let end = first.find([',', '"']).unwrap_or(first.len());
                let dll = unq(&first[..end]);
                (!dll.is_empty() && dll.contains('\\')).then(|| self.expand(&dll))
            }
            "wscript" | "cscript" | "mshta" | "powershell" | "pwsh" | "cmd" => {
                const EXT: &[&str] = &[".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".ps1", ".bat", ".cmd"];
                tokens_quoted(args)
                    .into_iter()
                    .find(|t| EXT.iter().any(|e| t.to_lowercase().ends_with(e)) && t.contains('\\'))
                    .map(|t| self.expand(&t))
            }
            _ => None,
        }
    }
}

/// Splits arguments honoring double quotes.
fn tokens_quoted(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

const MINER_NAMES: &[&str] = &[
    "xmrig", "xmrig-notls", "xmrig-cuda", "xmr-stak", "xmr-stak-rx", "xmr-stak-cpu", "xmrstak", "nbminer", "t-rex",
    "phoenixminer", "lolminer", "teamredminer", "nanominer", "ethminer", "cpuminer", "cpuminer-opt",
    "cpuminer-multi", "ccminer", "bminer", "ethdcrminer64", "nsgpucnminer", "srbminer", "srbminer-multi",
    "wildrig", "wildrig-multi", "cgminer", "bfgminer", "minerd", "nheqminer", "excavator", "nicehashquickminer",
    "nicehashminer", "minergate", "minergate-cli", "kawpowminer", "ttminer", "z-enemy", "cryptodredge",
    "onezerominer", "bzminer", "miniz", "sgminer", "xmrigdaemon", "xmrigminer", "honeyminer", "xmrminer",
    "monerominer", "coinminer", "kryptex", "unmineable", "rigel", "gminer",
];

fn is_miner_name(st: &str) -> bool {
    MINER_NAMES.iter().any(|m| {
        st == *m || (st.starts_with(m) && !st[m.len()..].starts_with(|c: char| c.is_ascii_alphabetic()))
    })
}

const POOLS: &[&str] = &[
    "supportxmr", "minexmr", "moneroocean", "nanopool.org", "2miners.com", "f2pool", "ethermine", "hashvault",
    "herominers", "c3pool", "unmineable.com", "nicehash.com", "minergate", "xmrpool", "monerohash", "zergpool",
    "prohashing", "miningpoolhub", "flypool", "hiveon", "dwarfpool", "slushpool", "viabtc", "antpool", "poolin",
    "woolypooly", "kryptex.network", "mining-dutch", "zpool.ca", "rplant.xyz", "xmrfast", "gntl.uk", "monerop.com",
    "crazypool", "k1pool", "solopool", "luckpool", "ravenminer", "ezil.me", "xmr.pool", "pool.xmr",
];

const STRATUM: &[&str] = &["stratum+tcp://", "stratum+ssl://", "stratum+tls://", "stratum2+tcp://", "stratum1+tcp://", "stratum://"];

const MINER_ARGS: &[&str] = &[
    "--donate-level", "--cpu-max-threads-hint", "--max-cpu-usage", "--randomx-", "--coin=", "--coin ",
    "--algo=", "--algo ", "-a rx/", "-a cn/", "-a cn-", "--nicehash", "--rig-id", "--cuda-loader",
    "--opencl-platform", "-a kawpow", "-a ethash", "-a etchash", "-a autolykos", "-a kheavyhash", "--asm=",
    "--huge-pages-jit", "--wallet",
];

/// Windows process names that must only run from the Windows folder.
const SYSTEM_NAMES: &[&str] = &[
    "svchost", "csrss", "lsass", "winlogon", "services", "smss", "wininit", "dwm", "conhost", "taskhostw",
    "runtimebroker", "spoolsv", "sihost", "ctfmon", "dllhost", "audiodg", "wmiprvse", "searchindexer",
    "searchprotocolhost", "searchfilterhost", "fontdrvhost", "taskmgr", "rundll32", "regsvr32", "wuauclt",
    "smartscreen", "lsaiso", "explorer", "mshta", "wscript", "cscript", "msiexec", "cmd", "powershell",
    "certutil", "userinit", "wermgr", "werfault", "backgroundtaskhost", "sgrmbroker", "msdtc", "dashost",
    "wudfhost", "lsm", "taskhost", "securityhealthservice", "securityhealthsystray",
];

const DEFENDER_NAMES: &[&str] = &["msmpeng", "nissrv", "mpcmdrun", "mpdefendercoreservice", "msmpengcp"];

/// Look-alike names (letters swapped, extra "s"...).
const TYPO_NAMES: &[&str] = &[
    "svhost", "svchosts", "scvhost", "svch0st", "svchost32", "svchostt", "svcchost", "svchots", "csrs", "cssrs",
    "crss", "csrsss", "lsas", "lssas", "isass", "lsasss", "winlogin", "winlogon32", "expl0rer", "explorerr",
    "exploer", "dlhost", "dllhst", "dllhosts", "taskhosts", "taskhostw32", "runtimebrokers", "spoolsvc",
    "smsss", "wininlt", "conhosts", "conhostt", "rundl32", "rundll", "regsvr", "taskmngr", "taskmgrs",
    "wuaucit", "msmpengs", "ctfmom", "wmiprvse32", "windowsupdate", "winupdate", "system32", "windefender",
    "windowsdefender", "securityhealth",
];

/// Microsoft .NET/Windows tools that miners and loaders inject into
/// ("process hollowing"); they rarely run on their own for long.
const HOLLOW_HOSTS: &[&str] = &[
    "addinprocess", "addinprocess32", "addinutil", "regasm", "regsvcs", "installutil", "applaunch",
    "aspnet_compiler", "caspol", "jsc", "cvtres", "ilasm", "msbuild", "vbc", "csc",
];

/// Windows processes that never use the GPU for compute on their own
/// (service hosts are left out: some Windows services use GPU compute).
const NO_COMPUTE: &[&str] = &["notepad", "explorer", "conhost", "rundll32", "regsvr32", "werfault", "mshta", "wscript", "cscript"];

#[derive(Default, Clone, Debug)]
struct Score {
    points: i32,
    reasons: Vec<String>,
    miner: bool,
    malware: bool,
}

impl Score {
    fn add(&mut self, p: i32, r: impl Into<String>) {
        self.points += p;
        self.reasons.push(r.into());
    }
}

fn has_wallet(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    let user_flag = ["-u ", "--user", "-wal ", "--wallet", "-ewal", "-o "].iter().any(|f| lower.contains(f));
    cmd.split(|c: char| c.is_whitespace() || matches!(c, '"' | '=' | ':' | '.' | '/' | ','))
        .any(|t| {
            let xmr = (t.len() == 95 || t.len() == 106)
                && (t.starts_with('4') || t.starts_with('8'))
                && t.chars().all(|c| c.is_ascii_alphanumeric() && !"0OIl".contains(c));
            let eth = user_flag && t.len() == 42 && t.starts_with("0x") && t[2..].chars().all(|c| c.is_ascii_hexdigit());
            xmr || eth
        })
}

/// Command-line signals: mining pools, wallets, obfuscated PowerShell, LOLBins.
fn analyze_command(places: &Places, cmd: &str, sc: &mut Score) {
    if cmd.trim().is_empty() {
        return;
    }
    let l = cmd.to_lowercase();
    if let Some(p) = STRATUM.iter().find(|p| l.contains(*p)) {
        sc.miner = true;
        sc.add(80, format!("Su línea de comandos conecta a un pool de minería ({})", p.trim_end_matches("://")));
    } else if let Some(p) = POOLS.iter().find(|p| l.contains(*p)) {
        sc.miner = true;
        sc.add(70, format!("Su línea de comandos menciona un pool de minería ({p})"));
    }
    let args: Vec<&str> = MINER_ARGS.iter().copied().filter(|a| l.contains(a)).collect();
    if !args.is_empty() {
        sc.miner = true;
        sc.add(40, format!("Usa opciones típicas de programas de minería ({})", args.iter().take(3).map(|a| a.trim()).collect::<Vec<_>>().join(", ")));
    }
    if has_wallet(cmd) {
        sc.miner = true;
        sc.add(50, "Incluye una dirección de monedero de criptomonedas");
    }

    // Obfuscated / downloading PowerShell.
    if l.contains("powershell") || l.contains("pwsh") || l.contains("-encodedcommand") {
        const STRONG: &[&str] = &[
            "-enc ", "-encodedcommand", "-ec ", "frombase64string", "downloadstring", "downloadfile", "iex(", "iex (",
            "invoke-expression", "net.webclient", "add-mppreference", "set-mppreference", "invoke-webrequest",
            "start-bitstransfer", "-e jab", "-e sqb",
        ];
        const WEAK: &[&str] = &["bypass", "-w hidden", "-windowstyle hidden", "-win hidden", "-nop", "-noprofile", "hidden"];
        let strong: Vec<&str> = STRONG.iter().copied().filter(|p| l.contains(p)).collect();
        let weak = WEAK.iter().filter(|p| l.contains(*p)).count();
        if !strong.is_empty() && strong.len() + weak >= 2 {
            sc.malware = true;
            sc.add(45, format!("Ejecuta PowerShell oculto u ofuscado ({})", strong.iter().take(2).map(|s| s.trim()).collect::<Vec<_>>().join(", ")));
        } else if !strong.is_empty() {
            sc.add(25, format!("Ejecuta PowerShell con comandos de riesgo ({})", strong[0].trim()));
        } else if weak >= 2 {
            sc.add(10, "Ejecuta PowerShell en modo oculto");
        }
    }

    // Living-off-the-land binaries used to download or run payloads.
    let lol: &[(&str, &[&str], i32, &str)] = &[
        ("mshta", &["http:", "https:", "javascript:", "vbscript:"], 45, "mshta ejecutando código remoto o incrustado"),
        ("regsvr32", &["/i:http", "scrobj"], 45, "regsvr32 cargando un script remoto"),
        ("rundll32", &["javascript:", "http:", "https:"], 45, "rundll32 ejecutando código remoto o incrustado"),
        ("certutil", &["-urlcache", "-decode", "/urlcache", "/decode"], 35, "certutil usado para descargar o decodificar archivos"),
        ("bitsadmin", &["/transfer", "/addfile"], 30, "bitsadmin usado para descargar archivos"),
    ];
    for (bin, pats, pts, why) in lol {
        if l.contains(bin) && pats.iter().any(|p| l.contains(p)) {
            sc.malware = true;
            sc.add(*pts, *why);
        }
    }
    let (exe, args) = places.split_command(cmd);
    if let Some(payload) = places.payload(&exe, &args) {
        let loc = places.classify(&payload.to_lowercase());
        if matches!(loc, Loc::Suspicious | Loc::UserApps) {
            let host = stem(&exe);
            if matches!(host.as_str(), "wscript" | "cscript" | "mshta") {
                sc.malware = true;
                sc.add(30, format!("Ejecuta el script {} desde una carpeta de usuario", file_name(&payload)));
            } else if host == "rundll32" {
                sc.add(25, format!("Carga la DLL {} desde una carpeta de usuario", file_name(&payload)));
            } else if loc == Loc::Suspicious {
                sc.add(20, format!("Ejecuta {} desde {}", file_name(&payload), places.short(&payload.to_lowercase())));
            }
        }
    }
}

/// File-level signals: miner names, masquerading, odd locations, hidden files.
fn analyze_file(places: &Places, path: &str, sc: &mut Score) -> Loc {
    let p = path.to_lowercase();
    let loc = places.classify(&p);
    let st = stem(&p);
    let fname = file_name(path);
    if is_miner_name(&st) {
        sc.miner = true;
        sc.add(70, format!("«{fname}» es el nombre de un programa de minería conocido"));
    } else if let Some(dir) = p.split('\\').rev().skip(1).find(|d| is_miner_name(d)) {
        sc.miner = true;
        sc.add(35, format!("Está dentro de una carpeta llamada «{dir}»"));
    }
    if loc == Loc::Suspicious {
        sc.add(20, format!("Está en {}, un lugar poco habitual para programas", places.short(&p)));
    }
    if loc != Loc::Unknown && loc != Loc::Windows && SYSTEM_NAMES.contains(&st.as_str()) {
        let defender_ok = DEFENDER_NAMES.contains(&st.as_str());
        let store_app = p.contains("\\windowsapps\\");
        if !defender_ok && !store_app {
            sc.malware = true;
            sc.add(60, format!("Se hace pasar por un archivo de Windows ({fname}) pero no está en la carpeta de Windows"));
        }
    }
    if DEFENDER_NAMES.contains(&st.as_str()) && loc != Loc::Unknown && loc != Loc::Windows
        && !p.contains("\\windows defender\\") && !p.contains("\\microsoft\\windows defender")
    {
        sc.malware = true;
        sc.add(60, format!("Se hace pasar por Microsoft Defender ({fname}) desde otra carpeta"));
    }
    if TYPO_NAMES.contains(&st.as_str()) {
        sc.malware = true;
        sc.add(45, format!("Su nombre imita a un proceso de Windows ({fname})"));
    }
    if loc != Loc::Windows && loc != Loc::Unknown {
        let attrs = unsafe { GetFileAttributesW(wide(path).as_ptr()) };
        if attrs != INVALID_FILE_ATTRIBUTES && attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) != 0 {
            sc.add(15, "El archivo está marcado como oculto o de sistema");
        }
    }
    loc
}

/// Signature and version-resource adjustments once the file was verified.
fn apply_signature(path: &str, loc: Loc, sig: &Signature, sc: &mut Score) {
    match sig.state {
        SignState::Trusted => {
            if sc.points > 0 {
                sc.points -= 35;
            }
        }
        SignState::Unsigned => match loc {
            Loc::Suspicious | Loc::UserApps => sc.add(15, "No tiene firma digital"),
            Loc::Other | Loc::ProgramFiles => sc.add(5, "No tiene firma digital"),
            _ => {}
        },
        SignState::Invalid => sc.add(25, "Su firma digital no es válida (archivo alterado o certificado no fiable)"),
        SignState::Unknown => {}
    }
    if loc == Loc::Windows || sig.trusted() {
        return;
    }
    if let Some(vi) = sign::version_info(Path::new(path)) {
        let orig = stem(&vi.original_name);
        let cur = stem(path);
        if !orig.is_empty() && orig != cur && is_miner_name(&orig) && !is_miner_name(&cur) {
            sc.miner = true;
            sc.add(60, format!("En realidad es «{}» renombrado como «{}»", vi.original_name, file_name(path)));
        }
        let text = format!("{} {} {}", vi.product, vi.description, vi.company).to_lowercase();
        const WORDS: &[&str] = &["xmrig", "miner", "monero", "nicehash", "cryptonight", "randomx", "minería", "mining"];
        if let Some(w) = WORDS.iter().find(|w| text.contains(*w)) {
            if !is_miner_name(&cur) {
                sc.miner = true;
                sc.add(40, format!("Su descripción indica un programa de minería («{w}»)"));
            }
        }
    }
}

struct SigCache(Mutex<HashMap<String, Signature>>);

impl SigCache {
    fn get(&self, path: &str) -> Signature {
        let key = path.to_lowercase();
        if let Some(s) = self.0.lock().get(&key) {
            return s.clone();
        }
        let s = sign::verify(Path::new(path));
        self.0.lock().insert(key, s.clone());
        s
    }
}

// ---------- Processes ----------

struct ProcGroup {
    key: String,
    name: String,
    exe: Option<String>,
    cmd: String,
    pids: Vec<u32>,
    parents: Vec<String>,
    cpu: f32,
    memory: u64,
    write_rate: u64,
    written_total: u64,
    windowed: bool,
    gpu: ProcGpu,
    missing: bool,
}

unsafe extern "system" fn enum_window(hwnd: HWND, lparam: LPARAM) -> windows_sys::core::BOOL {
    let set = &mut *(lparam as *mut HashSet<u32>);
    if IsWindowVisible(hwnd) != 0 && GetWindow(hwnd, GW_OWNER).is_null() {
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, &mut pid);
        set.insert(pid);
    }
    1
}

/// Processes that own a visible top-level window.
fn windowed_pids() -> HashSet<u32> {
    let mut set = HashSet::new();
    unsafe { EnumWindows(Some(enum_window), &mut set as *mut _ as LPARAM) };
    set
}

/// Samples every process for ~1.6 s: CPU, memory, disk writes and GPU.
fn sample_processes() -> (Vec<ProcGroup>, f32, Option<f32>, usize) {
    let gpu_query = GpuQuery::open();
    let mut sys = System::new();
    let kind = ProcessRefreshKind::nothing()
        .with_cpu()
        .with_memory()
        .with_disk_usage()
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_cmd(UpdateKind::OnlyIfNotSet);
    sys.refresh_cpu_usage();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
    let t0 = Instant::now();
    std::thread::sleep(SAMPLE);
    sys.refresh_cpu_usage();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
    let secs = t0.elapsed().as_secs_f64().max(0.2);
    let gpu: GpuSample = gpu_query.as_ref().map(|q| q.sample()).unwrap_or_default();
    let windows = windowed_pids();
    let cores = sys.cpus().len().max(1) as f32;

    let names: HashMap<u32, String> =
        sys.processes().iter().map(|(pid, p)| (pid.as_u32(), stem(&p.name().to_string_lossy()))).collect();
    let mut groups: HashMap<String, ProcGroup> = HashMap::new();
    for (pid, p) in sys.processes() {
        let pid = pid.as_u32();
        let name = p.name().to_string_lossy().to_string();
        if pid <= 4 || matches!(name.as_str(), "Registry" | "Memory Compression" | "Secure System" | "System Idle Process") {
            continue;
        }
        let exe = p.exe().filter(|e| !e.as_os_str().is_empty()).map(display_path);
        let key = exe.as_ref().map(|e| e.to_lowercase()).unwrap_or_else(|| format!("pid:{pid}"));
        let cmd = p.cmd().iter().map(|a| a.to_string_lossy()).collect::<Vec<_>>().join(" ");
        let g = groups.entry(key.clone()).or_insert_with(|| ProcGroup {
            missing: exe.as_ref().is_some_and(|e| !present(e)),
            key,
            name: name.clone(),
            exe: exe.clone(),
            cmd: String::new(),
            pids: Vec::new(),
            parents: Vec::new(),
            cpu: 0.0,
            memory: 0,
            write_rate: 0,
            written_total: 0,
            windowed: false,
            gpu: ProcGpu::default(),
        });
        g.pids.push(pid);
        if g.cmd.len() < cmd.len() {
            g.cmd = cmd;
        }
        if let Some(parent) = p.parent().and_then(|pp| names.get(&pp.as_u32())) {
            if !g.parents.contains(parent) {
                g.parents.push(parent.clone());
            }
        }
        g.cpu += p.cpu_usage() / cores;
        g.memory += p.memory();
        let du = p.disk_usage();
        g.write_rate += (du.written_bytes as f64 / secs) as u64;
        g.written_total += du.total_written_bytes;
        g.windowed |= windows.contains(&pid);
        if let Some(pg) = gpu.procs.get(&pid) {
            g.gpu.usage = g.gpu.usage.max(pg.usage);
            g.gpu.compute |= pg.compute;
            g.gpu.vram += pg.vram;
        }
    }
    let count = sys.processes().len();
    let gpu_total = gpu.available.then_some(gpu.total);
    (groups.into_values().collect(), sys.global_cpu_usage(), gpu_total, count)
}

fn score_process(places: &Places, g: &ProcGroup) -> (Score, Loc) {
    let mut sc = Score::default();
    let st = stem(&g.name);
    let loc = match &g.exe {
        Some(exe) => analyze_file(places, exe, &mut sc),
        None => {
            if is_miner_name(&st) {
                sc.miner = true;
                sc.add(70, format!("«{}» es el nombre de un programa de minería conocido", g.name));
            }
            Loc::Unknown
        }
    };
    analyze_command(places, &g.cmd, &mut sc);
    if g.missing {
        sc.add(20, "Su ejecutable ya no existe en el disco (técnica para ocultarse)");
    }

    let busy = g.cpu >= 10.0 || g.gpu.usage >= 10.0;
    if loc == Loc::Windows && HOLLOW_HOSTS.contains(&st.as_str()) && busy && !g.windowed {
        let dev_parent = g.parents.iter().any(|p| {
            matches!(p.as_str(), "devenv" | "msbuild" | "dotnet" | "code" | "rider64" | "servicehub.host.dotnet.x64" | "vbcscompiler")
        });
        if !dev_parent {
            sc.malware = true;
            let weight = if matches!(st.as_str(), "msbuild" | "vbc" | "csc") { 35 } else { 55 };
            sc.add(
                weight,
                format!("{} es una herramienta de .NET que no suele ejecutarse sola: los mineros se inyectan en ella para esconderse", g.name),
            );
        }
    }
    if NO_COMPUTE.contains(&st.as_str()) && g.gpu.compute && g.gpu.usage >= 15.0 {
        sc.malware = true;
        sc.miner = true;
        sc.add(50, format!("{} está usando la GPU en modo cómputo: posible minero inyectado", g.name));
    }

    // Resource signals only count for background processes, and for Windows'
    // own binaries (Windows Update, indexer...) or unknown paths only when
    // something else already looks wrong.
    let judge_resources = !matches!(loc, Loc::Windows | Loc::Unknown) || sc.points > 0;
    if !g.windowed && judge_resources {
        if g.gpu.usage >= 25.0 {
            sc.add(20, format!("Usa el {:.0} % de la GPU sin tener ninguna ventana abierta", g.gpu.usage));
            if g.gpu.compute {
                sc.add(15, "Usa la GPU en modo cómputo (CUDA/Compute), como hacen los mineros");
            }
        }
        if g.gpu.vram >= 1536 * MB {
            sc.add(10, format!("Reserva {:.1} GB de memoria de vídeo en segundo plano", g.gpu.vram as f64 / GB as f64));
        }
        if g.cpu >= 50.0 {
            sc.add(20, format!("Usa el {:.0} % de la CPU en segundo plano", g.cpu));
        } else if g.cpu >= 20.0 {
            sc.add(10, format!("Usa el {:.0} % de la CPU en segundo plano", g.cpu));
        }
        if g.write_rate >= 30 * MB {
            sc.add(10, format!("Escribe {} MB/s en el disco en segundo plano", g.write_rate / MB));
        }
    }
    (sc, loc)
}

// ---------- Persistence ----------

struct Entry {
    kind: Kind,
    id: String,
    key: String,
    title_name: String,
    source: String,
    command: String,
    remove: Vec<FixStep>,
    extra: Score,
    /// The entry itself is the problem (Winlogon/IFEO hijack): show even if
    /// the target looks legitimate.
    always: bool,
}

const RUN_KEYS: &[(bool, &str, &str)] = &[
    (false, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "Registro (usuario) · RunOnce"),
    (true, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "Registro (equipo) · RunOnce"),
    (false, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "Directiva (usuario) · Run"),
    (true, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "Directiva (equipo) · Run"),
];

fn root(machine: bool) -> RegKey {
    RegKey::predef(if machine { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER })
}

fn startup_entries(places: &Places) -> Vec<Entry> {
    let mut out = Vec::new();
    for item in crate::startup::list() {
        let remove = match crate::startup::location(&item.id) {
            Some(crate::startup::Location::Registry { machine, subkey, name }) => {
                vec![FixStep::DeleteRegValue { machine, subkey: subkey.to_string(), name }]
            }
            Some(crate::startup::Location::File(path)) => vec![FixStep::Quarantine { path }],
            None => Vec::new(),
        };
        let is_file = item.command.to_lowercase().ends_with(".lnk");
        let command = if is_file { lnk_target(Path::new(&item.command)).unwrap_or_default() } else { item.command.clone() };
        let mut extra = Score::default();
        if !is_file && item.source.starts_with("Carpeta") {
            let l = item.command.to_lowercase();
            if [".vbs", ".js", ".jse", ".vbe", ".bat", ".cmd", ".ps1", ".hta", ".wsf"].iter().any(|e| l.ends_with(e)) {
                extra.malware = true;
                extra.add(25, "Es un script colocado directamente en la carpeta Inicio");
            }
        }
        out.push(Entry {
            kind: Kind::Startup,
            id: format!("startup:{}", item.id),
            key: format!("startup:{}", item.id.to_lowercase()),
            title_name: item.name.clone(),
            source: item.source.clone(),
            command: if command.is_empty() { item.command.clone() } else { command },
            remove,
            extra,
            always: false,
        });
    }
    for (machine, subkey, label) in RUN_KEYS {
        let Ok(key) = root(*machine).open_subkey_with_flags(subkey, KEY_READ | KEY_WOW64_64KEY) else { continue };
        for (name, value) in key.enum_values().flatten() {
            if name.is_empty() {
                continue;
            }
            out.push(Entry {
                kind: Kind::Startup,
                id: format!("run:{}:{subkey}:{name}", *machine as u8),
                key: format!("run:{}:{}", *machine as u8, name.to_lowercase()),
                title_name: name.clone(),
                source: label.to_string(),
                command: value.to_string().trim_matches('"').to_string(),
                remove: vec![FixStep::DeleteRegValue { machine: *machine, subkey: subkey.to_string(), name }],
                extra: Score::default(),
                always: false,
            });
        }
    }

    // Winlogon Shell / Userinit hijacks.
    let wl = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    if let Ok(key) = root(true).open_subkey_with_flags(wl, KEY_READ | KEY_WOW64_64KEY) {
        let shell: String = key.get_value("Shell").unwrap_or_default();
        let userinit: String = key.get_value("Userinit").unwrap_or_default();
        let sh = shell.trim().to_lowercase();
        if !sh.is_empty() && sh != "explorer.exe" && !sh.ends_with("\\explorer.exe") {
            let mut extra = Score { malware: true, ..Default::default() };
            extra.add(55, "Cambia el «Shell» de Windows: se ejecuta en lugar de (o junto a) el Explorador al iniciar sesión");
            out.push(Entry {
                kind: Kind::Startup,
                id: "winlogon:shell".into(),
                key: "winlogon:shell".into(),
                title_name: "Winlogon Shell".into(),
                source: "Registro · Winlogon".into(),
                command: shell.trim().to_string(),
                remove: vec![FixStep::SetRegValue { machine: true, subkey: wl.into(), name: "Shell".into(), value: "explorer.exe".into() }],
                extra,
                always: true,
            });
        }
        let ui = userinit.trim().to_lowercase();
        let extra_items: Vec<&str> = ui
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty() && !p.ends_with("\\userinit.exe") && *p != "userinit.exe" && *p != "userinit")
            .collect();
        if !ui.is_empty() && !extra_items.is_empty() {
            let mut extra = Score { malware: true, ..Default::default() };
            extra.add(55, "Añade un programa a «Userinit»: se ejecuta cada vez que inicias sesión");
            out.push(Entry {
                kind: Kind::Startup,
                id: "winlogon:userinit".into(),
                key: "winlogon:userinit".into(),
                title_name: "Winlogon Userinit".into(),
                source: "Registro · Winlogon".into(),
                command: extra_items.join(" "),
                remove: vec![FixStep::SetRegValue {
                    machine: true,
                    subkey: wl.into(),
                    name: "Userinit".into(),
                    value: format!("{}\\system32\\userinit.exe,", places.windir_display),
                }],
                extra,
                always: true,
            });
        }
    }

    // Image File Execution Options "Debugger": hijacks or blocks programs.
    let ifeo = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    if let Ok(key) = root(true).open_subkey_with_flags(ifeo, KEY_READ | KEY_WOW64_64KEY) {
        for exe in key.enum_keys().flatten() {
            let Ok(sub) = key.open_subkey_with_flags(&exe, KEY_READ) else { continue };
            let Ok(debugger) = sub.get_value::<String, _>("Debugger") else { continue };
            let d = debugger.to_lowercase();
            // Process Explorer replacing Task Manager and VS JIT debuggers are legitimate.
            if d.is_empty() || d.contains("procexp") || d.contains("vsjitdebugger") || d.contains("windbg") {
                continue;
            }
            let mut extra = Score { malware: true, ..Default::default() };
            extra.add(55, format!("Secuestra {exe}: al abrirlo, Windows ejecuta otro programa en su lugar (o lo bloquea)"));
            out.push(Entry {
                kind: Kind::Startup,
                id: format!("ifeo:{exe}"),
                key: format!("ifeo:{}", exe.to_lowercase()),
                title_name: format!("Secuestro de {exe}"),
                source: "Registro · Image File Execution Options".into(),
                command: debugger.clone(),
                remove: vec![FixStep::DeleteRegValue { machine: true, subkey: format!(r"{ifeo}\{exe}"), name: "Debugger".into() }],
                extra,
                always: true,
            });
        }
    }

    // AppInit_DLLs: DLLs injected into every GUI process.
    let win = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
    if let Ok(key) = root(true).open_subkey_with_flags(win, KEY_READ | KEY_WOW64_64KEY) {
        let dlls: String = key.get_value("AppInit_DLLs").unwrap_or_default();
        let load: u32 = key.get_value("LoadAppInit_DLLs").unwrap_or(0);
        if load != 0 && !dlls.trim().is_empty() {
            let mut extra = Score::default();
            extra.add(45, "AppInit_DLLs inyecta estas DLL en todos los programas con ventana");
            out.push(Entry {
                kind: Kind::Startup,
                id: "appinit".into(),
                key: "appinit".into(),
                title_name: "AppInit_DLLs".into(),
                source: "Registro · Windows".into(),
                command: dlls.trim().to_string(),
                remove: vec![FixStep::SetRegValue { machine: true, subkey: win.into(), name: "AppInit_DLLs".into(), value: String::new() }],
                extra,
                always: true,
            });
        }
    }
    out
}

/// Target path of a .lnk shortcut (LinkInfo local base path + arguments).
fn lnk_target(path: &Path) -> Option<String> {
    let b = std::fs::read(path).ok()?;
    if b.len() < 0x4C || u32::from_le_bytes(b[0..4].try_into().ok()?) != 0x4C {
        return None;
    }
    let flags = u32::from_le_bytes(b[0x14..0x18].try_into().ok()?);
    let mut off = 0x4C;
    if flags & 0x1 != 0 {
        let len = u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?) as usize;
        off += 2 + len;
    }
    let mut target = None;
    if flags & 0x2 != 0 {
        let info = b.get(off..)?;
        let size = u32::from_le_bytes(info.get(0..4)?.try_into().ok()?) as usize;
        let header = u32::from_le_bytes(info.get(4..8)?.try_into().ok()?) as usize;
        let base_off = u32::from_le_bytes(info.get(16..20)?.try_into().ok()?) as usize;
        if header >= 0x24 {
            let uoff = u32::from_le_bytes(info.get(28..32)?.try_into().ok()?) as usize;
            let units: Vec<u16> = info
                .get(uoff..)?
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect();
            target = Some(String::from_utf16_lossy(&units));
        } else if base_off > 0 {
            let bytes: Vec<u8> = info.get(base_off..)?.iter().copied().take_while(|&c| c != 0).collect();
            target = Some(crate::util::decode_bytes(&bytes));
        }
        off += size;
    }
    // StringData: NAME, RELATIVE_PATH, WORKING_DIR, ARGUMENTS (counted strings).
    let unicode = flags & 0x80 != 0;
    let mut args = String::new();
    for (bit, is_args) in [(0x4, false), (0x8, false), (0x10, false), (0x20, true)] {
        if flags & bit == 0 {
            continue;
        }
        let count = u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?) as usize;
        off += 2;
        let len = if unicode { count * 2 } else { count };
        let raw = b.get(off..off + len)?;
        if is_args {
            args = if unicode {
                String::from_utf16_lossy(&raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>())
            } else {
                crate::util::decode_bytes(raw)
            };
        }
        off += len;
    }
    let target = target.filter(|t| !t.is_empty())?;
    Some(if args.is_empty() { format!("\"{target}\"") } else { format!("\"{target}\" {args}") })
}

fn xml_tags<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(a) = rest.find(&open) {
        let after = &rest[a + open.len()..];
        let Some(b) = after.find(&close) else { break };
        out.push(&after[..b]);
        rest = &after[b + close.len()..];
    }
    out
}

fn xml_unescape(s: &str) -> String {
    s.replace("&quot;", "\"").replace("&apos;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").trim().to_string()
}

/// Scheduled tasks read from their XML definitions (admin only).
fn task_entries(places: &Places) -> Option<Vec<Entry>> {
    let dir = PathBuf::from(&places.windir_display).join(r"System32\Tasks");
    let mut files = Vec::new();
    let mut stack = vec![dir.clone()];
    let mut readable = false;
    while let Some(d) = stack.pop() {
        let res = read_dir_fast(&d, |e| {
            let p = d.join(&e.name);
            if e.is_dir() {
                if !e.is_link() {
                    stack.push(p);
                }
            } else {
                files.push(p);
            }
        });
        if d == dir {
            readable = res.is_ok();
        }
    }
    if !readable {
        return None;
    }
    let base = display_path(&dir).trim_end_matches('\\').to_string();
    let entries = files
        .par_iter()
        .filter_map(|f| {
            let bytes = std::fs::read(f).ok()?;
            let xml = decode_console(&bytes);
            let disp = display_path(f);
            let name = disp.get(base.len()..).unwrap_or(&disp).to_string();
            let commands: Vec<String> = xml_tags(&xml, "Exec")
                .iter()
                .filter_map(|exec| {
                    let cmd = xml_tags(exec, "Command").first().map(|c| xml_unescape(c))?;
                    let args = xml_tags(exec, "Arguments").first().map(|a| xml_unescape(a)).unwrap_or_default();
                    let cmd = if cmd.contains(' ') && !cmd.starts_with('"') { format!("\"{cmd}\"") } else { cmd };
                    Some(if args.is_empty() { cmd } else { format!("{cmd} {args}") })
                })
                .collect();
            if commands.is_empty() {
                return None;
            }
            let settings = xml_tags(&xml, "Settings").first().copied().unwrap_or("");
            if xml_tags(settings, "Enabled").first().is_some_and(|v| v.trim() == "false") {
                return None;
            }
            let hidden = xml_tags(settings, "Hidden").first().is_some_and(|v| v.trim() == "true");
            let author = xml_tags(&xml, "Author").first().map(|a| xml_unescape(a)).unwrap_or_default();
            let mut extra = Score::default();
            let lname = name.to_lowercase();
            let target_user = {
                let (exe, _) = places.split_command(&commands[0]);
                matches!(places.classify(&exe.to_lowercase()), Loc::Suspicious | Loc::UserApps)
            };
            if hidden && target_user && !author.to_lowercase().contains("microsoft") {
                extra.add(15, "La tarea está marcada como oculta");
            }
            if target_user && ["microsoft", "windows", "update", "google", "defender", "security"].iter().any(|w| lname.contains(w)) {
                extra.add(15, "Su nombre imita a una tarea del sistema, pero ejecuta un programa de una carpeta de usuario");
            }
            Some(
                commands
                    .into_iter()
                    .map(|command| Entry {
                        kind: Kind::Task,
                        id: format!("task:{}", name),
                        key: format!("task:{}", name.to_lowercase()),
                        title_name: name.rsplit('\\').next().unwrap_or(&name).to_string(),
                        source: format!("Tarea programada {name}"),
                        command,
                        remove: vec![FixStep::DeleteTask { name: name.clone(), xml: f.clone() }],
                        extra: extra.clone(),
                        always: false,
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .flatten()
        .collect();
    Some(entries)
}

/// Win32 services and drivers from the registry (readable without admin).
fn service_entries(places: &Places) -> (Vec<Entry>, usize) {
    let mut out = Vec::new();
    let Ok(services) = root(true).open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Services", KEY_READ) else {
        return (out, 0);
    };
    let mut count = 0;
    for name in services.enum_keys().flatten() {
        let Ok(key) = services.open_subkey_with_flags(&name, KEY_READ) else { continue };
        let Ok(image) = key.get_value::<String, _>("ImagePath") else { continue };
        let ty: u32 = key.get_value("Type").unwrap_or(0);
        let start: u32 = key.get_value("Start").unwrap_or(3);
        if start == 4 || image.trim().is_empty() {
            continue;
        }
        count += 1;
        let display: String = key.get_value("DisplayName").unwrap_or_default();
        let display = if display.is_empty() || display.starts_with('@') { name.clone() } else { display };
        let driver = ty & 0x3 != 0;
        let image = places.expand(&image);
        let mut extra = Score::default();
        let remove = vec![FixStep::DisableService { name: name.clone() }];
        let mut command = image.clone();

        if driver {
            let (exe, _) = places.split_command(&image);
            let loc = places.classify(&exe.to_lowercase());
            if matches!(loc, Loc::Suspicious | Loc::UserApps) {
                extra.malware = true;
                extra.add(45, "Es un driver de kernel cargado desde una carpeta de usuario");
            } else if !stem(&exe).contains("winring0") {
                continue; // Ordinary driver: nothing to judge cheaply.
            }
            if stem(&exe).contains("winring0") {
                extra.add(
                    20,
                    "Driver WinRing0: XMRig lo instala para acelerar la minería (también lo usan programas de ventiladores/RGB)",
                );
            }
        } else if image.to_lowercase().contains("\\svchost.exe") {
            // Shared services: the code lives in Parameters\ServiceDll.
            let dll: String = key
                .open_subkey_with_flags("Parameters", KEY_READ)
                .and_then(|p| p.get_value("ServiceDll"))
                .unwrap_or_default();
            let dll = places.expand(&dll);
            if dll.is_empty() || places.classify(&dll.to_lowercase()) == Loc::Windows {
                continue;
            }
            extra.add(25, "svchost carga para este servicio una DLL de fuera de Windows");
            command = format!("\"{dll}\"");
        }
        out.push(Entry {
            kind: Kind::Service,
            id: format!("service:{name}"),
            key: format!("service:{}", name.to_lowercase()),
            title_name: display,
            source: format!("Servicio «{name}»{}", if driver { " (driver)" } else { "" }),
            command,
            remove,
            extra,
            always: false,
        });
    }
    (out, count)
}

/// WMI event consumers (fileless persistence). Admin only.
fn wmi_entries() -> Option<Vec<Entry>> {
    let con = wmiq::connect(r"ROOT\subscription")?;
    let cli = con.raw_query::<wmiq::Row>("SELECT Name, CommandLineTemplate, ExecutablePath FROM CommandLineEventConsumer").ok()?;
    let scripts = wmiq::query(&con, "SELECT Name, ScriptingEngine, ScriptText, ScriptFileName FROM ActiveScriptEventConsumer");
    let mut out = Vec::new();
    for r in cli {
        let name = s(&r, "Name");
        let mut command = s(&r, "CommandLineTemplate");
        if command.is_empty() {
            command = s(&r, "ExecutablePath");
        }
        let mut extra = Score::default();
        extra.add(40, "Se ejecuta mediante una suscripción de eventos WMI (técnica de malware «sin archivos»)");
        out.push(Entry {
            kind: Kind::Wmi,
            id: format!("wmi:{name}"),
            key: format!("wmi:{}", name.to_lowercase()),
            title_name: name.clone(),
            source: "Suscripción WMI (CommandLineEventConsumer)".into(),
            command,
            remove: vec![FixStep::RemoveWmi { name }],
            extra,
            always: false,
        });
    }
    for r in scripts {
        let name = s(&r, "Name");
        let text = s(&r, "ScriptText");
        let file = s(&r, "ScriptFileName");
        let mut extra = Score { malware: true, ..Default::default() };
        extra.add(60, format!("Ejecuta un script {} oculto en WMI (técnica de malware «sin archivos»)", s(&r, "ScriptingEngine")));
        out.push(Entry {
            kind: Kind::Wmi,
            id: format!("wmi:{name}"),
            key: format!("wmi:{}", name.to_lowercase()),
            title_name: name.clone(),
            source: "Suscripción WMI (ActiveScriptEventConsumer)".into(),
            command: if file.is_empty() { text.chars().take(400).collect() } else { file },
            remove: vec![FixStep::RemoveWmi { name }],
            extra,
            always: true,
        });
    }
    Some(out)
}

// ---------- Antivirus ----------

fn bool_of(row: &wmiq::Row, key: &str) -> Option<bool> {
    match row.get(key)? {
        wmi::Variant::Bool(b) => Some(*b),
        _ => None,
    }
}

fn strings_of(row: &wmiq::Row, key: &str) -> Vec<String> {
    match row.get(key) {
        Some(wmi::Variant::Array(items)) => items
            .iter()
            .filter_map(|v| match v {
                wmi::Variant::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        Some(wmi::Variant::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

fn threat_status(id: u64) -> (&'static str, bool) {
    match id {
        1 => ("Detectada", true),
        2 => ("Limpiada", false),
        3 => ("En cuarentena", false),
        4 => ("Eliminada", false),
        5 => ("Permitida por el usuario", false),
        6 => ("Bloqueada", false),
        102 => ("No se pudo poner en cuarentena", true),
        103 => ("No se pudo eliminar", true),
        104 => ("No se pudo permitir", false),
        105 => ("Abandonada", true),
        107 => ("No se pudo bloquear", true),
        _ => ("Desconocido", false),
    }
}

fn av_status(places: &Places) -> AvStatus {
    let mut av = AvStatus::default();
    if let Some(con) = wmiq::connect(r"ROOT\SecurityCenter2") {
        for r in wmiq::query(&con, "SELECT displayName, productState FROM AntiVirusProduct") {
            let name = s(&r, "displayName");
            let st = u(&r, "productState");
            av.products.push(AvProduct {
                defender: name.to_lowercase().contains("defender"),
                enabled: (st >> 12) & 0xF == 1,
                up_to_date: (st >> 4) & 0xF == 0,
                name,
            });
        }
    }
    if let Some(con) = wmiq::connect(r"ROOT\Microsoft\Windows\Defender") {
        if let Some(r) = wmiq::query(
            &con,
            "SELECT AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected, AMRunningMode, AntivirusSignatureAge, AntivirusSignatureLastUpdated, QuickScanAge, FullScanAge FROM MSFT_MpComputerStatus",
        )
        .into_iter()
        .next()
        {
            let age = |k: &str| opt_u(&r, k).filter(|&v| v < 60_000);
            av.defender = Some(DefenderStatus {
                service: bool_of(&r, "AMServiceEnabled"),
                antivirus: bool_of(&r, "AntivirusEnabled"),
                realtime: bool_of(&r, "RealTimeProtectionEnabled"),
                tamper: bool_of(&r, "IsTamperProtected"),
                mode: s(&r, "AMRunningMode"),
                signature_age: age("AntivirusSignatureAge"),
                signature_date: cim_date(&s(&r, "AntivirusSignatureLastUpdated")),
                quick_scan_age: age("QuickScanAge"),
                full_scan_age: age("FullScanAge"),
            });
        }
        let threats: HashMap<String, (String, u64, bool)> = wmiq::query(&con, "SELECT ThreatID, ThreatName, SeverityID, IsActive FROM MSFT_MpThreat")
            .iter()
            .map(|r| (s(r, "ThreatID"), (s(r, "ThreatName"), u(r, "SeverityID"), bool_of(r, "IsActive").unwrap_or(false))))
            .collect();
        let mut dets: Vec<Detection> = wmiq::query(&con, "SELECT ThreatID, ThreatStatusID, Resources, InitialDetectionTime FROM MSFT_MpThreatDetection")
            .iter()
            .map(|r| {
                let id = s(r, "ThreatID");
                let (name, sev, is_active) = threats.get(&id).cloned().unwrap_or_else(|| (format!("Amenaza {id}"), 0, false));
                let (status, open) = threat_status(u(r, "ThreatStatusID"));
                Detection {
                    name,
                    severity: match sev {
                        5 => "Grave",
                        4 => "Alta",
                        2 => "Media",
                        1 => "Baja",
                        _ => "Desconocida",
                    }
                    .into(),
                    status: status.into(),
                    active: is_active || open,
                    resources: strings_of(r, "Resources")
                        .into_iter()
                        .map(|x| x.split_once(":_").map(|(_, p)| p.to_string()).unwrap_or(x))
                        .take(6)
                        .collect(),
                    date: cim_date(&s(r, "InitialDetectionTime")),
                }
            })
            .collect();
        dets.sort_by(|a, b| b.active.cmp(&a.active).then(b.date.cmp(&a.date)));
        dets.truncate(15);
        av.detections = dets;
    }

    // Exclusions (the keys are readable only as administrator).
    let mut readable = false;
    for (policy, base) in [
        (false, r"SOFTWARE\Microsoft\Windows Defender\Exclusions"),
        (true, r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"),
    ] {
        for (kind, sub) in [(ExclKind::Path, "Paths"), (ExclKind::Process, "Processes"), (ExclKind::Extension, "Extensions")] {
            match root(true).open_subkey_with_flags(format!(r"{base}\{sub}"), KEY_READ | KEY_WOW64_64KEY) {
                Ok(key) => {
                    readable |= !policy;
                    for (value, _) in key.enum_values().flatten() {
                        if value.is_empty() {
                            continue;
                        }
                        let risk = exclusion_risk(places, kind, &value);
                        av.exclusions.push(Exclusion { kind, value, policy, risk });
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && !policy => readable = true,
                Err(_) => {}
            }
        }
    }
    av.exclusions_readable = readable;
    av
}

fn exclusion_risk(places: &Places, kind: ExclKind, value: &str) -> Option<String> {
    let v = value.trim().trim_end_matches('\\').to_lowercase();
    match kind {
        ExclKind::Path => {
            let home = env_path("USERPROFILE").map(|p| norm(&p)).unwrap_or_default();
            let wide_dirs = [
                places.users.clone(),
                home.clone(),
                format!("{home}\\appdata"),
                format!("{home}\\appdata\\local"),
                format!("{home}\\appdata\\roaming"),
                format!("{home}\\downloads"),
                format!("{home}\\desktop"),
                format!("{home}\\documents"),
                places.programdata.clone(),
                places.windir.clone(),
                format!("{}\\system32", places.windir),
                places.public.clone(),
            ];
            if v.len() <= 3 || v == "*" || v.ends_with(":\\*") {
                Some("Excluye una unidad entera: el antivirus no analiza nada de ella".into())
            } else if wide_dirs.contains(&v) || places.program_files.contains(&v) || places.temps.contains(&v) {
                Some("Excluye una carpeta enorme del sistema o del usuario".into())
            } else if places.temps.iter().any(|t| under(&v, t)) || under(&v, &places.public) {
                Some("Excluye una carpeta temporal: lugar típico de malware".into())
            } else if v.contains('*') && v.matches('\\').count() <= 2 {
                Some("Usa comodines sobre una ruta muy amplia".into())
            } else if v.contains("\\appdata\\") && v.matches('\\').count() <= 5 {
                Some("Excluye una carpeta dentro de AppData (los mineros suelen excluir la suya)".into())
            } else {
                None
            }
        }
        ExclKind::Process => {
            let st = stem(&v);
            if is_miner_name(&st) {
                Some("Excluye un programa de minería".into())
            } else if SYSTEM_NAMES.contains(&st.as_str()) || ["pwsh", "wmic", "bitsadmin"].contains(&st.as_str()) {
                Some("Excluye un proceso de Windows que el malware usa para ejecutarse".into())
            } else if v.contains('\\') && places.classify(&v) == Loc::Suspicious {
                Some("Excluye un programa de una carpeta temporal".into())
            } else {
                None
            }
        }
        ExclKind::Extension => {
            const RISKY: &[&str] = &["exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "js", "jse", "vbe", "hta", "msi", "com", "pif", "jar", "lnk", "sys", "wsf"];
            RISKY.contains(&v.trim_start_matches('.').trim_start_matches('*').trim_start_matches('.'))
                .then(|| "Excluye un tipo de archivo ejecutable de todos los análisis".into())
        }
    }
}

// ---------- Hosts ----------

const PROTECTED_DOMAINS: &[&str] = &[
    "virustotal.com", "malwarebytes.com", "malwarebytes.org", "kaspersky.com", "kaspersky-labs.com", "eset.com",
    "avast.com", "avg.com", "bitdefender.com", "bitdefender.net", "mcafee.com", "norton.com", "symantec.com",
    "nortonlifelock.com", "sophos.com", "trendmicro.com", "f-secure.com", "avira.com", "drweb.com",
    "emsisoft.com", "hitmanpro.com", "pandasecurity.com", "webroot.com", "gdata.de", "zonealarm.com",
    "comodo.com", "bleepingcomputer.com", "sysinternals.com", "update.microsoft.com", "windowsupdate.com",
    "windowsupdate.microsoft.com", "wdcp.microsoft.com", "wdcpalt.microsoft.com", "definitionupdates.microsoft.com",
    "smartscreen.microsoft.com", "smartscreen-prod.microsoft.com", "wd.microsoft.com", "go.microsoft.com",
    "download.microsoft.com", "security.microsoft.com",
];

pub fn hosts_path(places: &Places) -> PathBuf {
    PathBuf::from(&places.windir_display).join(r"System32\drivers\etc\hosts")
}

fn hosts_check(places: &Places) -> (bool, Vec<String>) {
    let Ok(bytes) = std::fs::read(hosts_path(places)) else { return (false, Vec::new()) };
    let text = String::from_utf8_lossy(&bytes);
    let bad = text
        .lines()
        .filter(|line| {
            let l = line.trim().to_lowercase();
            if l.is_empty() || l.starts_with('#') {
                return false;
            }
            let content = l.split('#').next().unwrap_or("");
            content.split_whitespace().skip(1).any(|host| {
                PROTECTED_DOMAINS.iter().any(|d| host == *d || host.ends_with(&format!(".{d}")))
            })
        })
        .map(|l| l.trim_end_matches('\r').to_string())
        .collect();
    (true, bad)
}

// ---------- Disk ----------

const NOTES: &[(&str, &str)] = &[
    ("ext4.vhdx", "Disco virtual de WSL (Linux en Windows)"),
    (".vhdx", "Disco virtual (WSL, Docker o máquina virtual)"),
    (".vhd", "Disco virtual"),
    (".vmdk", "Disco de máquina virtual"),
    ("\\docker", "Datos de Docker"),
    ("\\nvidia\\dxcache", "Caché de sombreadores de NVIDIA (se puede borrar en Limpieza)"),
    ("\\nvidia\\glcache", "Caché de sombreadores de NVIDIA (se puede borrar en Limpieza)"),
    ("\\nvidia\\perdriverversion", "Caché de sombreadores de NVIDIA (se puede borrar en Limpieza)"),
    ("\\nv_cache", "Caché de sombreadores de NVIDIA (se puede borrar en Limpieza)"),
    ("\\nvidia corporation\\downloader", "Descargas de drivers de NVIDIA (se pueden borrar en Limpieza)"),
    ("\\d3dscache", "Caché de sombreadores de DirectX"),
    ("\\amd\\", "Caché de sombreadores de AMD"),
    ("\\google\\chrome", "Datos y caché de Chrome"),
    ("\\microsoft\\edge", "Datos y caché de Edge"),
    ("\\bravesoftware", "Datos de Brave"),
    ("\\mozilla", "Datos de Firefox"),
    ("\\opera software", "Datos de Opera"),
    ("\\discord", "Discord"),
    ("\\npm-cache", "Caché de npm"),
    ("\\pnpm", "Almacén de pnpm"),
    ("\\pip\\cache", "Caché de pip"),
    ("\\yarn", "Caché de Yarn"),
    ("\\nuget", "Paquetes NuGet"),
    ("\\microsoft\\search\\data", "Índice de búsqueda de Windows"),
    ("\\microsoft\\windows\\wer", "Informes de errores de Windows (se pueden borrar en Limpieza)"),
    ("crashdumps", "Volcados de errores de programas"),
    ("livekernelreports", "Informes de fallos del kernel"),
    (".dmp", "Volcado de memoria"),
    (".ost", "Caché de correo de Outlook"),
    (".pst", "Archivo de correo de Outlook"),
    ("\\steam", "Steam"),
    ("\\epic", "Epic Games"),
    ("\\battle.net", "Battle.net"),
    ("\\riot", "Riot Games"),
    ("\\ubisoft", "Ubisoft Connect"),
    ("\\electronic arts", "EA app"),
    ("\\ea desktop", "EA app"),
    ("\\package cache", "Instaladores guardados por programas de Microsoft"),
    ("\\deliveryoptimization", "Optimización de distribución de Windows Update"),
    ("\\softwaredistribution", "Windows Update"),
    ("\\packages\\", "Datos de una app de Microsoft Store"),
    ("\\obs-studio", "OBS Studio"),
    ("\\onedrive", "OneDrive"),
    ("\\spotify", "Caché de Spotify"),
    ("\\jetbrains", "JetBrains"),
    ("cbspersist", "Registros de CBS de Windows (pueden crecer sin control; se borran en Limpieza)"),
    ("\\logs\\cbs", "Registros de CBS de Windows (se borran en Limpieza)"),
    ("\\nexfix\\", "Cuarentena de NexFix"),
    ("\\containers\\", "Capas de Windows Sandbox/contenedores: casi todo son enlaces duros (ocupan menos de lo que aparentan). Libéralas desactivando Windows Sandbox en Mantenimiento"),
];

fn explain(path_lower: &str) -> Option<String> {
    NOTES.iter().find(|(k, _)| path_lower.contains(k)).map(|(_, v)| v.to_string())
}

#[derive(Default)]
struct Acc {
    recent: u64,
    recent_files: u64,
    files: u64,
    big: Vec<(PathBuf, u64, u64)>,
}

impl Acc {
    fn merge(&mut self, o: Acc) {
        self.recent += o.recent;
        self.recent_files += o.recent_files;
        self.files += o.files;
        self.big.extend(o.big);
    }
}

struct DiskCtx {
    cutoff: u64,
    skip: Vec<String>,
}

fn offer_file(ctx: &DiskCtx, acc: &mut Acc, path: PathBuf, size: u64, mtime: u64) {
    acc.files += 1;
    let recent = mtime >= ctx.cutoff;
    if recent {
        acc.recent += size;
        acc.recent_files += 1;
    }
    if (recent && size >= 256 * MB) || size >= 2 * GB {
        acc.big.push((path, size, mtime));
    }
}

fn walk_all(dir: &Path, ctx: &DiskCtx) -> Acc {
    let mut acc = Acc::default();
    let mut subs = Vec::new();
    let _ = read_dir_fast(dir, |e| {
        let p = dir.join(&e.name);
        if e.is_dir() {
            if !e.is_link() && !ctx.skip.contains(&norm(&p)) {
                subs.push(p);
            }
        } else {
            offer_file(ctx, &mut acc, p, e.size, e.mtime);
        }
    });
    for a in subs.into_par_iter().map(|s| walk_all(&s, ctx)).collect::<Vec<_>>() {
        acc.merge(a);
    }
    acc
}

/// Walks `dir`, accounting everything below `depth` levels to its own group.
fn group_walk(dir: &Path, depth: u32, ctx: &DiskCtx) -> Vec<(PathBuf, Acc)> {
    if depth == 0 {
        return vec![(dir.to_path_buf(), walk_all(dir, ctx))];
    }
    let mut own = Acc::default();
    let mut subs = Vec::new();
    let _ = read_dir_fast(dir, |e| {
        let p = dir.join(&e.name);
        if e.is_dir() {
            if !e.is_link() && !ctx.skip.contains(&norm(&p)) {
                subs.push(p);
            }
        } else {
            offer_file(ctx, &mut own, p, e.size, e.mtime);
        }
    });
    let mut out: Vec<(PathBuf, Acc)> = subs.into_par_iter().flat_map(|s| group_walk(&s, depth - 1, ctx)).collect();
    out.push((dir.to_path_buf(), own));
    out
}

fn disk_activity(places: &Places) -> (DiskActivity, Vec<Finding>) {
    let now_ticks = (now_unix() as u64) * 10_000_000 + 116_444_736_000_000_000;
    let local = env_path("LOCALAPPDATA");
    let mut skip: Vec<String> = places.temps.clone();
    if let Some(pd) = env_path("ProgramData") {
        skip.push(norm(&pd.join(r"Microsoft\Windows\Containers")));
    }
    let ctx = DiskCtx { cutoff: now_ticks.saturating_sub(RECENT_DAYS * 86_400 * 10_000_000), skip };

    let win = PathBuf::from(&places.windir_display);
    let mut roots: Vec<(PathBuf, u32)> = Vec::new();
    let mut seen = HashSet::new();
    for t in &places.temps {
        if seen.insert(t.clone()) {
            roots.push((PathBuf::from(t), 1));
        }
    }
    for (p, d) in [
        (local.clone(), 2),
        (env_path("APPDATA"), 2),
        (env_path("USERPROFILE").map(|h| h.join(r"AppData\LocalLow")), 2),
        (env_path("ProgramData"), 2),
        (env_path("PUBLIC"), 1),
        (Some(win.join("Logs")), 1),
    ] {
        if let Some(p) = p {
            roots.push((p, d));
        }
    }
    // Temps are skipped below LocalAppData (the skip list only applies to
    // sub-folders) and walked as roots of their own.
    let groups: Vec<(PathBuf, Acc)> = roots.par_iter().flat_map(|(p, d)| group_walk(p, *d, &ctx)).collect();

    // Files straight in the system drive root.
    let mut root_acc = Acc::default();
    let sys_root = PathBuf::from(format!("{}\\", system_drive()));
    let _ = read_dir_fast(&sys_root, |e| {
        let n = e.name_lossy().to_lowercase();
        if !e.is_dir() && !matches!(n.as_str(), "pagefile.sys" | "hiberfil.sys" | "swapfile.sys" | "dumpstack.log.tmp") {
            offer_file(&ctx, &mut root_acc, sys_root.join(&e.name), e.size, e.mtime);
        }
    });

    let mut all: Vec<(PathBuf, Acc)> = groups;
    all.push((sys_root.clone(), root_acc));
    let mut activity = DiskActivity { days: RECENT_DAYS, ..Default::default() };
    let mut big = Vec::new();
    let mut growth = Vec::new();
    for (path, acc) in all {
        activity.recent_bytes += acc.recent;
        activity.scanned_files += acc.files;
        big.extend(acc.big);
        if acc.recent >= 64 * MB {
            let p = display_path(&path);
            growth.push(GrowthDir { note: explain(&p.to_lowercase()), path: p, bytes: acc.recent, files: acc.recent_files });
        }
    }
    growth.sort_unstable_by(|a, b| b.bytes.cmp(&a.bytes));
    growth.truncate(12);
    activity.growth = growth;

    let mut findings = Vec::new();
    big.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    big.dedup_by(|a, b| a.0 == b.0);
    let recent_cut = ctx.cutoff;
    for (path, size, mtime) in &big {
        let p = display_path(path);
        let l = p.to_lowercase();
        let note = explain(&l);
        let suspicious = note.is_none() && places.classify(&l) == Loc::Suspicious && *size >= GB && *mtime >= recent_cut;
        if suspicious {
            findings.push(file_finding(
                &p,
                *size,
                *mtime,
                format!("Archivo enorme y reciente en {}", places.short(&l)),
                "Un archivo de varios GB creado hace poco en una carpeta temporal o pública no es normal: algunos programas maliciosos (o defectuosos) llenan el disco así.".into(),
                vec![format!("Ocupa {:.1} GB y se modificó en los últimos {RECENT_DAYS} días", *size as f64 / GB as f64)],
                40,
                vec![FixStep::DeleteFiles { paths: vec![path.clone()] }],
            ));
        } else if l.ends_with(".log") && *size >= GB && *mtime >= recent_cut {
            findings.push(file_finding(
                &p,
                *size,
                *mtime,
                format!("Archivo de registro desbocado: {}", file_name(&p)),
                "Un archivo de log que crece sin parar llena el disco. Suele deberse a un programa que falla en bucle.".into(),
                vec![format!("Ocupa {:.1} GB y sigue creciendo", *size as f64 / GB as f64)],
                35,
                vec![FixStep::DeleteFiles { paths: vec![path.clone()] }],
            ));
        } else if (l.ends_with("\\windows.edb") || l.ends_with("\\windows.db")) && *size >= 8 * GB {
            findings.push(file_finding(
                &p,
                *size,
                *mtime,
                "El índice de búsqueda de Windows es enorme".into(),
                "Un fallo conocido hace crecer el índice sin control. Reconstrúyelo: Opciones de indización → Avanzadas → Reconstruir.".into(),
                vec![format!("Ocupa {:.1} GB", *size as f64 / GB as f64)],
                35,
                Vec::new(),
            ));
        }
    }
    activity.big_files = big
        .into_iter()
        .take(30)
        .map(|(path, size, mtime)| {
            let p = display_path(&path);
            let l = p.to_lowercase();
            let note = explain(&l);
            BigFile {
                suspicious: note.is_none() && places.classify(&l) == Loc::Suspicious && size >= GB,
                note,
                path: p,
                size,
                mtime: filetime_to_unix(mtime),
            }
        })
        .collect();

    // Known Windows bug: makecab fills Windows\Temp with cab_* files.
    let wtemp = win.join("Temp");
    let mut cabs = Vec::new();
    let _ = read_dir_fast(&wtemp, |e| {
        let n = e.name_lossy().to_lowercase();
        if !e.is_dir() && (n.starts_with("cab_") || n.ends_with(".cab")) {
            cabs.push((wtemp.join(&e.name), e.size));
        }
    });
    let cab_total: u64 = cabs.iter().map(|c| c.1).sum();
    if cab_total >= 512 * MB {
        findings.push(file_finding(
            &display_path(&wtemp),
            cab_total,
            0,
            "Windows está llenando C:\\Windows\\Temp con archivos CAB".into(),
            "Fallo conocido de Windows: el servicio de registros (CBS) comprime sus logs una y otra vez y llena el disco. Borrar estos CAB es seguro.".into(),
            vec![format!("{} archivos CAB ocupan {:.1} GB", cabs.len(), cab_total as f64 / GB as f64)],
            55,
            vec![FixStep::DeleteFiles { paths: cabs.into_iter().map(|c| c.0).collect() }],
        ));
    }
    (activity, findings)
}

#[allow(clippy::too_many_arguments)]
fn file_finding(path: &str, size: u64, mtime: u64, title: String, summary: String, reasons: Vec<String>, score: i32, steps: Vec<FixStep>) -> Finding {
    Finding {
        id: format!("file:{}", path.to_lowercase()),
        key: format!("file:{}", path.to_lowercase()),
        kind: Kind::File,
        level: level_for(score),
        score,
        category: "disco",
        title,
        summary,
        reasons,
        path: Some(path.to_string()),
        command: None,
        pids: Vec::new(),
        signer: None,
        sign_state: None,
        cpu: None,
        gpu: None,
        vram: None,
        write_rate: None,
        size: Some(size),
        mtime: (mtime > 0).then(|| filetime_to_unix(mtime)),
        plan: steps.iter().map(|s| s.describe()).collect(),
        needs_admin: steps.iter().any(|s| s.needs_admin()),
        ignored: false,
        steps,
    }
}

// ---------- Assembly ----------

fn blank(id: String, key: String, kind: Kind, score: i32, category: &'static str, title: String, summary: String) -> Finding {
    Finding {
        id,
        key,
        kind,
        level: level_for(score),
        score,
        category,
        title,
        summary,
        reasons: Vec::new(),
        path: None,
        command: None,
        pids: Vec::new(),
        signer: None,
        sign_state: None,
        cpu: None,
        gpu: None,
        vram: None,
        write_rate: None,
        size: None,
        mtime: None,
        plan: Vec::new(),
        needs_admin: false,
        ignored: false,
        steps: Vec::new(),
    }
}

fn finish(mut f: Finding, steps: Vec<FixStep>) -> Finding {
    f.plan = steps.iter().map(|s| s.describe()).collect();
    f.needs_admin = steps.iter().any(|s| s.needs_admin());
    f.steps = steps;
    f.level = level_for(f.score);
    f
}

const MINER_SUMMARY: &str = "Los mineros ocultos usan tu CPU o tu gráfica para ganar criptomonedas para otra persona: más temperatura, ruido y consumo, y menos FPS. Si no lo instalaste tú, elimínalo.";
const MALWARE_SUMMARY: &str = "Los programas que imitan archivos de Windows, se inyectan en procesos legítimos o se esconden suelen ser malware.";
const BACKGROUND_SUMMARY: &str = "Consume muchos recursos sin ninguna ventana y sin una firma que lo identifique. Si no sabes qué es, revísalo.";
const PERSIST_SUMMARY: &str = "Se ejecuta solo al encender el PC. Es la forma en que el malware vuelve aunque cierres el proceso.";

pub fn scan(is_admin: bool, ignored: &HashSet<String>) -> SecurityReport {
    let t0 = Instant::now();
    let places = Places::new();
    let sigs = SigCache(Mutex::new(HashMap::new()));

    let ((procs_data, (persist, services, tasks, wmi)), (av, ((hosts_ok, hosts_bad), (disk, disk_findings)))) = rayon::join(
        || {
            rayon::join(sample_processes, || {
                let mut entries = startup_entries(&places);
                let startup_count = entries.len();
                let (svc, svc_count) = service_entries(&places);
                let tasks = if is_admin { task_entries(&places) } else { None };
                let wmi = if is_admin { wmi_entries() } else { None };
                let task_count = tasks.as_ref().map(|t| t.len());
                let wmi_count = wmi.as_ref().map(|w| w.len());
                entries.extend(svc);
                entries.extend(tasks.unwrap_or_default());
                entries.extend(wmi.unwrap_or_default());
                (entries, (startup_count, svc_count), task_count, wmi_count)
            })
        },
        || rayon::join(|| av_status(&places), || rayon::join(|| hosts_check(&places), || disk_activity(&places))),
    );
    let (groups, cpu_total, gpu_total, proc_count) = procs_data;

    // ---- Processes ----
    let mut scored: Vec<(ProcGroup, Score, Loc)> = groups
        .into_iter()
        .filter(|g| g.key != places.own_exe)
        .map(|g| {
            let (sc, loc) = score_process(&places, &g);
            (g, sc, loc)
        })
        .collect();
    // Verify signatures of whatever looks interesting (in parallel, cached).
    let mut verify: Vec<String> = scored
        .iter()
        .filter(|(g, sc, loc)| {
            *loc != Loc::Windows
                && *loc != Loc::Unknown
                && (sc.points > 0 || g.cpu >= 5.0 || g.gpu.usage >= 5.0 || g.gpu.vram >= 512 * MB || g.write_rate >= 5 * MB)
        })
        .filter_map(|(g, _, _)| g.exe.clone())
        .collect();
    verify.truncate(60);
    verify.par_iter().for_each(|p| {
        sigs.get(p);
    });

    let mut findings: Vec<Finding> = Vec::new();
    let mut rows: Vec<(f32, ProcRow)> = Vec::new();
    for (g, mut sc, loc) in scored.drain(..) {
        let sig = g.exe.as_ref().filter(|_| loc != Loc::Windows && loc != Loc::Unknown).map(|p| {
            let key = p.to_lowercase();
            sigs.0.lock().get(&key).cloned()
        });
        let sig = sig.flatten();
        if let (Some(exe), Some(sig)) = (&g.exe, &sig) {
            apply_signature(exe, loc, sig, &mut sc);
        }
        let flagged = sc.points >= SHOW_SCORE;
        let weight = g.gpu.usage * 2.0 + g.cpu + (g.write_rate / MB) as f32 / 5.0 + (g.gpu.vram as f32 / GB as f32) * 10.0;
        if flagged || weight >= 2.0 {
            rows.push((
                if flagged { 1e6 + weight } else { weight },
                ProcRow {
                    name: g.name.clone(),
                    path: g.exe.clone(),
                    pids: g.pids.clone(),
                    cpu: g.cpu,
                    gpu: g.gpu.usage,
                    compute: g.gpu.compute,
                    vram: g.gpu.vram,
                    memory: g.memory,
                    write_rate: g.write_rate,
                    written_total: g.written_total,
                    windowed: g.windowed,
                    signer: sig.as_ref().and_then(|s| s.signer.clone()),
                    sign_state: sig.as_ref().map(|s| s.state),
                    flagged,
                },
            ));
        }
        if !flagged {
            continue;
        }
        let (category, title, summary) = if sc.miner {
            ("mineria", format!("Minero de criptomonedas: {}", g.name), MINER_SUMMARY)
        } else if sc.malware {
            ("malware", format!("Proceso sospechoso: {}", g.name), MALWARE_SUMMARY)
        } else {
            ("malware", format!("Consumo sospechoso en segundo plano: {}", g.name), BACKGROUND_SUMMARY)
        };
        let mut f = blank(
            format!("proc:{}", g.key),
            g.exe.as_ref().map(|e| format!("exe:{}", e.to_lowercase())).unwrap_or_else(|| format!("proc:{}", g.name.to_lowercase())),
            Kind::Process,
            sc.points,
            category,
            title,
            summary.into(),
        );
        f.reasons = sc.reasons;
        f.path = g.exe.clone();
        f.command = (!g.cmd.is_empty()).then(|| g.cmd.clone());
        f.pids = g.pids.clone();
        f.signer = sig.as_ref().and_then(|s| s.signer.clone());
        f.sign_state = sig.as_ref().map(|s| s.state);
        f.cpu = Some(g.cpu);
        f.gpu = Some(g.gpu.usage);
        f.vram = Some(g.gpu.vram);
        f.write_rate = Some(g.write_rate);
        let mut steps = vec![FixStep::Kill { pids: g.pids.clone(), exe: g.exe.as_ref().map(PathBuf::from) }];
        if let Some(exe) = &g.exe {
            if loc != Loc::Windows && Path::new(exe).is_file() {
                steps.push(FixStep::Quarantine { path: PathBuf::from(exe) });
            }
        }
        findings.push(finish(f, steps));
    }
    rows.sort_by(|a, b| b.0.total_cmp(&a.0));
    let resources: Vec<ProcRow> = rows.into_iter().take(20).map(|r| r.1).collect();
    let disk_write_rate = resources.iter().map(|r| r.write_rate).sum();

    // ---- Persistence ----
    let checked_startup = services.0;
    let checked_services = services.1;
    let prepared: Vec<(Entry, String, String, Score, Loc)> = persist
        .into_iter()
        .map(|e| {
            let mut sc = e.extra.clone();
            let (exe, args) = places.split_command(&e.command);
            let target = places.payload(&exe, &args).unwrap_or_else(|| exe.clone());
            let loc = if target.contains('\\') { analyze_file(&places, &target, &mut sc) } else { Loc::Unknown };
            analyze_command(&places, &e.command, &mut sc);
            (e, exe, target, sc, loc)
        })
        .collect();
    let to_verify: Vec<String> = prepared
        .iter()
        .filter(|(e, _, t, sc, loc)| {
            (sc.points > 0 || e.always) && !matches!(loc, Loc::Windows | Loc::Unknown) && Path::new(t).is_file()
        })
        .map(|(_, _, t, _, _)| t.clone())
        .take(120)
        .collect();
    to_verify.par_iter().for_each(|p| {
        sigs.get(p);
    });

    let mut seen_entries = HashSet::new();
    for (e, exe, target, mut sc, loc) in prepared {
        let exists = target.contains('\\') && present(&target);
        let sig = (!matches!(loc, Loc::Windows | Loc::Unknown) && exists)
            .then(|| sigs.0.lock().get(&target.to_lowercase()).cloned())
            .flatten();
        if let Some(sig) = &sig {
            apply_signature(&target, loc, sig, &mut sc);
        }
        let orphan = !exists && target.contains('\\') && matches!(e.kind, Kind::Startup | Kind::Task) && !e.always;
        if sc.points < SHOW_SCORE && !orphan && !(e.always && sc.points > 0) {
            continue;
        }
        if !seen_entries.insert(e.id.clone()) {
            continue;
        }
        let (category, title, summary): (&'static str, String, String) = if orphan && sc.points < SHOW_SCORE {
            (
                "persistencia",
                format!("Entrada de inicio rota: {}", e.title_name),
                "Apunta a un programa que ya no existe. No es peligrosa, pero sobra: puedes quitarla.".into(),
            )
        } else {
            let what = match e.kind {
                Kind::Task => "Tarea programada sospechosa",
                Kind::Service => "Servicio sospechoso",
                Kind::Wmi => "Persistencia WMI",
                _ => "Inicio automático sospechoso",
            };
            (
                if sc.miner { "mineria" } else { "persistencia" },
                format!("{what}: {}", e.title_name),
                if sc.miner { MINER_SUMMARY.into() } else { PERSIST_SUMMARY.into() },
            )
        };
        let score = if orphan && sc.points < SHOW_SCORE { 10 } else { sc.points.max(SHOW_SCORE) };
        let mut f = blank(e.id.clone(), e.key.clone(), e.kind, score, category, title, summary);
        if orphan {
            sc.reasons.insert(0, format!("El archivo {} ya no existe", file_name(&target)));
        }
        f.reasons = sc.reasons;
        f.reasons.push(format!("Origen: {}", e.source));
        f.path = target.contains('\\').then(|| target.clone());
        f.command = Some(e.command.clone());
        f.signer = sig.as_ref().and_then(|s| s.signer.clone());
        f.sign_state = sig.as_ref().map(|s| s.state);
        // Remove the entry first (a service must stop before its file can
        // move), then close the program, then quarantine its file.
        let mut steps = e.remove.clone();
        let quarantine_target = exists && sc.points >= SHOW_SCORE && loc != Loc::Windows && Path::new(&target).is_file();
        // Only kill when the target is the program itself, never a shared
        // host such as wscript.exe or rundll32.exe.
        if quarantine_target && e.kind != Kind::Wmi && target.eq_ignore_ascii_case(&exe) {
            steps.push(FixStep::Kill { pids: Vec::new(), exe: Some(PathBuf::from(&exe)) });
        }
        if quarantine_target {
            let already = steps.iter().any(|s| matches!(s, FixStep::Quarantine { path } if norm(path) == target.to_lowercase()));
            if !already {
                steps.push(FixStep::Quarantine { path: PathBuf::from(&target) });
            }
        }
        findings.push(finish(f, steps));
    }

    // ---- Antivirus ----
    let active_av: Vec<&AvProduct> = av.products.iter().filter(|p| p.enabled).collect();
    let defender_rt = av.defender.as_ref().and_then(|d| d.realtime);
    if (av.products.is_empty() && defender_rt == Some(false)) || (!av.products.is_empty() && active_av.is_empty()) {
        let mut f = blank(
            "av:none".into(),
            "av:none".into(),
            Kind::Defender,
            70,
            "proteccion",
            "No hay ningún antivirus activo".into(),
            "Sin protección en tiempo real cualquier programa malicioso se ejecuta sin control. Activa Microsoft Defender (Seguridad de Windows → Protección antivirus y contra amenazas).".into(),
        );
        f.reasons = av.products.iter().map(|p| format!("{}: desactivado", p.name)).collect();
        findings.push(f);
    }
    for d in av.detections.iter().filter(|d| d.active) {
        let mut f = blank(
            format!("det:{}", d.name),
            format!("det:{}", d.name.to_lowercase()),
            Kind::Defender,
            90,
            if d.name.to_lowercase().contains("miner") { "mineria" } else { "malware" },
            format!("Microsoft Defender detectó «{}» y sigue activa", d.name),
            "Defender no pudo terminar de eliminarla. Ejecuta el análisis sin conexión de Microsoft Defender (reinicia el PC y analiza antes de que arranque Windows).".into(),
        );
        f.reasons = vec![format!("Estado: {} · gravedad {}", d.status, d.severity)];
        f.reasons.extend(d.resources.iter().map(|r| format!("Afecta a {r}")));
        f.path = d.resources.first().cloned();
        findings.push(f);
    }
    if let Some(def) = &av.defender {
        let defender_active = av.products.iter().any(|p| p.defender && p.enabled) || def.realtime == Some(true);
        if defender_active {
            if let Some(age) = def.signature_age.filter(|&a| a > 7) {
                let mut f = blank(
                    "av:signatures".into(),
                    "av:signatures".into(),
                    Kind::Defender,
                    35,
                    "proteccion",
                    format!("Las firmas de Microsoft Defender tienen {age} días"),
                    "Con firmas antiguas el antivirus no reconoce las amenazas nuevas. Actualízalas.".into(),
                );
                f.reasons = vec!["Defender suele actualizarse a diario".into()];
                findings.push(f);
            }
        }
    }
    for ex in av.exclusions.iter().filter(|e| e.risk.is_some()) {
        let mut f = blank(
            format!("excl:{:?}:{}", ex.kind, ex.value.to_lowercase()),
            format!("excl:{:?}:{}", ex.kind, ex.value.to_lowercase()),
            Kind::Exclusion,
            55,
            "proteccion",
            format!("El antivirus ignora {}: {}", ex.kind.label(), ex.value),
            "Las exclusiones hacen que Microsoft Defender no analice esa ruta, proceso o tipo de archivo. Los mineros suelen añadirse a sí mismos para que no los detecte.".into(),
        );
        f.reasons = vec![ex.risk.clone().unwrap_or_default()];
        if ex.policy {
            f.reasons.push("Está configurada por directiva de grupo: quítala desde gpedit.msc".into());
            findings.push(f);
        } else {
            findings.push(finish(f, vec![FixStep::RemoveExclusion { kind: ex.kind, value: ex.value.clone() }]));
        }
    }

    // ---- Hosts ----
    if !hosts_bad.is_empty() {
        let mut f = blank(
            "hosts".into(),
            "hosts".into(),
            Kind::Hosts,
            60,
            "proteccion",
            "El archivo hosts bloquea sitios de seguridad".into(),
            "El malware edita el archivo hosts para impedir que el antivirus y Windows Update se actualicen o que visites webs de seguridad.".into(),
        );
        f.reasons = hosts_bad.iter().take(8).map(|l| format!("Línea: {l}")).collect();
        f.path = Some(display_path(&hosts_path(&places)));
        findings.push(finish(f, vec![FixStep::CommentHosts { lines: hosts_bad.clone() }]));
    }

    findings.extend(disk_findings);
    for f in &mut findings {
        f.ignored = ignored.contains(&f.key);
    }
    findings.sort_by(|a, b| b.level.cmp(&a.level).then(b.score.cmp(&a.score)));

    SecurityReport {
        findings,
        resources,
        cpu_total,
        gpu_total,
        disk_write_rate,
        av,
        disk,
        checked: Checked {
            processes: proc_count,
            startup: checked_startup,
            tasks,
            services: checked_services,
            wmi,
            hosts: hosts_ok,
        },
        is_admin,
        elapsed_ms: t0.elapsed().as_millis() as u64,
    }
}
