import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

// ---------- Types (mirror the Rust structs; fields stay snake_case) ----------

export interface OsInfo {
  name: string;
  version: string;
  build: string;
  arch: string;
  hostname: string;
  install_date: string | null;
  uptime_secs: number;
}
export interface CpuInfo {
  name: string;
  vendor: string;
  cores: number;
  threads: number;
  max_mhz: number;
  l2_kb: number;
  l3_kb: number;
  socket: string;
}
export interface MemModule {
  capacity: number;
  speed: number;
  configured_speed: number;
  manufacturer: string;
  part_number: string;
  locator: string;
  mem_type: string;
}
export interface GpuInfo {
  name: string;
  vendor: string;
  driver_version: string;
  driver_date: string | null;
  vram: number;
  refresh_rate: number;
  width: number;
  height: number;
  integrated: boolean;
}
export interface DisplayInfo {
  name: string;
  adapter: string;
  width: number;
  height: number;
  current_hz: number;
  max_hz: number;
  primary: boolean;
}
export interface SystemInfo {
  os: OsInfo;
  cpu: CpuInfo;
  memory: { total: number; modules: MemModule[]; slots: number };
  gpus: GpuInfo[];
  board: {
    manufacturer: string;
    product: string;
    bios_vendor: string;
    bios_version: string;
    bios_date: string | null;
    system_model: string;
  };
  displays: DisplayInfo[];
  is_admin: boolean;
}
export interface ProcInfo {
  name: string;
  count: number;
  memory: number;
  cpu: number;
}
export interface LiveStats {
  cpu_total: number;
  per_core: number[];
  cpu_mhz: number;
  mem_total: number;
  mem_used: number;
  swap_total: number;
  swap_used: number;
  process_count: number;
  top_memory: ProcInfo[];
  top_cpu: ProcInfo[];
  uptime_secs: number;
}
export interface NvmeHealth {
  critical_warning: number;
  temperature_c: number;
  available_spare: number;
  spare_threshold: number;
  percentage_used: number;
  data_read_bytes: number;
  data_written_bytes: number;
  power_cycles: number;
  power_on_hours: number;
  unsafe_shutdowns: number;
  media_errors: number;
  error_log_entries: number;
  warning_temp_minutes: number;
  critical_temp_minutes: number;
  sensors_c: number[];
}
export interface Reliability {
  temperature: number | null;
  temperature_max: number | null;
  wear: number | null;
  power_on_hours: number | null;
  read_errors: number | null;
  write_errors: number | null;
}
export interface PhysicalDisk {
  number: number;
  model: string;
  serial: string;
  firmware: string;
  media: string;
  bus: string;
  is_nvme: boolean;
  is_ssd: boolean;
  size: number;
  health: "healthy" | "warning" | "unhealthy" | "unknown";
  spindle_rpm: number;
  nvme: NvmeHealth | null;
  nvme_error: string | null;
  reliability: Reliability | null;
  volumes: string[];
  vendor_tool: string | null;
}
export interface Volume {
  letter: string;
  label: string;
  fs: string;
  total: number;
  free: number;
  disk_number: number | null;
  is_system: boolean;
  removable: boolean;
}
export interface StorageInfo {
  disks: PhysicalDisk[];
  volumes: Volume[];
  trim_ntfs: boolean | null;
  trim_refs: boolean | null;
  system_files: { pagefile: number; hiberfil: number; swapfile: number };
  windows_old: boolean;
  is_admin: boolean;
}

export type Risk = "safe" | "moderate" | "caution";
export interface JunkItem {
  path: string;
  size: number;
  mtime: number;
}
export interface JunkCategory {
  id: string;
  name: string;
  group: string;
  description: string;
  risk: Risk;
  default_on: boolean;
  admin: boolean;
  found: boolean;
  denied: boolean;
  size: number;
  count: number;
  min_age_hours: number;
  recycle: boolean;
  explicit: boolean;
  top: JunkItem[];
}
export interface CleanReport {
  freed: number;
  deleted: number;
  failed: number;
  categories: { id: string; freed: number; deleted: number; failed: number; sample_error: string | null }[];
}

export interface NodeDto {
  id: number;
  name: string;
  size: number;
  files: number;
  dirs: number;
  mtime: number;
  denied: boolean;
  skipped: boolean;
}
export interface FileDto {
  name: string;
  path: string;
  size: number;
  mtime: number;
}
export interface Listing {
  node: NodeDto;
  path: string;
  crumbs: { id: number; name: string }[];
  dirs: NodeDto[];
  files: FileDto[];
  files_more: number;
  files_more_size: number;
}
export interface ScanSummary {
  id: number;
  root: NodeDto;
  path: string;
  errors: number;
  elapsed_ms: number;
  method: string;
}
export interface ExtStat {
  ext: string;
  size: number;
  count: number;
}
export interface DeleteReport {
  deleted: number;
  freed: number;
  failed: { path: string; error: string }[];
}
export interface ScanProgress {
  id: number;
  files: number;
  dirs: number;
  bytes: number;
  errors: number;
  current: string;
}
export interface ScanDone {
  id: number;
  ok: boolean;
  error: string | null;
  summary: ScanSummary | null;
}

export interface TaskDef {
  id: string;
  name: string;
  description: string;
  admin: boolean;
  needs_drive: boolean;
  duration: string;
  category: string;
}
export interface TaskOutput {
  task: string;
  line: string;
  replace: boolean;
}
export interface TaskDone {
  task: string;
  code: number | null;
  success: boolean;
  cancelled: boolean;
}

export interface PowerPlan {
  guid: string;
  name: string;
  active: boolean;
}
export interface Tweaks {
  power_plans: PowerPlan[];
  game_mode: boolean;
  game_dvr: boolean;
  hags: boolean | null;
  mouse_accel: boolean;
  hibernation: boolean;
  hiberfil_size: number;
  storage_sense: boolean;
  is_admin: boolean;
}
export interface StartupItem {
  id: string;
  name: string;
  command: string;
  source: string;
  machine: boolean;
  enabled: boolean;
}

// ---------- Commands (arguments are camelCase on the JS side) ----------

export const api = {
  isAdmin: () => invoke<boolean>("is_admin"),
  relaunchAdmin: () => invoke<void>("relaunch_admin"),
  systemInfo: () => invoke<SystemInfo>("system_info"),
  liveStats: () => invoke<LiveStats>("live_stats"),
  storageInfo: () => invoke<StorageInfo>("storage_info"),

  junkScan: () => invoke<JunkCategory[]>("junk_scan"),
  junkClean: (ids: string[], excluded: string[], included: string[]) =>
    invoke<CleanReport>("junk_clean", { ids, excluded, included }),

  analyzerStart: (path: string) => invoke<number>("analyzer_start", { path }),
  analyzerCancel: (id: number) => invoke<void>("analyzer_cancel", { id }),
  analyzerList: (id: number, node: number) => invoke<Listing>("analyzer_list", { id, node }),
  analyzerTopFiles: (id: number) => invoke<FileDto[]>("analyzer_top_files", { id }),
  analyzerExtensions: (id: number) => invoke<ExtStat[]>("analyzer_extensions", { id }),
  analyzerSummary: (id: number) => invoke<ScanSummary>("analyzer_summary", { id }),
  deletePaths: (scanId: number | null, paths: string[], toRecycle: boolean) =>
    invoke<DeleteReport>("delete_paths", { scanId, paths, toRecycle }),
  reveal: (path: string) => invoke<void>("reveal_in_explorer", { path }),

  maintenanceTasks: () => invoke<TaskDef[]>("maintenance_tasks"),
  taskRun: (id: string, drive: string | null) => invoke<void>("task_run", { id, drive }),
  taskCancel: (id: string) => invoke<void>("task_cancel", { id }),

  tweaks: () => invoke<Tweaks>("tweaks_get"),
  tweakSet: (name: string, enabled: boolean) => invoke<void>("tweak_set", { name, enabled }),
  powerPlanSet: (guid: string) => invoke<void>("power_plan_set", { guid }),
  powerPlanAddUltimate: () => invoke<void>("power_plan_add_ultimate"),
  startupList: () => invoke<StartupItem[]>("startup_list"),
  startupSet: (id: string, enabled: boolean) => invoke<void>("startup_set", { id, enabled }),
};

export function on<T>(event: string, cb: (payload: T) => void): Promise<UnlistenFn> {
  return listen<T>(event, (e) => cb(e.payload));
}

export function errText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}
