import {
  api,
  errText,
  type JunkCategory,
  type SecurityReport,
  type StartupItem,
  type StorageInfo,
  type SystemInfo,
  type Tweaks,
} from "./api";

export type View = "dashboard" | "hardware" | "storage" | "cleaner" | "analyzer" | "security" | "optimize" | "maintenance";

export const app = $state({
  view: "dashboard" as View,
  admin: false,
  system: null as SystemInfo | null,
  storage: null as StorageInfo | null,
  tweaks: null as Tweaks | null,
  startup: null as StartupItem[] | null,
  junk: null as JunkCategory[] | null,
  security: null as SecurityReport | null,
  /** Set by other views to ask the analyzer to scan a path. */
  analyzeRequest: null as string | null,
  /** Set by other views to pre-select a maintenance task. */
  taskRequest: null as { id: string; drive: string | null } | null,
});

export function go(view: View) {
  app.view = view;
}

// ---------- Data loaders (deduplicated) ----------

const inflight = new Map<string, Promise<unknown>>();
function once<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const cur = inflight.get(key) as Promise<T> | undefined;
  if (cur) return cur;
  const p = fn().finally(() => inflight.delete(key));
  inflight.set(key, p);
  return p;
}

export function loadSystem(force = false) {
  if (app.system && !force) return Promise.resolve(app.system);
  return once("system", async () => (app.system = await api.systemInfo()));
}

export function loadStorage(force = false) {
  if (app.storage && !force) return Promise.resolve(app.storage);
  return once("storage", async () => (app.storage = await api.storageInfo()));
}

export function loadTweaks(force = false) {
  if (app.tweaks && !force) return Promise.resolve(app.tweaks);
  return once("tweaks", async () => (app.tweaks = await api.tweaks()));
}

export function loadStartup(force = false) {
  if (app.startup && !force) return Promise.resolve(app.startup);
  return once("startup", async () => (app.startup = await api.startupList()));
}

export function loadSecurity(force = false) {
  if (app.security && !force) return Promise.resolve(app.security);
  return once("security", async () => (app.security = await api.securityScan()));
}

// ---------- Toasts ----------

export type ToastKind = "ok" | "info" | "warn" | "error";
export const toasts = $state<{ id: number; kind: ToastKind; text: string }[]>([]);
let toastId = 0;

export function toast(text: string, kind: ToastKind = "info", ms = 4500) {
  const id = ++toastId;
  toasts.push({ id, kind, text });
  setTimeout(() => {
    const i = toasts.findIndex((t) => t.id === id);
    if (i >= 0) toasts.splice(i, 1);
  }, ms);
}

export function toastError(e: unknown) {
  toast(errText(e), "error", 7000);
}

// ---------- Confirmation dialog ----------

export interface DialogOpts {
  title: string;
  body: string;
  details?: string[];
  confirm?: string;
  cancel?: string;
  danger?: boolean;
}

export const dialog = $state<{ current: (DialogOpts & { resolve: (v: boolean) => void }) | null }>({ current: null });

export function ask(opts: DialogOpts): Promise<boolean> {
  return new Promise((resolve) => {
    dialog.current = { ...opts, resolve };
  });
}

export function closeDialog(result: boolean) {
  const d = dialog.current;
  dialog.current = null;
  d?.resolve(result);
}

export async function relaunchAsAdmin() {
  const ok = await ask({
    title: "Reiniciar como administrador",
    body: "NexFix se cerrará y Windows te pedirá permiso para abrirlo con privilegios de administrador. Así podrás leer el SMART completo del M.2, limpiar archivos del sistema, ejecutar las tareas de mantenimiento y hacer un análisis de seguridad completo (tareas programadas, servicios, exclusiones del antivirus).",
    confirm: "Reiniciar",
  });
  if (!ok) return;
  try {
    await api.relaunchAdmin();
  } catch (e) {
    toastError(e);
  }
}
