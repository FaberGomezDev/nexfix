const UNITS = ["B", "KB", "MB", "GB", "TB", "PB"];

/** Bytes in binary units with Spanish decimal comma: 1,5 GB. */
export function bytes(n: number | null | undefined, digits = 1): string {
  if (n == null || !isFinite(n)) return "—";
  if (n < 1024) return `${n} B`;
  let i = 0;
  let v = n;
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024;
    i++;
  }
  const d = v >= 100 ? 0 : digits;
  return `${v.toLocaleString("es-ES", { maximumFractionDigits: d, minimumFractionDigits: d })} ${UNITS[i]}`;
}

/** Decimal units, as drive makers quote endurance (TBW): 42,0 TB. */
export function bytesDecimal(n: number): string {
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  let v = n;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v.toLocaleString("es-ES", { maximumFractionDigits: 1 })} ${units[i]}`;
}

export function num(n: number): string {
  return n.toLocaleString("es-ES");
}

export function pct(part: number, total: number, digits = 0): string {
  if (!total) return "0 %";
  return `${((part / total) * 100).toLocaleString("es-ES", { maximumFractionDigits: digits })} %`;
}

export function duration(secs: number): string {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (d > 0) return `${d} d ${h} h`;
  if (h > 0) return `${h} h ${m} min`;
  return `${m} min`;
}

export function ms(n: number): string {
  return n >= 1000 ? `${(n / 1000).toLocaleString("es-ES", { maximumFractionDigits: 1 })} s` : `${n} ms`;
}

export function date(unix: number): string {
  if (!unix) return "—";
  return new Date(unix * 1000).toLocaleDateString("es-ES", { day: "2-digit", month: "short", year: "numeric" });
}

export function isoDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso + "T00:00:00");
  return d.toLocaleDateString("es-ES", { day: "2-digit", month: "short", year: "numeric" });
}

/** Days elapsed since an ISO date (yyyy-mm-dd). */
export function daysSince(iso: string | null): number | null {
  if (!iso) return null;
  const t = new Date(iso + "T00:00:00").getTime();
  if (isNaN(t)) return null;
  return Math.floor((Date.now() - t) / 86_400_000);
}

export function ago(days: number): string {
  if (days < 31) return `${days} días`;
  const months = Math.round(days / 30.4);
  if (months < 24) return `${months} meses`;
  return `${(days / 365).toLocaleString("es-ES", { maximumFractionDigits: 1 })} años`;
}
