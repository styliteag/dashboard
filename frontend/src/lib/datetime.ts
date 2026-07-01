/**
 * Local-timezone date/time formatting in ISO 8601 layout.
 *
 * API timestamps are UTC (the backend emits a trailing "Z"); `new Date()` converts
 * them to the viewer's local zone. We render with explicit local getters so the
 * output is always ISO ("YYYY-MM-DD HH:MM:SS") regardless of the browser locale —
 * `toLocaleString("de-DE")` would otherwise produce the non-ISO "01.07.2026, 22:15:42".
 */

const pad = (n: number): string => String(n).padStart(2, "0");

/** "2026-07-01 22:15:42" in local time. "—" for empty, the raw string if unparseable. */
export function fmtDateTime(value: string | Date | null | undefined): string {
  if (!value) return "—";
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return typeof value === "string" ? value : "—";
  return `${fmtDate(d)} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/** "2026-07-01" in local time. Accepts an ISO string or a Date. */
export function fmtDate(value: string | Date | null | undefined): string {
  if (!value) return "—";
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return typeof value === "string" ? value : "—";
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** "22:15" (24h) in local time — for compact chart axis ticks. */
export function fmtTimeShort(value: string | Date | null | undefined): string {
  if (!value) return "";
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return typeof value === "string" ? value : "";
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
