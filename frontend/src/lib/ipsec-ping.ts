/**
 * Pure helpers for IPsec Phase-2 ping monitors. Kept out of the component file
 * so React Fast Refresh stays happy (a component module should export only
 * components).
 */
import type { IPsecChild, IPsecPingMonitor, PingState } from "./types";

/** Match a stored ping monitor to a live child (by name, then selector pair). */
export function findMonitor(
  monitors: IPsecPingMonitor[],
  tunnelId: string,
  child: IPsecChild,
): IPsecPingMonitor | null {
  return (
    monitors.find(
      (m) =>
        m.tunnel_id === tunnelId &&
        ((m.child_name && m.child_name === child.name) ||
          (!!m.local_ts && m.local_ts === child.local_ts && m.remote_ts === child.remote_ts)),
    ) ?? null
  );
}

/**
 * Best-guess pingable host from a Phase-2 remote traffic selector.
 *
 * A selector is a network, not a host — e.g. "192.168.48.0/24|/0" — so it can't
 * be pinged as-is. We take the first IPv4 token, and for a network address
 * return its first usable host (network + 1, a common gateway/firewall IP); a
 * concrete host or /31-/32 is returned unchanged. Returns "" when nothing
 * IPv4-looking is found, so the field falls back to its placeholder.
 */
export function firstHostFromSelector(remoteTs: string): string {
  for (const token of remoteTs.split(/[|,\s]+/).filter(Boolean)) {
    const m = token.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
    if (!m) continue;
    const octets = [m[1], m[2], m[3], m[4]].map(Number);
    if (octets.some((o) => o > 255)) continue;
    const prefix = m[5] === undefined ? 32 : Number(m[5]);
    if (prefix > 32) continue;
    const ipInt = octets.reduce((acc, o) => (acc << 8) | o, 0) >>> 0;
    // A host or a tiny block (/31, /32) is already a concrete address.
    if (prefix >= 31) return token.split("/")[0];
    const mask = prefix === 0 ? 0 : ((0xffffffff << (32 - prefix)) >>> 0);
    const firstHost = (((ipInt & mask) >>> 0) + 1) >>> 0;
    return [24, 16, 8, 0].map((s) => (firstHost >>> s) & 0xff).join(".");
  }
  return "";
}

const _PING_RANK: Record<string, number> = { none: 0, ok: 1, error: 2, fail: 3 };

/** Worst ping state across a tunnel's children — fail > error > ok > none. */
export function worstPing(entries: IPsecChild[]): PingState {
  let worst: PingState = "none";
  for (const ch of entries) {
    const ps = (ch.ping_state || "none") as PingState;
    if ((_PING_RANK[ps] ?? 0) > (_PING_RANK[worst] ?? 0)) worst = ps;
  }
  return worst;
}
