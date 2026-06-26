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
