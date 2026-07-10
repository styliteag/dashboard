// Types + pure grouping/health logic for the cross-instance VPN overview.
// Rendering lives in pages/VPNOverviewPage.tsx and components/TunnelRow.tsx.

import type { IPsecChild } from "./types";
import { worstPing } from "./ipsec-ping";
import type { Accessors } from "./use-sort";

export interface GlobalTunnel {
  instance_id: number;
  instance_name: string;
  tunnel_id: string;
  unique_id: string;
  description: string;
  remote: string;
  local: string;
  phase1_status: string;
  phase2_up: number;
  phase2_total: number;
  seconds_established: number;
  bytes_in: number;
  bytes_out: number;
  tags?: string[];
  agent_mode?: boolean;
  device_type?: string;
  base_url?: string;
  stale?: boolean;
  stale_seconds?: number | null;
  children: IPsecChild[];
  ike_init_spi?: string;
  ike_resp_spi?: string;
  local_ip_mismatch?: boolean; // public local endpoint IP ≠ box's external IP ("lip-mismatch")
  peer_instance_id?: number | null;
  peer_instance_name?: string | null;
  peer_tunnel_id?: string | null;
}

export interface TunnelGroup {
  members: GlobalTunnel[];
  paired: boolean;
}

export interface GlobalVPNResponse {
  tunnels: GlobalTunnel[];
  total: number;
  up: number;
  down: number;
}

export function isUp(phase1_status: string): boolean {
  const s = phase1_status.toLowerCase();
  return s.includes("established") || s.includes("connected");
}

export const rowKey = (t: GlobalTunnel) => `${t.instance_id}-${t.tunnel_id}`;

/** The firewall's own IPsec status page, per device type ("" for unknown types → GUI root). */
export function ipsecUiPath(deviceType?: string): string {
  if (deviceType === "pfsense") return "/status_ipsec.php";
  if (deviceType === "opnsense") return "/ui/ipsec/sessions";
  return ""; // e.g. securepoint — no known deep link, land on the GUI root
}

/** Direct (non-proxied) deep link to the firewall's IPsec page, if a base URL is known. */
export function ipsecDirectUrl(t: GlobalTunnel): string | undefined {
  // base_url may hold several comma-separated web-UI URLs; use the first.
  const base = (t.base_url ?? "").split(",")[0]?.trim().replace(/\/+$/, "");
  return base ? base + (ipsecUiPath(t.device_type) || "/") : undefined;
}

/** Group the two ends of the same tunnel (peer pairing) so they render together. */
export function buildGroups(tunnels: GlobalTunnel[]): TunnelGroup[] {
  const byKey = new Map<string, GlobalTunnel>();
  for (const t of tunnels) byKey.set(`${t.instance_id}-${t.tunnel_id}`, t);
  const seen = new Set<string>();
  const groups: TunnelGroup[] = [];
  for (const t of tunnels) {
    const k = `${t.instance_id}-${t.tunnel_id}`;
    if (seen.has(k)) continue;
    const peerK = t.peer_instance_id != null ? `${t.peer_instance_id}-${t.peer_tunnel_id}` : null;
    const peer = peerK ? byKey.get(peerK) : undefined;
    if (peer && peerK && !seen.has(peerK)) {
      groups.push({ members: [t, peer], paired: true });
      seen.add(k);
      seen.add(peerK);
    } else {
      groups.push({ members: [t], paired: false });
      seen.add(k);
    }
  }
  return groups;
}

/** Combined health of a paired link, for the group header badge. */
export function pairHealth(a: GlobalTunnel, b: GlobalTunnel): { cls: string; label: string } {
  // Staleness wins: if either end's agent is silent, this side's status is
  // last-known, not live — never report a stale pair as "both up" (it must stay
  // expanded, not collapse as healthy).
  if (a.stale || b.stale) return { cls: "bg-amber-600/20 text-amber-400", label: "stale" };
  const aUp = isUp(a.phase1_status);
  const bUp = isUp(b.phase1_status);
  if (aUp !== bUp) return { cls: "bg-red-600/20 text-red-400", label: "status mismatch" };
  if (!aUp && !bUp) return { cls: "bg-slate-700 text-slate-300", label: "both down" };
  // Both Phase 1 up — but "established" doesn't mean traffic flows. Fold the
  // Phase-2 ping monitor into the health so a tunnel that's up yet not passing
  // traffic isn't reported "both up" and auto-collapsed (the whole point of the
  // collapse is to hide *healthy* pairs). Symmetric failure (both ends fail) is
  // the usual outage shape, so rank by the worst end across both — a plain
  // mismatch check misses it. No monitor configured (state "none") stays green.
  const pa = worstPing(a.children ?? []);
  const pb = worstPing(b.children ?? []);
  const worst = worstPing([...(a.children ?? []), ...(b.children ?? [])]);
  if (worst === "fail") return { cls: "bg-red-600/20 text-red-400", label: "ping fail" };
  // Only a genuine mismatch when *both* ends actually monitor. A one-sided probe
  // (the other end is "none") is not a mismatch — it just means one side pings.
  if (pa !== "none" && pb !== "none" && pa !== pb)
    return { cls: "bg-amber-600/20 text-amber-400", label: "ping mismatch" };
  if (worst === "error") return { cls: "bg-amber-600/20 text-amber-400", label: "ping error" };
  return { cls: "bg-emerald-600/20 text-emerald-400", label: "both up" };
}

export const VPN_ACCESSORS: Accessors<GlobalTunnel> = {
  instance: (t) => t.instance_name.toLowerCase(),
  tunnel: (t) => (t.description || t.tunnel_id).toLowerCase(),
  remote: (t) => t.remote,
  status: (t) => (isUp(t.phase1_status) ? 0 : 1),
  phase2: (t) => t.phase2_up,
  uptime: (t) => t.seconds_established,
  in: (t) => t.bytes_in,
  out: (t) => t.bytes_out,
};
