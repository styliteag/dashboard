import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import type { Instance, ServiceAlert } from "./types";

/**
 * id → agent_mode, sourced from the shared ["instances"] query cache. The global
 * list views (VPN, Connectivity, Alerts, Firmware) use it to decide whether a row
 * can offer the tunneled-WebGUI icon — only agent-mode boxes have a GUI proxy.
 */
export function useAgentModeMap(): Map<number, boolean> {
  const { data } = useQuery({
    queryKey: ["instances"],
    queryFn: () => api.get<Instance[]>("/api/instances"),
    staleTime: 60_000,
  });
  return useMemo(() => {
    const map = new Map<number, boolean>();
    for (const i of data ?? []) map.set(i.id, i.agent_mode);
    return map;
  }, [data]);
}

/**
 * id → per-instance shell (terminal) opt-in, from the same shared ["instances"]
 * query. The global list views use it to decide whether a row shows the terminal
 * icon next to the WebGUI icon. The server-wide DASH_SHELL_ENABLED gate is enforced
 * on the WS itself; a box with the per-instance flag off never offers the icon.
 */
export function useShellEnabledMap(): Map<number, boolean> {
  const { data } = useQuery({
    queryKey: ["instances"],
    queryFn: () => api.get<Instance[]>("/api/instances"),
    staleTime: 60_000,
  });
  return useMemo(() => {
    const map = new Map<number, boolean>();
    for (const i of data ?? []) map.set(i.id, i.shell_enabled);
    return map;
  }, [data]);
}

export interface InstanceAlertSummary {
  warn: number;
  crit: number;
}

/**
 * instance_id → WARN/CRIT service-check counts, sourced from the shared
 * ["alerts"] query (same data + query key as the Alerts page, so no extra
 * polling). Powers the Instances overview's warning bubble so a problem is
 * visible without opening each instance. OK/UNKNOWN checks don't count.
 */
export function useInstanceAlertSummaryMap(): Map<number, InstanceAlertSummary> {
  const { data } = useQuery({
    queryKey: ["alerts"],
    queryFn: () => api.get<ServiceAlert[]>("/api/checks"),
    refetchInterval: 30_000,
  });
  return useMemo(() => {
    const map = new Map<number, InstanceAlertSummary>();
    for (const a of data ?? []) {
      if (a.state !== 1 && a.state !== 2) continue;
      const prev = map.get(a.instance_id) ?? { warn: 0, crit: 0 };
      map.set(a.instance_id, {
        warn: prev.warn + (a.state === 1 ? 1 : 0),
        crit: prev.crit + (a.state === 2 ? 1 : 0),
      });
    }
    return map;
  }, [data]);
}
