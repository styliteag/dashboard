import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import type { Instance } from "./types";

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
