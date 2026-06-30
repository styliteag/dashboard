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
