import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useAuth } from "../lib/use-auth";

interface HealthResponse {
  status: string;
  db: string;
  version?: string;
  db_revision?: string | null;
  detail?: string;
}

const FRONTEND_VERSION = import.meta.env.VITE_APP_VERSION ?? "dev";

export default function VersionFooter() {
  const { user } = useAuth();
  const { data } = useQuery({
    queryKey: ["health"],
    queryFn: () => api.get<HealthResponse>("/api/health"),
    staleTime: 60_000,
    refetchOnWindowFocus: false,
    retry: false,
  });
  // Global blocked-request count — visible to every logged-in user (details
  // stay superadmin-only on the Access page).
  const denials = useQuery({
    queryKey: ["geoip-denials-summary"],
    queryFn: () => api.get<{ total: number }>("/api/geoip/denials/summary"),
    enabled: !!user,
    refetchInterval: 60_000,
    retry: false,
  });

  const backend = data?.version ?? "—";
  const dbRev = data?.db_revision ?? "—";
  const ownIp = user?.client_ip
    ? `${user.client_ip}${user.client_country ? ` (${user.client_country})` : ""}`
    : null;

  return (
    <footer className="border-t border-slate-800 bg-slate-950/80 px-6 py-2 text-xs text-slate-500">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <span title="Your IP as seen by the dashboard (country via local GeoIP DB)">
            {ownIp ? `your IP ${ownIp}` : ""}
          </span>
          {denials.data && denials.data.total > 0 && (
            <span
              className="text-slate-400"
              title="Requests blocked by the GeoIP/CrowdSec gate (all-time). Details: superadmin → Access."
            >
              🛡 {denials.data.total.toLocaleString("en-US")} blocked
            </span>
          )}
        </div>
        <div className="flex items-center gap-4">
          <span title="Frontend bundle version">frontend {FRONTEND_VERSION}</span>
          <span className="text-slate-700">·</span>
          <span title="Backend image version">backend {backend}</span>
          <span className="text-slate-700">·</span>
          <span title="Alembic schema revision">db {dbRev}</span>
        </div>
      </div>
    </footer>
  );
}
