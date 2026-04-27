import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";

interface HealthResponse {
  status: string;
  db: string;
  version?: string;
  db_revision?: string | null;
  detail?: string;
}

const FRONTEND_VERSION = import.meta.env.VITE_APP_VERSION ?? "dev";

export default function VersionFooter() {
  const { data } = useQuery({
    queryKey: ["health"],
    queryFn: () => api.get<HealthResponse>("/api/health"),
    staleTime: 60_000,
    refetchOnWindowFocus: false,
    retry: false,
  });

  const backend = data?.version ?? "—";
  const dbRev = data?.db_revision ?? "—";

  return (
    <footer className="border-t border-slate-800 bg-slate-950/80 px-6 py-2 text-xs text-slate-500">
      <div className="mx-auto flex max-w-7xl items-center justify-end gap-4">
        <span title="Frontend bundle version">frontend {FRONTEND_VERSION}</span>
        <span className="text-slate-700">·</span>
        <span title="Backend image version">backend {backend}</span>
        <span className="text-slate-700">·</span>
        <span title="Alembic schema revision">db {dbRev}</span>
      </div>
    </footer>
  );
}
