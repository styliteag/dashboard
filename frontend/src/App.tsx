import { useQuery } from "@tanstack/react-query";

type HealthResponse = {
  status: string;
  db: string;
  detail?: string;
};

async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch("/api/health");
  // Health endpoint returns 503 with a JSON body when degraded; we still want to render it.
  return (await res.json()) as HealthResponse;
}

export default function App() {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["health"],
    queryFn: fetchHealth,
    refetchInterval: 5_000,
  });

  return (
    <main className="min-h-screen flex items-center justify-center p-8">
      <div className="max-w-xl w-full rounded-2xl border border-slate-800 bg-slate-900/60 p-8 shadow-xl">
        <h1 className="text-3xl font-semibold tracking-tight">opnsense-dash</h1>
        <p className="mt-2 text-slate-400">
          Skeleton up. Backend health below.
        </p>

        <section className="mt-6 rounded-xl bg-slate-800/60 p-4 font-mono text-sm">
          {isLoading && <span className="text-slate-400">loading…</span>}
          {isError && (
            <span className="text-red-400">error: {String(error)}</span>
          )}
          {data && (
            <pre className="whitespace-pre-wrap break-words">
              {JSON.stringify(data, null, 2)}
            </pre>
          )}
        </section>
      </div>
    </main>
  );
}
