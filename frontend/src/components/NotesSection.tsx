import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { StickyNote } from "lucide-react";
import { api } from "../lib/api";
import type { Instance } from "../lib/types";

// Free-text comment for one instance. Persists via PATCH /instances/{id} (the
// backend already accepts `notes`). Shares the ["instance", id] query cache with
// the detail page so a save keeps the rest of the page in sync.
export default function NotesSection({ instanceId }: { instanceId: number }) {
  const qc = useQueryClient();
  const qk = ["instance", String(instanceId)];

  const { data } = useQuery({
    queryKey: qk,
    queryFn: () => api.get<Instance>(`/api/instances/${instanceId}`),
  });
  const saved = data?.notes ?? "";

  const [draft, setDraft] = useState(saved);
  // Re-seed the textarea when the server value changes (initial load / refetch).
  useEffect(() => setDraft(saved), [saved]);

  const mut = useMutation({
    mutationFn: (notes: string) => api.patch(`/api/instances/${instanceId}`, { notes }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk }),
  });

  const dirty = draft !== saved;

  return (
    <section className="mt-8">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
        <StickyNote className="h-4 w-4" /> Comment
      </h2>
      <textarea
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        rows={3}
        placeholder="Notes about this instance…"
        className="mt-2 w-full rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
      />
      <div className="mt-2 flex items-center gap-3">
        <button
          type="button"
          onClick={() => mut.mutate(draft)}
          disabled={!dirty || mut.isPending}
          className="rounded-lg bg-emerald-600 px-3 py-1.5 text-sm text-white hover:bg-emerald-500 disabled:opacity-50"
        >
          {mut.isPending ? "Saving…" : "Save"}
        </button>
        {dirty && !mut.isPending && (
          <button
            type="button"
            onClick={() => setDraft(saved)}
            className="text-xs text-slate-400 hover:text-slate-200"
          >
            Discard
          </button>
        )}
        {!dirty && mut.isSuccess && <span className="text-xs text-emerald-500">Saved</span>}
      </div>
    </section>
  );
}
