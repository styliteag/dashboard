import { useState, type FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import type { Instance } from "../lib/types";
import Dialog from "./Dialog";

interface Props {
  instance: Instance;
  onClose: () => void;
}

export default function DeleteInstanceDialog({ instance, onClose }: Props) {
  const queryClient = useQueryClient();
  const [confirmName, setConfirmName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () => api.del(`/api/instances/${instance.id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["instances"] });
      onClose();
    },
    onError: (err) => {
      setError(err instanceof ApiError ? err.message : "Failed to delete.");
    },
  });

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (confirmName !== instance.name) {
      setError(`Please type exactly "${instance.name}".`);
      return;
    }
    setError(null);
    mutation.mutate();
  };

  return (
    <Dialog title="Delete instance" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <p className="text-sm text-slate-400">
          Really delete instance <strong className="text-slate-200">{instance.name}</strong>?
          Historical metrics will be retained.
        </p>
        <p className="text-sm text-slate-400">
          Type the name to confirm:
        </p>

        {error && (
          <div className="rounded-lg bg-red-900/40 px-3 py-2 text-sm text-red-300">{error}</div>
        )}

        <input
          type="text"
          value={confirmName}
          onChange={(e) => setConfirmName(e.target.value)}
          placeholder={instance.name}
          className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm focus:border-red-600 focus:outline-none focus:ring-1 focus:ring-red-600"
        />

        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg px-4 py-2 text-sm text-slate-400 hover:text-slate-200"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={mutation.isPending || confirmName !== instance.name}
            className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-50"
          >
            {mutation.isPending ? "…" : "Delete permanently"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
