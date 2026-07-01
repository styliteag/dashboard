import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fingerprint, KeyRound, ShieldCheck, Trash2 } from "lucide-react";
import { api, ApiError } from "../lib/api";
import { fmtDate } from "../lib/datetime";
import { passkeyAdd, type Passkey } from "../lib/webauthn";

interface MfaMethods {
  totp_enabled: boolean;
  passkeys: Passkey[];
}

const QK = ["mfa-methods"];

export default function SecurityPage() {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const { data } = useQuery({
    queryKey: QK,
    queryFn: () => api.get<MfaMethods>("/api/auth/mfa/methods"),
  });

  const fail = (e: unknown, fallback: string) => {
    if (e instanceof ApiError) setError(e.message || fallback);
    else if (e instanceof Error && (e.name === "NotAllowedError" || e.name === "AbortError"))
      setError("Passkey prompt was dismissed.");
    else setError(fallback);
  };
  const invalidate = () => qc.invalidateQueries({ queryKey: QK });

  const addMut = useMutation({
    mutationFn: () => passkeyAdd(name.trim() || undefined),
    onSuccess: () => {
      setName("");
      setError(null);
      invalidate();
    },
    onError: (e) => fail(e, "Failed to add passkey"),
  });

  const removeMut = useMutation({
    mutationFn: (id: number) => api.del(`/api/auth/mfa/passkeys/${id}`),
    onSuccess: () => {
      setError(null);
      invalidate();
    },
    onError: (e) => fail(e, "Failed to remove passkey"),
  });

  const passkeys = data?.passkeys ?? [];

  return (
    <div className="mx-auto max-w-2xl">
      <h1 className="flex items-center gap-2 text-xl font-semibold">
        <ShieldCheck className="h-5 w-5 text-slate-400" /> Security
      </h1>
      <p className="mt-1 text-sm text-slate-400">
        Two-factor authentication is mandatory. Manage your authenticator and passkeys here.
      </p>

      {error && (
        <div className="mt-4 rounded-lg bg-red-900/40 px-3 py-2 text-sm text-red-300">{error}</div>
      )}

      <div className="mt-5 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
          <KeyRound className="h-4 w-4 text-slate-400" /> Authenticator app (TOTP)
        </h3>
        <p className="mt-1 text-sm text-slate-400">
          {data?.totp_enabled
            ? "Enabled. To re-enroll, ask an admin to reset your 2FA."
            : "Not enabled — you signed in with a passkey."}
        </p>
      </div>

      <div className="mt-5 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
          <Fingerprint className="h-4 w-4 text-slate-400" /> Passkeys
        </h3>
        <div className="mt-3 flex items-center gap-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Passkey name (optional)"
            className="w-56 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm focus:border-emerald-600 focus:outline-none"
          />
          <button
            type="button"
            disabled={addMut.isPending}
            onClick={() => addMut.mutate()}
            className="inline-flex items-center gap-1 rounded-lg bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
          >
            <Fingerprint className="h-4 w-4" /> Add passkey
          </button>
        </div>

        <table className="mt-4 w-full text-sm">
          <tbody>
            {passkeys.length === 0 && (
              <tr>
                <td className="py-2 text-xs text-slate-500">No passkeys registered.</td>
              </tr>
            )}
            {passkeys.map((p) => (
              <tr key={p.id} className="border-t border-slate-800">
                <td className="py-2">{p.name || `Passkey #${p.id}`}</td>
                <td className="py-2 text-xs text-slate-400">
                  {p.last_used_at ? `last used ${fmtDate(p.last_used_at)}` : "never used"}
                </td>
                <td className="py-2 text-right">
                  <button
                    type="button"
                    onClick={() => removeMut.mutate(p.id)}
                    className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-red-400 hover:bg-slate-800"
                  >
                    <Trash2 className="h-3 w-3" /> Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
