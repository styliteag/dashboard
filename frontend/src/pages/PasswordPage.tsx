import { useState, type FormEvent } from "react";
import { ApiError } from "../lib/api";
import { api } from "../lib/api";

export default function PasswordPage() {
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setMessage(null);

    if (newPassword !== confirm) {
      setMessage({ ok: false, text: "Neue Passwoerter stimmen nicht ueberein." });
      return;
    }
    if (newPassword.length < 12) {
      setMessage({ ok: false, text: "Neues Passwort muss mindestens 12 Zeichen lang sein." });
      return;
    }

    setSubmitting(true);
    try {
      await api.post("/api/auth/password", {
        old_password: oldPassword,
        new_password: newPassword,
      });
      setMessage({ ok: true, text: "Passwort geaendert." });
      setOldPassword("");
      setNewPassword("");
      setConfirm("");
    } catch (err) {
      setMessage({
        ok: false,
        text: err instanceof ApiError ? err.message : "Fehler beim Aendern.",
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="mx-auto max-w-md">
      <h1 className="text-xl font-semibold">Passwort aendern</h1>
      <form onSubmit={handleSubmit} className="mt-6 space-y-4">
        {message && (
          <div
            className={`rounded-lg px-4 py-2 text-sm ${
              message.ok
                ? "bg-emerald-900/40 text-emerald-300"
                : "bg-red-900/40 text-red-300"
            }`}
          >
            {message.text}
          </div>
        )}

        <Field
          label="Aktuelles Passwort"
          type="password"
          autoComplete="current-password"
          value={oldPassword}
          onChange={setOldPassword}
        />
        <Field
          label="Neues Passwort (min. 12 Zeichen)"
          type="password"
          autoComplete="new-password"
          value={newPassword}
          onChange={setNewPassword}
        />
        <Field
          label="Neues Passwort bestaetigen"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={setConfirm}
        />

        <button
          type="submit"
          disabled={submitting}
          className="w-full rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
        >
          {submitting ? "…" : "Passwort aendern"}
        </button>
      </form>
    </div>
  );
}

function Field({
  label,
  type,
  autoComplete,
  value,
  onChange,
}: {
  label: string;
  type: string;
  autoComplete: string;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="space-y-1">
      <label className="text-sm text-slate-400">{label}</label>
      <input
        type={type}
        autoComplete={autoComplete}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        required
        className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
      />
    </div>
  );
}
