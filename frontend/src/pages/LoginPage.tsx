import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { QRCodeSVG } from "qrcode.react";
import { Shield } from "lucide-react";
import { useAuth, type LoginChallenge, type User } from "../lib/use-auth";
import { api, ApiError } from "../lib/api";

type Stage = "password" | "enroll" | "verify";
interface TotpSetup {
  secret: string;
  otpauth_uri: string;
}

export default function LoginPage() {
  const { login, completeLogin } = useAuth();
  const navigate = useNavigate();
  const [stage, setStage] = useState<Stage>("password");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [setup, setSetup] = useState<TotpSetup | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const showError = (err: unknown, fallback: string) => {
    if (err instanceof ApiError) {
      setError(err.status === 429 ? "Too many attempts. Please wait." : err.message || fallback);
    } else {
      setError("Cannot connect to the backend.");
    }
  };

  const onPassword = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const challenge: LoginChallenge = await login(username, password);
      if (challenge.stage === "enroll") {
        const s = await api.post<TotpSetup>("/api/auth/mfa/setup/totp");
        setSetup(s);
        setStage("enroll");
      } else {
        setStage("verify");
      }
      setCode("");
    } catch (err) {
      showError(err, "Login failed. Check your credentials.");
    } finally {
      setBusy(false);
    }
  };

  const onCode = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const path =
        stage === "enroll" ? "/api/auth/mfa/confirm/totp" : "/api/auth/mfa/verify/totp";
      const me = await api.post<User>(path, { code: code.trim() });
      completeLogin(me);
      navigate("/", { replace: true });
    } catch (err) {
      showError(err, "Invalid code.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <div className="w-full max-w-sm space-y-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-8 shadow-xl">
        <div className="flex items-center gap-2 text-xl font-semibold">
          <Shield className="h-6 w-6 text-emerald-500" />
          Orbit Dashboard
        </div>

        {error && (
          <div className="rounded-lg bg-red-900/40 px-4 py-2 text-sm text-red-300">{error}</div>
        )}

        {stage === "password" && (
          <form onSubmit={onPassword} className="space-y-6">
            <div className="space-y-1">
              <label className="text-sm text-slate-400" htmlFor="username">
                Username
              </label>
              <input
                id="username"
                type="text"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm text-slate-400" htmlFor="password">
                Password
              </label>
              <input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
              />
            </div>
            <button
              type="submit"
              disabled={busy}
              className="w-full rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
            >
              {busy ? "…" : "Continue"}
            </button>
          </form>
        )}

        {(stage === "enroll" || stage === "verify") && (
          <form onSubmit={onCode} className="space-y-5">
            {stage === "enroll" && setup && (
              <div className="space-y-3">
                <p className="text-sm text-slate-300">
                  Two-factor authentication is required. Scan this with an authenticator app, then
                  enter the 6-digit code.
                </p>
                <div className="flex justify-center rounded-lg bg-white p-3">
                  <QRCodeSVG value={setup.otpauth_uri} size={172} />
                </div>
                <p className="break-all text-center text-xs text-slate-500">
                  Manual key: <code className="text-slate-400">{setup.secret}</code>
                </p>
              </div>
            )}
            {stage === "verify" && (
              <p className="text-sm text-slate-300">
                Enter the 6-digit code from your authenticator app.
              </p>
            )}
            <div className="space-y-1">
              <label className="text-sm text-slate-400" htmlFor="code">
                Authenticator code
              </label>
              <input
                id="code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                maxLength={8}
                required
                autoFocus
                className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-center text-lg tracking-[0.3em] focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
              />
            </div>
            <button
              type="submit"
              disabled={busy || code.length < 6}
              className="w-full rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
            >
              {busy ? "…" : stage === "enroll" ? "Enable & sign in" : "Verify"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
