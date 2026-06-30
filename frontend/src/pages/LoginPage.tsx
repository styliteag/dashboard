import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { QRCodeSVG } from "qrcode.react";
import { Fingerprint, Shield } from "lucide-react";
import { useAuth, type LoginChallenge, type User } from "../lib/use-auth";
import { api, ApiError } from "../lib/api";
import { passkeyAuthenticate, passkeyEnroll } from "../lib/webauthn";

type Stage = "password" | "enroll" | "verify";
interface TotpSetup {
  secret: string;
  otpauth_uri: string;
}

export default function LoginPage() {
  const { login, completeLogin } = useAuth();
  const navigate = useNavigate();
  const [stage, setStage] = useState<Stage>("password");
  const [challenge, setChallenge] = useState<LoginChallenge | null>(null);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [setup, setSetup] = useState<TotpSetup | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const showError = (err: unknown, fallback: string) => {
    if (err instanceof ApiError) {
      setError(err.status === 429 ? "Too many attempts. Please wait." : err.message || fallback);
    } else if (err instanceof Error && (err.name === "NotAllowedError" || err.name === "AbortError")) {
      setError("Passkey prompt was dismissed.");
    } else {
      setError("Cannot connect to the backend.");
    }
  };

  const finish = (me: User) => {
    completeLogin(me);
    navigate("/", { replace: true });
  };

  const onPassword = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const ch = await login(username, password);
      if (ch.stage === "done" && ch.user) {
        finish(ch.user); // password-only bootstrap admin
        return;
      }
      setChallenge(ch);
      if (ch.stage === "enroll") {
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
      finish(await api.post<User>(path, { code: code.trim() }));
    } catch (err) {
      showError(err, "Invalid code.");
    } finally {
      setBusy(false);
    }
  };

  const runPasskey = async (fn: () => Promise<User>) => {
    setError(null);
    setBusy(true);
    try {
      finish(await fn());
    } catch (err) {
      showError(err, "Passkey failed.");
    } finally {
      setBusy(false);
    }
  };

  const PasskeyButton = ({ label, fn }: { label: string; fn: () => Promise<User> }) => (
    <button
      type="button"
      disabled={busy}
      onClick={() => runPasskey(fn)}
      className="flex w-full items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-sm font-medium text-slate-100 hover:bg-slate-700 disabled:opacity-50"
    >
      <Fingerprint className="h-4 w-4" /> {label}
    </button>
  );

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

        {stage === "enroll" && (
          <div className="space-y-5">
            <p className="text-sm text-slate-300">
              Two-factor authentication is required. Set up an authenticator app, or register a
              passkey.
            </p>
            {setup && (
              <form onSubmit={onCode} className="space-y-4">
                <div className="flex justify-center rounded-lg bg-white p-3">
                  <QRCodeSVG value={setup.otpauth_uri} size={172} />
                </div>
                <p className="break-all text-center text-xs text-slate-500">
                  Manual key: <code className="text-slate-400">{setup.secret}</code>
                </p>
                <input
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                  maxLength={8}
                  placeholder="6-digit code"
                  className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-center text-lg tracking-[0.3em] focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
                />
                <button
                  type="submit"
                  disabled={busy || code.length < 6}
                  className="w-full rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
                >
                  {busy ? "…" : "Enable & sign in"}
                </button>
              </form>
            )}
            <div className="flex items-center gap-3 text-xs text-slate-600">
              <div className="h-px flex-1 bg-slate-800" /> or <div className="h-px flex-1 bg-slate-800" />
            </div>
            <PasskeyButton label="Register a passkey" fn={() => passkeyEnroll()} />
          </div>
        )}

        {stage === "verify" && (
          <div className="space-y-5">
            {challenge?.webauthn && (
              <PasskeyButton label="Sign in with passkey" fn={passkeyAuthenticate} />
            )}
            {challenge?.totp && (
              <form onSubmit={onCode} className="space-y-4">
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
                <button
                  type="submit"
                  disabled={busy || code.length < 6}
                  className="w-full rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
                >
                  {busy ? "…" : "Verify"}
                </button>
              </form>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
