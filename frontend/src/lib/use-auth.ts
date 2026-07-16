/**
 * Auth context, hook, and shared types — kept JSX-free and separate from the
 * AuthProvider component so React Fast Refresh only sees component exports there.
 */
import { createContext, useContext } from "react";
import type { GroupBrief, UserRole } from "./types";

export interface User {
  id: number;
  username: string;
  role: UserRole;
  is_admin: boolean;
  is_superadmin: boolean;
  groups: GroupBrief[];
  session_token?: string | null;
  // Filled only by /auth/me: the caller's own IP (+country when the GeoIP DB
  // resolves it) for the footer display.
  client_ip?: string | null;
  client_country?: string | null;
  client_country_name?: string | null;
}

/** True for roles allowed to mutate (everything except view_only). */
export function canWrite(user: User | null): boolean {
  return user?.role === "admin" || user?.role === "user";
}

/** Step-1 login result. `done` = already authenticated (password-only bootstrap admin). */
export interface LoginChallenge {
  stage: "enroll" | "verify" | "done";
  totp: boolean;
  webauthn: boolean;
  user?: User | null;
}

export interface AuthContextValue {
  user: User | null;
  loading: boolean;
  /** Step 1 — verify password; resolves to the 2FA challenge (no session yet). */
  login: (username: string, password: string) => Promise<LoginChallenge>;
  /** Step 2 — adopt the user returned by an /auth/mfa/* completion. */
  completeLogin: (user: User) => void;
  logout: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
