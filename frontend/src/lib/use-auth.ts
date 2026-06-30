/**
 * Auth context, hook, and shared types — kept JSX-free and separate from the
 * AuthProvider component so React Fast Refresh only sees component exports there.
 */
import { createContext, useContext } from "react";
import type { UserRole } from "./types";

export interface User {
  id: number;
  username: string;
  role: UserRole;
  is_admin: boolean;
  session_token?: string | null;
}

/** True for roles allowed to mutate (everything except view_only). */
export function canWrite(user: User | null): boolean {
  return user?.role === "admin" || user?.role === "user";
}

export interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
