/**
 * Auth context, hook, and shared types — kept JSX-free and separate from the
 * AuthProvider component so React Fast Refresh only sees component exports there.
 */
import { createContext, useContext } from "react";

export interface User {
  id: number;
  username: string;
  is_admin: boolean;
  session_token?: string | null;
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
