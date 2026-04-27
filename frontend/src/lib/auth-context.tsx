/**
 * Session-cookie auth: hydrate user from /api/auth/me on mount,
 * expose login/logout helpers via context.
 */
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, ApiError } from "./api";

export interface User {
  id: number;
  username: string;
  is_admin: boolean;
}

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const me = await api.get<User>("/api/auth/me");
        if (!cancelled) setUser(me);
      } catch (err) {
        if (!(err instanceof ApiError) || err.status !== 401) {
          console.error("auth bootstrap failed", err);
        }
        if (!cancelled) setUser(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const login = async (username: string, password: string) => {
    const me = await api.post<User>("/api/auth/login", { username, password });
    setUser(me);
  };

  const logout = async () => {
    try {
      await api.post<void>("/api/auth/logout");
    } finally {
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
