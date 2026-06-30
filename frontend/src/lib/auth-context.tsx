/**
 * Session-cookie auth: hydrate user from /api/auth/me on mount,
 * expose login/logout helpers via context.
 */
import { useEffect, useState, type ReactNode } from "react";
import { api, ApiError, setAuthToken, unauthorizedEvent } from "./api";
import { AuthContext, type LoginChallenge, type User } from "./use-auth";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const clearUser = () => {
      setAuthToken(null);
      setUser(null);
    };
    window.addEventListener(unauthorizedEvent, clearUser);
    return () => window.removeEventListener(unauthorizedEvent, clearUser);
  }, []);

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

  const login = async (username: string, password: string): Promise<LoginChallenge> => {
    // Step 1: password only. Never yields a session — returns the 2FA challenge.
    return api.post<LoginChallenge>("/api/auth/login", { username, password });
  };

  const completeLogin = (me: User) => {
    setAuthToken(me.session_token ?? null);
    setUser(me);
  };

  const logout = async () => {
    try {
      await api.post<void>("/api/auth/logout");
    } finally {
      setAuthToken(null);
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, completeLogin, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
