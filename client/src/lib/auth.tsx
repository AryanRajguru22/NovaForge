import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { apiGet, apiPost } from "./api.js";

interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: string;
}

type AuthStatus = "loading" | "authenticated" | "anonymous";

interface AuthContextValue {
  status: AuthStatus;
  user: AuthUser | null;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>("loading");
  const [user, setUser] = useState<AuthUser | null>(null);

  async function refresh() {
    try {
      const me = await apiGet<AuthUser>("/auth/me");
      setUser(me);
      setStatus("authenticated");
    } catch {
      setUser(null);
      setStatus("anonymous");
    }
  }

  async function logout() {
    try {
      await apiPost("/auth/logout", {});
    } catch {
      // best-effort -- proceed to clear local state even if the request fails
    }
    setUser(null);
    setStatus("anonymous");
  }

  useEffect(() => {
    void refresh();
  }, []);

  return <AuthContext.Provider value={{ status, user, refresh, logout }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
