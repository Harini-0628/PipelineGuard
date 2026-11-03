import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, setUnauthorizedHandler, tokenStore } from "./api/client";
import type { Role, User } from "./api/types";

interface AuthCtx {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  can: (...roles: Role[]) => boolean;
}
const Ctx = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(!!tokenStore.get());

  const logout = useCallback(() => { tokenStore.clear(); setUser(null); }, []);
  useEffect(() => { setUnauthorizedHandler(logout); }, [logout]);
  useEffect(() => {
    if (!tokenStore.get()) return;
    api.me().then(setUser).catch(() => tokenStore.clear()).finally(() => setLoading(false));
  }, []);

  const value = useMemo<AuthCtx>(() => ({
    user, loading, logout,
    login: async (email, password) => {
      const { access_token } = await api.login(email, password);
      tokenStore.set(access_token);
      setUser(await api.me());
    },
    can: (...roles) => !!user && roles.includes(user.role),
  }), [user, loading, logout]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("useAuth outside AuthProvider");
  return c;
}
