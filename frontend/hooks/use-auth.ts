import { useState, useEffect, useCallback } from "react";
import { authApi } from "@/lib/api";
import type { User } from "@/lib/types";

/**
 * 认证状态管理 Hook
 */
export function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      setLoading(false);
      return;
    }
    authApi.me()
      .then((data: any) => {
        setUser(data);
      })
      .catch(() => {
        localStorage.removeItem("token");
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const data = await authApi.login(username, password);
    if (data.access_token) {
      localStorage.setItem("token", data.access_token);
      setUser({ username: data.username, role: data.role } as User);
    }
    return data;
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } finally {
      localStorage.removeItem("token");
      setUser(null);
      window.location.href = "/login";
    }
  }, []);

  return { user, loading, login, logout, isAuthenticated: !!user };
}

/**
 * 检查是否已登录（用于路由守卫）
 */
export function useIsAuthenticated() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      setChecked(true);
      return;
    }
    authApi.me()
      .then(() => setIsAuthenticated(true))
      .catch(() => localStorage.removeItem("token"))
      .finally(() => setChecked(true));
  }, []);

  return { isAuthenticated, checked };
}
