"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { Spinner } from "@heroui/react";
import { getToken, getUser, fetchMe, type CurrentUser } from "@/lib/api/client";
import { ToastHost } from "@/components/ui/toast-host";
import { Sidebar, Topbar } from "@/components/layout/sidebar";
import { findNavItem } from "@/config/nav";
import { useDocumentTitle } from "@/i18n/use-document-title";

type AuthState =
  | { status: "checking" }
  | { status: "authed"; user: CurrentUser }
  | { status: "anonymous" };

/**
 * 客户端认证守卫 + 管理台外壳。
 * 静态导出模式无服务端中间件，鉴权在客户端完成：
 * 校验本地凭据后调用 /auth/me 确认会话有效，失效则回登录页。
 */
export function AdminShell({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [auth, setAuth] = useState<AuthState>({ status: "checking" });

  useDocumentTitle(findNavItem(pathname)?.labelKey ?? "brand.name");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!getToken()) {
        router.replace("/login");
        return;
      }
      try {
        const me = await fetchMe();
        if (!cancelled) setAuth({ status: "authed", user: me });
      } catch {
        if (!cancelled) router.replace("/login");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [router]);

  if (auth.status !== "authed") {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner size="lg" />
      </div>
    );
  }

  const user = auth.status === "authed" ? auth.user : getUser();
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar username={user?.username} role={user?.role} />
        <main className="ambient-canvas min-w-0 flex-1 p-5">{children}</main>
      </div>
      <ToastHost />
    </div>
  );
}
