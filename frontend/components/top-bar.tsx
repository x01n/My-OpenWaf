/**
 * 顶部栏组件
 * 显示页面标题、用户信息、退出登录
 */

"use client";

import { useTranslation } from "react-i18next";
import { usePathname } from "next/navigation";
import { MobileSidebar } from "./sidebar-nav";
import { useAuth } from "@/hooks/use-auth";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { IconLogout, IconUser, IconReload } from "@tabler/icons-react";
import { toast } from "sonner";
import { useSystemReload } from "@/hooks/use-api";
import { cn } from "@/lib/utils";
import { LanguageSwitcher } from "./language-switcher";

function getPageTitle(pathname: string): string {
  const titles: Record<string, string> = {
    "/dashboard": "nav.dashboard",
    "/sites": "nav.sites",
    "/attacks": "nav.attacks",
    "/rules": "nav.rules",
    "/cc-protection": "nav.ccProtection",
    "/captcha": "nav.captcha",
    "/auth-config": "nav.authConfig",
    "/settings": "nav.settings",
    "/security-events": "nav.securityEvents",
    "/access-logs": "nav.accessLogs",
    "/drop-events": "nav.dropEvents",
  };
  for (const [path, key] of Object.entries(titles)) {
    if (pathname.startsWith(path)) return key;
  }
  return "My OpenWAF";
}

export function TopBar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();
  const reload = useSystemReload();
  const { t } = useTranslation();

  const handleReload = async () => {
    try {
      await reload.execute({});
      toast.success(t("common.saveSuccess"));
    } catch {
      toast.error(t("common.saveFailed"));
    }
  };

  return (
    <header className="flex h-14 items-center gap-4 border-b bg-card px-4 lg:px-6">
      <MobileSidebar />
      <h1 className="text-sm font-semibold lg:text-base">{t(getPageTitle(pathname))}</h1>
      <div className="ml-auto flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={handleReload}
          disabled={reload.loading}
          className="hidden sm:flex"
        >
          <IconReload className={cn("mr-2 h-4 w-4", reload.loading && "animate-spin")} />
          {t("common.save")}
        </Button>
        <LanguageSwitcher />
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="relative h-8 w-8 rounded-full">
              <Avatar className="h-8 w-8">
                <AvatarFallback className="bg-primary text-primary-foreground text-xs">
                  {user?.username?.slice(0, 2)?.toUpperCase() || "U"}
                </AvatarFallback>
              </Avatar>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem className="flex items-center gap-2">
              <IconUser className="h-4 w-4" />
              <span>{user?.username || t("common.user")}</span>
            </DropdownMenuItem>
            <DropdownMenuItem
              className="flex items-center gap-2 text-destructive focus:text-destructive"
              onClick={logout}
            >
              <IconLogout className="h-4 w-4" />
              <span>{t("common.logout")}</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
