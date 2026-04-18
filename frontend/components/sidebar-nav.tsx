"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { logout } from "@/lib/api";
import { useRouter } from "next/navigation";
import {
  LayoutDashboard,
  Shield,
  Globe,
  Key,
  FileText,
  Settings,
  Lock,
  LogOut,
  ShieldAlert,
  Ban,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";

const groups = [
  {
    title: "概览",
    items: [
      { href: "/dashboard/", label: "仪表盘", icon: LayoutDashboard },
    ],
  },
  {
    title: "接入",
    items: [
      { href: "/sites/", label: "站点", icon: Globe },
      { href: "/certificates/", label: "证书", icon: Lock },
    ],
  },
  {
    title: "安全",
    items: [
      { href: "/security-events/", label: "安全事件", icon: ShieldAlert },
      { href: "/ip-lists/", label: "IP 黑白名单", icon: Ban },
      { href: "/policies/", label: "策略", icon: FileText },
      { href: "/rules/", label: "规则", icon: Shield },
      { href: "/protection/", label: "防护设置", icon: Shield },
    ],
  },
  {
    title: "系统",
    items: [
      { href: "/settings/", label: "系统设置", icon: Settings },
      { href: "/api-keys/", label: "API 密钥", icon: Key },
    ],
  },
];

interface SidebarNavProps {
  collapsed: boolean;
  onToggle: () => void;
}

export function SidebarNav({ collapsed, onToggle }: SidebarNavProps) {
  const pathname = usePathname();
  const router = useRouter();

  async function handleLogout() {
    await logout();
    router.push("/login/");
  }

  return (
    <aside
      className={cn(
        "flex flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground transition-all duration-300 card-shadow-lg",
        collapsed ? "w-16" : "w-64"
      )}
    >
      <div className="flex h-14 items-center justify-between px-4">
        {!collapsed && (
          <div className="font-bold text-lg tracking-tight bg-gradient-to-r from-primary to-chart-2 bg-clip-text text-transparent">
            My-OpenWAF
          </div>
        )}
        <Button
          variant="ghost"
          size="icon"
          onClick={onToggle}
          className="h-8 w-8 text-muted-foreground hover:text-foreground"
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </Button>
      </div>
      <Separator className="bg-sidebar-border" />
      <nav className="flex-1 overflow-y-auto px-2 py-4 text-sm space-y-6">
        {groups.map((g) => (
          <div key={g.title}>
            {!collapsed && (
              <div className="mb-2 px-3 text-xs font-semibold uppercase text-muted-foreground tracking-wider">
                {g.title}
              </div>
            )}
            <div className="space-y-1">
              {g.items.map((item) => {
                const active = pathname === item.href || pathname?.startsWith(item.href.replace(/\/$/, "") + "/");
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={cn(
                      "flex items-center gap-3 rounded-lg px-3 py-2.5 transition-all duration-200",
                      active
                        ? "nav-item-active"
                        : "text-muted-foreground nav-item-hover",
                      collapsed && "justify-center"
                    )}
                    title={collapsed ? item.label : undefined}
                  >
                    <item.icon className={cn("h-5 w-5 flex-shrink-0", active && "text-primary")} />
                    {!collapsed && <span className="truncate">{item.label}</span>}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>
      <Separator className="bg-sidebar-border" />
      <div className="p-2">
        <Button
          variant="ghost"
          size="sm"
          className={cn(
            "w-full gap-3 text-muted-foreground hover:text-foreground hover:bg-destructive/10",
            collapsed ? "justify-center px-2" : "justify-start"
          )}
          onClick={handleLogout}
          title={collapsed ? "退出登录" : undefined}
        >
          <LogOut className="h-4 w-4 flex-shrink-0" />
          {!collapsed && "退出登录"}
        </Button>
      </div>
    </aside>
  );
}
