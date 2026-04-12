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
  Server,
  Key,
  FileText,
  Settings,
  Lock,
  Network,
  LogOut,
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
      { href: "/listeners/", label: "监听器", icon: Server },
      { href: "/sites/", label: "站点", icon: Globe },
      { href: "/certificates/", label: "证书", icon: Lock },
      { href: "/forwarding-profiles/", label: "转发配置", icon: Network },
    ],
  },
  {
    title: "安全",
    items: [
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

export function SidebarNav() {
  const pathname = usePathname();
  const router = useRouter();

  async function handleLogout() {
    await logout();
    router.push("/login/");
  }

  return (
    <aside className="flex w-56 flex-col border-r bg-sidebar text-sidebar-foreground">
      <div className="flex h-14 items-center px-4 font-semibold tracking-tight">
        My-OpenWAF
      </div>
      <Separator />
      <nav className="flex-1 overflow-y-auto px-2 py-3 text-sm">
        {groups.map((g) => (
          <div key={g.title} className="mb-4">
            <div className="mb-1 px-2 text-xs font-medium uppercase text-muted-foreground">
              {g.title}
            </div>
            {g.items.map((item) => {
              const active = pathname === item.href || pathname?.startsWith(item.href.replace(/\/$/, "") + "/");
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={cn(
                    "flex items-center gap-2 rounded-md px-2 py-1.5 transition-colors",
                    active
                      ? "bg-accent font-medium text-accent-foreground"
                      : "text-muted-foreground hover:bg-accent/50 hover:text-foreground",
                  )}
                >
                  <item.icon className="h-4 w-4" />
                  {item.label}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>
      <Separator />
      <div className="p-2">
        <Button
          variant="ghost"
          size="sm"
          className="w-full justify-start gap-2 text-muted-foreground"
          onClick={handleLogout}
        >
          <LogOut className="h-4 w-4" />
          退出登录
        </Button>
      </div>
    </aside>
  );
}
