"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { logout } from "@/lib/api";
import { useRouter } from "next/navigation";
import {
  BarChart3,
  Shield,
  ShieldAlert,
  List,
  Zap,
  Bot,
  Key,
  Settings,
  LogOut,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";

const navItems = [
  { href: "/dashboard/", label: "统计报表", icon: BarChart3 },
  { href: "/sites/", label: "防护应用", icon: Shield },
  { href: "/protection/", label: "攻击防护", icon: ShieldAlert },
  { href: "/ip-lists/", label: "黑白名单", icon: List },
  { href: "/cc-protection/", label: "CC 防护", icon: Zap },
  { href: "/captcha/", label: "人机验证", icon: Bot },
  { href: "/auth-settings/", label: "身份认证", icon: Key },
  { href: "/settings/", label: "通用设置", icon: Settings },
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
        "flex flex-col border-r border-white/10 bg-[#1a2236] text-gray-300 transition-all duration-300",
        collapsed ? "w-16" : "w-[180px]"
      )}
    >
      <div className="flex h-14 items-center justify-between px-3">
        {!collapsed && (
          <div className="font-bold text-base tracking-tight bg-gradient-to-r from-[#0d9488] to-[#2dd4bf] bg-clip-text text-transparent">
            My-OpenWAF
          </div>
        )}
        <Button
          variant="ghost"
          size="icon"
          onClick={onToggle}
          className="h-8 w-8 text-gray-400 hover:text-white"
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </Button>
      </div>
      <Separator className="bg-white/10" />
      <nav className="flex-1 overflow-y-auto px-2 py-3 text-sm space-y-0.5">
        {navItems.map((item) => {
          const active = pathname === item.href || pathname?.startsWith(item.href.replace(/\/$/, "") + "/");
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-2.5 rounded-md px-3 py-2 transition-all duration-200",
                active
                  ? "bg-teal-500 text-white font-medium"
                  : "text-gray-400 hover:bg-white/10 hover:text-white",
                collapsed && "justify-center px-2"
              )}
              title={collapsed ? item.label : undefined}
            >
              <item.icon className={cn("h-[18px] w-[18px] flex-shrink-0", active && "text-white")} />
              {!collapsed && <span className="truncate text-[13px]">{item.label}</span>}
            </Link>
          );
        })}
      </nav>
      <Separator className="bg-white/10" />
      <div className="p-2">
        <Button
          variant="ghost"
          size="sm"
          className={cn(
            "w-full gap-2.5 text-gray-400 hover:text-red-400 hover:bg-white/10 rounded-md",
            collapsed ? "justify-center px-2" : "justify-start"
          )}
          onClick={handleLogout}
          title={collapsed ? "退出登录" : undefined}
        >
          <LogOut className="h-4 w-4 flex-shrink-0" />
          {!collapsed && <span className="text-[13px]">退出登录</span>}
        </Button>
      </div>
    </aside>
  );
}
