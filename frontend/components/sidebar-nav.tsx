"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { ChevronLeft, ChevronRight, LogOut, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { logout } from "@/lib/api";
import { consoleNavItems } from "@/lib/console";
import { cn } from "@/lib/utils";

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

  const groups = consoleNavItems.reduce<Record<string, typeof consoleNavItems>>((acc, item) => {
    if (!acc[item.group]) acc[item.group] = [];
    acc[item.group].push(item);
    return acc;
  }, {});

  return (
    <aside
      className={cn(
        "relative hidden h-svh shrink-0 flex-col border-r border-white/8 bg-[linear-gradient(180deg,#09111f_0%,#0d182b_42%,#0b1120_100%)] text-white shadow-[30px_0_80px_rgba(2,6,23,0.35)] lg:flex",
        collapsed ? "w-[92px]" : "w-[316px]",
      )}
    >
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(6,182,212,0.12),transparent_32%),radial-gradient(circle_at_bottom,rgba(16,185,129,0.08),transparent_22%)]" />
      <div className="relative flex h-full flex-col">
        <div className="px-4 pb-4 pt-5">
          <div className="console-glass rounded-[28px] p-4">
            <div className="flex items-start justify-between gap-3">
              {!collapsed ? (
                <div className="space-y-2">
                  <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] tracking-[0.22em] text-white/70 uppercase">
                    <Sparkles className="h-3.5 w-3.5" /> Security Console
                  </div>
                  <div>
                    <div className="text-xl font-semibold tracking-tight text-white">My-OpenWAF</div>
                    <p className="mt-1 text-xs leading-5 text-slate-300/70">
                      统一管理站点接入、检测引擎、阻断策略与运行状态。
                    </p>
                  </div>
                </div>
              ) : (
                <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-2xl bg-cyan-400/12 text-cyan-200">
                  <Sparkles className="h-5 w-5" />
                </div>
              )}
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={onToggle}
                className="shrink-0 rounded-xl text-slate-300 hover:bg-white/8 hover:text-white"
              >
                {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
              </Button>
            </div>
          </div>
        </div>

        <nav className="relative flex-1 overflow-y-auto px-3 pb-4">
          <div className="space-y-5">
            {Object.entries(groups).map(([groupName, items]) => (
              <div key={groupName} className="space-y-2">
                {!collapsed ? (
                  <div className="px-3 text-[11px] font-medium tracking-[0.22em] text-slate-500 uppercase">
                    {groupName}
                  </div>
                ) : null}
                <div className="space-y-1.5">
                  {items.map((item) => {
                    const active = pathname === item.href || pathname?.startsWith(item.href);
                    const disabled = item.enabled === false;
                    return (
                      <Link
                        key={item.href}
                        href={disabled ? "#" : item.href}
                        onClick={(event) => {
                          if (disabled) event.preventDefault();
                        }}
                        className={cn("console-sidebar-link", disabled && "opacity-55", collapsed && "justify-center")}
                        data-active={active}
                        title={collapsed ? item.label : undefined}
                      >
                        <div className={cn(
                          "mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border",
                          active
                            ? "border-cyan-300/20 bg-cyan-300/14 text-cyan-100"
                            : "border-white/8 bg-white/5 text-slate-300",
                        )}>
                          <item.icon className="h-4.5 w-4.5" />
                        </div>
                        {!collapsed ? (
                          <div className="min-w-0 flex-1">
                            <div className="truncate text-sm font-medium text-white">{item.label}</div>
                            <div className="mt-0.5 line-clamp-2 text-xs leading-5 text-slate-400/80">
                              {item.description}
                            </div>
                          </div>
                        ) : null}
                      </Link>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </nav>

        <div className="relative p-3 pt-0">
          <div className="console-glass rounded-[24px] p-3">
            <Button
              variant="ghost"
              onClick={handleLogout}
              className={cn(
                "h-auto w-full justify-start rounded-2xl px-3 py-3 text-slate-300 hover:bg-white/8 hover:text-white",
                collapsed && "justify-center px-2",
              )}
              title={collapsed ? "退出登录" : undefined}
            >
              <LogOut className="mr-2 h-4 w-4 shrink-0" />
              {!collapsed ? <span className="text-sm">退出登录</span> : null}
            </Button>
          </div>
        </div>
      </div>
    </aside>
  );
}
