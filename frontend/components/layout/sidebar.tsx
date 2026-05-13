"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { ChevronLeft, ChevronRight, LogOut, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { logout } from "@/lib/api";
import { consoleNavGroups } from "@/lib/console";
import { cn } from "@/lib/utils";

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const pathname = usePathname();
  const router = useRouter();

  async function handleLogout() {
    await logout();
    router.push("/login/");
  }

  return (
    <aside
      className={cn(
        "flex h-svh shrink-0 flex-col border-r border-slate-200 bg-slate-50 text-slate-950 transition-[width] duration-200 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-50",
        collapsed ? "w-[68px]" : "w-[240px]",
      )}
    >
      <div className="flex h-16 items-center gap-2.5 border-b border-slate-200 px-4 dark:border-slate-800">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-slate-950 text-white dark:bg-slate-100 dark:text-slate-950">
          <ShieldCheck className="h-4.5 w-4.5" />
        </div>
        {!collapsed && (
          <span className="text-[15px] font-semibold tracking-tight text-slate-950 dark:text-slate-50">
            My-OpenWAF
          </span>
        )}
        <Button
          variant="ghost"
          size="icon"
          onClick={onToggle}
          className={cn(
            "ml-auto h-7 w-7 shrink-0 rounded-md text-slate-500 hover:bg-slate-100 hover:text-slate-950 dark:text-slate-400 dark:hover:bg-slate-900 dark:hover:text-white",
            collapsed && "ml-0",
          )}
        >
          {collapsed ? (
            <ChevronRight className="h-4 w-4" />
          ) : (
            <ChevronLeft className="h-4 w-4" />
          )}
        </Button>
      </div>

      <nav className="flex-1 overflow-y-auto px-2 py-4">
        <div className="space-y-6">
          {consoleNavGroups.map((group) => (
            <div key={group.title}>
              {!collapsed && (
                <div className="mb-2 px-3 text-[11px] font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  {group.title}
                </div>
              )}
              <div className="space-y-0.5">
                {group.items.map((item) => {
                  const active =
                    pathname === item.href ||
                    (item.exact !== false && pathname?.startsWith(item.href));
                  const disabled = item.enabled === false;
                  return (
                    <Link
                      key={item.href}
                      href={disabled ? "#" : item.href}
                      onClick={(e) => {
                        if (disabled) e.preventDefault();
                      }}
                      className={cn(
                        "console-sidebar-link",
                        disabled && "pointer-events-none opacity-40",
                        collapsed && "justify-center px-0",
                      )}
                      data-active={active}
                      title={collapsed ? item.label : undefined}
                    >
                      <item.icon
                        className={cn(
                          "h-[18px] w-[18px] shrink-0",
                          active ? "text-slate-700 dark:text-slate-200" : "text-slate-400 dark:text-slate-500",
                        )}
                      />
                      {!collapsed && <span className="truncate">{item.label}</span>}
                    </Link>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </nav>

      <div className="border-t border-slate-200 p-2 dark:border-slate-800">
        <button
          onClick={handleLogout}
          className={cn(
            "flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-950 dark:text-slate-400 dark:hover:bg-slate-900 dark:hover:text-white",
            collapsed && "justify-center px-0",
          )}
          title={collapsed ? "退出登录" : undefined}
        >
          <LogOut className="h-[18px] w-[18px] shrink-0" />
          {!collapsed && <span>退出登录</span>}
        </button>
      </div>
    </aside>
  );
}
