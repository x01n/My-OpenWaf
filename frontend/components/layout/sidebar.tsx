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
        "flex h-svh shrink-0 flex-col bg-gray-800 text-white transition-[width] duration-200",
        collapsed ? "w-[68px]" : "w-[240px]",
      )}
    >
      {/* Logo / Brand */}
      <div className="flex h-16 items-center gap-2.5 border-b border-white/10 px-4">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-cyan-500 text-white">
          <ShieldCheck className="h-4.5 w-4.5" />
        </div>
        {!collapsed && (
          <span className="text-[15px] font-semibold tracking-tight text-gray-50">
            My-OpenWAF
          </span>
        )}
        <Button
          variant="ghost"
          size="icon"
          onClick={onToggle}
          className={cn(
            "ml-auto h-7 w-7 shrink-0 rounded-md text-gray-400 hover:bg-white/10 hover:text-white",
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

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-2 py-4">
        <div className="space-y-6">
          {consoleNavGroups.map((group) => (
            <div key={group.title}>
              {!collapsed && (
                <div className="mb-2 px-3 text-[11px] font-medium tracking-wider text-gray-500 uppercase">
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
                          active ? "text-cyan-400" : "text-gray-400",
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

      {/* Bottom: Logout */}
      <div className="border-t border-white/10 p-2">
        <button
          onClick={handleLogout}
          className={cn(
            "flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-gray-400 transition-colors hover:bg-white/8 hover:text-white",
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
