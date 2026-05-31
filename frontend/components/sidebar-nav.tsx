"use client"

import Link from "next/link"
import { usePathname, useRouter } from "next/navigation"
import { ChevronLeft, ChevronRight, LogOut, Shield } from "lucide-react"
import { Button } from "@/components/ui/button"
import { logout } from "@/lib/api"
import { consoleNavItems } from "@/lib/console"
import { cn } from "@/lib/utils"

interface SidebarNavProps {
  collapsed: boolean
  onToggle: () => void
}

export function SidebarNav({ collapsed, onToggle }: SidebarNavProps) {
  const pathname = usePathname()
  const router = useRouter()

  async function handleLogout() {
    await logout()
    router.push("/login/")
  }

  const groups = consoleNavItems.reduce<Record<string, typeof consoleNavItems>>(
    (acc, item) => {
      if (!acc[item.group]) acc[item.group] = []
      acc[item.group].push(item)
      return acc
    },
    {}
  )

  return (
    <aside
      className={cn(
        "relative flex h-svh shrink-0 flex-col border-r border-slate-200 bg-slate-50 text-slate-950 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-50",
        collapsed ? "w-[92px]" : "w-[316px]"
      )}
    >
      <div className="relative flex h-full flex-col">
        <div className="border-b border-slate-200 px-4 pt-5 pb-4 dark:border-slate-800">
          <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <div className="flex items-start justify-between gap-3">
              {!collapsed ? (
                <div className="space-y-2">
                  <div className="inline-flex items-center gap-2 rounded-md border border-slate-200 bg-slate-50 px-3 py-1 text-[11px] tracking-[0.18em] text-slate-500 uppercase dark:border-slate-800 dark:bg-slate-950 dark:text-slate-400">
                    <Shield className="h-3.5 w-3.5 text-slate-600" /> 控制台
                  </div>
                  <div>
                    <div className="text-xl font-semibold tracking-tight text-slate-950 dark:text-slate-50">
                      My-OpenWAF
                    </div>
                    <p className="mt-1 text-xs leading-5 text-slate-600 dark:text-slate-400">
                      统一管理站点接入、检测引擎、阻断策略与运行状态。
                    </p>
                  </div>
                </div>
              ) : (
                <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-lg border border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300">
                  <Shield className="h-5 w-5" />
                </div>
              )}
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={onToggle}
                className="shrink-0 rounded-md text-slate-500 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-50"
              >
                {collapsed ? (
                  <ChevronRight className="h-4 w-4" />
                ) : (
                  <ChevronLeft className="h-4 w-4" />
                )}
              </Button>
            </div>
          </div>
        </div>

        <nav className="relative flex-1 overflow-y-auto px-3 pt-3 pb-4">
          <div className="space-y-5">
            {Object.entries(groups).map(([groupName, items]) => (
              <div key={groupName} className="space-y-2">
                {!collapsed ? (
                  <div className="px-3 text-[11px] font-medium tracking-[0.18em] text-slate-500 uppercase dark:text-slate-400">
                    {groupName}
                  </div>
                ) : null}
                <div className="space-y-1.5">
                  {items.map((item) => {
                    const active =
                      pathname === item.href || pathname?.startsWith(item.href)
                    const disabled = item.enabled === false
                    return (
                      <Link
                        key={item.href}
                        href={disabled ? "#" : item.href}
                        onClick={(event) => {
                          if (disabled) event.preventDefault()
                        }}
                        className={cn(
                          "console-sidebar-link",
                          disabled && "opacity-55",
                          collapsed && "justify-center"
                        )}
                        data-active={active}
                        title={collapsed ? item.label : undefined}
                      >
                        <div
                          className={cn(
                            "mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-md border",
                            active
                              ? "border-slate-200 bg-slate-100 text-slate-950 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-50"
                              : "border-slate-200 bg-white text-slate-500 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300"
                          )}
                        >
                          <item.icon className="h-4.5 w-4.5" />
                        </div>
                        {!collapsed ? (
                          <div className="min-w-0 flex-1">
                            <div className="truncate text-sm font-medium text-slate-900 dark:text-slate-50">
                              {item.label}
                            </div>
                            <div className="mt-0.5 line-clamp-2 text-xs leading-5 text-slate-500 dark:text-slate-400">
                              {item.description}
                            </div>
                          </div>
                        ) : null}
                      </Link>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>
        </nav>

        <div className="relative border-t border-slate-200 p-3 pt-0 dark:border-slate-800">
          <div className="rounded-lg border border-slate-200 bg-white p-3 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <Button
              variant="ghost"
              onClick={handleLogout}
              className={cn(
                "h-auto w-full justify-start rounded-md px-3 py-3 text-slate-600 hover:bg-slate-100 hover:text-slate-950 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-slate-50",
                collapsed && "justify-center px-2"
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
  )
}
