"use client"

import Link from "next/link"
import { usePathname, useRouter } from "next/navigation"
import { ChevronLeft, ChevronRight, LogOut, Shield } from "@/lib/icons"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
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
        "relative flex h-svh shrink-0 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground",
        collapsed ? "w-[92px]" : "w-[316px]"
      )}
    >
      <div className="relative flex h-full flex-col">
        <div className="px-4 pt-5 pb-4">
          <div className="rounded-lg border border-sidebar-border bg-sidebar-accent/60 p-4 shadow-sm">
            <div className="flex items-start justify-between gap-3">
              {!collapsed ? (
                <div className="flex flex-col gap-2">
                  <div className="inline-flex items-center gap-2 rounded-md border border-sidebar-border bg-sidebar px-3 py-1 text-[11px] tracking-[0.18em] text-sidebar-foreground/60 uppercase">
                    <Shield className="size-3.5" aria-hidden="true" />
                    控制台
                  </div>
                  <div>
                    <div className="text-xl font-semibold tracking-tight text-sidebar-foreground">
                      My-OpenWAF
                    </div>
                    <p className="mt-1 text-xs leading-5 text-sidebar-foreground/65">
                      统一管理站点接入、检测引擎、阻断策略与运行状态。
                    </p>
                  </div>
                </div>
              ) : (
                <div className="mx-auto flex size-11 items-center justify-center rounded-lg border border-sidebar-border bg-sidebar text-sidebar-foreground/70">
                  <Shield className="size-5" aria-hidden="true" />
                </div>
              )}
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={onToggle}
                aria-label={collapsed ? "展开侧边栏" : "收起侧边栏"}
                className="shrink-0 rounded-md text-sidebar-foreground/60 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
              >
                {collapsed ? (
                  <ChevronRight data-icon="inline-start" />
                ) : (
                  <ChevronLeft data-icon="inline-start" />
                )}
              </Button>
            </div>
          </div>
        </div>
        <Separator />

        <nav className="relative flex-1 overflow-y-auto px-3 pt-3 pb-4">
          <div className="flex flex-col gap-5">
            {Object.entries(groups).map(([groupName, items]) => (
              <div key={groupName} className="flex flex-col gap-2">
                {!collapsed ? (
                  <div className="px-3 text-[11px] font-medium tracking-[0.18em] text-sidebar-foreground/55 uppercase">
                    {groupName}
                  </div>
                ) : null}
                <div className="flex flex-col gap-1.5">
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
                            "mt-0.5 flex size-10 shrink-0 items-center justify-center rounded-md border",
                            active
                              ? "border-sidebar-primary/35 bg-sidebar-primary/10 text-sidebar-primary"
                              : "border-sidebar-border bg-sidebar-accent/60 text-sidebar-foreground/55"
                          )}
                        >
                          <item.icon className="size-4" aria-hidden="true" />
                        </div>
                        {!collapsed ? (
                          <div className="min-w-0 flex-1">
                            <div className="truncate text-sm font-medium text-sidebar-foreground">
                              {item.label}
                            </div>
                            <div className="mt-0.5 line-clamp-2 text-xs leading-5 text-sidebar-foreground/60">
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

        <Separator />
        <div className="relative p-3 pt-0">
          <div className="rounded-lg border border-sidebar-border bg-sidebar-accent/60 p-3 shadow-sm">
            <Button
              variant="destructive"
              size={collapsed ? "icon" : "default"}
              onClick={handleLogout}
              className={cn(
                !collapsed && "w-full justify-start",
                collapsed && "mx-auto"
              )}
              aria-label="退出登录"
              title={collapsed ? "退出登录" : undefined}
            >
              <LogOut data-icon="inline-start" />
              {!collapsed ? <span className="text-sm">退出登录</span> : null}
            </Button>
          </div>
        </div>
      </div>
    </aside>
  )
}
