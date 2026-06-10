"use client"

import { useState } from "react"
import Link from "next/link"
import { usePathname, useRouter } from "next/navigation"
import {
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  LogOut,
  ShieldCheck,
} from "@/lib/icons"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { logout } from "@/lib/api"
import {
  consoleNavGroups,
  isConsoleNavPathActive,
  type ConsoleNavItem,
} from "@/lib/console"
import { cn } from "@/lib/utils"

interface SidebarProps {
  collapsed: boolean
  onToggle: () => void
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const pathname = usePathname()
  const router = useRouter()
  const [expandedItems, setExpandedItems] = useState<Set<string>>(new Set())

  function toggleExpand(href: string) {
    setExpandedItems((prev) => {
      const next = new Set(prev)
      if (next.has(href)) next.delete(href)
      else next.add(href)
      return next
    })
  }

  function isActive(item: ConsoleNavItem): boolean {
    if (isConsoleNavPathActive(pathname, item)) return true
    if (item.children)
      return item.children.some((c) => isConsoleNavPathActive(pathname, c))
    return false
  }

  async function handleLogout() {
    await logout()
    router.push("/login/")
  }

  return (
    <aside
      className={cn(
        "flex h-svh shrink-0 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground transition-[width] duration-200",
        collapsed ? "w-[68px]" : "w-[248px]"
      )}
    >
      {/* Logo */}
      <div className="flex h-14 items-center gap-2.5 px-4">
        <div className="flex size-8 shrink-0 items-center justify-center rounded-md bg-sidebar-primary text-sidebar-primary-foreground shadow-sm">
          <ShieldCheck className="size-[18px]" />
        </div>
        {!collapsed && (
          <span className="text-[15px] font-bold tracking-tight text-sidebar-foreground">
            My-OpenWAF
          </span>
        )}
        <Button
          variant="ghost"
          size="icon-sm"
          onClick={onToggle}
          aria-label={collapsed ? "展开侧边栏" : "收起侧边栏"}
          className={cn(
            "ms-auto shrink-0 rounded-md text-sidebar-foreground/55 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
            collapsed && "ms-0"
          )}
        >
          {collapsed ? (
            <ChevronRight data-icon="inline-start" />
          ) : (
            <ChevronLeft data-icon="inline-start" />
          )}
        </Button>
      </div>
      <Separator />

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-2 py-3">
        <div className="flex flex-col gap-4">
          {consoleNavGroups.map((group) => (
            <div key={group.title || "main"} className="flex flex-col gap-1">
              {!collapsed && group.title ? (
                <div className="px-3 pt-2 pb-1 text-[10px] font-semibold tracking-[0.18em] text-sidebar-foreground/45 uppercase">
                  {group.title}
                </div>
              ) : null}
              <div className="flex flex-col gap-0.5">
                {group.items.map((item) => {
                  const active = isActive(item)
                  const hasChildren = item.children && item.children.length > 0
                  const expanded =
                    expandedItems.has(item.href) || (hasChildren && active)
                  const disabled = item.enabled === false

                  return (
                    <div key={item.href}>
                      <div className="flex items-center">
                        <Link
                          href={disabled ? "#" : item.href}
                          onClick={(e) => {
                            if (disabled) e.preventDefault()
                            if (hasChildren && !collapsed) {
                              e.preventDefault()
                              toggleExpand(item.href)
                            }
                          }}
                          className={cn(
                            "flex flex-1 items-center gap-2.5 rounded-md border border-transparent px-3 py-2 text-[13.5px] font-medium transition-all duration-150",
                            active
                              ? "border-sidebar-primary bg-sidebar-primary text-sidebar-primary-foreground shadow-sm"
                              : "text-sidebar-foreground/72 hover:border-sidebar-border hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
                            disabled && "pointer-events-none opacity-40",
                            collapsed && "justify-center px-0"
                          )}
                          title={collapsed ? item.label : undefined}
                        >
                          <item.icon
                            className={cn(
                              "size-[18px] shrink-0",
                              active
                                ? "text-sidebar-primary-foreground"
                                : "text-sidebar-foreground/45"
                            )}
                          />
                          {!collapsed && (
                            <span className="flex-1 truncate">
                              {item.label}
                            </span>
                          )}
                          {!collapsed && hasChildren && (
                            <ChevronDown
                              className={cn(
                                "size-3.5 shrink-0 transition-transform",
                                expanded && "rotate-180",
                                active
                                  ? "text-sidebar-primary-foreground/80"
                                  : "text-sidebar-foreground/45"
                              )}
                            />
                          )}
                        </Link>
                      </div>

                      {/* Sub-items */}
                      {!collapsed && hasChildren && expanded && (
                        <div className="ms-4 mt-0.5 flex flex-col gap-0.5 border-l border-sidebar-border pl-3">
                          {item.children!.map((child) => {
                            const childActive = isConsoleNavPathActive(
                              pathname,
                              child
                            )
                            return (
                              <Link
                                key={child.href}
                                href={child.href}
                                className={cn(
                                  "flex items-center gap-2 rounded-lg border border-transparent px-2.5 py-1.5 text-[13px] transition-all",
                                  childActive
                                    ? "border-sidebar-primary/35 bg-primary/10 font-medium text-sidebar-accent-foreground"
                                    : "text-sidebar-foreground/58 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                                )}
                              >
                                <child.icon
                                  className={cn(
                                    "size-3.5",
                                    childActive
                                      ? "text-sidebar-primary"
                                      : "text-sidebar-foreground/40"
                                  )}
                                />
                                <span>{child.label}</span>
                              </Link>
                            )
                          })}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      </nav>

      {/* Logout */}
      <Separator />
      <div className="p-2">
        <Button
          type="button"
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
          {!collapsed && <span>退出登录</span>}
        </Button>
      </div>
    </aside>
  )
}
