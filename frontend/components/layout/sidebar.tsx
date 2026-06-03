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
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { logout } from "@/lib/api"
import { consoleNavGroups, type ConsoleNavItem } from "@/lib/console"
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
    if (!pathname) return false
    if (pathname === item.href) return true
    if (item.exact !== false && pathname.startsWith(item.href)) return true
    if (item.children)
      return item.children.some(
        (c) => pathname === c.href || pathname.startsWith(c.href)
      )
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
      <div className="flex h-14 items-center gap-2.5 border-b border-sidebar-border px-4">
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
          size="icon"
          onClick={onToggle}
          className={cn(
            "ml-auto size-7 shrink-0 rounded-md text-sidebar-foreground/55 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
            collapsed && "ml-0"
          )}
        >
          {collapsed ? (
            <ChevronRight data-icon="inline" />
          ) : (
            <ChevronLeft data-icon="inline" />
          )}
        </Button>
      </div>

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
                              "h-[18px] w-[18px] shrink-0",
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
                                "h-3.5 w-3.5 shrink-0 transition-transform",
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
                        <div className="mt-0.5 ml-4 flex flex-col gap-0.5 border-l border-sidebar-border pl-3">
                          {item.children!.map((child) => {
                            const childActive =
                              pathname === child.href ||
                              (child.exact !== false &&
                                pathname?.startsWith(child.href))
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
                                    "h-3.5 w-3.5",
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
      <div className="border-t border-sidebar-border p-2">
        <button
          onClick={handleLogout}
          className={cn(
            "flex w-full items-center gap-2.5 rounded-md border border-transparent px-3 py-2 text-[13.5px] text-sidebar-foreground/60 transition-colors hover:border-rose-200 hover:bg-rose-50 hover:text-rose-700",
            collapsed && "justify-center px-0"
          )}
          title={collapsed ? "退出登录" : undefined}
        >
          <LogOut className="h-[18px] w-[18px] shrink-0" />
          {!collapsed && <span>退出登录</span>}
        </button>
      </div>
    </aside>
  )
}
