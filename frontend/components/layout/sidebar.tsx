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

  const allItems = consoleNavGroups.flatMap((g) => g.items)

  return (
    <aside
      className={cn(
        "flex h-svh shrink-0 flex-col border-r border-slate-200 bg-white transition-[width] duration-200",
        collapsed ? "w-[68px]" : "w-[220px]"
      )}
    >
      {/* Logo */}
      <div className="flex h-14 items-center gap-2.5 border-b border-slate-200 px-4">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-teal-500 text-white">
          <ShieldCheck className="h-4.5 w-4.5" />
        </div>
        {!collapsed && (
          <span className="text-[15px] font-bold tracking-tight text-slate-800">
            My-OpenWAF
          </span>
        )}
        <Button
          variant="ghost"
          size="icon"
          onClick={onToggle}
          className={cn(
            "ml-auto h-7 w-7 shrink-0 rounded-md text-slate-400 hover:bg-slate-100 hover:text-slate-700",
            collapsed && "ml-0"
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
      <nav className="flex-1 overflow-y-auto px-2 py-3">
        <div className="space-y-0.5">
          {allItems.map((item) => {
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
                      "flex flex-1 items-center gap-2.5 rounded-lg px-3 py-2 text-[13.5px] font-medium transition-all duration-150",
                      active
                        ? "bg-teal-500 text-white shadow-sm"
                        : "text-slate-600 hover:bg-slate-100 hover:text-slate-900",
                      disabled && "pointer-events-none opacity-40",
                      collapsed && "justify-center px-0"
                    )}
                    title={collapsed ? item.label : undefined}
                  >
                    <item.icon
                      className={cn(
                        "h-[18px] w-[18px] shrink-0",
                        active ? "text-white" : "text-slate-400"
                      )}
                    />
                    {!collapsed && (
                      <span className="flex-1 truncate">{item.label}</span>
                    )}
                    {!collapsed && hasChildren && (
                      <ChevronDown
                        className={cn(
                          "h-3.5 w-3.5 shrink-0 transition-transform",
                          expanded && "rotate-180",
                          active ? "text-teal-100" : "text-slate-400"
                        )}
                      />
                    )}
                  </Link>
                </div>

                {/* Sub-items */}
                {!collapsed && hasChildren && expanded && (
                  <div className="mt-0.5 ml-4 space-y-0.5 border-l border-slate-200 pl-3">
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
                            "flex items-center gap-2 rounded-md px-2.5 py-1.5 text-[13px] transition-all",
                            childActive
                              ? "bg-teal-50 font-medium text-teal-700"
                              : "text-slate-500 hover:bg-slate-50 hover:text-slate-700"
                          )}
                        >
                          <child.icon
                            className={cn(
                              "h-3.5 w-3.5",
                              childActive ? "text-teal-500" : "text-slate-400"
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
      </nav>

      {/* Logout */}
      <div className="border-t border-slate-200 p-2">
        <button
          onClick={handleLogout}
          className={cn(
            "flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-[13.5px] text-slate-500 transition-colors hover:bg-red-50 hover:text-red-600",
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
