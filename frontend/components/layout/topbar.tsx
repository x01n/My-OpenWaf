"use client"

import { Activity, AlertCircle, ChevronRight, Menu, User, Wifi } from "@/lib/icons"
import { usePathname, useRouter } from "next/navigation"
import { getAdminHealth, logout } from "@/lib/api"
import { useAdminRealtime } from "@/lib/admin-realtime"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Separator } from "@/components/ui/separator"
import { getNavMeta } from "@/lib/console"
import { deferEffect } from "@/lib/effects"
import { useEffect, useState } from "react"

type ApiHealthState = "checking" | "ok" | "error"

export function Topbar({
  onMobileMenuToggle,
}: {
  onMobileMenuToggle?: () => void
}) {
  const pathname = usePathname()
  const router = useRouter()
  const meta = getNavMeta(pathname)
  const realtime = useAdminRealtime()
  const [apiHealth, setApiHealth] = useState<ApiHealthState>("checking")

  useEffect(() => {
    let active = true

    async function checkHealth() {
      try {
        const data = await getAdminHealth()
        if (active) {
          setApiHealth(data.status === "ok" ? "ok" : "error")
        }
      } catch {
        if (active) {
          setApiHealth("error")
        }
      }
    }

    const cleanup = deferEffect(checkHealth)
    const timer = window.setInterval(checkHealth, 30000)

    return () => {
      active = false
      cleanup()
      window.clearInterval(timer)
    }
  }, [])

  async function handleLogout() {
    await logout()
    router.push("/login/")
  }

  return (
    <header className="sticky top-0 z-30 shrink-0 bg-card">
      <div className="flex h-14 items-center justify-between px-4 sm:px-5">
        <div className="flex min-w-0 items-center gap-3">
          {onMobileMenuToggle && (
            <Button
              variant="ghost"
              size="icon"
              className="shrink-0 rounded-md text-muted-foreground hover:bg-accent hover:text-accent-foreground lg:hidden"
              onClick={onMobileMenuToggle}
            >
              <Menu data-icon="inline" />
            </Button>
          )}
          <nav className="flex items-center gap-1.5 text-[13px] text-muted-foreground">
            <span>My-OpenWAF</span>
            <ChevronRight className="size-3 text-muted-foreground/55" />
            <span>{meta.group}</span>
            <ChevronRight className="size-3 text-muted-foreground/55" />
            <span className="font-medium text-foreground">{meta.label}</span>
          </nav>
        </div>

        <div className="flex items-center gap-2">
          <Badge
            variant={
              apiHealth === "ok"
                ? "default"
                : apiHealth === "error"
                  ? "destructive"
                  : "secondary"
            }
            className="hidden rounded-md sm:inline-flex"
          >
            {apiHealth === "error" ? (
              <AlertCircle data-icon="inline-start" />
            ) : (
              <Activity data-icon="inline-start" />
            )}
            {apiHealth === "ok"
              ? "API 正常"
              : apiHealth === "error"
                ? "API 异常"
                : "API 检查中"}
          </Badge>
          <Badge
            variant={realtime.status === "open" ? "default" : "secondary"}
            className="hidden rounded-md sm:inline-flex"
          >
            <Wifi data-icon="inline-start" />
            {realtime.status === "open" ? "实时" : "兜底"}
          </Badge>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="size-8 rounded-md text-muted-foreground hover:bg-accent hover:text-accent-foreground"
              >
                <User data-icon="inline" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              align="end"
              className="w-48 rounded-lg border-border bg-popover shadow-lg"
            >
              <DropdownMenuLabel className="text-popover-foreground">
                管理员账户
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuGroup>
                <DropdownMenuItem
                  variant="destructive"
                  onClick={handleLogout}
                  className="cursor-pointer"
                >
                  退出登录
                </DropdownMenuItem>
              </DropdownMenuGroup>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
      <Separator />
    </header>
  )
}
