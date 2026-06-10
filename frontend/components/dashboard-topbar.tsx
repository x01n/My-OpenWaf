"use client"

import { Bell, ChevronRight, Menu, RefreshCcw, User } from "@/lib/icons"
import { usePathname, useRouter } from "next/navigation"
import { logout } from "@/lib/api"
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

export function DashboardTopbar({
  onMobileMenuToggle,
}: {
  onMobileMenuToggle?: () => void
}) {
  const pathname = usePathname()
  const router = useRouter()
  const meta = getNavMeta(pathname)

  async function handleLogout() {
    await logout()
    router.push("/login/")
  }

  return (
    <header className="sticky top-0 z-30 bg-background">
      <div className="mx-auto flex w-full max-w-[1600px] items-center justify-between gap-4 px-4 py-4 sm:px-5 md:px-7">
        <div className="flex min-w-0 items-center gap-3">
          {onMobileMenuToggle && (
            <Button
              variant="ghost"
              size="icon-sm"
              className="shrink-0 rounded-md lg:hidden"
              aria-label="打开移动端导航"
              onClick={onMobileMenuToggle}
            >
              <Menu data-icon="inline-start" />
            </Button>
          )}
          <div className="flex min-w-0 flex-col gap-2">
            <div className="flex items-center gap-2 text-xs font-medium tracking-[0.18em] text-muted-foreground uppercase">
              <span>控制台</span>
              <ChevronRight className="size-3.5" />
              <span>{meta.group}</span>
            </div>
            <div>
              <h2 className="truncate text-xl font-semibold tracking-tight text-foreground">
                {meta.label}
              </h2>
              <p className="mt-1 hidden truncate text-sm text-muted-foreground sm:block">
                {meta.description}
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="hidden rounded-md md:inline-flex"
            onClick={() => window.location.reload()}
          >
            <RefreshCcw data-icon="inline-start" />
            刷新数据
          </Button>
          <Button
            variant="ghost"
            size="icon-sm"
            className="rounded-md"
            aria-label="查看通知"
          >
            <Bell data-icon="inline-start" />
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon-sm"
                className="rounded-md"
                aria-label="打开账户菜单"
              >
                <User data-icon="inline-start" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56 rounded-md">
              <DropdownMenuLabel>管理员账户</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuGroup>
                <DropdownMenuItem onClick={handleLogout} variant="destructive">
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
