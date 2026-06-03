"use client"

import { ChevronRight, Menu, User } from "lucide-react"
import { usePathname, useRouter } from "next/navigation"
import { logout } from "@/lib/api"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { getNavMeta } from "@/lib/console"

export function Topbar({
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
    <header className="sticky top-0 z-30 flex h-14 shrink-0 items-center justify-between border-b border-border bg-card px-4 sm:px-5">
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
            <DropdownMenuItem
              onClick={handleLogout}
              className="cursor-pointer text-red-600 focus:bg-red-50 focus:text-red-700"
            >
              退出登录
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}
