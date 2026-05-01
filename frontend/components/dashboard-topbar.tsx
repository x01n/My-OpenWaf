"use client";

import { Bell, ChevronRight, Menu, RefreshCcw, User } from "lucide-react";
import { usePathname, useRouter } from "next/navigation";
import { logout } from "@/lib/api";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { getNavMeta } from "@/lib/console";

export function DashboardTopbar({ onMobileMenuToggle }: { onMobileMenuToggle?: () => void }) {
  const pathname = usePathname();
  const router = useRouter();
  const meta = getNavMeta(pathname);

  async function handleLogout() {
    await logout();
    router.push("/login/");
  }

  return (
    <header className="sticky top-0 z-30 border-b border-slate-200/70 bg-white/78 backdrop-blur-xl">
      <div className="mx-auto flex w-full max-w-[1600px] items-center justify-between gap-4 px-4 py-4 sm:px-5 md:px-7">
        <div className="flex min-w-0 items-center gap-3">
          {onMobileMenuToggle && (
            <Button
              variant="ghost"
              size="icon-sm"
              className="shrink-0 rounded-xl text-slate-500 hover:bg-slate-100 hover:text-slate-900 lg:hidden"
              onClick={onMobileMenuToggle}
            >
              <Menu className="h-5 w-5" />
            </Button>
          )}
          <div className="min-w-0 space-y-2">
            <div className="flex items-center gap-2 text-xs font-medium tracking-[0.18em] text-slate-400 uppercase">
              <span>控制台</span>
              <ChevronRight className="h-3.5 w-3.5" />
              <span>{meta.group}</span>
            </div>
            <div>
              <h2 className="truncate text-xl font-semibold tracking-tight text-slate-950">{meta.label}</h2>
              <p className="mt-1 hidden truncate text-sm text-slate-500 sm:block">{meta.description}</p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" className="hidden rounded-xl border-slate-200 text-slate-600 md:inline-flex" onClick={() => window.location.reload()}>
            <RefreshCcw className="mr-2 h-4 w-4" />
            刷新数据
          </Button>
          <Button variant="ghost" size="icon-sm" className="rounded-xl text-slate-500 hover:bg-slate-100 hover:text-slate-900">
            <Bell className="h-4 w-4" />
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon-sm" className="rounded-xl text-slate-600 hover:bg-slate-100 hover:text-slate-950">
                <User className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56 rounded-2xl border-slate-200 bg-white/96 backdrop-blur">
              <DropdownMenuLabel>管理员账户</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={handleLogout} className="text-rose-600 cursor-pointer">
                退出登录
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  );
}
