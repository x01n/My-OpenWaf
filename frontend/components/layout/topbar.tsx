"use client";

import { ChevronRight, Menu, RefreshCw, User } from "lucide-react";
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

export function Topbar({
  onMobileMenuToggle,
}: {
  onMobileMenuToggle?: () => void;
}) {
  const pathname = usePathname();
  const router = useRouter();
  const meta = getNavMeta(pathname);

  async function handleLogout() {
    await logout();
    router.push("/login/");
  }

  return (
    <header className="sticky top-0 z-30 flex h-12 shrink-0 items-center justify-between border-b border-slate-200 bg-white px-4 sm:px-5">
      <div className="flex min-w-0 items-center gap-3">
        {onMobileMenuToggle && (
          <Button
            variant="ghost"
            size="icon"
            className="shrink-0 rounded-md text-slate-500 hover:bg-slate-100 hover:text-slate-900 lg:hidden"
            onClick={onMobileMenuToggle}
          >
            <Menu className="h-5 w-5" />
          </Button>
        )}
        <nav className="flex items-center gap-1.5 text-[13px] text-slate-500">
          <span className="text-slate-400">My-OpenWAF</span>
          <ChevronRight className="h-3 w-3 text-slate-300" />
          <span className="font-medium text-slate-700">{meta.label}</span>
        </nav>
      </div>

      <div className="flex items-center gap-2">
        <select className="h-8 rounded-md border border-slate-200 bg-white px-2.5 text-xs text-slate-600 outline-none focus:border-teal-400 focus:ring-1 focus:ring-teal-400/30">
          <option>全部应用</option>
        </select>
        <select className="h-8 rounded-md border border-slate-200 bg-white px-2.5 text-xs text-slate-600 outline-none focus:border-teal-400 focus:ring-1 focus:ring-teal-400/30">
          <option>近 24 小时</option>
          <option>近 7 天</option>
          <option>近 30 天</option>
        </select>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 rounded-md text-slate-500 hover:bg-slate-100 hover:text-slate-800"
            >
              <User className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            align="end"
            className="w-48 rounded-lg border-slate-200 bg-white shadow-lg"
          >
            <DropdownMenuLabel className="text-slate-700">
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
  );
}
