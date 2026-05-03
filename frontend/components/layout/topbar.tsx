"use client";

import { ChevronRight, Menu, User } from "lucide-react";
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
    <header className="sticky top-0 z-30 flex h-14 shrink-0 items-center justify-between border-b border-gray-200 bg-white px-4 sm:px-6">
      <div className="flex min-w-0 items-center gap-3">
        {onMobileMenuToggle && (
          <Button
            variant="ghost"
            size="icon"
            className="shrink-0 rounded-md text-gray-500 hover:bg-gray-100 hover:text-gray-900 lg:hidden"
            onClick={onMobileMenuToggle}
          >
            <Menu className="h-5 w-5" />
          </Button>
        )}
        <nav className="flex items-center gap-1.5 text-sm text-gray-500">
          <span>控制台</span>
          <ChevronRight className="h-3.5 w-3.5 text-gray-400" />
          <span className="font-medium text-gray-900">{meta.label}</span>
        </nav>
      </div>

      <div className="flex items-center gap-2">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 rounded-full bg-cyan-500 text-white hover:bg-cyan-600 hover:text-white"
            >
              <User className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            align="end"
            className="w-48 rounded-lg border-gray-200 bg-white"
          >
            <DropdownMenuLabel className="text-gray-700">
              管理员账户
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={handleLogout}
              className="cursor-pointer text-rose-600"
            >
              退出登录
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
