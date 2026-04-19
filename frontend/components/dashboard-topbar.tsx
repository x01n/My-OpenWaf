"use client";

import { usePathname } from "next/navigation";
import { ChevronRight, User } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { logout } from "@/lib/api";
import { useRouter } from "next/navigation";

const routeMeta = [
  { prefix: "/dashboard/", title: "仪表盘", description: "查看流量、错误、拦截与配置修订概览。", breadcrumb: "仪表盘" },
  { prefix: "/sites/", title: "防护应用", description: "管理您的 Web 应用防护配置与上游服务。", breadcrumb: "防护应用" },
  { prefix: "/certificates/", title: "证书", description: "维护站点与监听器使用的 TLS 证书。", breadcrumb: "证书管理" },
  { prefix: "/security-events/", title: "安全事件", description: "查看 WAF 拦截与观察日志，按 IP、类型与时间筛选。", breadcrumb: "安全事件" },
  { prefix: "/ip-lists/", title: "IP 黑白名单", description: "按 IP 或 CIDR 管理黑名单与白名单条目。", breadcrumb: "IP 黑白名单" },
  { prefix: "/policies/", title: "策略", description: "按策略分组组织规则并绑定到站点。", breadcrumb: "策略管理" },
  { prefix: "/rules/", title: "规则", description: "管理拦截、观察与放行规则，覆盖多个评估阶段。", breadcrumb: "规则管理" },
  { prefix: "/protection/", title: "防护设置", description: "统一配置限流、内置 OWASP 与全局维护模式。", breadcrumb: "防护设置" },
  { prefix: "/settings/", title: "系统设置", description: "查看与维护系统级键值配置。", breadcrumb: "系统设置" },
  { prefix: "/api-keys/", title: "API 密钥", description: "管理自动化访问使用的长期 Bearer Token。", breadcrumb: "API 密钥" },
];

const defaultMeta = {
  title: "控制台",
  description: "统一管理多站点 WAF 的接入、防护与系统配置。",
  breadcrumb: "控制台",
};

export function DashboardTopbar() {
  const pathname = usePathname();
  const router = useRouter();
  const meta = routeMeta.find((item) => pathname?.startsWith(item.prefix)) ?? defaultMeta;

  async function handleLogout() {
    await logout();
    router.push("/login/");
  }

  return (
    <header className="border-b border-gray-200 bg-white">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-6 py-2.5">
        <div className="flex items-center gap-3 min-w-0 flex-1">
          <div className="flex items-center gap-2 text-sm">
            <span className="text-gray-400 cursor-pointer hover:text-gray-600 transition-colors">控制台</span>
            <ChevronRight className="h-4 w-4 text-gray-400" />
            <span className="text-gray-700 font-medium truncate">{meta.breadcrumb}</span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-9 w-9 rounded-full">
                <User className="h-4 w-4 text-gray-500" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <DropdownMenuLabel>管理员账户</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={handleLogout} className="text-destructive cursor-pointer">
                退出登录
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  );
}
