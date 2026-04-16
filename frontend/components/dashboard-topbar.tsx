"use client";

import { usePathname } from "next/navigation";

import { Badge } from "@/components/ui/badge";

const routeMeta = [
  { prefix: "/dashboard/", title: "仪表盘", description: "查看流量、错误、拦截与配置修订概览。" },
  { prefix: "/listeners/", title: "监听器", description: "管理数据面与管理面的监听地址、TLS 与协议栈。" },
  { prefix: "/sites/", title: "站点", description: "按 Host 绑定上游、证书、维护页与阻断页。" },
  { prefix: "/certificates/", title: "证书", description: "维护站点与监听器使用的 TLS 证书。" },
  { prefix: "/forwarding-profiles/", title: "转发配置", description: "配置 XFF 信任链、Host 复写与转发策略。" },
  { prefix: "/security-events/", title: "安全事件", description: "查看 WAF 拦截与观察日志，按 IP、类型与时间筛选。" },
  { prefix: "/ip-lists/", title: "IP 黑白名单", description: "按 IP 或 CIDR 管理黑名单与白名单条目。" },
  { prefix: "/policies/", title: "策略", description: "按策略分组组织规则并绑定到站点。" },
  { prefix: "/rules/", title: "规则", description: "管理拦截、观察与放行规则，覆盖多个评估阶段。" },
  { prefix: "/protection/", title: "防护设置", description: "统一配置限流、内置 OWASP 与全局维护模式。" },
  { prefix: "/settings/", title: "系统设置", description: "查看与维护系统级键值配置。" },
  { prefix: "/api-keys/", title: "API 密钥", description: "管理自动化访问使用的长期 Bearer Token。" },
];

const defaultMeta = {
  title: "控制台",
  description: "统一管理多站点 WAF 的接入、防护与系统配置。",
};

export function DashboardTopbar() {
  const pathname = usePathname();
  const meta = routeMeta.find((item) => pathname?.startsWith(item.prefix)) ?? defaultMeta;

  return (
    <header className="border-b bg-background/95 backdrop-blur">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-6 py-4">
        <div className="space-y-1">
          <p className="text-xs font-medium tracking-[0.22em] text-muted-foreground uppercase">
            My-OpenWAF Console
          </p>
          <div>
            <h1 className="text-base font-semibold">{meta.title}</h1>
            <p className="text-sm text-muted-foreground">{meta.description}</p>
          </div>
        </div>
        <Badge variant="outline" className="font-mono text-[11px]">
          {pathname || "/"}
        </Badge>
      </div>
    </header>
  );
}
