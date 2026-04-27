"use client";

import { PlanningNotice, PageIntro } from "@/components/console-shell";

export default function ForwardingProfilesPage() {
  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Architecture"
        title="转发配置"
        description="当前后端没有独立的 forwarding-profiles 资源接口。XFF、可信 CIDR、Host 保留和上游 TLS 控制均已并入站点模型。"
      />
      <PlanningNotice
        title="转发策略已并入站点配置"
        description="请前往防护应用详情页管理 xff_mode、trusted_cidr、preserve_original_host、upstream_tls_skip_verify 与 upstream_urls。"
        href="/sites/"
      />
    </div>
  );
}
