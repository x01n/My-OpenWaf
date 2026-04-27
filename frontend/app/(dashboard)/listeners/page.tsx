"use client";

import { PlanningNotice, PageIntro } from "@/components/console-shell";

export default function ListenersPage() {
  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Architecture"
        title="监听器"
        description="当前后端并未提供独立的 listeners CRUD API。监听地址、TLS 和热更新能力已并入 Site 模型与运行时协调逻辑。"
      />
      <PlanningNotice
        title="监听器已并入站点模型"
        description="在当前系统架构中，bind、network、tls_enabled、cert_id、ALPN 等字段都由 /api/v1/sites 管理，运行时通过 reconcileListeners 完成热更新。"
        href="/sites/"
      />
    </div>
  );
}
