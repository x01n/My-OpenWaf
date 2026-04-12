"use client";
import { CrudPage } from "@/components/crud-page";

export default function SitesPage() {
  return (
    <CrudPage
      title="站点"
      description="每个站点绑定 Host 到上游服务，并可配置策略、证书、维护模式等。"
      apiPath="/api/v1/sites"
      fields={[
        { key: "host", label: "Host" },
        { key: "listener_id", label: "监听器 ID", type: "number" },
        { key: "upstream_urls", label: "上游地址（逗号分隔）" },
        { key: "policy_id", label: "策略 ID", type: "number", nullable: true, hideInTable: true },
        { key: "cert_id", label: "证书 ID", type: "number", nullable: true, hideInTable: true },
        { key: "forwarding_profile_id", label: "转发配置 ID", type: "number", nullable: true, hideInTable: true },
        { key: "inherit_listener_cert", label: "继承监听器证书", type: "boolean", defaultValue: false, hideInTable: true },
        { key: "max_body_bytes", label: "最大请求体（字节）", type: "number", defaultValue: 10485760, hideInTable: true },
        { key: "upstream_tls_skip_verify", label: "忽略上游 TLS 校验", type: "boolean", defaultValue: false, hideInTable: true },
        { key: "upstream_tls_server_name", label: "上游 TLS Server Name", hideInTable: true },
        { key: "maintenance_enabled", label: "维护模式", type: "boolean", defaultValue: false, hideInTable: true },
        { key: "maintenance_html", label: "维护页 HTML", type: "textarea", hideInTable: true },
        { key: "maintenance_status", label: "维护状态码", type: "number", defaultValue: 503, hideInTable: true },
        { key: "block_html", label: "阻断页 HTML", type: "textarea", hideInTable: true },
        { key: "block_status", label: "阻断状态码", type: "number", defaultValue: 403, hideInTable: true },
      ]}
    />
  );
}
