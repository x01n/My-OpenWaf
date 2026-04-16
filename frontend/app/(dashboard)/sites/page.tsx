"use client";
import { CrudPage } from "@/components/crud-page";

export default function SitesPage() {
  return (
    <CrudPage
      title="站点"
      description="每个站点绑定 Host 到上游服务，并可配置策略、证书、维护模式等。"
      apiPath="/api/v1/sites"
      fields={[
        { key: "host", label: "Host", placeholder: "example.com" },
        {
          key: "listener_id",
          label: "监听器",
          type: "async-select",
          asyncOptions: {
            apiPath: "/api/v1/listeners",
            labelKey: (item) => `${item.name || "监听器"} (${item.bind})`,
          },
        },
        { key: "upstream_urls", label: "上游地址（逗号分隔）", placeholder: "http://127.0.0.1:8080" },
        {
          key: "policy_id",
          label: "安全策略",
          type: "async-select",
          nullable: true,
          asyncOptions: {
            apiPath: "/api/v1/policies",
            labelKey: (item) => `${item.name}`,
          },
          description: "不选择则不应用额外策略规则",
        },
        {
          key: "cert_id",
          label: "TLS 证书",
          type: "async-select",
          nullable: true,
          asyncOptions: {
            apiPath: "/api/v1/certificates",
            labelKey: (item) => `${item.name || item.domain || "证书 #" + item.id}`,
          },
          description: "绑定站点级 TLS 证书（优先级高于监听器证书）",
        },
        {
          key: "forwarding_profile_id",
          label: "转发配置",
          type: "async-select",
          nullable: true,
          asyncOptions: {
            apiPath: "/api/v1/forwarding-profiles",
            labelKey: (item) => `${item.name}`,
          },
          hideInTable: true,
        },
        { key: "inherit_listener_cert", label: "继承监听器证书", type: "boolean", defaultValue: false, description: "使用监听器级 TLS 证书" },
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
