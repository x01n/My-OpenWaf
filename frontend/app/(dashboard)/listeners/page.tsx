"use client";
import { CrudPage } from "@/components/crud-page";

export default function ListenersPage() {
  return (
    <CrudPage
      title="监听器"
      description="管理数据面与管理面的网络监听地址。"
      apiPath="/api/v1/listeners"
      fields={[
        { key: "role", label: "角色", type: "select", defaultValue: "data", options: [{ value: "data", label: "数据面" }, { value: "admin", label: "管理面" }] },
        { key: "bind", label: "绑定地址" },
        { key: "network", label: "网络协议", defaultValue: "tcp" },
        { key: "enabled", label: "启用", type: "boolean", defaultValue: true },
        { key: "tls_enabled", label: "TLS", type: "boolean", defaultValue: false },
        { key: "cert_id", label: "证书 ID", type: "number", nullable: true, hideInTable: true },
        { key: "min_tls_version", label: "最低 TLS 版本", defaultValue: "TLS12", hideInTable: true },
        { key: "max_tls_version", label: "最高 TLS 版本", defaultValue: "TLS13", hideInTable: true },
        { key: "alpn", label: "ALPN", defaultValue: "h2,http/1.1", hideInTable: true },
      ]}
    />
  );
}
