"use client";
import { CrudPage } from "@/components/crud-page";

export default function ListenersPage() {
  return (
    <CrudPage
      title="监听器"
      description="管理数据面与管理面的网络监听地址。TLS 证书在此绑定后，所有关联站点自动启用 HTTPS。"
      apiPath="/api/v1/listeners"
      fields={[
        {
          key: "name",
          label: "名称",
          placeholder: "HTTP 主监听器",
        },
        {
          key: "role",
          label: "角色",
          type: "select",
          defaultValue: "data",
          options: [
            { value: "data", label: "数据面" },
            { value: "admin", label: "管理面" },
          ],
        },
        { key: "bind", label: "绑定地址", placeholder: "0.0.0.0:443" },
        { key: "network", label: "网络协议", defaultValue: "tcp", hideInTable: true },
        { key: "enabled", label: "启用", type: "boolean", defaultValue: true },
        { key: "tls_enabled", label: "启用 TLS", type: "boolean", defaultValue: false, description: "开启后需绑定证书" },
        {
          key: "cert_id",
          label: "TLS 证书",
          type: "async-select",
          nullable: true,
          asyncOptions: {
            apiPath: "/api/v1/certificates",
            labelKey: (item: Record<string, unknown>) =>
              `${item.name || item.domain || "证书 #" + item.id}`,
          },
          description: "监听器级默认证书（站点可单独覆盖）",
        },
        {
          key: "min_tls_version",
          label: "最低 TLS 版本",
          type: "select",
          defaultValue: "TLS12",
          options: [
            { value: "TLS10", label: "TLS 1.0" },
            { value: "TLS11", label: "TLS 1.1" },
            { value: "TLS12", label: "TLS 1.2" },
            { value: "TLS13", label: "TLS 1.3" },
          ],
          hideInTable: true,
        },
        {
          key: "max_tls_version",
          label: "最高 TLS 版本",
          type: "select",
          defaultValue: "TLS13",
          options: [
            { value: "TLS12", label: "TLS 1.2" },
            { value: "TLS13", label: "TLS 1.3" },
          ],
          hideInTable: true,
        },
        {
          key: "alpn",
          label: "ALPN 协议",
          defaultValue: "h2,http/1.1",
          hideInTable: true,
          description: "逗号分隔的 ALPN 协议列表",
        },
      ]}
    />
  );
}
