"use client";

import { CrudPage } from "@/components/crud-page";

export default function CertificatesPage() {
  return (
    <CrudPage
      title="证书"
      description="维护站点接入 HTTPS 所需的 PEM 证书与私钥。当前后端证书模型仅包含名称、cert_pem 与 key_pem。"
      apiPath="/api/v1/certificates"
      fields={[
        { key: "name", label: "名称", placeholder: "例如：example.com" },
        { key: "cert_pem", label: "证书 PEM", type: "textarea", hideInTable: true, placeholder: "-----BEGIN CERTIFICATE-----" },
        { key: "key_pem", label: "私钥 PEM", type: "textarea", hideInTable: true, placeholder: "-----BEGIN PRIVATE KEY-----" },
      ]}
    />
  );
}
