"use client";
import { CrudPage } from "@/components/crud-page";

export default function CertificatesPage() {
  return (
    <CrudPage
      title="证书"
      description="管理 TLS 证书（PEM 格式）。"
      apiPath="/api/v1/certificates"
      fields={[
        { key: "name", label: "名称" },
        { key: "cert_pem", label: "证书 PEM", type: "textarea", hideInTable: true },
        { key: "key_pem", label: "私钥 PEM", type: "textarea", hideInTable: true },
      ]}
    />
  );
}
