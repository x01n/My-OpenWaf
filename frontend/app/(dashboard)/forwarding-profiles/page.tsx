"use client";
import { CrudPage } from "@/components/crud-page";

export default function ForwardingProfilesPage() {
  return (
    <CrudPage
      title="转发配置"
      description="配置 XFF 处理、Host 复写等转发策略，绑定到站点后生效。"
      apiPath="/api/v1/forwarding-profiles"
      fields={[
        { key: "name", label: "名称" },
        { key: "xff_mode", label: "XFF 模式", type: "select", options: [
          { value: "strip_all_and_set_remote", label: "剥离并设为远端 IP" },
          { value: "trust_outer_waf_cidr_then_take_leftmost", label: "信任外层 WAF 后取最左" },
        ]},
        { key: "trusted_cidr", label: "可信 CIDR", type: "textarea", hideInTable: true },
        { key: "outbound_host_rewrite", label: "出站 Host 重写", hideInTable: true },
        { key: "preserve_original_host", label: "保留原始 Host", type: "boolean", hideInTable: true },
      ]}
    />
  );
}
