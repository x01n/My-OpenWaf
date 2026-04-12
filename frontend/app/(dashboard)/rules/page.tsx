"use client";
import { CrudPage } from "@/components/crud-page";

export default function RulesPage() {
  return (
    <CrudPage
      title="规则"
      description="安全规则按策略分组，支持 ACL、签名、自定义阶段。动作可选拦截（阻断）或观察（仅日志）。DSL 示例：block_ip:1.2.3.0/24、block_path_regex:(?i)/admin、block_query_contains:union+select"
      apiPath="/api/v1/rules"
      fields={[
        { key: "policy_id", label: "策略 ID", type: "number" },
        { key: "phase", label: "阶段", type: "select", defaultValue: "acl", options: [
          { value: "acl", label: "ACL" },
          { value: "rate_limit", label: "请求限流" },
          { value: "owasp_default", label: "内置 OWASP" },
          { value: "signature", label: "签名" },
          { value: "custom", label: "自定义" },
        ]},
        { key: "pattern", label: "匹配模式 (DSL)" },
        { key: "action", label: "动作", type: "select", defaultValue: "intercept", options: [
          { value: "intercept", label: "拦截" },
          { value: "observe", label: "观察" },
          { value: "allow", label: "放行" },
        ]},
        { key: "priority", label: "优先级", type: "number" },
        { key: "enabled", label: "启用", type: "boolean", defaultValue: true },
      ]}
    />
  );
}
