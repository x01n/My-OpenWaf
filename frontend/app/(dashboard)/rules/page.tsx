"use client";
import { CrudPage } from "@/components/crud-page";
import { RulePatternBuilder } from "@/components/rule-pattern-builder";

export default function RulesPage() {
  return (
    <CrudPage
      title="规则"
      description="管理安全规则（ACL、签名、自定义匹配等）。可通过可视化编辑器构建规则或直接输入 DSL。"
      apiPath="/api/v1/rules"
      fields={[
        { key: "name", label: "名称", placeholder: "封禁恶意 IP 段" },
        {
          key: "policy_id",
          label: "所属策略",
          type: "async-select",
          asyncOptions: {
            apiPath: "/api/v1/policies",
            labelKey: (item) => `${item.name}`,
          },
          description: "规则所属的安全策略",
        },
        {
          key: "phase",
          label: "阶段",
          type: "select",
          options: [
            { value: "acl", label: "ACL（IP 层）" },
            { value: "signature", label: "签名匹配" },
            { value: "custom", label: "自定义" },
          ],
          defaultValue: "acl",
          description: "规则在请求处理管线的哪个阶段执行",
        },
        {
          key: "pattern",
          label: "匹配模式",
          customInput: ({ value, onChange }) => (
            <RulePatternBuilder
              value={String(value ?? "")}
              onChange={(v) => onChange(v)}
            />
          ),
          render: (value) => {
            const s = String(value ?? "");
            // Show kind:arg in a friendly format
            const colonIdx = s.indexOf(":");
            if (colonIdx > 0 && !s.startsWith("{")) {
              return (
                <span className="font-mono text-xs">
                  <span className="text-blue-600 dark:text-blue-400">{s.slice(0, colonIdx)}</span>
                  :{s.slice(colonIdx + 1)}
                </span>
              );
            }
            return <span className="font-mono text-xs">{s.length > 50 ? s.slice(0, 50) + "…" : s}</span>;
          },
        },
        {
          key: "action",
          label: "动作",
          type: "select",
          defaultValue: "block",
          options: [
            { value: "block", label: "阻断" },
            { value: "allow", label: "放行" },
            { value: "log", label: "仅记录" },
          ],
        },
        { key: "priority", label: "优先级", type: "number", defaultValue: 100, description: "数字越小优先级越高" },
        { key: "enabled", label: "启用", type: "boolean", defaultValue: true },
      ]}
    />
  );
}
