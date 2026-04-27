"use client";

import { CrudPage } from "@/components/crud-page";
import { RuleBuilder } from "@/components/rule-builder";

export default function RulesPage() {
  return (
    <CrudPage
      title="规则"
      description="管理 ACL、签名与自定义规则。规则将按 phase、priority 和 action 参与数据面处理链路。"
      apiPath="/api/v1/rules"
      fields={[
        { key: "name", label: "名称", placeholder: "例如：阻断恶意管理入口扫描" },
        {
          key: "policy_id",
          label: "所属策略",
          type: "async-select",
          asyncOptions: {
            apiPath: "/api/v1/policies",
            labelKey: (item) => String(item.name ?? "未命名策略"),
          },
          description: "规则所属策略对象。",
        },
        {
          key: "phase",
          label: "执行阶段",
          type: "select",
          defaultValue: "acl",
          options: [
            { value: "acl", label: "ACL" },
            { value: "signature", label: "签名匹配" },
            { value: "custom", label: "自定义" },
          ],
        },
        {
          key: "pattern",
          label: "匹配表达式",
          customInput: ({ value, onChange }) => <RuleBuilder value={String(value ?? "")} onChange={onChange} />,
          render: (value) => {
            const text = String(value ?? "");
            return <span className="font-mono text-xs">{text.length > 64 ? `${text.slice(0, 64)}…` : text}</span>;
          },
        },
        {
          key: "action",
          label: "命中动作",
          type: "select",
          defaultValue: "intercept",
          options: [
            { value: "intercept", label: "拦截" },
            { value: "observe", label: "观察" },
            { value: "allow", label: "放行" },
            { value: "drop", label: "断连" },
            { value: "redirect", label: "重定向" },
            { value: "challenge", label: "挑战" },
          ],
        },
        { key: "priority", label: "优先级", type: "number", defaultValue: 100, description: "数值越小越先执行。" },
        { key: "enabled", label: "启用", type: "boolean", defaultValue: true },
      ]}
    />
  );
}
