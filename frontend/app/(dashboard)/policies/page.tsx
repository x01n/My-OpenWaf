"use client";

import { CrudPage } from "@/components/crud-page";

export default function PoliciesPage() {
  return (
    <CrudPage
      title="策略"
      description="策略对象用于分组组织规则，并通过站点上的 policy_id 字段挂接到数据面运行时。"
      apiPath="/api/v1/policies"
      fields={[{ key: "name", label: "名称", placeholder: "例如：核心应用默认策略" }]}
    />
  );
}
