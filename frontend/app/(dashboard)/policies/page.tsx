"use client";
import { CrudPage } from "@/components/crud-page";

export default function PoliciesPage() {
  return (
    <CrudPage
      title="策略"
      description="策略用于分组管理安全规则，绑定到站点后生效。"
      apiPath="/api/v1/policies"
      fields={[
        { key: "name", label: "名称" },
      ]}
    />
  );
}
