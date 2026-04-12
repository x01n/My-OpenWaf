"use client";
import { CrudPage } from "@/components/crud-page";

export default function SettingsPage() {
  return (
    <CrudPage
      title="系统设置"
      description="键值对形式的系统配置。"
      apiPath="/api/v1/settings"
      idField="key"
      fields={[
        { key: "key", label: "键名" },
        { key: "value", label: "值", type: "textarea" },
      ]}
    />
  );
}
