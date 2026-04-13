"use client";

import { CrudPage, FieldDef } from "@/components/crud-page";

const fields: FieldDef[] = [
  {
    key: "kind",
    label: "类型",
    type: "select",
    options: [
      { value: "blacklist", label: "黑名单" },
      { value: "whitelist", label: "白名单" },
    ],
  },
  { key: "value", label: "IP / CIDR", type: "text" },
  { key: "note", label: "备注", type: "text" },
  { key: "enabled", label: "启用", type: "boolean", defaultValue: true },
];

export default function IPListsPage() {
  return (
    <CrudPage
      title="IP 黑白名单"
      description="管理 IP 黑名单和白名单条目，支持单 IP 和 CIDR 格式"
      apiPath="/api/v1/ip-lists"
      fields={fields}
    />
  );
}
