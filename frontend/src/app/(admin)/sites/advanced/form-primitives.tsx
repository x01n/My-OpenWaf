"use client";

/**
 * 站点高级配置面板的专用表单原语。
 *
 * 与系统设置面板解耦，只保留本站点模块需要的字段行、三态选择与卡片分区。
 * 三态语义与后端 store.Site 的 *bool / *string 覆盖字段保持一致：
 * 继承全局（null） / 覆盖启用 / 覆盖关闭。
 */

import type { ReactNode } from "react";
import { Input, TextArea } from "@heroui/react";
import { SimpleSelect } from "@/components/ui/primitives";
import { useI18n } from "@/i18n";

/** 卡片分区容器 */
export function Section({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: ReactNode;
}) {
  return (
    <div className="bg-surface flex flex-col gap-3 rounded-xl border border-separator p-4">
      <div>
        <h3 className="text-sm font-semibold">{title}</h3>
        {description && <p className="text-muted mt-0.5 text-xs">{description}</p>}
      </div>
      {children}
    </div>
  );
}

/** 字段行：标签 + 控件 + 说明 */
export function FieldRow({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-muted text-xs">{label}</span>
      {children}
      {hint && <span className="text-muted text-xs opacity-80">{hint}</span>}
    </div>
  );
}

/** 文本输入行 */
export function TextRow({
  label,
  value,
  onChange,
  placeholder,
  hint,
  type = "text",
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  hint?: string;
  type?: "text" | "number";
}) {
  return (
    <FieldRow label={label} hint={hint}>
      <Input
        aria-label={label}
        type={type}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </FieldRow>
  );
}

/** 多行文本输入行 */
export function TextAreaRow({
  label,
  value,
  onChange,
  placeholder,
  hint,
  rows = 4,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  hint?: string;
  rows?: number;
}) {
  return (
    <FieldRow label={label} hint={hint}>
      <TextArea
        aria-label={label}
        rows={rows}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </FieldRow>
  );
}

/** 三态布尔选择：继承全局 / 覆盖启用 / 覆盖关闭 */
export function TriStateBool({
  label,
  value,
  onChange,
  hint,
}: {
  label: string;
  value: boolean | null;
  onChange: (v: boolean | null) => void;
  hint?: string;
}) {
  const { t } = useI18n();
  const key: "inherit" | "on" | "off" = value === null ? "inherit" : value ? "on" : "off";
  return (
    <FieldRow label={label} hint={hint}>
      <SimpleSelect<"inherit" | "on" | "off">
        value={key}
        onChange={(v) => onChange(v === "inherit" ? null : v === "on")}
        label={label}
        className="w-44"
        options={[
          { key: "inherit", label: t("siteDetail.advanced.inherit") },
          { key: "on", label: t("siteDetail.advanced.overrideOn") },
          { key: "off", label: t("siteDetail.advanced.overrideOff") },
        ]}
      />
    </FieldRow>
  );
}

/** 三态字符串选择：空串表示继承全局 */
export function TriStateText({
  label,
  value,
  onChange,
  options,
  hint,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { key: string; label: string }[];
  hint?: string;
}) {
  const { t } = useI18n();
  return (
    <FieldRow label={label} hint={hint}>
      <SimpleSelect<string>
        value={value}
        onChange={onChange}
        label={label}
        className="w-44"
        options={[{ key: "", label: t("siteDetail.advanced.inherit") }, ...options]}
      />
    </FieldRow>
  );
}
