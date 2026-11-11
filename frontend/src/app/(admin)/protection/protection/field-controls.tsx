"use client";

/**
 * 防护设置各 Tab 共用的表单控件（DRY）。
 * 仅组合 HeroUI 原语与 Tailwind 工具类，不引入第二套样式体系。
 */

import { TextField, Input, TextArea } from "@heroui/react";
import type { ReactNode } from "react";
import { SimpleSelect, ToggleSwitch} from "@/components/ui/primitives";

/** 分组卡片：语义化中文标题 + 紧凑字段网格 */
export function SectionCard({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: ReactNode;
}) {
  return (
    <div className="bg-surface rounded-xl border border-separator p-4">
      <div className="mb-3">
        <h3 className="text-sm font-medium">{title}</h3>
        {description && (
          <p className="text-muted mt-0.5 text-xs [overflow-wrap:anywhere]">{description}</p>
        )}
      </div>
      <div className="flex flex-col gap-3">{children}</div>
    </div>
  );
}

/** 布尔开关行 */
export function SwitchRow({
  label,
  value,
  onChange,
  hint,
}: {
  label: string;
  value: boolean;
  onChange: (v: boolean) => void;
  hint?: string;
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div>
        <div className="text-sm">{label}</div>
        {hint && <div className="text-muted text-xs">{hint}</div>}
      </div>
      <ToggleSwitch isSelected={value} onChange={onChange} aria-label={label} />
    </div>
  );
}

/** 数字输入行（Input type=number） */
export function NumberField({
  label,
  value,
  onChange,
  hint,
  min,
  placeholder,
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
  hint?: string;
  min?: number;
  placeholder?: string;
}) {
  return (
    <TextField aria-label={label} className="flex flex-col gap-1">
      <div className="text-muted text-xs">{label}</div>
      <Input
        type="number"
        min={min}
        placeholder={placeholder}
        value={Number.isFinite(value) ? String(value) : ""}
        onChange={(e) => {
          const n = Number(e.target.value);
          onChange(Number.isFinite(n) ? n : 0);
        }}
      />
      {hint && <div className="text-muted text-xs">{hint}</div>}
    </TextField>
  );
}

/** 文本输入行 */
export function TextFieldRow({
  label,
  value,
  onChange,
  placeholder,
  hint,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  hint?: string;
}) {
  return (
    <TextField aria-label={label} className="flex flex-col gap-1">
      <div className="text-muted text-xs">{label}</div>
      <Input
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      {hint && <div className="text-muted text-xs">{hint}</div>}
    </TextField>
  );
}

/** 下拉选择行 */
export function SelectRow<T extends string>({
  label,
  value,
  onChange,
  options,
  hint,
}: {
  label: string;
  value: T;
  onChange: (v: T) => void;
  options: { key: T; label: string }[];
  hint?: string;
}) {
  return (
    <div className="flex flex-col gap-1">
      <div className="text-muted text-xs">{label}</div>
      <SimpleSelect<T> value={value} onChange={onChange} options={options} label={label} className="w-full" />
      {hint && <div className="text-muted text-xs">{hint}</div>}
    </div>
  );
}

/** JSON 文本编辑区（blob 字段专用，保存前由调用方 JSON.parse 校验） */
export function JsonTextArea({
  label,
  value,
  onChange,
  hint,
  minHeight = "min-h-[120px]",
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  hint?: string;
  minHeight?: string;
}) {
  return (
    <div className="flex flex-col gap-1">
      <div className="text-muted text-xs">{label}</div>
      <TextArea
        aria-label={label}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={`${minHeight} font-mono text-xs`}
      />
      {hint && <div className="text-muted text-xs">{hint}</div>}
    </div>
  );
}

/**
 * 枚举选项已迁至 `protection-model.ts`，此处再导出以保持既有导入路径稳定。
 * 新代码请直接从 model 导入，避免表单控件模块承担数据职责。
 */
export {
  SENSITIVITY_LEVELS,
  GENERIC_ACTIONS,
  CHALLENGE_ACTIONS,
  AUTO_BAN_ACTIONS,
  BROWSER_SIGN_ACTIONS,
  CAPTCHA_TYPES,
  CHAIN_STEP_TYPES,
  CHAIN_CONDITIONS,
  ANTI_REPLAY_MODES,
  JS_PROTECTION_MODES,
  ESCALATION_ACTIONS,
  HIGH_RISK_OPTIONS,
  SCORE_PARTS,
  DROP_SOURCE_KEYS,
  PAGE_TEMPLATE_META,
  PAGE_TEMPLATE_COMMON_FIELDS,
  PAGE_TEMPLATE_TYPE_FIELDS,
} from "./protection-model";
export type { PageTemplateFieldSpec } from "./protection-model";
