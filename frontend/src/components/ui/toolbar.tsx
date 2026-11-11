"use client";

import { Input, Select, ListBox } from "@heroui/react";
import type { ReactNode, Key } from "react";
import { useI18n } from "@/i18n";

/** 列表页工具条容器：统一间距与换行行为。 */
export function Toolbar({ children }: { children: ReactNode }) {
  return <div className="mb-3 flex flex-wrap items-center gap-2">{children}</div>;
}

/** 搜索框：占位符缺省取当前语言包。 */
export function SearchInput({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  const { t } = useI18n();
  const label = placeholder ?? t("common.search");
  return (
    <Input
      className="w-64"
      aria-label={label}
      placeholder={label}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}

/** HeroUI Select 的简化封装：单选、选项即 options。 */
export function SimpleSelect<T extends string>({
  value,
  onChange,
  options,
  label,
  className = "w-40",
}: {
  value: T;
  onChange: (v: T) => void;
  options: { key: T; label: string }[];
  label?: string;
  className?: string;
}) {
  const { t } = useI18n();
  const selected = options.find((o) => o.key === value);
  return (
    <Select
      className={className}
      aria-label={label ?? t("common.filter")}
      selectedKey={value}
      onSelectionChange={(key: Key | null) => {
        if (key !== null) onChange(key as T);
      }}
    >
      <Select.Trigger>
        <Select.Value>{selected?.label ?? value}</Select.Value>
      </Select.Trigger>
      <Select.Popover>
        <ListBox>
          {options.map((opt) => (
            <ListBox.Item key={opt.key} id={opt.key} textValue={opt.label}>
              {opt.label}
            </ListBox.Item>
          ))}
        </ListBox>
      </Select.Popover>
    </Select>
  );
}
