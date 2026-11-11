"use client";

import { Button, Chip } from "@heroui/react";
import { X } from "lucide-react";
import { useI18n } from "@/i18n";

/**
 * 单个已激活筛选条件的展示描述。
 *
 * `value` 是已经本地化后的可读文本，组件不再做任何翻译，
 * 因此调用方可自由组合枚举标签、状态分组名或后端返回的原文。
 */
export type ActiveFilter = {
  /** 稳定的筛选键，用于清除回调定位 */
  key: string;
  /** 条件名（已本地化），如「方法」「主机」 */
  label: string;
  /** 条件值（已本地化），如「GET」「test.local」 */
  value: string;
};

/**
 * 已激活筛选条件条。
 *
 * Cloudflare 式表格顶部信息条：筛选生效后必须在表格上方可见并可一键移除，
 * 否则被过滤的表格与未过滤的表格外观完全一致，用户会误读数据范围。
 * 无激活条件时不渲染任何节点，避免占用空白行。
 */
export function ActiveFilterBar({
  filters,
  onClear,
  onClearAll,
}: {
  filters: ActiveFilter[];
  onClear: (key: string) => void;
  onClearAll: () => void;
}) {
  const { t } = useI18n();
  if (filters.length === 0) return null;

  return (
    <div className="mb-3 flex flex-wrap items-center gap-1.5">
      <span className="text-muted text-xs">{t("common.activeFilters")}</span>
      {filters.map((filter) => (
        <Chip key={filter.key} size="sm" variant="soft" color="accent">
          <span className="whitespace-nowrap">
            {filter.label}: {filter.value}
          </span>
          <button
            type="button"
            aria-label={t("common.removeFilter", { name: filter.label })}
            className="text-muted hover:text-foreground ml-1 cursor-pointer"
            onClick={() => onClear(filter.key)}
          >
            <X className="size-3" />
          </button>
        </Chip>
      ))}
      <Button size="sm" variant="ghost" onPress={onClearAll}>
        {t("common.clearFilters")}
      </Button>
    </div>
  );
}