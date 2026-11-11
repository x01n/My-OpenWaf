"use client";

import type { ReactNode } from "react";
import type { StatusTone } from "./types";

/**
 * 指标卡：标签 + 数值 + 可选提示、图标与强调态。
 *
 * 数值使用等宽数字（`.tabular`）避免刷新时抖动；
 * `emphasis` 用于仪表盘主指标，放大字号并由 CSS 添加光晕。
 */
export function StatCard({
  label,
  value,
  hint,
  tone,
  icon,
  emphasis,
}: {
  label: string;
  value: string | number;
  hint?: string;
  tone?: StatusTone;
  /** 卡面右上角图标，仅作语义提示 */
  icon?: ReactNode;
  /** 主指标强调卡：更大字号与光晕背景 */
  emphasis?: boolean;
}) {
  const toneClass =
    tone === "danger"
      ? "text-danger"
      : tone === "warning"
        ? "text-warning"
        : tone === "success"
          ? "text-success"
          : tone === "info"
            ? "text-accent"
            : "";
  return (
    <div
      className={`stat-card ${emphasis ? "stat-card--emphasis" : ""}`}
      data-tone={tone ?? "neutral"}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="text-muted text-xs font-medium">{label}</span>
        {icon && <span className="stat-card__icon">{icon}</span>}
      </div>
      <div
        className={`tabular mt-1.5 font-semibold ${emphasis ? "text-[2rem] leading-none" : "text-2xl"} ${toneClass}`}
      >
        {value}
      </div>
      {hint && <div className="text-muted mt-1.5 text-xs">{hint}</div>}
    </div>
  );
}
