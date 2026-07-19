"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

/**
 * @typedef {object} EmptyStateProps
 * @property {React.ComponentType<{className?: string}>} [icon] 图标组件（可选，来自 @tabler/icons-react）
 * @property {React.ReactNode} title 主标题
 * @property {React.ReactNode} [description] 辅助描述
 * @property {React.ReactNode} [action] 主操作按钮（会以 primary 呈现）
 * @property {React.ReactNode} [secondaryAction] 次要操作按钮
 * @property {string} [className] 外层容器 className
 */
export interface EmptyStateProps {
  icon?: React.ComponentType<{ className?: string }>;
  title: React.ReactNode;
  description?: React.ReactNode;
  action?: React.ReactNode;
  secondaryAction?: React.ReactNode;
  className?: string;
}

/**
 * 通用空状态组件：统一的"暂无数据"呈现方式。
 * 用于列表页/卡片区在无数据时的占位，替代散落各处的 <p>暂无数据</p> 文本。
 */
export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  secondaryAction,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center rounded-xl border border-dashed py-16 px-6 text-center",
        className,
      )}
    >
      {Icon ? (
        <div className="mb-5 flex h-20 w-20 items-center justify-center rounded-full bg-primary/8 ring-1 ring-primary/10">
          <Icon className="h-10 w-10 text-primary/50" />
        </div>
      ) : null}
      <h3 className="mb-1.5 text-base font-semibold text-foreground">{title}</h3>
      {description ? (
        <p className="mb-5 max-w-sm text-sm leading-relaxed text-muted-foreground">
          {description}
        </p>
      ) : (
        <div className="mb-3" />
      )}
      {(action || secondaryAction) && (
        <div className="flex flex-wrap items-center justify-center gap-2.5">
          {action}
          {secondaryAction}
        </div>
      )}
    </div>
  );
}
