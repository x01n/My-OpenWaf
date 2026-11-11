"use client";

import type { ReactNode } from "react";

/**
 * 页面头部：标题 + 说明 + 右侧操作区。
 *
 * 统一分隔线与入场动效，避免各页面自行拼装导致间距不一致。
 */
export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="enter mb-5 flex flex-wrap items-end justify-between gap-x-4 gap-y-3 border-b border-separator/60 pb-3.5">
      <div className="min-w-0">
        <h1 className="text-[1.3125rem] leading-tight font-semibold tracking-tight">{title}</h1>
        {description && <p className="text-muted mt-1.5 max-w-2xl text-sm">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
