"use client";

import type { ReactNode } from "react";

/**
 * 带标题栏的玻璃面板：把同一语义分组的数据卡收拢为一个视觉单元。
 *
 * 尺寸与强调由内部内容决定，避免页面散落大量裸卡片。
 */
export function Panel({
  title,
  icon,
  actions,
  children,
  className,
}: {
  title: string;
  icon?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className ?? ""}`}>
      <header className="panel__head">
        <h2 className="panel__title">
          {icon}
          {title}
        </h2>
        {actions}
      </header>
      <div className="panel__body">{children}</div>
    </section>
  );
}
