"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

/**
 * @typedef {object} PageHeaderProps
 * @property {React.ReactNode} title 页面主标题（通常来自 i18n title key）
 * @property {React.ReactNode} [description] 标题下方的辅助描述文案
 * @property {React.ReactNode} [icon] 标题左侧图标（由调用方控制尺寸，如 h-6 w-6）
 * @property {React.ReactNode} [titleExtra] 标题右侧的行内元素（如统计 Badge）
 * @property {React.ReactNode} [actions] 页头右侧操作区（按钮、筛选等）
 * @property {string} [className] 外层容器附加 className
 */
export interface PageHeaderProps {
  title: React.ReactNode
  description?: React.ReactNode
  icon?: React.ReactNode
  titleExtra?: React.ReactNode
  actions?: React.ReactNode
  className?: string
}

/**
 * 统一页头组件：标题 + 描述 + 右侧操作区。
 * 样式完全走主题 CSS 变量（foreground / muted-foreground），随亮暗与蓝青主题联动。
 * @param {PageHeaderProps} props 组件属性
 * @returns {React.ReactElement} 页头元素
 */
export function PageHeader({
  title,
  description,
  icon,
  titleExtra,
  actions,
  className,
}: PageHeaderProps) {
  return (
    <div
      className={cn(
        "flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between",
        className
      )}
    >
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          {icon}
          <h1 className="text-2xl font-bold tracking-tight">{title}</h1>
          {titleExtra}
        </div>
        {description ? (
          <p className="mt-1 text-sm text-muted-foreground">{description}</p>
        ) : null}
      </div>
      {actions ? (
        <div className="flex flex-wrap items-center gap-2">{actions}</div>
      ) : null}
    </div>
  )
}
