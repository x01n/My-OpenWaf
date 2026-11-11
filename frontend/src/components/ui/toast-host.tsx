"use client";

/**
 * 全局 Toast 宿主与快捷方法。
 *
 * 对齐 HeroUI v3.2 Toast 官方 API：
 * - 触发：`toast` / `toast.success` / `toast.danger`（内部绑定默认 `toastQueue`）
 * - 渲染：无 children 的 `<ToastProvider />`，走组件内置默认 anatomy
 *
 * 重要：React Aria 的 `UNSTABLE_ToastRegion` 在 `useIsSSR()===true` 时
 * 不会 `createPortal` 到 document.body（条件：`visibleToasts.length>0 && !isSSR`）。
 * 静态导出 + 管理台鉴权后才挂载时，若 Provider 落在 SSR/hydration 快照上，
 * 队列有数据也不会出现 DOM。因此 Provider 仅在客户端 effect 之后挂载。
 */

import { useEffect, useState } from "react";
import { ToastProvider, toast } from "@heroui/react";

export type ToastTone = "accent" | "success" | "warning" | "danger";

export type AppToastContent = {
  title: string;
  description?: string;
  variant?: ToastTone;
};

/**
 * 通用 Toast 入队。
 *
 * @param content - 标题、可选描述与色调
 */
export function showToast(content: AppToastContent) {
  const timeout = content.variant === "danger" ? 6000 : 4000;
  const opts = {
    description: content.description,
    timeout,
    variant: content.variant ?? "accent",
  } as const;

  switch (content.variant) {
    case "success":
      toast.success(content.title, opts);
      return;
    case "danger":
      toast.danger(content.title, opts);
      return;
    case "warning":
      toast.warning(content.title, opts);
      return;
    case "accent":
      toast.info(content.title, opts);
      return;
    default:
      toast(content.title, opts);
  }
}

/**
 * 操作成功提示。
 *
 * @param title - 主文案
 * @param description - 可选补充说明
 */
export function showSuccess(title: string, description?: string) {
  showToast({ title, description, variant: "success" });
}

/**
 * 操作失败提示。
 *
 * @param title - 主文案
 * @param description - 可选错误详情（如 ApiError.message）
 */
export function showError(title: string, description?: string) {
  showToast({ title, description, variant: "danger" });
}

/**
 * 挂在管理台外壳 / 登录页根部的 Toast 区域。
 * placement 取 top end，避免遮挡底部操作条。
 * 仅客户端挂载，确保 React Aria ToastRegion 能 portal 到 body。
 */
export function ToastHost() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    setMounted(true);
  }, []);
  if (!mounted) return null;
  return <ToastProvider placement="top end" />;
}
