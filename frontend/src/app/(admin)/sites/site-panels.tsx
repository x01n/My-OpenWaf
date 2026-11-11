"use client";

/**
 * 站点详情抽屉功能面板的统一出口。
 *
 * 实现按子域拆分，避免单文件膨胀：
 * - 监听器：`site-panels-listeners.tsx`
 * - 访问控制：`site-panels-access.tsx`（认证提供方 / 本地用户 / 路径规则各自独立文件）
 * - 错误页：`site-panels-error-pages.tsx`
 * - 应用路由规则：`site-panels-routes.tsx`
 * - 录制资源：`site-panels-recorded.tsx`
 */

export { ListenersPanel } from "./site-panels-listeners";
export { AccessPanel } from "./site-panels-access";
export { ErrorPagesPanel } from "./site-panels-error-pages";
export { RulesPanel } from "./site-panels-routes";
export { RecordedResourcesPanel } from "./site-panels-recorded";
