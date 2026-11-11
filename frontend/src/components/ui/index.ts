/**
 * UI 组件统一出口（barrel）。
 *
 * 模块化约定：每个组件单文件、单一职责，页面一律从 `@/components/ui` 引入，
 * 不直接依赖具体文件名，便于后续替换实现而不触碰调用方。
 */

export { PageHeader } from "./page-header";
export { StatusChip } from "./status-chip";
export type { StatusTone } from "./types";
export { StatCard } from "./stat-card";
export { Panel } from "./panel";
export { TableSkeleton, CardSkeleton } from "./skeleton";
export { EmptyState, ErrorState } from "./empty-state";
export { Toolbar, SearchInput, SimpleSelect } from "./toolbar";
export { Pager } from "./pager";
export { ToggleSwitch } from "./toggle-switch";
export { DataTable } from "./data-table";
export type { DataTableColumn } from "./data-table";

/* HeroUI 按钮透传：调用方无需直接依赖 @heroui/react */
export { Button } from "@heroui/react";
