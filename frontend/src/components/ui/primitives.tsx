/**
 * 兼容层（deprecated）。
 *
 * 早期全站从 `@/components/ui/primitives` 引入组件；本文件仅做再导出，
 * 保证 52 个既有引用点无感迁移。新增代码请直接从 `@/components/ui` 引入，
 * 待存量引用全部迁移后可删除本文件。
 */
export {
  PageHeader,
  StatusChip,
  StatCard,
  Panel,
  TableSkeleton,
  CardSkeleton,
  EmptyState,
  ErrorState,
  Toolbar,
  SearchInput,
  SimpleSelect,
  Pager,
  ToggleSwitch,
  Button,
} from "./index";
export type { StatusTone } from "./types";
