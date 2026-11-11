"use client";

import { Table } from "@heroui/react";
import type { CSSProperties, ReactNode } from "react";
import { EmptyState, TableSkeleton } from "@/components/ui/primitives";
import { useI18n } from "@/i18n";

export type DataTableColumn<T> = {
  /** 列标题 */
  header: string;
  /** 单元格渲染；不传则显示空 */
  render?: (row: T) => ReactNode;
  /** 列级附加类名：同时作用于表头与单元格（列宽、对齐、换行策略） */
  className?: string;
};

/**
 * 通用数据表格：玻璃卡片容器 + 粘性表头 + 行 hover 强调条 + 统一加载骨架与空态。
 * HeroUI v3 的 Table 为外层容器，真正的表格集合必须是 Table.Content。
 *
 * React Aria 的 Table 会缓存已构建的 collection；语言切换时行数据引用未变，
 * 单元格内的渲染函数不会重新执行，导致表头更新而单元格保留旧语言。这里用
 * `key={locale}` 强制重建表格集合，保证切换语言后整表立即刷新。
 */
export function DataTable<T extends { id: string | number }>({
  columns,
  rows,
  loading,
  emptyMessage,
  ariaLabel,
}: {
  columns: DataTableColumn<T>[];
  rows: T[] | undefined;
  loading?: boolean;
  emptyMessage?: string;
  ariaLabel: string;
}) {
  const { locale, t } = useI18n();

  if (loading && !rows) {
    return <TableSkeleton rows={5} />;
  }
  return (
    <div
      className="table-shell owaf-table enter"
      style={{ "--enter-index": 1 } as CSSProperties}
    >
      <Table>
        <Table.ScrollContainer className="max-h-[calc(100vh-16rem)]">
          <Table.Content key={locale} aria-label={ariaLabel}>
            <Table.Header>
              {columns.map((col, i) => (
                <Table.Column key={i} id={`col-${i}`} className={col.className} isRowHeader={i === 0}>
                  {col.header}
                </Table.Column>
              ))}
            </Table.Header>
            <Table.Body
              items={rows ?? []}
              renderEmptyState={() => <EmptyState message={emptyMessage ?? t("common.empty")} />}
            >
              {(row) => (
                <Table.Row id={row.id}>
                  {columns.map((col, i) => (
                    <Table.Cell key={i} className={col.className}>
                      {col.render ? col.render(row) : ""}
                    </Table.Cell>
                  ))}
                </Table.Row>
              )}
            </Table.Body>
          </Table.Content>
        </Table.ScrollContainer>
      </Table>
    </div>
  );
}
