"use client";

import { Button, ButtonGroup } from "@heroui/react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { useI18n } from "@/i18n";

/** 轻量分页：页码窗口固定 5 个，文案接语言包。 */
export function Pager({
  page,
  pageSize,
  total,
  onPageChange,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (p: number) => void;
}) {
  const { t } = useI18n();
  /** 英文单数用独立键，避免出现 "1 items" */
  const totalText = t(total === 1 ? "common.totalOne" : "common.total", { count: total });
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (pages <= 1) return <div className="text-muted mt-3 text-xs">{totalText}</div>;

  const windowStart = Math.max(1, Math.min(page - 2, pages - 4));
  const windowEnd = Math.min(pages, windowStart + 4);
  const pageNumbers: number[] = [];
  for (let p = windowStart; p <= windowEnd; p++) pageNumbers.push(p);

  return (
    <div className="mt-3 flex items-center justify-between">
      <span className="text-muted text-xs">
        {totalText} · {t("common.page", { page, pages })}
      </span>
      <ButtonGroup size="sm">
        <Button
          variant="ghost"
          isDisabled={page <= 1}
          onPress={() => onPageChange(page - 1)}
          aria-label={t("common.prev")}
        >
          <ChevronLeft className="size-4" />
        </Button>
        {pageNumbers.map((p) => (
          <Button
            key={p}
            variant={p === page ? "primary" : "ghost"}
            onPress={() => onPageChange(p)}
          >
            {p}
          </Button>
        ))}
        <Button
          variant="ghost"
          isDisabled={page >= pages}
          onPress={() => onPageChange(page + 1)}
          aria-label={t("common.next")}
        >
          <ChevronRight className="size-4" />
        </Button>
      </ButtonGroup>
    </div>
  );
}
