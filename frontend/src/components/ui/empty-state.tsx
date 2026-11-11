"use client";

import { Button } from "@heroui/react";
import { RefreshCw, Inbox, CircleAlert } from "lucide-react";
import { useI18n } from "@/i18n";

/** 空态：图标 + 文案，文案缺省取当前语言包。 */
export function EmptyState({ message }: { message?: string }) {
  const { t } = useI18n();
  return (
    <div className="text-muted flex flex-col items-center justify-center gap-2 py-12">
      <Inbox className="size-8 opacity-50" />
      <span className="text-sm">{message ?? t("common.empty")}</span>
    </div>
  );
}

/** 错误态：错误信息 + 可选重试按钮。 */
export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  const { t } = useI18n();
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-12">
      <CircleAlert className="text-danger size-8" />
      <span className="text-danger text-sm">{message}</span>
      {onRetry && (
        <Button size="sm" variant="ghost" onPress={onRetry}>
          <RefreshCw className="size-3.5" /> {t("common.retry")}
        </Button>
      )}
    </div>
  );
}
