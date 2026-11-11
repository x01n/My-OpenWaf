"use client";

/**
 * 系统设置面板的共享表单套件：
 * - useConfigForm：GET 加载配置 → 本地副本编辑 → POST 保存并回写规范化结果
 * - PanelCard / Field / WarningBanner / PanelSkeleton / PanelError：布局原语
 */

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Chip,  } from "@heroui/react";
import { TriangleAlert } from "lucide-react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n, type MessageKey } from "@/i18n";
import { CardSkeleton, ErrorState, ToggleSwitch} from "@/components/ui/primitives";
import { showSuccess, showError } from "@/components/ui/toast-host";

/**
 * 配置表单 Hook：路径即「GET / POST」同端点的配置接口。
 * 保存成功后用后端返回的规范化配置覆盖本地副本，避免前后端值漂移。
 */
export function useConfigForm<T extends object>(path: string) {
  const { t } = useI18n();
  const [form, setForm] = useState<T | null>(null);
  const [saving, setSaving] = useState(false);
  const { data, loading, error, reload } = useApi<T>(
    useCallback(() => apiGet<T>(path), [path]),
  );

  useEffect(() => {
    if (data) setForm(structuredClone(data));
  }, [data]);

  const save = useCallback(
    async (payload?: unknown) => {
      if (payload === undefined && form === null) return;
      setSaving(true);
      try {
        const result = await apiPost<T>(path, payload ?? form);
        if (result && typeof result === "object") {
          setForm(structuredClone(result));
        }
        showSuccess(t("settings.panel.saved"));
      } catch (err) {
        showError(t("settings.panel.saveFailed"), err instanceof ApiError ? err.message : undefined);
      } finally {
        setSaving(false);
      }
    },
    [form, path, t],
  );

  return { form, setForm, loading, error, reload, saving, save };
}

/** 设置面板卡片容器 */
export function PanelCard({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: ReactNode;
}) {
  return (
    <div className="bg-surface flex flex-col gap-4 rounded-xl border border-separator p-4">
      <div>
        <h2 className="text-sm font-semibold">{title}</h2>
        {description && <p className="text-muted mt-0.5 text-xs">{description}</p>}
      </div>
      {children}
    </div>
  );
}

/** 字段容器：标签 + 控件 + 说明 */
export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-muted text-xs">{label}</span>
      {children}
      {hint && <span className="text-muted text-xs opacity-80">{hint}</span>}
    </div>
  );
}

/** 布尔开关行：开关 + 标签 + 可选说明 */
export function ToggleRow({
  label,
  description,
  checked,
  onChange,
}: {
  label: string;
  description?: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-start justify-between gap-3 rounded-lg border border-separator p-3">
      <span className="flex flex-col gap-0.5">
        <span className="text-sm">{label}</span>
        {description && <span className="text-muted text-xs">{description}</span>}
      </span>
      <ToggleSwitch isSelected={checked} onChange={onChange} aria-label={label} />
    </div>
  );
}

/** WarningBanner：黄色提示条（需重启、高危操作等） */
export function WarningBanner({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-start gap-2 rounded-lg bg-warning-soft p-3 text-sm text-warning">
      <TriangleAlert className="mt-0.5 size-4 shrink-0" />
      <div>{children}</div>
    </div>
  );
}

/** 面板错误态 */
export function PanelError({ message, onRetry }: { message: string; onRetry: () => void }) {
  return <ErrorState message={message} onRetry={onRetry} />;
}

/** 面板加载态 */
export function PanelSkeleton() {
  return <CardSkeleton height="h-56" />;
}

/** unknown 值的安全展示文本（null/undefined → "-"，对象 → JSON） */
export function valueText(value: unknown): string {
  if (value === null || value === undefined) return "-";
  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return "[object]";
    }
  }
  const text = String(value);
  return text === "" ? "-" : text;
}

/** 覆盖来源值 → 语言键映射 */
const SOURCE_LABELS: Record<string, MessageKey> = {
  env: "settings.panel.sourceEnv",
  db: "settings.panel.sourceDb",
};

/** 运行时覆盖项三态来源的展示 Chip */
export function SourceChip({ source }: { source: string }) {
  const { t } = useI18n();
  const tone: "accent" | "warning" | "default" =
    source === "env" ? "accent" : source === "db" ? "warning" : "default";
  return <Chip size="sm" variant="soft" color={tone}>{t(SOURCE_LABELS[source] ?? "settings.panel.sourceDefault")}</Chip>;
}
