"use client";

import * as React from "react";
import { useTranslation } from "react-i18next";
import { format } from "date-fns";
import type { DateRange } from "react-day-picker";
import {
  IconCalendarStats,
  IconChevronDown,
} from "@tabler/icons-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Calendar } from "@/components/ui/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Separator } from "@/components/ui/separator";

/**
 * @typedef {object} TimeRangeValue
 * @property {string} since ISO/RFC3339 起始（可能为空字符串）
 * @property {string} until ISO/RFC3339 结束（可能为空字符串）
 */
export interface TimeRangeValue {
  since: string;
  until: string;
}

interface DateRangePickerProps {
  value: TimeRangeValue;
  onChange: (value: TimeRangeValue) => void;
  className?: string;
  align?: "start" | "center" | "end";
}

type PresetKey = "1h" | "6h" | "24h" | "7d" | "custom";

const PRESET_MS: Record<Exclude<PresetKey, "custom">, number> = {
  "1h": 60 * 60 * 1000,
  "6h": 6 * 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
};

/**
 * 尝试把外部 since/until 反推为预设 key。
 * 只有 until 未指定（表示"到现在"）且 since = now - preset 时视为预设。
 */
function detectPreset(value: TimeRangeValue): PresetKey | null {
  if (!value.since) return null;
  const now = Date.now();
  const since = new Date(value.since).getTime();
  if (isNaN(since)) return null;
  if (value.until) return null;
  const delta = now - since;
  const tolerance = 60 * 1000; // 1 分钟容差
  for (const [key, ms] of Object.entries(PRESET_MS) as [
    Exclude<PresetKey, "custom">,
    number,
  ][]) {
    if (Math.abs(delta - ms) < tolerance) return key;
  }
  return null;
}

/**
 * 时间范围选择器：整合"快捷区间 + 自定义日期"两种选择模式。
 * 内部使用 Popover + Calendar（range），并在左侧列出预设。
 */
export function DateRangePicker({
  value,
  onChange,
  className,
  align = "start",
}: DateRangePickerProps) {
  const { t } = useTranslation();
  const [open, setOpen] = React.useState(false);
  const [tempRange, setTempRange] = React.useState<DateRange | undefined>(
    () => {
      const from = value.since ? new Date(value.since) : undefined;
      const to = value.until ? new Date(value.until) : undefined;
      return from || to ? { from, to } : undefined;
    },
  );

  const preset = detectPreset(value);

  const label = React.useMemo<string>(() => {
    if (preset === "1h") return t("timeRange.last1h");
    if (preset === "6h") return t("timeRange.last6h");
    if (preset === "24h") return t("timeRange.last24h");
    if (preset === "7d") return t("timeRange.last7d");
    if (!value.since && !value.until) return t("timeRange.allTime");
    const parts: string[] = [];
    if (value.since) parts.push(format(new Date(value.since), "yyyy-MM-dd HH:mm"));
    else parts.push(t("timeRange.anyStart"));
    parts.push("~");
    if (value.until) parts.push(format(new Date(value.until), "yyyy-MM-dd HH:mm"));
    else parts.push(t("timeRange.anyEnd"));
    return parts.join(" ");
  }, [preset, value, t]);

  const applyPreset = (key: Exclude<PresetKey, "custom">) => {
    const now = new Date();
    const since = new Date(now.getTime() - PRESET_MS[key]);
    onChange({ since: since.toISOString(), until: "" });
    setTempRange({ from: since, to: now });
    setOpen(false);
  };

  const applyCustom = () => {
    onChange({
      since: tempRange?.from ? tempRange.from.toISOString() : "",
      until: tempRange?.to ? tempRange.to.toISOString() : "",
    });
    setOpen(false);
  };

  const clearAll = () => {
    onChange({ since: "", until: "" });
    setTempRange(undefined);
    setOpen(false);
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className={cn(
            "h-8 justify-start gap-1.5 text-xs font-normal",
            className,
          )}
        >
          <IconCalendarStats className="h-3.5 w-3.5" />
          <span className="truncate">{label}</span>
          <IconChevronDown className="ml-auto h-3 w-3 opacity-60" />
        </Button>
      </PopoverTrigger>
      <PopoverContent align={align} className="w-auto p-0" sideOffset={4}>
        <div className="flex flex-col sm:flex-row">
          <div className="flex flex-col gap-1 border-b p-2 sm:border-r sm:border-b-0 sm:p-3">
            <PresetButton
              active={preset === "1h"}
              onClick={() => applyPreset("1h")}
            >
              {t("timeRange.last1h")}
            </PresetButton>
            <PresetButton
              active={preset === "6h"}
              onClick={() => applyPreset("6h")}
            >
              {t("timeRange.last6h")}
            </PresetButton>
            <PresetButton
              active={preset === "24h"}
              onClick={() => applyPreset("24h")}
            >
              {t("timeRange.last24h")}
            </PresetButton>
            <PresetButton
              active={preset === "7d"}
              onClick={() => applyPreset("7d")}
            >
              {t("timeRange.last7d")}
            </PresetButton>
            <Separator className="my-1" />
            <PresetButton
              active={!value.since && !value.until}
              onClick={clearAll}
            >
              {t("timeRange.allTime")}
            </PresetButton>
          </div>
          <div className="flex flex-col">
            <Calendar
              mode="range"
              numberOfMonths={1}
              selected={tempRange}
              onSelect={setTempRange}
              defaultMonth={tempRange?.from ?? new Date()}
              className="p-2"
            />
            <div className="flex items-center justify-end gap-2 border-t p-2">
              <Button
                variant="ghost"
                size="sm"
                className="h-7 text-xs"
                onClick={() => setOpen(false)}
              >
                {t("common.cancel")}
              </Button>
              <Button
                size="sm"
                className="h-7 text-xs"
                disabled={!tempRange?.from && !tempRange?.to}
                onClick={applyCustom}
              >
                {t("timeRange.apply")}
              </Button>
            </div>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}

function PresetButton({
  children,
  active,
  onClick,
}: {
  children: React.ReactNode;
  active?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "w-full rounded-md px-3 py-1.5 text-left text-xs transition-colors hover:bg-muted",
        active && "bg-primary/10 font-medium text-primary hover:bg-primary/15",
      )}
    >
      {children}
    </button>
  );
}
