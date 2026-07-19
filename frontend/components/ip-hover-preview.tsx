"use client";

import * as React from "react";
import { useTranslation } from "react-i18next";
import { format } from "date-fns";
import useSWR from "swr";

import { cn } from "@/lib/utils";
import { securityEventApi } from "@/lib/api";
import type { SecurityEvent } from "@/lib/types";
import {
  HoverCard,
  HoverCardContent,
  HoverCardTrigger,
} from "@/components/ui/hover-card";
import { Badge } from "@/components/ui/badge";
import { IconClock, IconRoute, IconWorld } from "@tabler/icons-react";

/**
 * 悬停时展示该 IP 最近 5 次安全事件的预览卡片。
 * 通过 SWR 懒加载，仅在 open 时首次拉取。
 */
export function IpHoverPreview({
  ip,
  className,
  children,
}: {
  ip: string;
  className?: string;
  children?: React.ReactNode;
}) {
  const { t } = useTranslation();
  const [enabled, setEnabled] = React.useState(false);

  const { data, isLoading } = useSWR(
    enabled && ip ? ["ip-hover-preview", ip] : null,
    async () => {
      const res = (await securityEventApi.list({
        client_ip: ip,
        page: 1,
        page_size: 5,
      })) as { items: SecurityEvent[]; total: number };
      return res;
    },
    { revalidateOnFocus: false },
  );

  return (
    <HoverCard
      openDelay={200}
      closeDelay={100}
      onOpenChange={(o) => {
        if (o) setEnabled(true);
      }}
    >
      <HoverCardTrigger asChild>
        <span
          className={cn(
            "cursor-help font-mono decoration-dotted underline-offset-2 hover:underline",
            className,
          )}
        >
          {children ?? ip}
        </span>
      </HoverCardTrigger>
      <HoverCardContent align="start" className="w-96 p-3">
        <div className="mb-2 flex items-center justify-between">
          <span className="font-mono text-sm font-semibold">{ip}</span>
          <span className="text-[10px] text-muted-foreground">
            {t("securityEvents.ipHover.recentTitle")}
          </span>
        </div>
        {isLoading ? (
          <p className="py-3 text-center text-xs text-muted-foreground">
            {t("common.loading")}
          </p>
        ) : !data || data.items.length === 0 ? (
          <p className="py-3 text-center text-xs text-muted-foreground">
            {t("securityEvents.ipHover.noEvent")}
          </p>
        ) : (
          <>
            <div className="mb-2 flex items-center gap-2 text-xs text-muted-foreground">
              <Badge variant="secondary" className="h-4 px-1.5 text-[10px]">
                {t("securityEvents.ipHover.totalCount", {
                  count: data.total,
                })}
              </Badge>
            </div>
            <ul className="space-y-1.5">
              {data.items.map((ev) => (
                <li
                  key={ev.id}
                  className="rounded-md border bg-muted/30 px-2 py-1.5 text-[11px]"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="inline-flex items-center gap-1 text-muted-foreground">
                      <IconClock className="h-3 w-3" />
                      {formatShortTime(ev.created_at)}
                    </span>
                    <Badge
                      variant={
                        ev.action === "intercept" ||
                        ev.action === "block" ||
                        ev.action === "drop"
                          ? "destructive"
                          : ev.action === "observe" || ev.action === "log_only"
                            ? "secondary"
                            : "outline"
                      }
                      className="h-4 px-1 text-[9px]"
                    >
                      {ev.action}
                    </Badge>
                  </div>
                  <div className="mt-1 flex items-center gap-1 truncate text-foreground/80">
                    <span className="rounded bg-muted px-1 font-mono text-[10px]">
                      {ev.method}
                    </span>
                    <span className="truncate font-mono" title={ev.path}>
                      {ev.path}
                    </span>
                  </div>
                  <div className="mt-0.5 flex items-center gap-2 truncate text-muted-foreground">
                    <span className="inline-flex items-center gap-0.5">
                      <IconWorld className="h-3 w-3" />
                      <span className="truncate">{ev.host || "-"}</span>
                    </span>
                    {ev.rule_id_str ? (
                      <span className="inline-flex items-center gap-0.5">
                        <IconRoute className="h-3 w-3" />
                        <span className="truncate">{ev.rule_id_str}</span>
                      </span>
                    ) : null}
                  </div>
                </li>
              ))}
            </ul>
          </>
        )}
      </HoverCardContent>
    </HoverCard>
  );
}

function formatShortTime(iso: string): string {
  try {
    return format(new Date(iso), "MM-dd HH:mm:ss");
  } catch {
    return iso;
  }
}
