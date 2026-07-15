"use client";

import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { ReactNode } from "react";

interface StatCardProps {
  title: string;
  value: string | number;
  description?: string;
  icon?: ReactNode;
  trend?: "up" | "down" | "neutral";
  className?: string;
  /** 紧凑模式：减少内边距，缩小文字 */
  compact?: boolean;
}

export function StatCard({ title, value, description, icon, trend, className, compact }: StatCardProps) {
  if (compact) {
    return (
      <Card className={cn("relative overflow-hidden", className)}>
        <CardContent className="px-3 py-2.5">
          <div className="flex items-start justify-between">
            <span className="text-xs font-medium text-muted-foreground leading-none">
              {title}
            </span>
            {icon && (
              <div className="text-muted-foreground/60 shrink-0">{icon}</div>
            )}
          </div>
          <div className="mt-1.5 text-xl font-bold tracking-tight leading-none">
            {value}
          </div>
          {description && (
            <p className={cn(
              "text-[11px] mt-1 leading-none",
              trend === "up" && "text-emerald-600",
              trend === "down" && "text-red-600",
              !trend && "text-muted-foreground"
            )}>
              {description}
            </p>
          )}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={cn("", className)}>
      <CardContent className="px-4 py-3">
        <div className="flex items-center justify-between space-y-0 pb-1.5">
          <span className="text-sm font-medium text-muted-foreground">
            {title}
          </span>
          {icon && <div className="text-muted-foreground">{icon}</div>}
        </div>
        <div className="text-2xl font-bold tracking-tight">{value}</div>
        {description && (
          <p className={cn(
            "text-xs mt-1",
            trend === "up" && "text-emerald-600",
            trend === "down" && "text-red-600",
            trend === "neutral" && "text-muted-foreground"
          )}>
            {description}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
