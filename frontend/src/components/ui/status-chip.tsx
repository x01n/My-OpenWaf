"use client";

import { Chip } from "@heroui/react";
import type { ReactNode } from "react";
import type { StatusTone } from "./types";

const TONE_CHIP: Record<
  StatusTone,
  { color: "success" | "warning" | "danger" | "accent" | "default" }
> = {
  success: { color: "success" },
  warning: { color: "warning" },
  danger: { color: "danger" },
  info: { color: "accent" },
  neutral: { color: "default" },
};

/**
 * 状态徽标：语义色 + 状态点。
 *
 * 成功态启用脉冲动画（`status-dot[data-live]`），表达「实时在线」。
 */
export function StatusChip({ tone, children }: { tone: StatusTone; children: ReactNode }) {
  const live = tone === "success";
  return (
    <Chip size="sm" variant="soft" color={TONE_CHIP[tone].color}>
      <span className="status-dot" data-live={live || undefined} aria-hidden="true" />
      {children}
    </Chip>
  );
}
