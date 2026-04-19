"use client";

import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Shield, Eye, Wrench } from "lucide-react";
import { cn } from "@/lib/utils";

export type ProtectionMode = "protect" | "observe" | "maintenance";

interface ProtectionModeDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  currentMode: ProtectionMode;
  onConfirm: (mode: ProtectionMode) => void;
  loading?: boolean;
}

const modes = [
  {
    key: "protect" as const,
    label: "防护模式",
    description: "发现攻击后将自动拦截，并记录攻击事件",
    icon: Shield,
    borderColor: "border-teal-500",
    bgColor: "bg-teal-500/10",
    textColor: "text-teal-600 dark:text-teal-400",
    ringColor: "ring-teal-500",
  },
  {
    key: "observe" as const,
    label: "观察模式",
    description: "发现攻击后仅记录攻击事件，不拦截",
    icon: Eye,
    borderColor: "border-amber-500",
    bgColor: "bg-amber-500/10",
    textColor: "text-amber-600 dark:text-amber-400",
    ringColor: "ring-amber-500",
  },
  {
    key: "maintenance" as const,
    label: "维护模式",
    description: "展示维护页面，任何人都将无法访问您的应用",
    icon: Wrench,
    borderColor: "border-rose-500",
    bgColor: "bg-rose-500/10",
    textColor: "text-rose-600 dark:text-rose-400",
    ringColor: "ring-rose-500",
  },
];

export function ProtectionModeDialog({
  open,
  onOpenChange,
  currentMode,
  onConfirm,
  loading,
}: ProtectionModeDialogProps) {
  const [selected, setSelected] = useState<ProtectionMode>(currentMode);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>选择防护模式</DialogTitle>
        </DialogHeader>
        <div className="grid gap-3 py-4">
          {modes.map((mode) => (
            <button
              key={mode.key}
              onClick={() => setSelected(mode.key)}
              className={cn(
                "flex items-start gap-4 rounded-lg border-2 p-4 text-left transition-all hover:shadow-md",
                selected === mode.key
                  ? `${mode.borderColor} ${mode.bgColor} ring-2 ${mode.ringColor} ring-offset-2`
                  : "border-border hover:border-muted-foreground/30"
              )}
            >
              <div
                className={cn(
                  "flex h-10 w-10 shrink-0 items-center justify-center rounded-lg",
                  mode.bgColor
                )}
              >
                <mode.icon className={cn("h-5 w-5", mode.textColor)} />
              </div>
              <div>
                <div className={cn("font-semibold", mode.textColor)}>
                  {mode.label}
                </div>
                <div className="mt-1 text-sm text-muted-foreground">
                  {mode.description}
                </div>
              </div>
            </button>
          ))}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button
            onClick={() => onConfirm(selected)}
            disabled={loading}
            className="bg-teal-600 hover:bg-teal-700 text-white"
          >
            确认
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function getProtectionMode(site: {
  maintenance_enabled?: boolean;
  attack_protection_level?: string;
}): ProtectionMode {
  if (site.maintenance_enabled) return "maintenance";
  if (site.attack_protection_level === "observe") return "observe";
  return "protect";
}

export function protectionModeLabel(mode: ProtectionMode): string {
  return modes.find((m) => m.key === mode)?.label ?? "防护模式";
}
