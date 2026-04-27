"use client";

import { useEffect, useState } from "react";
import { Eye, Shield, Wrench } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
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
    description: "命中攻击时直接拦截，并写入安全事件。",
    icon: Shield,
    classes: "border-cyan-300 bg-cyan-50 text-cyan-900",
    iconBox: "bg-cyan-100 text-cyan-700",
  },
  {
    key: "observe" as const,
    label: "观察模式",
    description: "仅记录攻击事件，不中断访问链路。",
    icon: Eye,
    classes: "border-amber-300 bg-amber-50 text-amber-900",
    iconBox: "bg-amber-100 text-amber-700",
  },
  {
    key: "maintenance" as const,
    label: "维护模式",
    description: "直接返回维护页面，不再继续访问上游。",
    icon: Wrench,
    classes: "border-rose-300 bg-rose-50 text-rose-900",
    iconBox: "bg-rose-100 text-rose-700",
  },
];

export function ProtectionModeDialog({ open, onOpenChange, currentMode, onConfirm, loading }: ProtectionModeDialogProps) {
  const [selected, setSelected] = useState<ProtectionMode>(currentMode);

  useEffect(() => {
    setSelected(currentMode);
  }, [currentMode, open]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl rounded-[28px] p-0">
        <DialogHeader className="border-b border-white/10 bg-[linear-gradient(135deg,rgba(10,19,34,0.96),rgba(11,27,48,0.9)_55%,rgba(10,69,88,0.5))] px-6 py-6 text-left text-white">
          <DialogTitle className="text-2xl font-semibold tracking-tight">选择防护模式</DialogTitle>
          <DialogDescription className="mt-2 text-sm leading-6 text-slate-300/90">该设置用于切换站点的即时处理策略，确认后会走真实更新接口并触发运行时生效。</DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 px-6 py-6 md:grid-cols-3">
          {modes.map((mode) => {
            const Icon = mode.icon;
            const active = selected === mode.key;
            return (
              <button
                key={mode.key}
                type="button"
                onClick={() => setSelected(mode.key)}
                className={cn(
                  "rounded-[24px] border p-5 text-left transition-all",
                  active ? `${mode.classes} shadow-[0_18px_40px_rgba(15,23,42,0.08)]` : "border-slate-200 bg-slate-50 text-slate-700 hover:border-slate-300 hover:bg-white"
                )}
              >
                <div className={cn("flex h-11 w-11 items-center justify-center rounded-2xl", active ? mode.iconBox : "bg-white text-slate-500")}>
                  <Icon className="h-5 w-5" />
                </div>
                <div className="mt-4 space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-sm font-semibold">{mode.label}</div>
                    <span className={active ? "console-badge border-white/40 bg-white/70 text-slate-900" : "console-badge bg-slate-100 text-slate-500 border-slate-200"}>
                      {active ? "当前选择" : "可切换"}
                    </span>
                  </div>
                  <p className={active ? "text-xs leading-6 text-current/85" : "text-xs leading-6 text-slate-500"}>{mode.description}</p>
                </div>
              </button>
            );
          })}
        </div>

        <DialogFooter className="border-t border-slate-200 bg-white px-6 py-4">
          <Button variant="outline" className="rounded-xl" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button onClick={() => onConfirm(selected)} disabled={loading} className="rounded-xl bg-slate-950 text-white hover:bg-slate-800">
            {loading ? "保存中..." : "确认切换"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function getProtectionMode(site: { maintenance_enabled?: boolean; attack_protection_level?: string }): ProtectionMode {
  if (site.maintenance_enabled) return "maintenance";
  if (site.attack_protection_level === "observe") return "observe";
  return "protect";
}

export function protectionModeLabel(mode: ProtectionMode): string {
  return modes.find((item) => item.key === mode)?.label ?? "防护模式";
}
