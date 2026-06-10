"use client"

import { useState } from "react"
import { Eye, Shield, Wrench } from "@/lib/icons"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Separator } from "@/components/ui/separator"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { cn } from "@/lib/utils"

export type ProtectionMode = "protect" | "observe" | "maintenance"
export type ProtectionModeDisplay = ProtectionMode | "custom"

interface ProtectionModeDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  currentMode: ProtectionModeDisplay
  onConfirm: (mode: ProtectionMode) => void
  loading?: boolean
}

const modes = [
  {
    key: "protect" as const,
    label: "防护模式",
    description: "命中攻击时直接拦截，并写入安全事件。",
    icon: Shield,
    classes: "border-primary/30 bg-primary/10 text-foreground",
    iconBox: "bg-primary/10 text-primary",
  },
  {
    key: "observe" as const,
    label: "观察模式",
    description: "仅记录攻击事件，不中断访问链路。",
    icon: Eye,
    classes: "border-chart-3/30 bg-chart-3/10 text-foreground",
    iconBox: "bg-chart-3/15 text-foreground",
  },
  {
    key: "maintenance" as const,
    label: "维护模式",
    description: "直接返回维护页面，不再继续访问上游。",
    icon: Wrench,
    classes: "border-destructive/30 bg-destructive/10 text-destructive",
    iconBox: "bg-destructive/10 text-destructive",
  },
]

export function ProtectionModeDialog({
  open,
  onOpenChange,
  currentMode,
  onConfirm,
  loading,
}: ProtectionModeDialogProps) {
  const [selected, setSelected] = useState<ProtectionMode>(
    selectableProtectionMode(currentMode)
  )

  return (
    <Dialog
      key={`${open}-${currentMode}`}
      open={open}
      onOpenChange={onOpenChange}
    >
      <DialogContent className="max-w-2xl rounded-lg p-0">
        <DialogHeader className="bg-card px-6 py-5 text-left">
          <DialogTitle className="text-xl font-semibold tracking-tight text-foreground">
            选择防护模式
          </DialogTitle>
          <DialogDescription className="mt-1 text-sm leading-6 text-muted-foreground">
            该设置用于切换站点的即时处理策略，确认后会走真实更新接口并触发运行时生效。快捷模式会写入站点级 OWASP、CVE、频率限制和 Bot 覆盖值；如需恢复继承全局，请进入站点详情的高级配置切回“继承全局”。
          </DialogDescription>
        </DialogHeader>
        <Separator />

        <ToggleGroup
          type="single"
          value={selected}
          onValueChange={(value) => {
            if (value) setSelected(value as ProtectionMode)
          }}
          className="grid w-full gap-4 px-6 py-6 md:grid-cols-3"
        >
          {modes.map((mode) => {
            const Icon = mode.icon
            const active = selected === mode.key
            return (
              <ToggleGroupItem
                key={mode.key}
                value={mode.key}
                className={cn(
                  "h-auto min-w-0 items-start justify-start rounded-lg border p-5 text-left hover:bg-background hover:text-foreground data-[state=on]:shadow-sm",
                  active
                    ? mode.classes
                    : "border-border bg-muted/35 text-muted-foreground"
                )}
              >
                <div className="flex w-full flex-col">
                  <div
                    className={cn(
                      "flex size-11 items-center justify-center rounded-lg [&_svg]:size-5",
                      active
                        ? mode.iconBox
                        : "bg-background text-muted-foreground"
                    )}
                  >
                    <Icon aria-hidden="true" />
                  </div>
                  <div className="mt-4 flex flex-col gap-2">
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-sm font-semibold">{mode.label}</div>
                      <Badge
                        variant={active ? "secondary" : "outline"}
                        className="shrink-0"
                      >
                        {active ? "当前选择" : "可切换"}
                      </Badge>
                    </div>
                    <p
                      className={
                        active
                          ? "text-xs leading-6 text-current/85"
                          : "text-xs leading-6 text-muted-foreground"
                      }
                    >
                      {mode.description}
                    </p>
                  </div>
                </div>
              </ToggleGroupItem>
            )
          })}
        </ToggleGroup>

        <Separator />
        <DialogFooter className="bg-card px-6 py-4">
          <Button
            variant="outline"
            className="rounded-md"
            onClick={() => onOpenChange(false)}
          >
            取消
          </Button>
          <Button
            onClick={() => onConfirm(selected)}
            disabled={loading}
            className="rounded-md"
          >
            {loading ? "保存中..." : "确认切换"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export function getProtectionMode(site: {
  maintenance_enabled?: boolean
  bot_protection_enabled?: boolean | null
  owasp_enabled?: boolean | null
  owasp_action?: string
  cve_enabled?: boolean | null
  cve_action?: string
  rate_limit_enabled?: boolean | null
  rate_limit_action?: string
}): ProtectionModeDisplay {
  if (site.maintenance_enabled) return "maintenance"
  if (
    site.bot_protection_enabled === false &&
    site.owasp_enabled === true &&
    site.owasp_action === "observe" &&
    site.cve_enabled === true &&
    site.cve_action === "observe" &&
    site.rate_limit_enabled === true &&
    site.rate_limit_action === "observe"
  ) {
    return "observe"
  }
  if (
    site.bot_protection_enabled === true &&
    site.owasp_enabled === true &&
    site.owasp_action === "intercept" &&
    site.cve_enabled === true &&
    site.cve_action === "intercept" &&
    site.rate_limit_enabled === true &&
    site.rate_limit_action === "rate_limit"
  ) {
    return "protect"
  }
  return "custom"
}

export function protectionModeLabel(mode: ProtectionModeDisplay): string {
  if (mode === "custom") return "自定义配置"
  return modes.find((item) => item.key === mode)?.label ?? "防护模式"
}

export function selectableProtectionMode(
  mode: ProtectionModeDisplay
): ProtectionMode {
  if (mode === "custom") return "protect"
  return mode
}
