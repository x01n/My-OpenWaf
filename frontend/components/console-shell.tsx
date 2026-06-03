"use client"

import { buttonVariants } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { cn } from "@/lib/utils"

export function PageIntro({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string
  title: string
  description: string
  actions?: React.ReactNode
}) {
  return (
    <div className="flex flex-col gap-4 rounded-lg border border-border bg-card px-5 py-4 shadow-sm md:flex-row md:items-end md:justify-between">
      <div className="flex flex-col gap-3">
        {eyebrow ? (
          <div className="inline-flex w-fit items-center rounded-md border border-primary/25 bg-primary/10 px-2.5 py-1 text-[11px] font-semibold tracking-[0.18em] text-primary uppercase">
            {eyebrow}
          </div>
        ) : null}
        <div className="flex flex-col gap-1.5">
          <h1 className="text-xl font-semibold tracking-tight text-foreground md:text-2xl">
            {title}
          </h1>
          <p className="max-w-3xl text-sm leading-6 text-muted-foreground">
            {description}
          </p>
        </div>
      </div>
      {actions ? (
        <div className="flex flex-wrap items-center gap-2">{actions}</div>
      ) : null}
    </div>
  )
}

export function MetricGrid({ children }: { children: React.ReactNode }) {
  return <div className="console-data-grid">{children}</div>
}

export function MetricCard({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string
  value: React.ReactNode
  hint?: React.ReactNode
  tone?: "default" | "danger" | "warning" | "success"
}) {
  const toneClass = {
    default: "text-slate-950",
    danger: "text-rose-600",
    warning: "text-amber-600",
    success: "text-emerald-600",
  }[tone]

  const accentClass = {
    default: "bg-muted",
    danger: "bg-rose-500",
    warning: "bg-amber-500",
    success: "bg-emerald-500",
  }[tone]

  return (
    <Card className="relative overflow-hidden rounded-lg border-border bg-card shadow-sm">
      <div className={cn("absolute inset-y-0 left-0 w-1", accentClass)} />
      <CardHeader className="flex flex-col gap-2 pt-4 pb-3">
        <CardDescription className="text-xs font-semibold tracking-[0.18em] text-slate-500 uppercase">
          {label}
        </CardDescription>
        <CardTitle
          className={cn("text-2xl font-semibold tracking-tight", toneClass)}
        >
          {value}
        </CardTitle>
      </CardHeader>
      {hint ? (
        <CardContent className="pt-0 text-xs leading-6 text-slate-500">
          {hint}
        </CardContent>
      ) : null}
    </Card>
  )
}

export function Surface({
  title,
  description,
  action,
  children,
  className,
}: {
  title?: string
  description?: string
  action?: React.ReactNode
  children: React.ReactNode
  className?: string
}) {
  return (
    <Card className={cn("console-panel overflow-hidden", className)}>
      {title || description || action ? (
        <CardHeader className="flex flex-col gap-3 border-b border-border bg-muted/35 px-4 py-3 md:flex-row md:items-end md:justify-between">
          <div className="flex flex-col gap-1">
            {title ? (
              <CardTitle className="text-base text-foreground">
                {title}
              </CardTitle>
            ) : null}
            {description ? (
              <CardDescription className="text-sm leading-6 text-muted-foreground">
                {description}
              </CardDescription>
            ) : null}
          </div>
          {action ? (
            <div className="flex items-center gap-2">{action}</div>
          ) : null}
        </CardHeader>
      ) : null}
      <CardContent className="p-4">{children}</CardContent>
    </Card>
  )
}

export function ConsoleTableShell({
  title,
  description,
  toolbar,
  state,
  footer,
  children,
  className,
}: {
  title?: string
  description?: string
  toolbar?: React.ReactNode
  state?: React.ReactNode
  footer?: React.ReactNode
  children?: React.ReactNode
  className?: string
}) {
  return (
    <section
      className={cn(
        "overflow-hidden rounded-lg border border-border bg-card shadow-sm",
        className
      )}
    >
      {title || description || toolbar ? (
        <div className="flex flex-col gap-3 border-b border-border bg-card px-4 py-3">
          {title || description ? (
            <div className="flex flex-col gap-1">
              {title ? (
                <h2 className="text-base font-semibold text-foreground">
                  {title}
                </h2>
              ) : null}
              {description ? (
                <p className="text-sm leading-6 text-muted-foreground">
                  {description}
                </p>
              ) : null}
            </div>
          ) : null}
          {toolbar ? (
            <div className="flex flex-col gap-3">{toolbar}</div>
          ) : null}
        </div>
      ) : null}
      <div className="bg-card">{state ?? children}</div>
      {footer ? (
        <div className="border-t border-border bg-card px-4 py-3">{footer}</div>
      ) : null}
    </section>
  )
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string
  description: string
  action?: React.ReactNode
}) {
  return (
    <div className="flex min-h-[220px] flex-col items-center justify-center rounded-lg border border-dashed border-border bg-muted/45 px-6 text-center">
      <div className="flex max-w-md flex-col items-center gap-3">
        <h3 className="text-base font-semibold text-foreground">{title}</h3>
        <p className="text-sm leading-6 text-muted-foreground">{description}</p>
        {action ? <div className="pt-2">{action}</div> : null}
      </div>
    </div>
  )
}

export function InlineMeta({
  label,
  value,
}: {
  label: string
  value: React.ReactNode
}) {
  return (
    <div className="flex flex-col gap-1 rounded-lg border border-border bg-muted/45 p-3">
      <div className="text-[11px] font-semibold tracking-[0.16em] text-slate-400 uppercase">
        {label}
      </div>
      <div className="text-sm font-medium text-slate-900">{value}</div>
    </div>
  )
}

export function Notice({
  tone = "amber",
  title,
  children,
  action,
  className,
  size = "md",
}: {
  tone?: "amber" | "sky" | "emerald" | "slate"
  title?: React.ReactNode
  children: React.ReactNode
  action?: React.ReactNode
  className?: string
  size?: "sm" | "md"
}) {
  const toneClass = {
    amber: "border-amber-200 bg-amber-50 text-amber-900",
    sky: "border-sky-200 bg-sky-50 text-sky-900",
    emerald: "border-emerald-200 bg-emerald-50 text-emerald-900",
    slate: "border-slate-200 bg-slate-50 text-slate-700",
  }[tone]

  return (
    <div
      className={cn(
        "rounded-lg border",
        size === "sm" ? "px-3 py-3 text-xs" : "px-4 py-3 text-sm",
        toneClass,
        className
      )}
    >
      <div
        className={cn(
          "flex flex-col gap-1",
          size === "sm" ? "leading-5" : "leading-6"
        )}
      >
        {title ? <div className="font-medium">{title}</div> : null}
        <div>{children}</div>
      </div>
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  )
}

export function SourceSiteNotice({
  sourceSite,
  scope,
  onBack,
  backHref,
  className,
}: {
  sourceSite: React.ReactNode
  scope: React.ReactNode
  onBack?: () => void
  backHref?: string
  className?: string
}) {
  const backAction = onBack ? (
    <button
      type="button"
      onClick={onBack}
      className="text-sm font-medium text-amber-900 underline underline-offset-4"
    >
      返回当前站点
    </button>
  ) : backHref ? (
    <a
      href={backHref}
      className="text-sm font-medium text-amber-900 underline underline-offset-4"
    >
      返回当前站点
    </a>
  ) : null

  return (
    <Notice tone="amber" className={className} action={backAction}>
      你是从站点 “{sourceSite}” 跳转过来的。当前页面配置的是{scope}
      ，修改后会影响所有站点。
    </Notice>
  )
}

export function PlanningNotice({
  title,
  description,
  href,
}: {
  title: string
  description: string
  href?: string
}) {
  return (
    <Surface title={title} description={description}>
      <div className="flex flex-col gap-4 rounded-lg border border-amber-200 bg-amber-50 p-5 md:flex-row md:items-center md:justify-between">
        <div className="space-y-1">
          <div className="text-sm font-semibold text-amber-900">
            后端当前未提供独立资源接口
          </div>
          <p className="text-sm leading-6 text-amber-800/90">
            该能力在现有架构中已并入站点或系统配置。此页面保留为信息架构占位，并引导到真实可用入口。
          </p>
        </div>
        {href ? (
          <a
            href={href}
            className={cn(
              buttonVariants({ variant: "outline" }),
              "border-amber-300 bg-white text-amber-900 hover:bg-amber-50"
            )}
          >
            前往可用页面
          </a>
        ) : null}
      </div>
    </Surface>
  )
}

export function statusToneClass(status: string) {
  switch (status) {
    case "running":
    case "enabled":
    case "success":
    case "hit":
    case "challenge_passed":
      return "bg-emerald-50 text-emerald-700 border-emerald-200"
    case "observe":
    case "warning":
    case "miss":
      return "bg-amber-50 text-amber-700 border-amber-200"
    case "intercept":
    case "block":
    case "drop":
    case "error":
      return "bg-rose-50 text-rose-700 border-rose-200"
    default:
      return "bg-slate-100 text-slate-600 border-slate-200"
  }
}
