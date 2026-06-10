"use client"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
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
    default: "text-foreground",
    danger: "text-destructive",
    warning: "text-chart-3",
    success: "text-chart-2",
  }[tone]

  const accentClass = {
    default: "bg-muted",
    danger: "bg-destructive",
    warning: "bg-chart-3",
    success: "bg-chart-2",
  }[tone]

  return (
    <Card className="relative overflow-hidden rounded-lg border-border bg-card shadow-sm">
      <div className={cn("absolute inset-y-0 left-0 w-1", accentClass)} />
      <CardHeader className="flex flex-col gap-2 pt-4 pb-3">
        <CardDescription className="text-xs font-semibold tracking-[0.18em] text-muted-foreground uppercase">
          {label}
        </CardDescription>
        <CardTitle
          className={cn("text-2xl font-semibold tracking-tight", toneClass)}
        >
          {value}
        </CardTitle>
      </CardHeader>
      {hint ? (
        <CardContent className="pt-0 text-xs leading-6 text-muted-foreground">
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
        <CardHeader className="flex flex-col gap-3 bg-muted/35 px-4 py-3 md:flex-row md:items-end md:justify-between">
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
      {title || description || action ? <Separator /> : null}
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
        <div className="flex flex-col gap-3 bg-card px-4 py-3">
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
      {title || description || toolbar ? <Separator /> : null}
      <div className="bg-card">{state ?? children}</div>
      {footer ? (
        <>
          <Separator />
          <div className="bg-card px-4 py-3">{footer}</div>
        </>
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
      <div className="text-[11px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">
        {label}
      </div>
      <div className="text-sm font-medium text-foreground">{value}</div>
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
    amber: "border-chart-3/25 bg-chart-3/10",
    sky: "border-primary/25 bg-primary/10",
    emerald: "border-chart-2/25 bg-chart-2/10",
    slate: "border-border bg-muted/35",
  }[tone]

  return (
    <Alert
      className={cn(
        size === "sm" ? "px-3 py-3 text-xs" : "px-4 py-3 text-sm",
        toneClass,
        className
      )}
    >
      {title ? (
        <AlertTitle className={size === "sm" ? "text-xs" : "text-sm"}>
          {title}
        </AlertTitle>
      ) : null}
      <AlertDescription
        className={cn(
          "text-foreground",
          size === "sm" ? "text-xs leading-5" : "text-sm leading-6"
        )}
      >
        {children}
      </AlertDescription>
      {action ? <div className="mt-2">{action}</div> : null}
    </Alert>
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
    <Button type="button" variant="link" size="sm" onClick={onBack}>
      返回当前站点
    </Button>
  ) : backHref ? (
    <Button asChild variant="link" size="sm">
      <a href={backHref}>返回当前站点</a>
    </Button>
  ) : null

  return (
    <Notice tone="amber" className={className} action={backAction}>
      你是从站点 “{sourceSite}” 跳转过来的。当前页面配置的是{scope}
      ，修改后会影响所有站点。
    </Notice>
  )
}

export function statusToneClass(status: string) {
  switch (status) {
    case "running":
    case "enabled":
    case "success":
    case "hit":
    case "challenge_passed":
      return "border-chart-2/30 bg-chart-2/10 text-foreground"
    case "observe":
    case "warning":
    case "miss":
      return "border-chart-3/30 bg-chart-3/10 text-foreground"
    case "intercept":
    case "block":
    case "drop":
    case "error":
      return "border-destructive/30 bg-destructive/10 text-destructive"
    default:
      return "border-border bg-muted/60 text-muted-foreground"
  }
}
