"use client";

import { buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

export function PageIntro({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-4 rounded-lg border border-slate-200 bg-white px-6 py-5 shadow-sm md:flex-row md:items-end md:justify-between">
      <div className="space-y-3">
        {eyebrow ? (
          <div className="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-[11px] font-medium tracking-[0.22em] text-slate-500 uppercase">
            {eyebrow}
          </div>
        ) : null}
        <div className="space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight text-slate-950 md:text-3xl">{title}</h1>
          <p className="max-w-3xl text-sm leading-6 text-slate-600">{description}</p>
        </div>
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function MetricGrid({ children }: { children: React.ReactNode }) {
  return <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">{children}</div>;
}

export function MetricCard({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: React.ReactNode;
  hint?: React.ReactNode;
  tone?: "default" | "danger" | "warning" | "success";
}) {
  const toneClass = {
    default: "text-slate-950",
    danger: "text-rose-600",
    warning: "text-amber-600",
    success: "text-emerald-600",
  }[tone];

  return (
    <Card className="overflow-hidden border-slate-200 bg-white shadow-sm">
      <CardHeader className="space-y-2 pb-3">
        <CardDescription className="text-xs font-medium tracking-[0.18em] text-slate-500 uppercase">{label}</CardDescription>
        <CardTitle className={cn("text-3xl font-semibold tracking-tight", toneClass)}>{value}</CardTitle>
      </CardHeader>
      {hint ? <CardContent className="pt-0 text-xs leading-6 text-slate-500">{hint}</CardContent> : null}
    </Card>
  );
}

export function Surface({
  title,
  description,
  action,
  children,
  className,
}: {
  title?: string;
  description?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <Card className={cn("border-slate-200 bg-white shadow-sm", className)}>
      {title || description || action ? (
        <CardHeader className="flex flex-col gap-3 border-b border-slate-200 pb-4 md:flex-row md:items-end md:justify-between">
          <div className="space-y-1">
            {title ? <CardTitle className="text-lg text-slate-950">{title}</CardTitle> : null}
            {description ? <CardDescription className="text-sm leading-6 text-slate-600">{description}</CardDescription> : null}
          </div>
          {action ? <div className="flex items-center gap-2">{action}</div> : null}
        </CardHeader>
      ) : null}
      <CardContent className="p-5">{children}</CardContent>
    </Card>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex min-h-[280px] flex-col items-center justify-center rounded-lg border border-dashed border-slate-300 bg-slate-50 px-6 text-center">
      <div className="max-w-md space-y-3">
        <h3 className="text-lg font-semibold text-slate-900">{title}</h3>
        <p className="text-sm leading-6 text-slate-500">{description}</p>
        {action ? <div className="pt-2">{action}</div> : null}
      </div>
    </div>
  );
}

export function InlineMeta({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="space-y-1 rounded-lg border border-slate-200 bg-slate-50 p-4">
      <div className="text-[11px] font-medium tracking-[0.16em] text-slate-400 uppercase">{label}</div>
      <div className="text-sm font-medium text-slate-900">{value}</div>
    </div>
  );
}

export function Notice({
  tone = "amber",
  title,
  children,
  action,
  className,
  size = "md",
}: {
  tone?: "amber" | "sky" | "emerald" | "slate";
  title?: React.ReactNode;
  children: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
  size?: "sm" | "md";
}) {
  const toneClass = {
    amber: "border-amber-200 bg-amber-50 text-amber-900",
    sky: "border-sky-200 bg-sky-50 text-sky-900",
    emerald: "border-emerald-200 bg-emerald-50 text-emerald-900",
    slate: "border-slate-200 bg-slate-50 text-slate-700",
  }[tone];

  return (
    <div className={cn("rounded-lg border", size === "sm" ? "px-3 py-3 text-xs" : "px-4 py-3 text-sm", toneClass, className)}>
      <div className={cn("space-y-1", size === "sm" ? "leading-5" : "leading-6")}>
        {title ? <div className="font-medium">{title}</div> : null}
        <div>{children}</div>
      </div>
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

export function SourceSiteNotice({
  sourceSite,
  scope,
  onBack,
  backHref,
  className,
}: {
  sourceSite: React.ReactNode;
  scope: React.ReactNode;
  onBack?: () => void;
  backHref?: string;
  className?: string;
}) {
  const backAction = onBack ? (
    <button type="button" onClick={onBack} className="text-sm font-medium text-amber-900 underline underline-offset-4">
      返回当前站点
    </button>
  ) : backHref ? (
    <a href={backHref} className="text-sm font-medium text-amber-900 underline underline-offset-4">
      返回当前站点
    </a>
  ) : null;

  return (
    <Notice tone="amber" className={className} action={backAction}>
      你是从站点 “{sourceSite}” 跳转过来的。当前页面配置的是{scope}，修改后会影响所有站点。
    </Notice>
  );
}

export function PlanningNotice({ title, description, href }: { title: string; description: string; href?: string }) {
  return (
    <Surface title={title} description={description}>
      <div className="flex flex-col gap-4 rounded-lg border border-amber-200 bg-amber-50 p-5 md:flex-row md:items-center md:justify-between">
        <div className="space-y-1">
          <div className="text-sm font-semibold text-amber-900">后端当前未提供独立资源接口</div>
          <p className="text-sm leading-6 text-amber-800/90">
            该能力在现有架构中已并入站点或系统配置。此页面保留为信息架构占位，并引导到真实可用入口。
          </p>
        </div>
        {href ? (
          <a href={href} className={cn(buttonVariants({ variant: "outline" }), "border-amber-300 bg-white text-amber-900 hover:bg-amber-50")}>前往可用页面</a>
        ) : null}
      </div>
    </Surface>
  );
}

export function statusToneClass(status: string) {
  switch (status) {
    case "running":
    case "enabled":
    case "success":
    case "hit":
    case "challenge_passed":
      return "bg-emerald-50 text-emerald-700 border-emerald-200";
    case "observe":
    case "warning":
    case "miss":
      return "bg-amber-50 text-amber-700 border-amber-200";
    case "intercept":
    case "block":
    case "drop":
    case "error":
      return "bg-rose-50 text-rose-700 border-rose-200";
    default:
      return "bg-slate-100 text-slate-600 border-slate-200";
  }
}
