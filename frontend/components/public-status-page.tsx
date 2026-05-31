import { ShieldAlert, ShieldCheck, ShieldX } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"

type StatusTone = "blocked" | "maintenance"

interface FactItem {
  label: string
  value: string
}

interface PublicStatusPageProps {
  tone: StatusTone
  statusCode: number
  eyebrow: string
  title: string
  description: string
  facts: FactItem[]
}

const toneMeta: Record<
  StatusTone,
  {
    badgeVariant: "destructive" | "secondary"
    badgeLabel: string
    icon: typeof ShieldX
    iconClassName: string
    panelClassName: string
  }
> = {
  blocked: {
    badgeVariant: "destructive",
    badgeLabel: "已阻断",
    icon: ShieldX,
    iconClassName: "text-rose-600",
    panelClassName: "border-rose-200 bg-white",
  },
  maintenance: {
    badgeVariant: "secondary",
    badgeLabel: "维护中",
    icon: ShieldCheck,
    iconClassName: "text-slate-600",
    panelClassName: "border-slate-200 bg-white",
  },
}

export function PublicStatusPage({
  tone,
  statusCode,
  eyebrow,
  title,
  description,
  facts,
}: PublicStatusPageProps) {
  const meta = toneMeta[tone]
  const Icon = meta.icon

  return (
    <main className="min-h-svh bg-slate-50 px-6 py-10 text-slate-950">
      <div className="mx-auto flex max-w-6xl flex-col gap-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-xs font-medium tracking-[0.24em] text-slate-500 uppercase">
              My-OpenWAF
            </p>
            <h1 className="mt-2 text-xl font-semibold">公共响应页面</h1>
          </div>
          <div className="flex items-center gap-2">
            <Badge
              variant="outline"
              className="border-slate-200 bg-white text-slate-700"
            >
              HTTP {statusCode}
            </Badge>
            <Badge variant={meta.badgeVariant}>{meta.badgeLabel}</Badge>
          </div>
        </div>

        <div className="grid gap-6 lg:grid-cols-[minmax(0,1.6fr)_minmax(280px,0.9fr)]">
          <Card className={`${meta.panelClassName} shadow-sm`}>
            <CardHeader className="gap-3">
              <div className="flex items-center gap-3">
                <div className="flex size-11 items-center justify-center rounded-full bg-slate-100">
                  <Icon className={`size-5 ${meta.iconClassName}`} />
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-medium tracking-[0.18em] text-slate-500 uppercase">
                    {eyebrow}
                  </p>
                  <CardTitle className="text-2xl text-slate-950">
                    {title}
                  </CardTitle>
                </div>
              </div>
              <CardDescription className="max-w-2xl text-sm leading-6 text-slate-500">
                {description}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
                <div className="flex items-start gap-3">
                  <ShieldAlert className="mt-0.5 size-4 text-slate-600" />
                  <div className="space-y-1">
                    <p className="text-sm font-medium text-slate-900">
                      排查提示
                    </p>
                    <p className="text-sm leading-6 text-slate-600">
                      如需排查本次请求，请将页面中的请求标识提供给管理员，并在访问日志、安全事件和阻断记录中检索对应条目。
                    </p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-200 bg-white shadow-sm">
            <CardHeader>
              <CardTitle className="text-slate-950">诊断信息</CardTitle>
              <CardDescription className="text-slate-500">
                以下字段用于日志检索与安全审计。
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {facts.map((fact) => (
                <div
                  key={fact.label}
                  className="space-y-1 rounded-lg border border-slate-200 bg-slate-50 p-3"
                >
                  <p className="text-xs font-medium tracking-wide text-slate-500 uppercase">
                    {fact.label}
                  </p>
                  <code className="block overflow-x-auto rounded-md bg-white px-3 py-2 font-mono text-xs text-slate-700">
                    {fact.value}
                  </code>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </main>
  )
}
