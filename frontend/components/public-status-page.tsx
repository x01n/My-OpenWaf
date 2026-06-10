import { ShieldAlert, ShieldCheck, ShieldX } from "@/lib/icons"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
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
    iconBoxClassName: string
  }
> = {
  blocked: {
    badgeVariant: "destructive",
    badgeLabel: "已阻断",
    icon: ShieldX,
    iconClassName: "text-destructive",
    panelClassName: "border-destructive/25 bg-card",
    iconBoxClassName: "bg-destructive/10",
  },
  maintenance: {
    badgeVariant: "secondary",
    badgeLabel: "维护中",
    icon: ShieldCheck,
    iconClassName: "text-foreground",
    panelClassName: "border-border bg-card",
    iconBoxClassName: "bg-muted",
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
    <main className="min-h-svh bg-muted/35 px-6 py-10 text-foreground">
      <div className="mx-auto flex max-w-6xl flex-col gap-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-xs font-medium tracking-[0.24em] text-muted-foreground uppercase">
              My-OpenWAF
            </p>
            <h1 className="mt-2 text-xl font-semibold">公共响应页面</h1>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline">HTTP {statusCode}</Badge>
            <Badge variant={meta.badgeVariant}>{meta.badgeLabel}</Badge>
          </div>
        </div>

        <div className="grid gap-6 lg:grid-cols-[minmax(0,1.6fr)_minmax(280px,0.9fr)]">
          <Card className={`${meta.panelClassName} shadow-sm`}>
            <CardHeader className="gap-3">
              <div className="flex items-center gap-3">
                <div
                  className={`flex size-11 items-center justify-center rounded-full ${meta.iconBoxClassName}`}
                >
                  <Icon className={`size-5 ${meta.iconClassName}`} />
                </div>
                <div className="flex flex-col gap-1">
                  <p className="text-xs font-medium tracking-[0.18em] text-muted-foreground uppercase">
                    {eyebrow}
                  </p>
                  <CardTitle className="text-2xl text-foreground">
                    {title}
                  </CardTitle>
                </div>
              </div>
              <CardDescription className="max-w-2xl text-sm leading-6 text-muted-foreground">
                {description}
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <Alert>
                <ShieldAlert aria-hidden="true" />
                <AlertTitle>排查提示</AlertTitle>
                <AlertDescription>
                  如需排查本次请求，请将页面中的请求标识提供给管理员，并在访问日志、安全事件和阻断记录中检索对应条目。
                </AlertDescription>
              </Alert>
            </CardContent>
          </Card>

          <Card className="border-border bg-card shadow-sm">
            <CardHeader>
              <CardTitle className="text-foreground">诊断信息</CardTitle>
              <CardDescription className="text-muted-foreground">
                以下字段用于日志检索与安全审计。
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              {facts.map((fact) => (
                <div
                  key={fact.label}
                  className="flex flex-col gap-1 rounded-lg border border-border bg-muted/35 p-3"
                >
                  <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
                    {fact.label}
                  </p>
                  <code className="block overflow-x-auto rounded-md bg-background px-3 py-2 font-mono text-xs text-foreground">
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
