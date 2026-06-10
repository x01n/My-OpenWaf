"use client"

import { Suspense, useMemo, useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import {
  Activity,
  AlertCircle,
  Info,
  LockKeyhole,
  Shield,
  Waves,
} from "@/lib/icons"
import { login } from "@/lib/api"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"

function LoginContent() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const [username, setUsername] = useState("admin")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  const tip = useMemo(() => {
    const reason = searchParams.get("reason")
    if (reason === "session_expired") return "会话已失效，请重新登录。"
    if (reason === "forbidden") return "当前账户无权访问目标资源。"
    return ""
  }, [searchParams])

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    setError("")
    setLoading(true)
    try {
      await login(username, password)
      router.push("/dashboard/")
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "登录失败")
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="relative min-h-svh overflow-hidden bg-background px-4 py-10 text-foreground">
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,var(--card),color-mix(in_oklch,var(--muted)_55%,transparent)),linear-gradient(to_right,color-mix(in_oklch,var(--border)_45%,transparent)_1px,transparent_1px),linear-gradient(to_bottom,color-mix(in_oklch,var(--border)_45%,transparent)_1px,transparent_1px)] bg-[size:auto,48px_48px,48px_48px]" />
      <div className="relative mx-auto grid min-h-[calc(100svh-5rem)] max-w-5xl items-center gap-8 lg:grid-cols-[1.15fr_0.85fr]">
        <section className="hidden lg:block">
          <div className="mb-8 inline-flex items-center gap-2 rounded-full border border-primary/20 bg-card/70 px-4 py-2 text-sm font-medium text-primary shadow-sm backdrop-blur">
            <Shield data-icon="inline-start" /> My-OpenWAF 控制平面
          </div>
          <h1 className="max-w-xl text-5xl font-semibold text-foreground">
            把流量、威胁与站点策略放在同一个安全视野里。
          </h1>
          <p className="mt-5 max-w-lg text-base leading-7 text-muted-foreground">
            登录态由短期 access token 与 HttpOnly refresh session 共同维护，敏感
            cookie 仅在认证端点携带。
          </p>
          <div className="mt-8 grid max-w-xl grid-cols-3 gap-3">
            {[
              { icon: Activity, label: "实时态势", value: "5s" },
              { icon: Waves, label: "链路防护", value: "WAF" },
              { icon: LockKeyhole, label: "会话安全", value: "JWT" },
            ].map((item) => (
              <div
                key={item.label}
                className="rounded-lg border border-border bg-card/70 p-4 shadow-sm backdrop-blur"
              >
                <item.icon className="text-primary" />
                <div className="mt-4 text-2xl font-semibold text-foreground">
                  {item.value}
                </div>
                <div className="mt-1 text-xs text-muted-foreground">
                  {item.label}
                </div>
              </div>
            ))}
          </div>
        </section>

        <Card className="w-full border-border bg-card/90 shadow-lg backdrop-blur-xl">
          <CardHeader className="flex flex-col gap-3 pb-6">
            <div className="flex size-12 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-lg">
              <Shield />
            </div>
            <div className="flex flex-col gap-2">
              <CardTitle className="text-2xl text-foreground">
                安全控制台登录
              </CardTitle>
              <CardDescription className="text-sm leading-6 text-muted-foreground">
                使用管理员账号继续访问站点、防护规则和系统设置。
              </CardDescription>
            </div>
          </CardHeader>
          <Separator />

          <CardContent className="p-6">
            <form onSubmit={handleSubmit} className="flex flex-col gap-4">
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="username">用户名</FieldLabel>
                  <Input
                    id="username"
                    value={username}
                    onChange={(event) => setUsername(event.target.value)}
                    autoComplete="username"
                    className="h-11 bg-background"
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor="password">密码</FieldLabel>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    autoComplete="current-password"
                    className="h-11 bg-background"
                  />
                </Field>
              </FieldGroup>
              {tip ? (
                <Alert>
                  <Info />
                  <AlertDescription>{tip}</AlertDescription>
                </Alert>
              ) : null}
              {error ? (
                <Alert variant="destructive">
                  <AlertCircle />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              ) : null}
              <Button type="submit" disabled={loading} className="h-11 w-full">
                {loading ? "登录中..." : "进入控制台"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </main>
  )
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginContent />
    </Suspense>
  )
}
