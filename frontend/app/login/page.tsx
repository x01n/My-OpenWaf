"use client"

import { Suspense, useMemo, useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { Activity, LockKeyhole, Shield, Waves } from "lucide-react"
import { login } from "@/lib/api"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

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
    <main className="relative min-h-svh overflow-hidden bg-[#eef4f7] px-4 py-10 text-slate-950">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_20%_20%,rgba(20,184,166,0.20),transparent_28%),radial-gradient(circle_at_80%_10%,rgba(59,130,246,0.15),transparent_24%),linear-gradient(135deg,rgba(255,255,255,0.85),rgba(226,232,240,0.45))]" />
      <div className="relative mx-auto grid min-h-[calc(100svh-5rem)] max-w-5xl items-center gap-8 lg:grid-cols-[1.15fr_0.85fr]">
        <section className="hidden lg:block">
          <div className="mb-8 inline-flex items-center gap-2 rounded-full border border-teal-200 bg-white/70 px-4 py-2 text-sm font-medium text-teal-700 shadow-sm backdrop-blur">
            <Shield className="h-4 w-4" /> My-OpenWAF 控制平面
          </div>
          <h1 className="max-w-xl text-5xl font-semibold tracking-[-0.04em] text-slate-950">
            把流量、威胁与站点策略放在同一个安全视野里。
          </h1>
          <p className="mt-5 max-w-lg text-base leading-7 text-slate-600">
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
                className="rounded-2xl border border-white/70 bg-white/65 p-4 shadow-sm backdrop-blur"
              >
                <item.icon className="h-5 w-5 text-teal-600" />
                <div className="mt-4 text-2xl font-semibold text-slate-950">
                  {item.value}
                </div>
                <div className="mt-1 text-xs text-slate-500">{item.label}</div>
              </div>
            ))}
          </div>
        </section>

        <Card className="w-full border-white/80 bg-white/82 shadow-[0_24px_80px_rgba(15,23,42,0.12)] backdrop-blur-xl">
          <CardHeader className="space-y-3 border-b border-slate-200/70 pb-6">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-teal-500 text-white shadow-lg shadow-teal-500/25">
              <Shield className="h-6 w-6" />
            </div>
            <div className="space-y-2">
              <CardTitle className="text-2xl text-slate-950">
                安全控制台登录
              </CardTitle>
              <CardDescription className="text-sm leading-6 text-slate-600">
                使用管理员账号继续访问站点、防护规则和系统设置。
              </CardDescription>
            </div>
          </CardHeader>

          <CardContent className="space-y-5 p-6">
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username">用户名</Label>
                <Input
                  id="username"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  autoComplete="username"
                  className="h-11 bg-white"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">密码</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  autoComplete="current-password"
                  className="h-11 bg-white"
                />
              </div>
              {tip ? (
                <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
                  {tip}
                </div>
              ) : null}
              {error ? (
                <div className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
                  {error}
                </div>
              ) : null}
              <Button
                type="submit"
                disabled={loading}
                className="h-11 w-full rounded-xl bg-teal-500 text-white shadow-lg shadow-teal-500/20 hover:bg-teal-600"
              >
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
