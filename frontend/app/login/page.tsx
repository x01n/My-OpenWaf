"use client";

import { Suspense, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Shield, ShieldAlert, Sparkles } from "lucide-react";
import { login } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

function LoginContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const tip = useMemo(() => {
    const reason = searchParams.get("reason");
    if (reason === "session_expired") return "会话已失效，请重新登录。";
    if (reason === "forbidden") return "当前账户无权访问目标资源。";
    return "";
  }, [searchParams]);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(username, password);
      router.push("/dashboard/");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "登录失败");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="relative min-h-svh overflow-hidden bg-[radial-gradient(circle_at_top,rgba(8,145,178,0.18),transparent_28%),radial-gradient(circle_at_80%_0%,rgba(16,185,129,0.12),transparent_18%),linear-gradient(180deg,#08111f,#0b1425_52%,#0b1321)] text-white">
      <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(15,23,42,0.55),transparent_36%,rgba(15,118,110,0.14))]" />
      <div className="relative mx-auto flex min-h-svh max-w-7xl flex-col justify-center gap-10 px-6 py-10 lg:flex-row lg:items-center lg:gap-16">
        <section className="max-w-2xl space-y-6">
          <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-4 py-2 text-[11px] tracking-[0.28em] text-white/70 uppercase">
            <Sparkles className="h-3.5 w-3.5" /> My-OpenWAF Security Console
          </div>
          <div className="space-y-4">
            <h1 className="max-w-3xl text-4xl font-semibold leading-tight tracking-tight md:text-6xl">
              构建面向实时防护的
              <span className="block bg-[linear-gradient(90deg,#a5f3fc,#67e8f9,#34d399)] bg-clip-text text-transparent">
                Web 安全控制中心
              </span>
            </h1>
            <p className="max-w-2xl text-sm leading-7 text-slate-300/85 md:text-base">
              管理站点接入、攻击检测、阻断策略、Bot 风险评分与安全事件追踪。所有实时配置变更都通过当前系统的真实 API 生效。
            </p>
          </div>
          <div className="grid gap-4 sm:grid-cols-3">
            <Card className="border-white/10 bg-white/5 text-white backdrop-blur-xl">
              <CardContent className="space-y-2 p-4">
                <Shield className="h-5 w-5 text-cyan-200" />
                <div className="text-sm font-medium">策略实时生效</div>
                <div className="text-xs leading-6 text-slate-300/75">通过 snapshot reload 与热更新监听器应用配置。</div>
              </CardContent>
            </Card>
            <Card className="border-white/10 bg-white/5 text-white backdrop-blur-xl">
              <CardContent className="space-y-2 p-4">
                <ShieldAlert className="h-5 w-5 text-emerald-200" />
                <div className="text-sm font-medium">多阶段检测</div>
                <div className="text-xs leading-6 text-slate-300/75">整合 OWASP、Bot、CVE、速率限制与事件审计。</div>
              </CardContent>
            </Card>
            <Card className="border-white/10 bg-white/5 text-white backdrop-blur-xl">
              <CardContent className="space-y-2 p-4">
                <Sparkles className="h-5 w-5 text-amber-200" />
                <div className="text-sm font-medium">统一控制台</div>
                <div className="text-xs leading-6 text-slate-300/75">覆盖站点、防护、设置与安全态势分析的完整视图。</div>
              </CardContent>
            </Card>
          </div>
        </section>

        <section className="w-full max-w-md">
          <div className="rounded-[32px] border border-white/10 bg-white/8 p-2 shadow-[0_30px_80px_rgba(2,6,23,0.45)] backdrop-blur-2xl">
            <div className="rounded-[28px] border border-white/10 bg-[linear-gradient(180deg,rgba(15,23,42,0.92),rgba(15,23,42,0.84))] p-6 sm:p-7">
              <div className="space-y-3">
                <div className="text-sm tracking-[0.22em] text-cyan-100/70 uppercase">管理员登录</div>
                <div>
                  <h2 className="text-2xl font-semibold tracking-tight text-white">进入控制台</h2>
                  <p className="mt-2 text-sm leading-6 text-slate-300/80">
                    使用管理员账号登录以管理站点、策略、证书与系统设置。
                  </p>
                </div>
              </div>

              <form onSubmit={handleSubmit} className="mt-8 space-y-5">
                <div className="space-y-2.5">
                  <Label htmlFor="username" className="text-slate-200">用户名</Label>
                  <Input
                    id="username"
                    value={username}
                    onChange={(event) => setUsername(event.target.value)}
                    autoComplete="username"
                    className="h-11 border-white/10 bg-white/5 text-white placeholder:text-slate-500"
                  />
                </div>
                <div className="space-y-2.5">
                  <Label htmlFor="password" className="text-slate-200">密码</Label>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    autoComplete="current-password"
                    className="h-11 border-white/10 bg-white/5 text-white placeholder:text-slate-500"
                  />
                </div>
                {tip ? <div className="rounded-2xl border border-amber-300/20 bg-amber-300/10 px-4 py-3 text-sm text-amber-100">{tip}</div> : null}
                {error ? <div className="rounded-2xl border border-rose-400/20 bg-rose-400/10 px-4 py-3 text-sm text-rose-100">{error}</div> : null}
                <Button type="submit" disabled={loading} className="h-11 w-full rounded-2xl bg-cyan-500 text-slate-950 hover:bg-cyan-400">
                  {loading ? "登录中..." : "登录并进入控制台"}
                </Button>
              </form>
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginContent />
    </Suspense>
  );
}
