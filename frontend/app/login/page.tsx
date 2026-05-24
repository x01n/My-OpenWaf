"use client";

import { Suspense, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Shield } from "lucide-react";
import { login } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
    <main className="min-h-svh bg-slate-50 px-4 py-10 text-slate-900">
      <div className="mx-auto flex min-h-[calc(100svh-5rem)] max-w-md items-center">
        <Card className="w-full border-slate-200 shadow-sm">
          <CardHeader className="space-y-3 border-b border-slate-200 pb-5">
            <div className="inline-flex items-center gap-2 text-sm font-medium text-slate-600">
              <Shield className="h-4 w-4 text-slate-600" /> 管理后台登录
            </div>
            <div className="space-y-2">
              <CardTitle className="text-2xl text-slate-950">登录到 My-OpenWAF</CardTitle>
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
                />
              </div>
              {tip ? <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">{tip}</div> : null}
              {error ? <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">{error}</div> : null}
              <Button type="submit" disabled={loading} className="h-11 w-full rounded-lg bg-teal-500 text-white hover:bg-teal-600">
                {loading ? "登录中..." : "登录"}
              </Button>
            </form>
          </CardContent>
        </Card>
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
