/**
 * 登录页面
 */

"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { useTranslation } from "react-i18next"
import { useAuth } from "@/hooks/use-auth"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { IconShieldCheck } from "@tabler/icons-react"
import { toast } from "sonner"

export default function LoginPage() {
  const router = useRouter()
  const { t } = useTranslation()
  const { login, isAuthenticated, loading: authLoading } = useAuth()
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!authLoading && isAuthenticated) {
      router.replace("/dashboard")
    }
  }, [authLoading, isAuthenticated, router])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!username || !password) {
      toast.error(t("login.emptyCredentials"))
      return
    }
    setLoading(true)
    try {
      await login(username, password)
      toast.success(t("login.success"))
      router.push("/dashboard")
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t("login.failed"))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-svh items-center justify-center bg-muted/40 p-4">
      <Card className="w-full max-w-sm">
        <CardHeader className="space-y-1">
          <div className="mb-4 flex items-center justify-center gap-2">
            <IconShieldCheck className="h-8 w-8 text-primary" />
            <span className="text-xl font-bold">OpenWAF</span>
          </div>
          <CardTitle className="text-center text-lg">
            {t("login.title")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="username">{t("common.username")}</Label>
              <Input
                id="username"
                name="username"
                autoComplete="username"
                placeholder={t("login.usernamePlaceholder")}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={loading || authLoading}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">{t("common.password")}</Label>
              <Input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                placeholder={t("login.passwordPlaceholder")}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={loading || authLoading}
              />
            </div>
            <Button
              type="submit"
              className="w-full"
              disabled={loading || authLoading}
            >
              {loading || authLoading
                ? t("login.submitting")
                : t("login.submit")}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
