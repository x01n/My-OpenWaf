"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"
import { useTranslation } from "react-i18next"
import { useAuth } from "@/hooks/use-auth"
import { getAccessToken } from "@/lib/api"

/**
 * 管理端路由认证闸门。
 *
 * 在认证检查完成前不挂载任何业务页面，避免未登录或旧 token 页面一次性
 * 触发大量 401 请求。检查通过后才渲染子树；明确失效时由路由替换到登录页。
 */
export function AuthGate({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const { t } = useTranslation()
  const { user, loading } = useAuth()
  const checked = !loading
  // 初始 /auth/me 遇到网络或 5xx 时，控制器会保留现有 access token；
  // 在这种情况下不应把暂时不可用误判为登出。明确 401 会由 apiRequest
  // 清理 token，随后本闸门再跳转登录页。
  const isAuthenticated = !!user || (!!getAccessToken() && checked)

  useEffect(() => {
    if (checked && !isAuthenticated) {
      router.replace("/login")
    }
  }, [checked, isAuthenticated, router])

  if (!checked || !isAuthenticated) {
    return (
      <main
        className="flex min-h-svh items-center justify-center bg-background p-6"
        role="status"
        aria-live="polite"
      >
        <p className="text-sm text-muted-foreground">{t("common.loading")}</p>
      </main>
    )
  }

  return <>{children}</>
}
