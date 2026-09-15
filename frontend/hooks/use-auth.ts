"use client"

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react"
import {
  authApi,
  ApiError,
  clearAuthToken,
  getAccessToken,
  getAccessTokenExpiry,
  refreshAuthSession,
  storeAuthToken,
  AUTH_TOKEN_STORAGE_KEY,
  AUTH_TOKEN_EXPIRES_AT_STORAGE_KEY,
  type AuthRole,
} from "@/lib/api"

export interface AuthUser {
  username: string
  role: AuthRole
}

class AuthTokenChangedError extends Error {}

interface AuthMeRequest {
  token: string | null
  promise: Promise<AuthUser>
}

/** 多个页面组件会同时挂载 useAuth；同一 access token 只保留一个在途请求。 */
let authMeRequest: AuthMeRequest | null = null

function loadAuthUserForCurrentToken(): Promise<AuthUser> {
  const token = getAccessToken()
  if (authMeRequest?.token === token) return authMeRequest.promise

  const promise = authApi
    .me()
    .then((data) => {
      if (getAccessToken() !== token) throw new AuthTokenChangedError()
      return { username: data.username, role: data.role }
    })
    .finally(() => {
      // 旧 token 的请求结束时不能清除新 token 已建立的在途请求。
      if (authMeRequest?.promise === promise) authMeRequest = null
    })
  authMeRequest = { token, promise }
  return promise
}

/** access token 在 /auth/me 期间轮换时仅重试一次，拒绝旧响应覆盖新会话。 */
async function loadAuthUser(): Promise<AuthUser> {
  try {
    return await loadAuthUserForCurrentToken()
  } catch (error) {
    if (!(error instanceof AuthTokenChangedError) || !getAccessToken()) {
      throw error
    }
    return loadAuthUserForCurrentToken()
  }
}

const REFRESH_LEAD_MS = 60_000
const REFRESH_RETRY_MS = 30_000
const RESUME_CHECK_INTERVAL_MS = 30_000

let lastResumeCheckAt = 0

function isBrowser(): boolean {
  return typeof window !== "undefined" && typeof document !== "undefined"
}

function shouldRefresh(expiry: number | null): boolean {
  return expiry === null || expiry - Date.now() <= REFRESH_LEAD_MS
}

/**
 * 认证状态管理 Hook。
 * access token 仅保存在本地，续期始终通过 HttpOnly refresh cookie 完成。
 */
export function useAuthController() {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [loading, setLoading] = useState(true)
  const refreshTimer = useRef<number | null>(null)
  const mounted = useRef(false)
  const refreshAccessRef = useRef<() => Promise<boolean>>(async () => false)

  const clearRefreshTimer = useCallback(() => {
    if (refreshTimer.current !== null && isBrowser()) {
      window.clearTimeout(refreshTimer.current)
      refreshTimer.current = null
    }
  }, [])

  const scheduleRefresh = useCallback(
    (retryDelay?: number) => {
      if (!isBrowser()) return
      clearRefreshTimer()
      const expiry = getAccessTokenExpiry()
      if (retryDelay !== undefined || expiry === null) {
        refreshTimer.current = window.setTimeout(() => {
          void refreshAccessRef.current()
        }, retryDelay ?? REFRESH_RETRY_MS)
        return
      }
      const delay = Math.max(5_000, expiry - Date.now() - REFRESH_LEAD_MS)
      refreshTimer.current = window.setTimeout(() => {
        void refreshAccessRef.current()
      }, delay)
    },
    [clearRefreshTimer]
  )

  const applyRefresh = useCallback(
    (result: Awaited<ReturnType<typeof refreshAuthSession>>): boolean => {
      // refresh 返回后可能紧接着发生登出或另一轮登录；旧结果
      // 不得恢复用户状态或重新安排定时器。
      if (result.ok && getAccessToken() !== result.accessToken) {
        return false
      }
      if (!result.ok) {
        if (result.reason === "unauthorized") {
          // 没有本地 access token 的首屏探测只表示当前没有会话；不要
          // 为了清理空存储项递增代次，否则并行认证消费者会再次发起同一 401。
          if (getAccessToken()) clearAuthToken()
          if (mounted.current) setUser(null)
        } else if (mounted.current) {
          // 网络错误或 5xx 不代表会话失效，保留 token 并安排稍后重试。
          // 没有 access token 时通常是未登录页面；不启动永久刷新轮询，
          // 避免认证服务不可用时每 30 秒制造一次无意义请求。
          if (getAccessToken()) scheduleRefresh(REFRESH_RETRY_MS)
        }
        return false
      }
      if (mounted.current) {
        setUser({ username: result.data.username, role: result.data.role })
        scheduleRefresh()
      }
      return true
    },
    [scheduleRefresh]
  )

  const refreshAccess = useCallback(async () => {
    const result = await refreshAuthSession()
    return applyRefresh(result)
  }, [applyRefresh])

  useEffect(() => {
    refreshAccessRef.current = refreshAccess
  }, [refreshAccess])

  const loadSession = useCallback(
    async (resumeCheck = false) => {
      if (resumeCheck) {
        const now = Date.now()
        if (now - lastResumeCheckAt < RESUME_CHECK_INTERVAL_MS) return
        lastResumeCheckAt = now
      }

      let token = getAccessToken()
      if (!token || shouldRefresh(getAccessTokenExpiry())) {
        const result = await refreshAuthSession()
        if (!applyRefresh(result)) {
          if (mounted.current) setLoading(false)
          return
        }
        token = getAccessToken()
      }

      if (!token) {
        if (mounted.current) setLoading(false)
        return
      }

      try {
        const data = await loadAuthUser()
        if (mounted.current) {
          setUser({ username: data.username, role: data.role })
          scheduleRefresh()
        }
      } catch {
        // apiRequest 仅在 refresh 明确返回 401 时清理 token；网络/5xx 保留当前状态。
        if (!getAccessToken() && mounted.current) setUser(null)
        if (mounted.current && getAccessToken()) {
          // /auth/me 的临时网络/5xx 失败不应让用户状态一直为空，
          // 也不应等到 access token 临近过期才再次确认会话。
          scheduleRefresh(REFRESH_RETRY_MS)
        }
      } finally {
        if (mounted.current) setLoading(false)
      }
    },
    [applyRefresh, scheduleRefresh]
  )

  const login = useCallback(
    async (username: string, password: string) => {
      const data = await authApi.login(username, password)
      storeAuthToken(data.access_token, data.expires_at)
      setUser({ username: data.username, role: data.role })
      scheduleRefresh()
      return data
    },
    [scheduleRefresh]
  )

  const logout = useCallback(async () => {
    try {
      await authApi.logout()
    } finally {
      clearRefreshTimer()
      clearAuthToken()
      setUser(null)
      window.location.href = "/login"
    }
  }, [clearRefreshTimer])

  useEffect(() => {
    mounted.current = true
    let active = true
    Promise.resolve().then(() => {
      if (active) void loadSession()
    })

    if (!isBrowser()) {
      return () => {
        active = false
        mounted.current = false
      }
    }

    const onResume = () => {
      if (document.visibilityState === "hidden") return
      void loadSession(true)
    }
    const onStorage = (event: StorageEvent) => {
      if (
        event.key !== AUTH_TOKEN_STORAGE_KEY &&
        event.key !== AUTH_TOKEN_EXPIRES_AT_STORAGE_KEY
      ) {
        return
      }
      // token 事件携带完整会话变化；到期时间事件单独变化时无需重新请求。
      if (event.key === AUTH_TOKEN_STORAGE_KEY) {
        // StorageEvent 可能晚于另一个标签页的更新到达，不能信任
        // event.newValue；始终以当前共享存储中的值为准，避免旧事件
        // 覆盖较新的登录或把新会话误清除。
        const nextToken = getAccessToken()
        if (!nextToken) {
          clearRefreshTimer()
          clearAuthToken()
          if (mounted.current) setUser(null)
          return
        }
        // 到期时间和 token 是两次独立的 storage 写入；从 token 自身
        // 解析 exp，避免读取到另一标签页尚未更新完成的旧时间。
        storeAuthToken(nextToken)
        if (mounted.current) {
          // 令牌可能属于另一个账号；在 /auth/me 确认新身份前不展示旧用户。
          setUser(null)
          setLoading(true)
        }
        // token 变化必须立即重载，不能受 focus/visibility 的 30 秒节流影响。
        void loadSession()
      }
    }
    window.addEventListener("focus", onResume)
    document.addEventListener("visibilitychange", onResume)
    window.addEventListener("storage", onStorage)

    return () => {
      active = false
      mounted.current = false
      clearRefreshTimer()
      window.removeEventListener("focus", onResume)
      document.removeEventListener("visibilitychange", onResume)
      window.removeEventListener("storage", onStorage)
    }
  }, [clearRefreshTimer, loadSession])

  return {
    user,
    loading,
    login,
    logout,
    isAuthenticated: !!user,
  }
}

export type AuthContextValue = ReturnType<typeof useAuthController>

/** 全应用唯一认证控制器的上下文；由根布局的 AuthProvider 提供。 */
export const AuthContext = createContext<AuthContextValue | null>(null)

/** 读取共享认证状态，避免每个页面各自创建刷新定时器和焦点监听器。 */
export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext)
  if (!value) {
    throw new Error("useAuth must be used within AuthProvider")
  }
  return value
}

/**
 * 检查是否已登录（用于路由守卫）。即使 localStorage 没有 token，也会尝试
 * 使用现有 HttpOnly refresh cookie 恢复会话。
 */
export function useIsAuthenticated() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [checked, setChecked] = useState(false)

  const check = useCallback(async () => {
    let token = getAccessToken()
    if (!token || shouldRefresh(getAccessTokenExpiry())) {
      const result = await refreshAuthSession()
      if (!result.ok) {
        if (result.reason === "unauthorized" && getAccessToken()) {
          clearAuthToken()
        }
        // 已有 access token 时，refresh 的网络/5xx 故障不能被路由闸门
        // 误判成登出；保留当前会话并等待下一次焦点/定时重试。
        return result.reason === "unavailable" && !!getAccessToken()
      }
      if (getAccessToken() !== result.accessToken) return false
      token = result.accessToken
    }
    if (!token) return false
    try {
      await loadAuthUser()
      return true
    } catch (error) {
      // /auth/me 返回 401 表示当前 token 已失效；不能把仍留在
      // localStorage 中的旧 token 当作已认证状态。网络错误或 5xx
      // 没有足够证据判定会话失效，暂时保留 token 以便稍后恢复。
      if (
        error instanceof ApiError &&
        error.status === 401 &&
        error.data?.refresh_status !== "unavailable"
      ) {
        clearAuthToken()
        return false
      }
      return !!getAccessToken()
    }
  }, [])

  useEffect(() => {
    let active = true
    const run = async () => {
      let result = false
      try {
        result = await check()
      } catch {
        // 认证探测的异常不能让 checked 永远保持 false；存在旧 token 时
        // 交由 AuthGate 的暂时不可用策略保留会话，下一次恢复事件再重试。
        try {
          result = !!getAccessToken()
        } catch {
          result = false
        }
      }
      if (active) {
        setIsAuthenticated(result)
        setChecked(true)
      }
    }
    void run()

    if (isBrowser()) {
      const onResume = () => {
        if (document.visibilityState === "hidden") return
        void run()
      }
      window.addEventListener("focus", onResume)
      document.addEventListener("visibilitychange", onResume)
      const onStorage = (event: StorageEvent) => {
        if (event.key !== AUTH_TOKEN_STORAGE_KEY) return
        // 事件可能落后于当前共享存储状态；以当前 token 判断会话，
        // 避免延迟的登出事件覆盖随后完成的登录。
        if (!getAccessToken()) {
          setIsAuthenticated(false)
          setChecked(true)
          return
        }
        setChecked(false)
        void run()
      }
      window.addEventListener("storage", onStorage)
      return () => {
        active = false
        window.removeEventListener("focus", onResume)
        document.removeEventListener("visibilitychange", onResume)
        window.removeEventListener("storage", onStorage)
      }
    }
    return () => {
      active = false
    }
  }, [check])

  return { isAuthenticated, checked }
}
