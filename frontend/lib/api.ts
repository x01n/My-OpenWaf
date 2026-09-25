/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * API 客户端封装
 * 统一 fetch 调用，处理 JWT 认证、Token 刷新、错误处理
 */

import type {
  BotScoreListResponse,
  BotScoreStats,
  BotSettings,
  ChainConfig,
  ChainSessionsResponse,
  DefaultErrorPagesResponse,
  ErrorPagePreviewRequest,
  ErrorPagePreviewResponse,
  RealtimeTicketResponse,
  RuleExportPayload,
  RuleImportResponse,
  RuleTemplate,
  SiteErrorPages,
} from "@/lib/types"

const API_BASE = "/api/v1"
const ACCESS_TOKEN_KEY = "token"
const ACCESS_TOKEN_EXPIRES_AT_KEY = "token_expires_at"
const FRONTEND_PAGE_SIZE = 200
const MAX_SITE_RESOURCE_PAGES = 10

/** 供跨标签页认证状态同步使用的存储键；不暴露 refresh cookie 内容。 */
export const AUTH_TOKEN_STORAGE_KEY = ACCESS_TOKEN_KEY
export const AUTH_TOKEN_EXPIRES_AT_STORAGE_KEY = ACCESS_TOKEN_EXPIRES_AT_KEY

// 认证凭据代次用于隔离登出/重新登录与在途 refresh 请求。浏览器无法
// 可靠取消已经发出的 fetch；旧响应到达时必须确认它仍属于当前会话。
let authEpoch = 0
const REFRESH_RESULT_CACHE_MS = 500
let refreshPromise: Promise<RefreshOutcome> | null = null
let refreshResultCache: {
  epoch: number
  token: string | null
  outcome: RefreshOutcome
  expiresAt: number
} | null = null

const REFRESH_LOCK_NAME = "my-openwaf-refresh"
const REFRESH_LOCK_STORAGE_KEY = "my_openwaf_refresh_lock"
const REFRESH_LOCK_INTENT_PREFIX = `${REFRESH_LOCK_STORAGE_KEY}.intent.`
const REFRESH_LOCK_TTL_MS = 15_000
const REFRESH_LOCK_WAIT_MS = 20_000
const REFRESH_LOCK_POLL_MS = 50
const REFRESH_LOCK_RENEW_MS = Math.floor(REFRESH_LOCK_TTL_MS / 3)

type RefreshLockManager = {
  request<T>(
    name: string,
    options: { mode: "exclusive" },
    callback: () => Promise<T>
  ): Promise<T>
}

type RefreshLockRecord = {
  owner: string
  expires_at: number
}

const refreshLockOwner =
  typeof globalThis.crypto?.randomUUID === "function"
    ? globalThis.crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(36).slice(2)}`

export type AuthRole = "admin" | "operator" | "readonly"

export interface AuthTokenResponse {
  access_token: string
  expires_at?: number
  username: string
  role: AuthRole
}

function isAuthRole(value: unknown): value is AuthRole {
  return value === "admin" || value === "operator" || value === "readonly"
}

function isAuthTokenResponse(value: unknown): value is AuthTokenResponse {
  if (!value || typeof value !== "object") return false
  const record = value as Record<string, unknown>
  return (
    typeof record.access_token === "string" &&
    record.access_token.length > 0 &&
    typeof record.username === "string" &&
    record.username.length > 0 &&
    isAuthRole(record.role)
  )
}

export interface AuthSessionInfo {
  id: number
  jti: string
  username: string
  ip: string
  user_agent: string
  device_info: string
  login_at: string
  last_active_at: string
  expires_at: string
}

export type RefreshOutcome =
  | {
      ok: true
      accessToken: string
      expiresAt: number | null
      data: AuthTokenResponse
    }
  | { ok: false; reason: "unauthorized" | "unavailable"; status?: number }

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public data?: any
  ) {
    super(message)
    this.name = "ApiError"
  }
}

/**
 * 获取存储的 access token
 */
function getToken(): string | null {
  if (typeof window === "undefined") return null
  return localStorage.getItem(ACCESS_TOKEN_KEY)
}

/** 获取当前保存的 access token，供认证状态钩子复用。 */
export function getAccessToken(): string | null {
  return getToken()
}

function parseExpiresAt(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value > 1_000_000_000_000 ? value : value * 1000
  }
  if (typeof value === "string" && /^\d+(?:\.\d+)?$/.test(value.trim())) {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) {
      return parsed > 1_000_000_000_000 ? parsed : parsed * 1000
    }
  }
  return null
}

function decodeTokenExpiry(token: string): number | null {
  if (typeof window === "undefined" || typeof window.atob !== "function") {
    return null
  }
  try {
    const encoded = token.split(".")[1]
    if (!encoded) return null
    const normalized = encoded.replace(/-/g, "+").replace(/_/g, "/")
    const padded = normalized.padEnd(
      normalized.length + ((4 - (normalized.length % 4)) % 4),
      "="
    )
    const payload = JSON.parse(window.atob(padded)) as { exp?: unknown }
    return parseExpiresAt(payload.exp)
  } catch {
    return null
  }
}

/** 获取后端返回的 access token 到期时间（毫秒时间戳）。 */
export function getAccessTokenExpiry(): number | null {
  if (typeof window === "undefined") return null
  const stored = parseExpiresAt(
    localStorage.getItem(ACCESS_TOKEN_EXPIRES_AT_KEY)
  )
  return stored ?? decodeTokenExpiry(getToken() || "")
}

/**
 * 设置 access token
 */
function setToken(token: string, expiresAt?: unknown): void {
  if (typeof window === "undefined") return
  localStorage.setItem(ACCESS_TOKEN_KEY, token)
  const normalized = parseExpiresAt(expiresAt) ?? decodeTokenExpiry(token)
  if (normalized !== null) {
    localStorage.setItem(ACCESS_TOKEN_EXPIRES_AT_KEY, String(normalized))
  } else {
    localStorage.removeItem(ACCESS_TOKEN_EXPIRES_AT_KEY)
  }
}

/** 保存登录或刷新响应中的 access token 与 expires_at。 */
export function storeAuthToken(token: string, expiresAt?: unknown): void {
  refreshResultCache = null
  authEpoch += 1
  setToken(token, expiresAt)
}

/**
 * 清除 token
 */
function clearToken(): void {
  if (typeof window === "undefined") return
  refreshResultCache = null
  authEpoch += 1
  localStorage.removeItem(ACCESS_TOKEN_KEY)
  localStorage.removeItem(ACCESS_TOKEN_EXPIRES_AT_KEY)
}

function staleRefreshOutcome(status?: number): RefreshOutcome {
  return { ok: false, reason: "unavailable", status }
}

function parseRefreshLockRecord(raw: string | null): RefreshLockRecord | null {
  if (!raw) return null
  try {
    const record = JSON.parse(raw) as Partial<RefreshLockRecord>
    if (
      typeof record.owner !== "string" ||
      record.owner.length === 0 ||
      typeof record.expires_at !== "number" ||
      !Number.isFinite(record.expires_at)
    ) {
      return null
    }
    return { owner: record.owner, expires_at: record.expires_at }
  } catch {
    return null
  }
}

function readRefreshLock(): RefreshLockRecord | null {
  if (typeof window === "undefined") return null
  try {
    return parseRefreshLockRecord(
      localStorage.getItem(REFRESH_LOCK_STORAGE_KEY)
    )
  } catch {
    return null
  }
}

/**
 * 读取所有仍有效的刷新意图。
 *
 * localStorage 没有 compare-and-set；每个标签页先登记独立意图，再以
 * 可见意图中的确定性最小 owner 竞争租约。这样一个标签页在读到空锁后，
 * 另一个标签页即使随后完成登记，也只能观察到已存在的租约并等待，不能
 * 依靠覆盖单一锁值取得第二个刷新请求。
 */
function readRefreshLockIntents(): RefreshLockRecord[] {
  if (typeof window === "undefined") return []
  const intents: RefreshLockRecord[] = []
  const now = Date.now()
  try {
    for (let index = 0; index < localStorage.length; index += 1) {
      const key = localStorage.key(index)
      if (!key?.startsWith(REFRESH_LOCK_INTENT_PREFIX)) continue
      const record = parseRefreshLockRecord(localStorage.getItem(key))
      if (record && record.expires_at > now) intents.push(record)
    }
  } catch {
    return []
  }
  return intents
}

function isRefreshLockTurn(): boolean {
  const intents = readRefreshLockIntents()
  if (intents.length === 0) return true
  let winner = intents[0].owner
  for (const intent of intents.slice(1)) {
    // 使用代码单元顺序，避免 localeCompare 受浏览器语言环境影响。
    if (intent.owner < winner) winner = intent.owner
  }
  return winner === refreshLockOwner
}

function removeRefreshLockIntent(): void {
  if (typeof window === "undefined") return
  try {
    const record = parseRefreshLockRecord(
      localStorage.getItem(`${REFRESH_LOCK_INTENT_PREFIX}${refreshLockOwner}`)
    )
    if (record?.owner === refreshLockOwner) {
      localStorage.removeItem(
        `${REFRESH_LOCK_INTENT_PREFIX}${refreshLockOwner}`
      )
    }
  } catch {
    // Storage can become unavailable while a page is being torn down.
  }
}

function sleepForRefreshLock(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms))
}

async function withLocalStorageRefreshLock(
  requestEpoch: number,
  requestToken: string | null
): Promise<RefreshOutcome> {
  if (typeof window === "undefined") return doRefreshToken()
  const deadline = Date.now() + REFRESH_LOCK_WAIT_MS
  let claimed = false
  let intentRegistered = false
  let leaseTimer: number | null = null
  try {
    const intentKey = `${REFRESH_LOCK_INTENT_PREFIX}${refreshLockOwner}`
    localStorage.setItem(
      intentKey,
      JSON.stringify({
        owner: refreshLockOwner,
        expires_at: Date.now() + REFRESH_LOCK_TTL_MS,
      } satisfies RefreshLockRecord)
    )
    intentRegistered = true
    while (Date.now() < deadline) {
      if (requestEpoch !== authEpoch || getToken() !== requestToken) {
        return staleRefreshOutcome()
      }
      const current = readRefreshLock()
      if (
        current &&
        current.owner !== refreshLockOwner &&
        current.expires_at > Date.now()
      ) {
        await sleepForRefreshLock(REFRESH_LOCK_POLL_MS)
        continue
      }
      if (!isRefreshLockTurn()) {
        await sleepForRefreshLock(REFRESH_LOCK_POLL_MS)
        continue
      }
      const record: RefreshLockRecord = {
        owner: refreshLockOwner,
        expires_at: Date.now() + REFRESH_LOCK_TTL_MS,
      }
      localStorage.setItem(REFRESH_LOCK_STORAGE_KEY, JSON.stringify(record))
      const confirmed = readRefreshLock()
      if (
        confirmed?.owner === refreshLockOwner &&
        confirmed.expires_at > Date.now() &&
        isRefreshLockTurn()
      ) {
        claimed = true
        if (typeof window.setInterval === "function") {
          leaseTimer = window.setInterval(() => {
            try {
              const currentLease = readRefreshLock()
              if (currentLease?.owner !== refreshLockOwner) return
              const renewed: RefreshLockRecord = {
                owner: refreshLockOwner,
                expires_at: Date.now() + REFRESH_LOCK_TTL_MS,
              }
              localStorage.setItem(
                REFRESH_LOCK_STORAGE_KEY,
                JSON.stringify(renewed)
              )
              localStorage.setItem(intentKey, JSON.stringify(renewed))
            } catch {
              // The lease still has a bounded expiry if storage is interrupted.
            }
          }, REFRESH_LOCK_RENEW_MS)
        }
        break
      }
      await sleepForRefreshLock(REFRESH_LOCK_POLL_MS)
    }
    if (!claimed) return staleRefreshOutcome()
    if (requestEpoch !== authEpoch || getToken() !== requestToken) {
      return staleRefreshOutcome()
    }
    return await doRefreshToken()
  } catch {
    // Storage can be unavailable in privacy-restricted contexts. Preserve the
    // existing in-tab epoch checks instead of failing an otherwise valid session.
    return doRefreshToken()
  } finally {
    if (leaseTimer !== null) window.clearInterval(leaseTimer)
    if (claimed) {
      try {
        if (readRefreshLock()?.owner === refreshLockOwner) {
          localStorage.removeItem(REFRESH_LOCK_STORAGE_KEY)
        }
      } catch {
        // Ignore storage cleanup failures; the lease expires automatically.
      }
    }
    if (intentRegistered) removeRefreshLockIntent()
  }
}

async function refreshWithCrossTabLock(
  requestEpoch: number,
  requestToken: string | null
): Promise<RefreshOutcome> {
  if (typeof navigator !== "undefined") {
    const lockManager = (
      navigator as Navigator & { locks?: RefreshLockManager }
    ).locks
    if (lockManager?.request) {
      try {
        return await lockManager.request(
          REFRESH_LOCK_NAME,
          { mode: "exclusive" },
          async () => {
            if (requestEpoch !== authEpoch || getToken() !== requestToken) {
              return staleRefreshOutcome()
            }
            return doRefreshToken()
          }
        )
      } catch {
        // Fall through to the lease-based fallback for browsers with a partial
        // or unavailable Web Locks implementation.
      }
    }
  }
  return withLocalStorageRefreshLock(requestEpoch, requestToken)
}

/** 清除 access token 及其到期元数据。 */
export function clearAuthToken(): void {
  clearToken()
}

/**
 * 刷新 token（并发去重：多个 401 只触发一次 refresh）
 */
async function refreshToken(): Promise<RefreshOutcome> {
  if (refreshPromise) return refreshPromise
  const now = Date.now()
  const token = getToken()
  const cachedNoSessionFailure =
    token === null &&
    refreshResultCache?.token === null &&
    refreshResultCache?.outcome.ok === false
  if (
    refreshResultCache &&
    (refreshResultCache.epoch === authEpoch || cachedNoSessionFailure) &&
    refreshResultCache.token === token &&
    now < refreshResultCache.expiresAt
  ) {
    return refreshResultCache.outcome
  }
  const requestEpoch = authEpoch
  refreshPromise = refreshWithCrossTabLock(requestEpoch, token).then(
    (outcome) => {
      // 只缓存仍属于当前会话的结果；登录、登出或跨标签页轮换会使旧结果
      // 失效，避免短暂去重窗口覆盖新凭据。
      if (requestEpoch === authEpoch) {
        refreshResultCache = {
          epoch: authEpoch,
          token: getToken(),
          outcome,
          expiresAt: Date.now() + REFRESH_RESULT_CACHE_MS,
        }
      }
      return outcome
    }
  )
  try {
    return await refreshPromise
  } finally {
    refreshPromise = null
  }
}

async function doRefreshToken(): Promise<RefreshOutcome> {
  const requestEpoch = authEpoch
  const requestToken = getToken()
  try {
    const resp = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      credentials: "include",
    })
    // 登出或重新登录已经改变了认证代次；此响应属于旧会话，
    // 不能覆盖当前 token，也不能触发旧会话的登出跳转。
    if (requestEpoch !== authEpoch || getToken() !== requestToken) {
      return { ok: false, reason: "unavailable", status: resp.status }
    }
    if (resp.status === 401) {
      return { ok: false, reason: "unauthorized", status: resp.status }
    }
    if (!resp.ok) {
      return { ok: false, reason: "unavailable", status: resp.status }
    }
    const data: unknown = await resp.json()
    if (!isAuthTokenResponse(data)) {
      return { ok: false, reason: "unavailable", status: resp.status }
    }
    if (requestEpoch !== authEpoch || getToken() !== requestToken) {
      return { ok: false, reason: "unavailable", status: resp.status }
    }
    const expiresAt = parseExpiresAt(data.expires_at)
    setToken(data.access_token, data.expires_at)
    return { ok: true, accessToken: data.access_token, expiresAt, data }
  } catch {
    return { ok: false, reason: "unavailable" }
  }
}

/**
 * 使用 HttpOnly refresh cookie 获取新的 access token。
 * 网络错误和 5xx 只返回 unavailable，不会清理当前 access token。
 */
export function refreshAuthSession(): Promise<RefreshOutcome> {
  return refreshToken()
}

function isAuthEndpoint(path: string): boolean {
  return (
    path === "/auth/login" ||
    path === "/auth/refresh" ||
    path === "/auth/logout"
  )
}

/**
 * 统一的 API 请求函数
 */
export async function apiRequest<T = any>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE}${path}`
  const token = getToken()

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((options.headers as Record<string, string>) || {}),
  }

  if (token) {
    headers["Authorization"] = `Bearer ${token}`
  }

  const config: RequestInit = {
    ...options,
    headers,
    credentials: "include",
  }

  // 开发模式打印请求
  if (process.env.NODE_ENV === "development") {
    console.log(`[API] ${config.method || "GET"} ${url}`)
  }

  let response = await fetch(url, config)
  let refreshUnavailable = false

  // 401 时尝试刷新 token
  if (response.status === 401 && !isAuthEndpoint(path)) {
    const tokenChangedBeforeRefresh = getToken()
    if (tokenChangedBeforeRefresh && tokenChangedBeforeRefresh !== token) {
      // 另一标签页可能已经完成轮换并写入 localStorage，但 storage 事件
      // 尚未让当前 JS 上下文重新执行。直接复用新 token，避免重复消费
      // 一次性 refresh token。
      headers["Authorization"] = `Bearer ${tokenChangedBeforeRefresh}`
      config.headers = headers
      response = await fetch(url, config)
    } else {
      const refresh = await refreshToken()
      if (refresh.ok && getToken() === refresh.accessToken) {
        headers["Authorization"] = `Bearer ${refresh.accessToken}`
        config.headers = headers
        response = await fetch(url, config)
      } else if (refresh.ok) {
        // 登出/重新登录已经替换了当前 token；不要用旧 refresh
        // 结果重试业务请求。
        throw new ApiError(401, "会话已变更，请重试")
      } else if (refresh.reason === "unauthorized") {
        clearToken()
        if (
          typeof window !== "undefined" &&
          window.location.pathname !== "/login"
        ) {
          window.location.href = "/login"
        }
        throw new ApiError(401, "会话已过期，请重新登录", {
          refresh_status: "unauthorized",
        })
      } else {
        // refresh 等待期间另一标签页可能刚好写入了新 token；确认变化后
        // 再重试一次原请求。token 未变化时保留原始 401 与可区分的原因。
        const currentToken = getToken()
        if (currentToken && currentToken !== token) {
          headers["Authorization"] = `Bearer ${currentToken}`
          config.headers = headers
          response = await fetch(url, config)
        } else {
          // Refresh 服务暂时不可达时保留原始 401 语义，但附带可区分的原因；
          // 路由守卫不能把一次网络/5xx 故障误判为凭据失效并清空 token。
          refreshUnavailable = true
        }
      }
    }
  }

  let data: any
  const contentType = response.headers.get("content-type")
  if (response.status === 204 || response.status === 205) {
    // 204/205 允许带 application/json 头，但响应体必须为空；不能调用 response.json()。
    data = null
  } else if (contentType && contentType.includes("application/json")) {
    // 某些成功接口会返回 JSON Content-Type 但没有响应体，空字符串不是合法 JSON。
    const text = await response.text()
    data = text ? JSON.parse(text) : null
  } else {
    const text = await response.text()
    data = text ? { text } : null
  }

  if (!response.ok) {
    const message = data?.error || `请求失败: ${response.status}`
    const errorData = refreshUnavailable
      ? {
          ...(data && typeof data === "object" && !Array.isArray(data)
            ? data
            : {}),
          refresh_status: "unavailable",
        }
      : data
    throw new ApiError(response.status, message, errorData)
  }

  return data as T
}

/**
 * GET 请求快捷方法
 */
export function get<T = any>(
  path: string,
  params?: Record<string, string | number | boolean | undefined>
): Promise<T> {
  const query = params
    ? "?" +
      Object.entries(params)
        .filter(([, v]) => v !== undefined && v !== "")
        .map(
          ([k, v]) =>
            `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`
        )
        .join("&")
    : ""
  return apiRequest<T>(`${path}${query}`)
}

/**
 * POST 请求快捷方法
 */
export function post<T = any>(path: string, body?: any): Promise<T> {
  return apiRequest<T>(path, {
    method: "POST",
    body: body ? JSON.stringify(body) : undefined,
  })
}

/**
 * PUT 请求快捷方法
 */
export function put<T = any>(path: string, body?: any): Promise<T> {
  return apiRequest<T>(path, {
    method: "PUT",
    body: body ? JSON.stringify(body) : undefined,
  })
}

/**
 * DELETE 请求快捷方法
 */
export function del<T = any>(path: string): Promise<T> {
  return apiRequest<T>(path, { method: "DELETE" })
}

/**
 * 实时推送相关 API。
 */
export const realtimeApi = {
  ticket: () => get<RealtimeTicketResponse>("/realtime/ticket"),
}

/**
 * 拉取站点资源型列表的全部分页；后端单页上限为 200，最多聚合 10 页，
 * 防止异常 total 让浏览器无限请求或一次性占用不可控内存。
 */
async function getAllSitePages<T>(
  path: string,
  first: { items: T[]; total: number }
): Promise<T[]> {
  const items = [...(first.items ?? [])]
  const total = Number.isFinite(first.total)
    ? Math.max(0, first.total)
    : items.length
  const pageCount = Math.min(
    MAX_SITE_RESOURCE_PAGES,
    Math.max(1, Math.ceil(total / FRONTEND_PAGE_SIZE))
  )
  if (pageCount <= 1) return items
  const pages = await Promise.all(
    Array.from({ length: pageCount - 1 }, (_, index) =>
      get<{ items: T[]; total: number }>(path, {
        page: index + 2,
        page_size: FRONTEND_PAGE_SIZE,
      })
    )
  )
  for (const page of pages) items.push(...(page.items ?? []))
  return items.slice(
    0,
    Math.min(total, FRONTEND_PAGE_SIZE * MAX_SITE_RESOURCE_PAGES)
  )
}

/**
 * 认证相关 API
 */
export const authApi = {
  login: (username: string, password: string) =>
    post<AuthTokenResponse>("/auth/login", { username, password }),
  refresh: () => refreshAuthSession(),
  logout: () => post("/auth/logout"),
  me: () => get<{ username: string; role: AuthRole }>("/auth/me"),
  changePassword: (oldPassword: string, newPassword: string) =>
    post<{ status: string }>("/auth/change-password", {
      old_password: oldPassword,
      new_password: newPassword,
    }),
  listSessions: () => get<{ sessions: AuthSessionInfo[] }>("/auth/sessions"),
  forceLogout: (jti: string) => post("/auth/sessions/force-logout", { jti }),
}

/**
 * 站点相关 API
 */
export const siteApi = {
  list: (params?: { page?: number; page_size?: number }) =>
    get<{ items: Site[]; total: number }>("/sites", params),
  get: (id: string | number) => get<Site>(`/sites/${id}`),
  create: (data: Partial<Site>) => post<Site>("/sites", data),
  update: (id: string | number, data: Partial<Site>) =>
    post<Site>(`/sites/${id}/update`, data),
  delete: (id: string | number) => post(`/sites/${id}/delete`),
  start: (id: string | number) => post(`/sites/${id}/start`),
  stop: (id: string | number) => post(`/sites/${id}/stop`),
  getStatus: (id: string | number) =>
    get<{ status: string }>(`/sites/${id}/status`),
  getListeners: (id: string | number) =>
    get<{ items: SiteListener[]; total: number }>(`/sites/${id}/listeners`),
  createListener: (id: string | number, data: Partial<SiteListener>) =>
    post(`/sites/${id}/listeners`, data),
  updateListener: (
    id: string | number,
    lid: string | number,
    data: Partial<SiteListener>
  ) => post(`/sites/${id}/listeners/${lid}/update`, data),
  deleteListener: (id: string | number, lid: string | number) =>
    post(`/sites/${id}/listeners/${lid}/delete`),
  getSecurityEvents: (id: string | number, params?: any) =>
    get(`/sites/${id}/security-events`, params),
  getAccessLogs: (id: string | number, params?: any) =>
    get(`/sites/${id}/access-logs`, params),
  getRules: (id: string | number) =>
    get<{ items: Rule[]; total: number; policy_id?: number }>(
      `/sites/${id}/rules`
    ),
  getRouteRules: (id: string | number) =>
    get<{ items: AppRouteRule[]; total: number }>(
      `/sites/${id}/application-route-rules`,
      { page: 1, page_size: FRONTEND_PAGE_SIZE }
    ).then((first) =>
      getAllSitePages(`/sites/${id}/application-route-rules`, first)
    ),
  getRecordedResources: (id: string | number) =>
    get<{ items: RecordedResource[]; total: number }>(
      `/sites/${id}/recorded-resources`,
      { page: 1, page_size: FRONTEND_PAGE_SIZE }
    ).then((first) =>
      getAllSitePages(`/sites/${id}/recorded-resources`, first)
    ),
  createRouteRule: (id: string | number, data: AppRouteRuleWriteInput) =>
    post<AppRouteRule>(`/sites/${id}/application-route-rules`, data),
  updateRouteRule: (
    id: string | number,
    rid: string | number,
    data: AppRouteRuleWriteInput
  ) =>
    post<AppRouteRule>(
      `/sites/${id}/application-route-rules/${rid}/update`,
      data
    ),
  deleteRouteRule: (id: string | number, rid: string | number) =>
    post(`/sites/${id}/application-route-rules/${rid}/delete`),
  clearRecordedResources: (id: string | number) =>
    post<{ status: string }>(`/sites/${id}/recorded-resources/clear`),
  getErrorPages: (id: string | number) =>
    get<SiteErrorPages>(`/sites/${id}/error-pages`),
  updateErrorPages: (
    id: string | number,
    data: { error_pages: Record<string, import("@/lib/types").ErrorPageConfig> }
  ) => post<SiteErrorPages>(`/sites/${id}/error-pages`, data),
}

/**
 * 证书相关 API
 */
export const certificateApi = {
  list: () =>
    get<{ items: Certificate[]; total: number }>("/certificates").then(
      (r) => r.items ?? []
    ),
  get: (id: string | number) => get<Certificate>(`/certificates/${id}`),
  create: (data: Partial<Certificate>) =>
    post<Certificate>("/certificates", data),
  update: (id: string | number, data: Partial<Certificate>) =>
    post<Certificate>(`/certificates/${id}/update`, data),
  delete: (id: string | number) => post(`/certificates/${id}/delete`),
  /** 解析证书 PEM，返回 CN / SAN / 到期时间与命中站点；不接收也不返回私钥 */
  parse: (certPem: string) =>
    post<CertificateParseResult>("/certificates/parse", { cert_pem: certPem }),
  applyToSites: (id: string | number, siteIds: number[]) =>
    post(`/certificates/${id}/apply-to-sites`, { site_ids: siteIds }),
  getACMEConfig: () => get("/certificates/acme/config"),
  updateACMEConfig: (data: any) => post("/certificates/acme/config", data),
  acmeApply: (data: any) => post("/certificates/acme/apply", data),
  acmeRenew: (id: string | number) => post(`/certificates/acme/${id}/renew`),
  getACMEStatus: () => get("/certificates/acme/status"),
}

/**
 * 规则相关 API
 */
export const ruleApi = {
  list: (params?: RuleListParams) =>
    get<RuleListResponse>("/rules", params ? { ...params } : undefined),
  get: (id: string | number) => get<Rule>(`/rules/${id}`),
  create: (data: Partial<Rule>) => post<Rule>("/rules", data),
  update: (id: string | number, data: Partial<Rule>) =>
    post(`/rules/${id}/update`, data),
  delete: (id: string | number) => post(`/rules/${id}/delete`),
  test: (data: any) => post("/rules/test", data),
  validate: (data: any) => post("/rules/validate", data),
  import: (data: Partial<RuleExportPayload>) =>
    post<RuleImportResponse>("/rules/import", data),
  export: () => get<RuleExportPayload>("/rules/export"),
  getTemplates: () => get<{ templates: RuleTemplate[] }>("/rules/templates"),
}

/**
 * 策略相关 API
 */
export const policyApi = {
  list: (params?: { page?: number; page_size?: number }) =>
    get<{ items: Policy[]; total: number }>("/policies", params),
  get: (id: string | number) => get<Policy>(`/policies/${id}`),
  getDefault: () => get<Policy>("/policies/default"),
  setDefault: (id: string | number) =>
    post<Policy>(`/policies/${id}/set-default`),
  create: (data: Partial<Policy>) => post<Policy>("/policies", data),
  update: (id: string | number, data: Partial<Policy>) =>
    post<Policy>(`/policies/${id}/update`, data),
  delete: (id: string | number) => post(`/policies/${id}/delete`),
}

/**
 * 防护设置相关 API
 */
export const protectionApi = {
  getSettings: () => get<ProtectionSettings>("/protection-settings"),
  updateSettings: (data: ProtectionSettingsUpdate) =>
    post<ProtectionSettings>("/protection-settings", data),
  getSensitivity: (id: string | number) =>
    get<SensitivityConfig>(`/protection/${id}/sensitivity`),
  updateSensitivity: (id: string | number, data: SensitivityConfig) =>
    post<SensitivityConfig>(`/protection/${id}/sensitivity`, data),
  getEscalation: (id: string | number) =>
    get<EscalationConfig>(`/protection/${id}/escalation`),
  updateEscalation: (id: string | number, data: EscalationConfigUpdate) =>
    post<EscalationConfig>(`/protection/${id}/escalation`, data),
  getEscalationStatus: (ip: string) => get(`/escalation/status/${ip}`),
  resetEscalation: (ip: string) => post(`/escalation/status/${ip}/reset`),
}

/**
 * IP 列表相关 API
 */
export const ipListApi = {
  list: (params?: { kind?: string; site_id?: number; page?: number }) =>
    get<{ items: IPEntry[]; total: number; page?: number }>(
      "/ip-lists",
      params
    ),
  get: (id: string | number) => get<IPEntry>(`/ip-lists/${id}`),
  create: (data: Partial<IPEntry>) => post<IPEntry>("/ip-lists", data),
  update: (id: string | number, data: Partial<IPEntry>) =>
    post<IPEntry>(`/ip-lists/${id}/update`, data),
  delete: (id: string | number) => post(`/ip-lists/${id}/delete`),
}

/**
 * 安全事件相关 API
 */
export const securityEventApi = {
  list: (params?: any) =>
    get<{ items: SecurityEvent[]; total: number; page: number }>(
      "/security-events",
      params
    ),
  get: (id: string | number) => get<SecurityEvent>(`/security-events/${id}`),
  getStats: (params?: any) => get("/security-events/stats", params),
  getTimeline: (params?: any) => get("/security-events/timeline", params),
  getSiteStats: (id: string | number, params?: any) =>
    get(`/sites/${id}/security-events/stats`, params),
  getSiteTimeline: (id: string | number, params?: any) =>
    get(`/sites/${id}/security-events/timeline`, params),
  listRequests: (params?: any) =>
    get<{ items: SecurityEventRequest[]; total: number; page: number }>(
      "/security-events/requests",
      params
    ),
}

/**
 * 访问日志相关 API
 */
export const accessLogApi = {
  list: (params?: any) =>
    get<{ items: AccessLog[]; total: number }>("/access-logs", params),
  get: (id: string | number) => get<AccessLog>(`/access-logs/${id}`),
  getSiteStats: (id: string | number, params?: any) =>
    get(`/sites/${id}/access-logs/stats`, params),
}

/**
 * 请求追踪相关 API
 * 通过 request_id 查询完整链路
 */
export const requestTraceApi = {
  get: (requestId: string) =>
    get<RequestTrace>(`/request/${encodeURIComponent(requestId)}`),
}

/**
 * Dashboard 相关 API
 */
export const dashboardApi = {
  getSummary: () => get<DashboardSummary>("/dashboard/summary"),
}

/**
 * Bot 相关 API
 */
export const botApi = {
  getSettings: () => get<BotSettings>("/bot-settings"),
  updateSettings: (data: Partial<BotSettings>) =>
    post<BotSettings>("/bot-settings/update", data),
  getStats: () => get<BotScoreStats>("/bot-stats"),
  getScores: (
    params?: Record<string, string | number | boolean | undefined>
  ) => get<BotScoreListResponse>("/bot-scores", params),
}

/**
 * 验证码相关 API
 */
export const captchaApi = {
  getConfig: () => get<CaptchaConfig>("/captcha/config"),
  updateConfig: (data: Partial<CaptchaConfig>) =>
    post<CaptchaConfig>("/captcha/config", data),
  test: (captchaType?: string) =>
    post<CaptchaTestResponse>(
      "/captcha/test",
      captchaType ? { captcha_type: captchaType } : undefined
    ),
}

/**
 * 链式验证相关 API
 */
export const chainApi = {
  getConfig: () => get<ChainConfig>("/chain/config"),
  updateConfig: (data: Partial<ChainConfig>) =>
    post<ChainConfig>("/chain/config", data),
  getSessions: () => get<ChainSessionsResponse>("/chain/sessions"),
  deleteSession: (id: string | number) => post(`/chain/sessions/${id}/delete`),
}

/**
 * CVE 规则相关 API
 */
export const cveApi = {
  list: (params?: Record<string, string | number | boolean | undefined>) =>
    get<CVERuleListResponse>("/cve-rules", params),
  getStats: (params?: Record<string, string | number | boolean | undefined>) =>
    get<CVEStats>("/cve-rules/stats", params),
  getFeedStatus: () => get("/cve-feed/status"),
  toggle: (id: string | number, enabled?: boolean) =>
    post(
      `/cve-rules/${id}/toggle`,
      enabled === undefined ? undefined : { enabled }
    ),
  patch: (id: string | number, data: Record<string, unknown>) =>
    post(`/cve-rules/${id}/patch`, data),
  /** 创建全局自定义 CVE 规则。 */
  create: (data: CVERuleWriteInput) => post<CVERuleItem>("/cve-rules", data),
  /** 更新全局自定义 CVE 规则；内置规则不得调用此端点。 */
  update: (id: string | number, data: Partial<CVERuleWriteInput>) =>
    post<CVERuleItem>(`/cve-rules/${id}/update`, data),
  /** 删除全局自定义 CVE 规则；后端会拒绝目录规则。 */
  delete: (id: string | number) =>
    post<{ message: string }>(`/cve-rules/${id}/delete`),
  reset: (id: string | number, data: Record<string, unknown>) => {
    const query = Object.entries(data)
      .filter(([, value]) => value !== undefined && value !== "")
      .map(
        ([key, value]) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`
      )
      .join("&")
    return post(`/cve-rules/${id}/reset${query ? `?${query}` : ""}`)
  },
  batch: (data: Record<string, unknown>) => post("/cve-rules/batch", data),
  sync: () => post("/cve-rules/sync"),
}

/**
 * OWASP 规则相关 API
 */
export const owaspApi = {
  list: (params?: Record<string, string | number | boolean | undefined>) =>
    get<OWASPRuleListResponse>("/owasp-rules", params),
  getStats: (params?: Record<string, string | number | boolean | undefined>) =>
    get<OWASPStats>("/owasp-rules/stats", params),
  update: (id: string | number, data: Record<string, unknown>) =>
    post(`/owasp-rules/${id}/update`, data),
  reset: (id: string | number, policyId: number) =>
    post(
      `/owasp-rules/${id}/reset?policy_id=${encodeURIComponent(String(policyId))}`
    ),
  batch: (data: Record<string, unknown>) => post("/owasp-rules/batch", data),
}

/**
 * 丢弃策略相关 API
 */
export const dropApi = {
  getPolicy: () => get("/drop-policy"),
  updatePolicy: (data: any) => post("/drop-policy/update", data),
  getStats: () => get("/drop-stats"),
  getEvents: (params?: any) => get("/drop-events", params),
}

/**
 * 系统设置相关 API
 */
export const settingsApi = {
  list: () => get("/settings"),
  get: (key: string) => get(`/settings/${key}`),
  set: (key: string, value: any) => post(`/settings/${key}`, { value }),
  delete: (key: string) => post(`/settings/${key}/delete`),
  getNetwork: () => get("/network-config"),
  updateNetwork: (data: any) => post("/network-config", data),
  getHTTP2: () => get("/http2-config"),
  updateHTTP2: (data: any) => post("/http2-config", data),
  getLog: () => get("/log-config"),
  updateLog: (data: any) => post("/log-config", data),
  getTLS: () => get("/tls-config"),
  updateTLS: (data: any) => post("/tls-config", data),
  getCipherSuites: () => get("/tls-cipher-suites"),
  getRedis: () => get("/redis-config"),
  updateRedis: (data: RedisConfigUpdate) =>
    post<RedisConfigResponse>("/redis-config", data),
}

/**
 * 上游相关 API
 */
export const upstreamApi = {
  getStatus: () => get<UpstreamStatusResponse>("/upstreams/status"),
}

/**
 * 运行时配置相关 API
 */
export const runtimeApi = {
  getConfig: () => get<RuntimeConfig>("/runtime-config"),
}

/**
 * API 密钥相关 API
 */
export const apiKeyApi = {
  list: () =>
    get<{ items: AdminAPIKey[] }>("/api-keys").then((r) => r.items ?? []),
  create: (data: { name: string }) =>
    post<{ token: string; id: number; name: string }>("/api-keys", data),
  delete: (id: string | number) => post(`/api-keys/${id}/delete`),
}

/**
 * 管理员账户相关 API
 */
export const adminUserApi = {
  list: () =>
    get<{ items: AdminUser[] }>("/admin-users").then((r) => r.items ?? []),
  create: (data: { username: string; password: string; role: string }) =>
    post<AdminUser>("/admin-users", data),
  updateRole: (id: string | number, role: string) =>
    post(`/admin-users/${id}/update-role`, { role }),
  updatePassword: (id: string | number, password: string) =>
    post(`/admin-users/${id}/update-password`, { password }),
  delete: (id: string | number) => post(`/admin-users/${id}/delete`),
}

/**
 * 错误页面相关 API
 */
export const errorPageApi = {
  getDefaults: () => get<DefaultErrorPagesResponse>("/error-pages/defaults"),
  preview: (data: ErrorPagePreviewRequest) =>
    post<ErrorPagePreviewResponse>("/error-pages/preview", data),
}

/**
 * 页面模板相关 API
 */
export const pageTemplateApi = {
  getAll: () => get("/page-templates"),
  get: (type: string) => get(`/page-templates/${type}`),
  update: (type: string, data: Record<string, string>) =>
    post(`/page-templates/${type}`, data),
  reset: (type: string) => post(`/page-templates/${type}/reset`),
  preview: (type: string) =>
    get<unknown>(`/page-templates/${type}/preview`).then(unwrapTextResponse),
  previewDraft: (type: string, data: Record<string, string>) =>
    post<unknown>(`/page-templates/${type}/preview`, data).then(
      unwrapTextResponse
    ),
}

/**
 * 解包返回 text/html 的管理端预览响应。
 * apiRequest 对非 JSON 响应统一包装为 { text }，而预览调用方需要原始 HTML
 * 字符串写入 sandbox iframe；仅在页面模板 API 边界转换，避免改变其他调用方契约。
 */
function unwrapTextResponse(value: unknown): string {
  if (typeof value === "string") return value
  if (value && typeof value === "object" && "text" in value) {
    const text = (value as { text?: unknown }).text
    return typeof text === "string" ? text : ""
  }
  return ""
}

/**
 * 系统相关 API
 */
export const systemApi = {
  reload: () => post("/reload"),
}

/**
 * 威胁情报订阅相关 API
 */
export const threatIntelApi = {
  list: () =>
    get<{ items: ThreatIntelFeed[]; total: number }>("/threat-intel-feeds"),
  create: (data: Partial<ThreatIntelFeed>) =>
    post<ThreatIntelFeed>("/threat-intel-feeds", data),
  update: (id: string | number, data: Partial<ThreatIntelFeed>) =>
    post<ThreatIntelFeed>(`/threat-intel-feeds/${id}/update`, data),
  delete: (id: string | number) => post(`/threat-intel-feeds/${id}/delete`),
  sync: (id: string | number) =>
    post<ThreatIntelFeed>(`/threat-intel-feeds/${id}/sync`),
  listSyncLogs: (params?: {
    page?: number
    page_size?: number
    feed_id?: number
    status?: "success" | "failed"
  }) =>
    get<{
      items: ThreatIntelSyncLog[]
      total: number
      page: number
      page_size: number
    }>("/threat-intel-sync-logs", params),
}

/**
 * 站点访问控制相关 API
 */
export const accessApi = {
  getConfig: (siteId: string | number) =>
    get<SiteAccessConfig>(`/sites/${siteId}/access`),
  saveConfig: (
    siteId: string | number,
    data: {
      enabled: boolean
      session_ttl: number
      shared_password?: string
      clear_shared_password?: boolean
    }
  ) => post(`/sites/${siteId}/access`, data),

  listProviders: (siteId: string | number) =>
    get<{ providers: AccessProvider[] }>(
      `/sites/${siteId}/access/providers`
    ).then((r) => r.providers ?? []),
  createProvider: (siteId: string | number, data: AccessProviderCreateInput) =>
    post<AccessProvider>(`/sites/${siteId}/access/providers`, data),
  updateProvider: (
    siteId: string | number,
    pid: string | number,
    data: AccessProviderUpdateInput
  ) => post(`/sites/${siteId}/access/providers/${pid}/update`, data),
  deleteProvider: (siteId: string | number, pid: string | number) =>
    post(`/sites/${siteId}/access/providers/${pid}/delete`),

  listUsers: (siteId: string | number) =>
    get<{ users: AccessUser[] }>(`/sites/${siteId}/access/users`).then(
      (r) => r.users ?? []
    ),
  createUser: (siteId: string | number, data: AccessUserCreateInput) =>
    post<AccessUser>(`/sites/${siteId}/access/users`, data),
  updateUser: (
    siteId: string | number,
    uid: string | number,
    data: AccessUserUpdateInput
  ) => post(`/sites/${siteId}/access/users/${uid}/update`, data),
  deleteUser: (siteId: string | number, uid: string | number) =>
    post(`/sites/${siteId}/access/users/${uid}/delete`),

  listPathRules: (siteId: string | number) =>
    get<{ rules: AccessPathRule[] }>(`/sites/${siteId}/access/rules`).then(
      (r) => r.rules ?? []
    ),
  createPathRule: (siteId: string | number, data: AccessPathRuleCreateInput) =>
    post<AccessPathRule>(`/sites/${siteId}/access/rules`, data),
  updatePathRule: (
    siteId: string | number,
    rid: string | number,
    data: AccessPathRuleUpdateInput
  ) => post(`/sites/${siteId}/access/rules/${rid}/update`, data),
  deletePathRule: (siteId: string | number, rid: string | number) =>
    post(`/sites/${siteId}/access/rules/${rid}/delete`),
}

/**
 * 误报反馈相关 API
 */
export const falsePositiveApi = {
  list: (params?: { page?: number; page_size?: number; status?: string }) =>
    get<{
      items: FalsePositiveReport[]
      total: number
      page?: number
      page_size?: number
    }>("/false-positives", params),
  create: (data: FalsePositiveCreateRequest) =>
    post<FalsePositiveReport>("/false-positives", data),
  updateStatus: (id: number, status: string) =>
    post<{ id: number; status: string }>(`/false-positives/${id}/status`, {
      status,
    }),
  delete: (id: number) => post(`/false-positives/${id}/delete`),
}

/**
 * 配置备份/恢复相关 API
 */
export const backupApi = {
  export: () => get<BackupData>("/backup/export"),
  import: (data: BackupData, replaceMode: boolean) =>
    post<ImportResult>("/backup/import", { data, replace_mode: replaceMode }),
}

/**
 * 预置爬虫白名单相关 API
 * - preview: 预览预置条目，不写库
 * - seed: 将预置条目写入 IP 白名单表（已存在的跳过）
 */
export const presetBotWhitelistApi = {
  preview: () =>
    get<{ items: Array<{ value: string; note: string }>; total: number }>(
      "/preset-bot-whitelist"
    ),
  seed: () =>
    post<{ added: number; skipped: number; entries: string[] }>(
      "/preset-bot-whitelist/seed"
    ),
}

/**
 * Lua 自定义策略插件相关 API
 *
 * update 只覆盖请求中提供的字段；site_id 显式传 null 才会改回「全站生效」，
 * 省略则保持原值——这是后端 json.RawMessage 三态语义，不能简化为可选字段。
 */
export const luaPluginApi = {
  list: () => get<{ items: LuaPlugin[]; total: number }>("/lua-plugins"),
  get: (id: string | number) => get<LuaPlugin>(`/lua-plugins/${id}`),
  create: (data: Partial<LuaPlugin>) => post<LuaPlugin>("/lua-plugins", data),
  update: (id: string | number, data: Partial<LuaPlugin>) =>
    post<LuaPlugin>(`/lua-plugins/${id}/update`, data),
  delete: (id: string | number) => post(`/lua-plugins/${id}/delete`),
  toggle: (id: string | number, enabled?: boolean) =>
    post<{ id: number; enabled: boolean }>(
      `/lua-plugins/${id}/toggle`,
      enabled === undefined ? undefined : { enabled }
    ),
  validate: (data: { stage: LuaPluginStage; source: string }) =>
    post<LuaValidateResult>("/lua-plugins/validate", data),
  dryRun: (data: LuaDryRunRequest) =>
    post<LuaDryRunResult>("/lua-plugins/dry-run", data),
  /** 运行时统计。按脚本名聚合，不含数据库 id，只覆盖当前已载入引擎的脚本。 */
  stats: () => get<LuaPluginStatsResponse>("/lua-plugins/stats"),
}

/** JavaScript 边缘插件相关 API。 */
export const jsPluginApi = {
  list: () => get<JSPluginListResponse>("/js-plugins"),
  get: (id: string | number) => get<JSPlugin>(`/js-plugins/${id}`),
  create: (data: JSPluginCreateRequest) => post<JSPlugin>("/js-plugins", data),
  update: (id: string | number, data: JSPluginUpdateRequest) =>
    post<JSPlugin>(`/js-plugins/${id}/update`, data),
  delete: (id: string | number) => post(`/js-plugins/${id}/delete`),
  toggle: (id: string | number, enabled?: boolean) =>
    post<JSPluginToggleResponse>(
      `/js-plugins/${id}/toggle`,
      enabled === undefined ? undefined : { enabled }
    ),
  validate: (data: JSPluginValidateRequest) =>
    post<JSPluginValidateResult>("/js-plugins/validate", data),
  dryRun: (data: JSPluginDryRunRequest) =>
    post<JSPluginDryRunResponse>("/js-plugins/dry-run", data),
  stats: () => get<JSPluginStatsResponse>("/js-plugins/stats"),
  runtime: () => get<JSPluginRuntimeStatus>("/js-plugins/runtime"),
}

/**
 * TLS 指纹相关 API
 */
export const fingerprintApi = {
  list: (params?: { page?: number; page_size?: number }) =>
    get<{ items: TLSFingerprintSummary[]; total: number }>("/fingerprints", params),
}

// 引入类型（避免循环依赖，在文件末尾导入类型声明）
import type {
  Site,
  SiteListener,
  Certificate,
  CertificateParseResult,
  Rule,
  RuleListParams,
  RuleListResponse,
  Policy,
  SecurityEvent,
  SecurityEventRequest,
  AccessLog,
  DashboardSummary,
  AppRouteRule,
  AppRouteRuleWriteInput,
  RecordedResource,
  SiteAccessConfig,
  AccessProvider,
  AccessProviderCreateInput,
  AccessProviderUpdateInput,
  AccessUser,
  AccessUserCreateInput,
  AccessUserUpdateInput,
  AccessPathRule,
  AccessPathRuleCreateInput,
  AccessPathRuleUpdateInput,
  AdminAPIKey,
  AdminUser,
  IPEntry,
  ThreatIntelFeed,
  ThreatIntelSyncLog,
  BackupData,
  ImportResult,
  FalsePositiveReport,
  FalsePositiveCreateRequest,
  RequestTrace,
  UpstreamStatusResponse,
  LuaPlugin,
  LuaPluginStage,
  LuaValidateResult,
  LuaDryRunRequest,
  LuaDryRunResult,
  LuaPluginStatsResponse,
  JSPlugin,
  JSPluginCreateRequest,
  JSPluginUpdateRequest,
  JSPluginListResponse,
  JSPluginToggleResponse,
  JSPluginValidateRequest,
  JSPluginValidateResult,
  JSPluginDryRunRequest,
  JSPluginDryRunResponse,
  JSPluginStatsResponse,
  JSPluginRuntimeStatus,
  CaptchaConfig,
  CaptchaTestResponse,
  CVERuleListResponse,
  CVERuleItem,
  CVERuleWriteInput,
  CVEStats,
  OWASPRuleListResponse,
  OWASPStats,
  RedisConfigUpdate,
  RedisConfigResponse,
  ProtectionSettings,
  ProtectionSettingsUpdate,
  SensitivityConfig,
  EscalationConfig,
  EscalationConfigUpdate,
  RuntimeConfig,
  TLSFingerprintSummary,
} from "./types"
