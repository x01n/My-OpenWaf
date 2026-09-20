import assert from "node:assert/strict"

interface TestStorage {
  readonly length: number
  key(index: number): string | null
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

const values = new Map<string, string>()
const storage: TestStorage = {
  get length() {
    return values.size
  },
  key: (index) => [...values.keys()][index] ?? null,
  getItem: (key) => values.get(key) ?? null,
  setItem: (key, value) => values.set(key, String(value)),
  removeItem: (key) => values.delete(key),
}

Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: {
    localStorage: storage,
    atob: globalThis.atob,
    location: { pathname: "/dashboard/" },
    setTimeout: globalThis.setTimeout,
    clearTimeout: globalThis.clearTimeout,
    setInterval: globalThis.setInterval,
    clearInterval: globalThis.clearInterval,
  },
})
Object.defineProperty(globalThis, "localStorage", {
  configurable: true,
  value: storage,
})

const api = await import("../lib/api")

async function resolveRefreshAfterMutation(mutate: () => void, token: string) {
  let resolveFetch: ((response: Response) => void) | undefined
  Object.defineProperty(globalThis, "fetch", {
    configurable: true,
    value: () =>
      new Promise<Response>((resolve) => {
        resolveFetch = resolve
      }),
  })
  const pending = api.refreshAuthSession()
  mutate()
  resolveFetch?.(
    new Response(
      JSON.stringify({
        access_token: token,
        expires_at: Math.floor(Date.now() / 1000) + 900,
        username: "alice",
        role: "admin",
      }),
      { status: 200, headers: { "content-type": "application/json" } }
    )
  )
  return pending
}

api.storeAuthToken("before-logout", Math.floor(Date.now() / 1000) + 900)
const afterLogout = await resolveRefreshAfterMutation(
  () => api.clearAuthToken(),
  "stale-after-logout"
)
assert.equal(afterLogout.ok, false, "旧 refresh 不应在登出后成功")
assert.equal(api.getAccessToken(), null, "旧 refresh 不应写回已清除 token")

api.storeAuthToken("before-login", Math.floor(Date.now() / 1000) + 900)
const afterLogin = await resolveRefreshAfterMutation(
  () => api.storeAuthToken("new-login", Math.floor(Date.now() / 1000) + 900),
  "stale-after-login"
)
assert.equal(afterLogin.ok, false, "旧 refresh 不应覆盖重新登录")
assert.equal(
  api.getAccessToken(),
  "new-login",
  "重新登录 token 被旧 refresh 覆盖"
)

// refresh 返回 5xx 时，业务 401 不能被路由守卫当成凭据失效；token 必须保留
// 以便稍后重试，而不是在短暂的认证服务故障期间把用户踢回登录页。
api.storeAuthToken("transient-refresh", Math.floor(Date.now() / 1000) + 900)
let businessRequests = 0
Object.defineProperty(globalThis, "fetch", {
  configurable: true,
  value: async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith("/auth/refresh")) {
      return new Response(
        JSON.stringify({ error: "temporarily unavailable" }),
        {
          status: 503,
          headers: { "content-type": "application/json" },
        }
      )
    }
    businessRequests += 1
    return new Response(JSON.stringify({ error: "expired" }), {
      status: 401,
      headers: { "content-type": "application/json" },
    })
  },
})
try {
  await api.apiRequest("/protected")
  throw new Error("业务 401 unexpectedly succeeded")
} catch (error) {
  assert.equal(error instanceof api.ApiError, true)
  assert.equal((error as InstanceType<typeof api.ApiError>).status, 401)
  assert.equal(
    (error as InstanceType<typeof api.ApiError>).data?.refresh_status,
    "unavailable"
  )
}
assert.equal(businessRequests, 1, "refresh 不可用时不应重放业务请求")
assert.equal(
  api.getAccessToken(),
  "transient-refresh",
  "refresh 5xx 不应清空当前 token"
)

// 200 响应也必须满足认证响应契约，不能把损坏的 access token 或角色写入状态。
api.storeAuthToken("malformed-refresh", Math.floor(Date.now() / 1000) + 900)
Object.defineProperty(globalThis, "fetch", {
  configurable: true,
  value: async (input: RequestInfo | URL) => {
    if (String(input).endsWith("/auth/refresh")) {
      return new Response(
        JSON.stringify({ access_token: {}, username: "alice", role: "admin" }),
        { status: 200, headers: { "content-type": "application/json" } }
      )
    }
    return new Response(null, { status: 204 })
  },
})
const malformedRefresh = await api.refreshAuthSession()
assert.equal(malformedRefresh.ok, false, "损坏的 refresh 响应必须被拒绝")
assert.equal(
  malformedRefresh.reason,
  "unavailable",
  "损坏的 refresh 响应应按暂时不可用处理"
)
assert.equal(
  api.getAccessToken(),
  "malformed-refresh",
  "损坏的 refresh 响应不得覆盖当前 token"
)

// 另一标签页在 refresh 请求期间完成轮换时，旧响应即使返回 401 也不能清除
// 已经写入的新 token；服务端一次性轮换与浏览器 storage 事件之间保持安全边界。
api.storeAuthToken("before-cross-tab", Math.floor(Date.now() / 1000) + 900)
const crossTab = await resolveRefreshAfterMutation(
  () => storage.setItem(api.AUTH_TOKEN_STORAGE_KEY, "other-tab-token"),
  "stale-cross-tab"
)
assert.equal(crossTab.ok, false, "跨标签页 token 变化后旧 refresh 不应成功")
assert.equal(
  api.getAccessToken(),
  "other-tab-token",
  "旧 refresh 不应覆盖另一标签页的新 token"
)

// 在途结果结束后的短窗口内，多个认证消费者应复用同一 refresh 结果，
// 避免一次页面挂载触发连续轮换和额外数据库写入。
api.storeAuthToken("dedupe-refresh", Math.floor(Date.now() / 1000) + 1)
let refreshCalls = 0
Object.defineProperty(globalThis, "fetch", {
  configurable: true,
  value: async (input: RequestInfo | URL) => {
    if (String(input).endsWith("/auth/refresh")) {
      refreshCalls += 1
      return new Response(
        JSON.stringify({
          access_token: "deduped-token",
          expires_at: Math.floor(Date.now() / 1000) + 900,
          username: "alice",
          role: "admin",
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      )
    }
    return new Response(null, { status: 204 })
  },
})
const firstRefresh = await api.refreshAuthSession()
const secondRefresh = await api.refreshAuthSession()
assert.equal(firstRefresh.ok, true)
assert.equal(secondRefresh.ok, true)
assert.equal(refreshCalls, 1, "连续 refresh 应在短窗口内去重")

// 跨标签页已替换 token 时，原业务 401 应使用当前 token 自动重试一次。
api.storeAuthToken("request-old-token", Math.floor(Date.now() / 1000) + 900)
let protectedCalls = 0
let crossTabRefreshCalls = 0
Object.defineProperty(globalThis, "fetch", {
  configurable: true,
  value: async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.endsWith("/auth/refresh")) {
      crossTabRefreshCalls += 1
      api.storeAuthToken("other-tab-token", Math.floor(Date.now() / 1000) + 900)
      return new Response(JSON.stringify({ error: "rotated elsewhere" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      })
    }
    protectedCalls += 1
    if (protectedCalls === 1) {
      assert.equal(
        (init?.headers as Record<string, string>)?.Authorization,
        "Bearer request-old-token"
      )
      return new Response(JSON.stringify({ error: "expired" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      })
    }
    assert.equal(
      (init?.headers as Record<string, string>)?.Authorization,
      "Bearer other-tab-token"
    )
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    })
  },
})
const retried = await api.apiRequest<{ ok: boolean }>("/protected")
assert.deepEqual(retried, { ok: true }, "跨标签页轮换后应重试原业务请求")
assert.equal(protectedCalls, 2, "跨标签页轮换应只额外重试一次业务请求")
assert.equal(crossTabRefreshCalls, 1, "跨标签页轮换只应触发一次 refresh")

// 初始业务 401 到达前另一标签页已经写入新 token 时，客户端应直接复用
// 新 token，不应再次消费一次性 refresh cookie。
api.storeAuthToken("request-before-rotation", Math.floor(Date.now() / 1000) + 900)
let preRotatedCalls = 0
let preRotatedRefreshCalls = 0
Object.defineProperty(globalThis, "fetch", {
  configurable: true,
  value: async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.endsWith("/auth/refresh")) {
      preRotatedRefreshCalls += 1
      return new Response(JSON.stringify({ error: "must not refresh" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      })
    }
    preRotatedCalls += 1
    if (preRotatedCalls === 1) {
      api.storeAuthToken("already-rotated-token", Math.floor(Date.now() / 1000) + 900)
      return new Response(JSON.stringify({ error: "expired" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      })
    }
    assert.equal(
      (init?.headers as Record<string, string>)?.Authorization,
      "Bearer already-rotated-token"
    )
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    })
  },
})
const preRotated = await api.apiRequest<{ ok: boolean }>("/protected")
assert.deepEqual(preRotated, { ok: true })
assert.equal(preRotatedCalls, 2)
assert.equal(preRotatedRefreshCalls, 0)

// 旧浏览器没有 Web Locks 时，两个独立模块实例共享同一 localStorage。
// 通过 query 导入得到两个独立 owner，验证意图仲裁只允许一个 refresh
// 请求进入服务端；另一个实例必须在令牌轮换后放弃，不重复消费 cookie。
const importFreshApi = (suffix: string) =>
  import(`../lib/api.ts?${suffix}`) as Promise<typeof import("../lib/api")>
const apiTabA = await importFreshApi("refresh-tab-a")
const apiTabB = await importFreshApi("refresh-tab-b")
apiTabA.storeAuthToken("cross-tab-race", Math.floor(Date.now() / 1000) + 900)
let crossTabRaceCalls = 0
let releaseCrossTabRace: (() => void) | null = null
Object.defineProperty(globalThis, "fetch", {
  configurable: true,
  value: async (input: RequestInfo | URL) => {
    if (!String(input).endsWith("/auth/refresh")) {
      return new Response(null, { status: 204 })
    }
    crossTabRaceCalls += 1
    if (crossTabRaceCalls === 1) {
      await new Promise<void>((resolve) => {
        releaseCrossTabRace = resolve
      })
    }
    return new Response(
      JSON.stringify({
        access_token: "cross-tab-race-refreshed",
        expires_at: Math.floor(Date.now() / 1000) + 900,
        username: "alice",
        role: "admin",
      }),
      { status: 200, headers: { "content-type": "application/json" } }
    )
  },
})
const tabARefresh = apiTabA.refreshAuthSession()
const tabBRefresh = apiTabB.refreshAuthSession()
await new Promise((resolve) => globalThis.setTimeout(resolve, 10))
assert.equal(crossTabRaceCalls, 1, "localStorage 兜底不能并发发起第二次 refresh")
const release = releaseCrossTabRace as (() => void) | null
if (release !== null) release()
const [tabAResult, tabBResult] = await Promise.all([tabARefresh, tabBRefresh])
assert.equal(
  [tabAResult, tabBResult].filter((result) => result.ok).length,
  1,
  "跨标签页竞态只能有一个 refresh 成功"
)
assert.equal(crossTabRaceCalls, 1, "跨标签页竞态只能消费一次 refresh cookie")

console.log("auth refresh epoch contract: ok")
