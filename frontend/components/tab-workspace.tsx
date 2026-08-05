/**
 * 顶部多标签页工作区（文档式）
 * 通过 React context 维护已打开标签，随路由自动增/激活，sessionStorage 持久化刷新不丢。
 * 标签标题复用 breadcrumb/top-bar 的 path -> i18n key 映射（routeTitleKeyMap）。
 */

"use client"

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react"
import { usePathname, useRouter, useSearchParams } from "next/navigation"
import { useTranslation } from "react-i18next"
import { IconX } from "@tabler/icons-react"
import { cn } from "@/lib/utils"
import { routeTitleKeyMap } from "@/lib/route-titles"

/** 固定标签，不可关闭。next.config.ts 开启了 trailingSlash，故带尾斜杠 */
const PINNED_PATH = "/dashboard/"
const STORAGE_KEY = "owaf.workspace.tabs"

/**
 * 归一化路径用于标签去重。
 * trailingSlash: true 时 usePathname() 返回 "/dashboard/"，而历史 sessionStorage
 * 里可能存着无尾斜杠的旧值；不归一化会让同一路由生成两个标签。
 */
function normalizePath(path: string): string {
  if (!path) return "/"
  const [rawPathname, rawQuery] = path.split("?", 2)
  const pathname =
    rawPathname !== "/" && rawPathname.endsWith("/")
      ? rawPathname.slice(0, -1)
      : rawPathname || "/"
  if (!rawQuery) return pathname
  const params = new URLSearchParams(rawQuery)
  params.sort()
  const query = params.toString()
  return query ? `${pathname}?${query}` : pathname
}

function tabIdentity(href: string): string {
  const normalized = normalizePath(href)
  const [pathname, query] = normalized.split("?", 2)
  if (pathname !== "/sites/detail" || !query) return pathname
  const siteID = new URLSearchParams(query).get("id")
  return siteID ? `${pathname}?id=${encodeURIComponent(siteID)}` : pathname
}

interface WorkspaceTab {
  /** 路由路径，作为唯一标识 */
  path: string
  /** 标题 i18n key；无映射时回落到 path 片段 */
  titleKey?: string
  /** 无 i18n key 时的原始标签文本 */
  rawLabel?: string
}

interface TabWorkspaceContextValue {
  tabs: WorkspaceTab[]
  activePath: string
}

const TabWorkspaceContext = createContext<TabWorkspaceContextValue | null>(null)

/** 解析路径对应的标题信息 */
function resolveTab(href: string): WorkspaceTab {
  const path = normalizePath(href)
  const pathname = path.split("?", 1)[0]
  const segments = pathname.split("/").filter(Boolean)
  // 取首段（顶层路由）作为标题依据，与 top-bar getPageTitle 的前缀语义一致
  const key = "/" + (segments[0] ?? "")
  const titleKey = routeTitleKeyMap[key]
  return {
    path,
    titleKey,
    rawLabel: titleKey
      ? undefined
      : decodeURIComponent(segments[segments.length - 1] ?? pathname),
  }
}

/** 从 sessionStorage 读取已保存标签 */
function loadTabs(): WorkspaceTab[] {
  if (typeof window === "undefined") return []
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw) as WorkspaceTab[]
    if (!Array.isArray(parsed)) return []
    return parsed.filter((t) => typeof t?.path === "string")
  } catch {
    return []
  }
}

export function TabWorkspaceProvider({
  children,
}: {
  children: React.ReactNode
}) {
  const pathname = usePathname()
  const searchParams = useSearchParams()
  const router = useRouter()
  const { t } = useTranslation()
  const currentPath = useMemo(() => {
    if (!pathname) return ""
    const query = searchParams.toString()
    return normalizePath(query ? `${pathname}?${query}` : pathname)
  }, [pathname, searchParams])
  const [tabs, setTabs] = useState<WorkspaceTab[]>([])
  const hydrated = useRef(false)

  // 首次挂载：恢复 sessionStorage，并确保固定标签存在。
  // 恢复时按归一化路径去重，清理历史遗留的尾斜杠不一致条目。
  useEffect(() => {
    const restored = loadTabs()
    const deduped: WorkspaceTab[] = []
    const seen = new Set<string>()
    for (const tab of restored) {
      const path = normalizePath(tab.path)
      const key = tabIdentity(path)
      if (seen.has(key)) continue
      seen.add(key)
      deduped.push({ ...tab, path })
    }
    const withPinned = seen.has(tabIdentity(PINNED_PATH))
      ? deduped
      : [resolveTab(PINNED_PATH), ...deduped]
    hydrated.current = true
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setTabs(withPinned)
  }, [])

  // 路由变化：若标签不存在则新增
  useEffect(() => {
    if (!hydrated.current || !currentPath) return
    setTabs((prev) => {
      const identity = tabIdentity(currentPath)
      const index = prev.findIndex((tab) => tabIdentity(tab.path) === identity)
      if (index === -1) return [...prev, resolveTab(currentPath)]
      if (normalizePath(prev[index].path) === currentPath) return prev
      return prev.map((tab, tabIndex) =>
        tabIndex === index ? resolveTab(currentPath) : tab
      )
    })
  }, [currentPath])

  // 持久化
  useEffect(() => {
    if (!hydrated.current || typeof window === "undefined") return
    try {
      window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(tabs))
    } catch {
      // 忽略写入失败（隐私模式等）
    }
  }, [tabs])

  const closeTab = useCallback(
    (path: string) => {
      const identity = tabIdentity(path)
      if (identity === tabIdentity(PINNED_PATH)) return
      setTabs((prev) => {
        const idx = prev.findIndex((tab) => tabIdentity(tab.path) === identity)
        if (idx === -1) return prev
        const next = prev.filter((tab) => tabIdentity(tab.path) !== identity)
        // 关闭的是当前激活标签，跳到相邻标签
        if (identity === tabIdentity(currentPath)) {
          const fallback = next[idx] ?? next[idx - 1] ?? next[next.length - 1]
          if (fallback) router.push(fallback.path)
        }
        return next
      })
    },
    [currentPath, router]
  )

  const label = useCallback(
    (tab: WorkspaceTab) =>
      tab.titleKey ? t(tab.titleKey) : (tab.rawLabel ?? tab.path),
    [t]
  )

  const ctxValue = useMemo(
    () => ({ tabs, activePath: currentPath }),
    [tabs, currentPath]
  )

  return (
    <TabWorkspaceContext.Provider value={ctxValue}>
      <div className="flex h-10 items-stretch gap-1 overflow-x-auto border-b bg-card px-2">
        {tabs.map((tab) => {
          const active = tabIdentity(tab.path) === tabIdentity(currentPath)
          const pinned = tabIdentity(tab.path) === tabIdentity(PINNED_PATH)
          return (
            <div
              key={tabIdentity(tab.path)}
              className={cn(
                "group relative flex shrink-0 items-center gap-1.5 self-end overflow-hidden rounded-t-md border border-b-0 px-3 py-1.5 text-sm transition-colors",
                // 活动标签：主色文字 + 顶部指示条，与非活动态的悬停高亮拉开区分
                active
                  ? "border-border bg-background font-medium text-primary before:absolute before:inset-x-0 before:top-0 before:h-0.5 before:bg-primary"
                  : "border-transparent text-muted-foreground hover:bg-accent hover:text-accent-foreground"
              )}
            >
              <button
                type="button"
                onClick={() => router.push(tab.path)}
                className="max-w-[12rem] truncate"
              >
                {label(tab)}
              </button>
              {!pinned && (
                <button
                  type="button"
                  aria-label={t("common.close")}
                  onClick={() => closeTab(tab.path)}
                  className="inline-flex h-4 w-4 items-center justify-center rounded opacity-60 hover:bg-muted hover:opacity-100"
                >
                  <IconX className="h-3 w-3" />
                </button>
              )}
            </div>
          )
        })}
      </div>
      {children}
    </TabWorkspaceContext.Provider>
  )
}

export function useTabWorkspace() {
  const ctx = useContext(TabWorkspaceContext)
  if (!ctx) {
    throw new Error("useTabWorkspace must be used within TabWorkspaceProvider")
  }
  return ctx
}
