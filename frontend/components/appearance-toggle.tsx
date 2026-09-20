/**
 * 外观切换控件
 * - ThemeToggle：亮/暗切换（next-themes）
 * - AccentToggle：蓝/青强调色切换（documentElement dataset + localStorage 持久化）
 * 静态导出下强调色在 useEffect 客户端应用，避免 hydration 警告。
 */

"use client"

import { useCallback, useEffect, useState } from "react"
import { useTheme } from "next-themes"
import { useTranslation } from "react-i18next"
import { IconMoon, IconSun, IconDroplet } from "@tabler/icons-react"
import { Button } from "@/components/ui/button"

const ACCENT_STORAGE_KEY = "owaf.accent"
type Accent = "teal" | "blue"

/** 亮/暗主题切换按钮 */
export function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme()
  const { t } = useTranslation()
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setMounted(true)
  }, [])

  const isDark = resolvedTheme === "dark"

  return (
    <Button
      variant="ghost"
      size="icon"
      className="h-8 w-8"
      aria-label={t("common.toggleTheme")}
      title={t("common.toggleTheme")}
      onClick={() => setTheme(isDark ? "light" : "dark")}
    >
      {mounted && isDark ? (
        <IconMoon className="h-4 w-4" />
      ) : (
        <IconSun className="h-4 w-4" />
      )}
    </Button>
  )
}

/** 应用强调色到 documentElement */
function applyAccent(accent: Accent) {
  if (accent === "blue") {
    document.documentElement.dataset.accent = "blue"
  } else {
    delete document.documentElement.dataset.accent
  }
}

/** 蓝/青强调色切换按钮 */
export function AccentToggle() {
  const { t } = useTranslation()
  const [accent, setAccent] = useState<Accent>("teal")
  const [mounted, setMounted] = useState(false)

  // 挂载后从 localStorage 读取并应用，避免 SSR/静态导出 hydration 不一致
  useEffect(() => {
    const saved =
      (window.localStorage.getItem(ACCENT_STORAGE_KEY) as Accent | null) ??
      "teal"
    const next: Accent = saved === "blue" ? "blue" : "teal"
    applyAccent(next)
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setAccent(next)
    setMounted(true)
  }, [])

  const toggle = useCallback(() => {
    setAccent((prev) => {
      const next: Accent = prev === "blue" ? "teal" : "blue"
      applyAccent(next)
      try {
        window.localStorage.setItem(ACCENT_STORAGE_KEY, next)
      } catch {
        // 忽略写入失败
      }
      return next
    })
  }, [])

  return (
    <Button
      variant="ghost"
      size="icon"
      className="h-8 w-8"
      aria-label={t("common.toggleAccent")}
      title={t(
        mounted && accent === "blue" ? "common.accentBlue" : "common.accentTeal"
      )}
      onClick={toggle}
    >
      <IconDroplet className="h-4 w-4" />
    </Button>
  )
}
