"use client";

import { useEffect, useState } from "react";
import { useTheme } from "next-themes";
import { Moon, Sun } from "lucide-react";
import { Button } from "@heroui/react";
import { useI18n } from "@/i18n";

/**
 * 明暗主题切换按钮。
 *
 * 主题由 `next-themes` 同时写入 `<html class="dark">` 与 `data-theme`，
 * 服务端无法预先得知用户持久化的选择。挂载前按默认深色渲染，挂载后再
 * 依据实际主题切换图标，避免服务端与客户端首帧不一致。
 */
export function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();
  const { t } = useI18n();
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);

  const isDark = mounted ? resolvedTheme === "dark" : true;

  return (
    <Button
      variant="ghost"
      size="sm"
      isIconOnly
      aria-label={t("common.toggleTheme")}
      onPress={() => setTheme(isDark ? "light" : "dark")}
    >
      {isDark ? <Sun className="size-4" /> : <Moon className="size-4" />}
    </Button>
  );
}
