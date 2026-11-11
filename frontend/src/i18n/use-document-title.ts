"use client";

import { useEffect } from "react";
import { useI18n, type MessageKey } from "./index";

/**
 * 将页面标题按当前语言写入 `document.title`。
 *
 * Next.js 静态导出时 `metadata.title` 在构建期固定为中文，客户端切换语言或
 * 路由后需要覆盖。React 水合完成后 Next 的 metadata 仍可能把 `<title>`
 * 写回构建期文案，因此这里用 `MutationObserver` 监听 `head`：
 * 一旦标题被外部改写，就重新应用本地化标题（值相同则跳过，避免循环）。
 */
export function useDocumentTitle(key: MessageKey) {
  const { t } = useI18n();

  useEffect(() => {
    const desired = `${t(key)} - ${t("brand.name")}`;
    const apply = () => {
      if (document.title !== desired) document.title = desired;
    };

    apply();
    const observer = new MutationObserver(apply);
    observer.observe(document.head, {
      childList: true,
      subtree: true,
      characterData: true,
    });
    return () => observer.disconnect();
  }, [key, t]);
}
