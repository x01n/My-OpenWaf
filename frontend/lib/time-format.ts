/**
 * 时间格式化工具
 */

import i18next from "i18next";

/**
 * 将 ISO 时间字符串格式化为相对时间描述。
 * - <60s → "刚刚"
 * - <60m → "X 分钟前"
 * - <24h → "X 小时前"
 * - <7d  → "X 天前"
 * - 其他 → 完整日期
 *
 * 无效或空输入返回 "-"。
 *
 * @param iso ISO 8601 时间字符串
 * @returns 相对时间描述
 */
export function formatRelative(iso?: string | null): string {
  if (!iso) return "-";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "-";

  const diffMs = Date.now() - t;
  // 未来时间也走 "刚刚"，避免出现负数分钟
  const diff = Math.max(0, diffMs);
  const sec = Math.floor(diff / 1000);
  const tt = i18next.t.bind(i18next);

  if (sec < 60) return tt("timeFormat.justNow", { defaultValue: "刚刚" });

  const min = Math.floor(sec / 60);
  if (min < 60) {
    return tt("timeFormat.minutesAgo", {
      defaultValue: "{{count}} 分钟前",
      count: min,
    });
  }

  const hour = Math.floor(min / 60);
  if (hour < 24) {
    return tt("timeFormat.hoursAgo", {
      defaultValue: "{{count}} 小时前",
      count: hour,
    });
  }

  const day = Math.floor(hour / 24);
  if (day < 7) {
    return tt("timeFormat.daysAgo", {
      defaultValue: "{{count}} 天前",
      count: day,
    });
  }

  const d = new Date(t);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
