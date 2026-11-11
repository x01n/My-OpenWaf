/** 通用格式化工具 */

/** RFC3339 / Unix 时间戳 → 本地化时间字符串 */
export function formatDateTime(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return "-";
  const date = typeof value === "number" ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("zh-CN", { hour12: false });
}

export function formatDate(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return "-";
  const date = typeof value === "number" ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleDateString("zh-CN");
}

/** 数量级格式化：1.2万 / 340万 */
export function formatCount(n: number | undefined): string {
  const v = n ?? 0;
  if (v >= 1_0000_0000) return `${(v / 1_0000_0000).toFixed(1)}亿`;
  if (v >= 10000) return `${(v / 10000).toFixed(1)}万`;
  return v.toLocaleString("zh-CN");
}

/** 字节数格式化 */
export function formatBytes(n: number | undefined): string {
  const v = n ?? 0;
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let num = v;
  while (num >= 1024 && i < units.length - 1) {
    num /= 1024;
    i++;
  }
  return `${num.toFixed(num >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

/** 截断长文本 */
export function truncate(text: string, max = 60): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

/**
 * 把 `datetime-local` 输入值转为 RFC3339 时间串。
 * 空值或无法解析时返回 undefined，便于直接放入查询参数。
 */
export function toIso(local: string): string | undefined {
  if (!local) return undefined;
  const d = new Date(local);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}
