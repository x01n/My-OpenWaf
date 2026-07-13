/**
 * 命中防护模块（category）到中文标签的映射。
 *
 * 与后端 pipeline phase / 引擎产出的 category 值保持一致：
 * owasp、cve、bot、rate_limit、ip_rep、access、anti_replay、signature、custom。
 * 未知值原样返回，避免因新增分类导致 UI 空白。
 */
const CATEGORY_LABELS_ZH: Record<string, string> = {
  owasp: "OWASP 攻击",
  cve: "CVE 漏洞",
  bot: "Bot 检测",
  rate_limit: "频率限制",
  ip_rep: "IP 声誉 / 黑名单",
  access: "访问控制",
  anti_replay: "防重放",
  signature: "特征签名",
  custom: "自定义规则",
};

/**
 * 将后端返回的攻击分类代码转换为中文可读名称。
 *
 * @param category 命中防护模块代码，例如 "owasp"、"cve"
 * @returns 对应中文标签；未知代码原样返回，空值返回"未知"
 */
export function categoryLabel(category: string | undefined | null): string {
  if (!category) return "未知";
  return CATEGORY_LABELS_ZH[category] ?? category;
}
