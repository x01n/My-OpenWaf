/**
 * ISO 3166-1 alpha-2 国家/地区代码到中文名称的映射。
 *
 * 覆盖常见的攻击来源国家/地区。未收录的代码由 {@link countryName} 原样返回。
 */
export const COUNTRY_NAMES_ZH: Record<string, string> = {
  CN: "中国",
  US: "美国",
  JP: "日本",
  DE: "德国",
  GB: "英国",
  FR: "法国",
  RU: "俄罗斯",
  KR: "韩国",
  IN: "印度",
  BR: "巴西",
  NL: "荷兰",
  CA: "加拿大",
  SG: "新加坡",
  HK: "香港",
  TW: "台湾",
  MO: "澳门",
  AU: "澳大利亚",
  IT: "意大利",
  ES: "西班牙",
  SE: "瑞典",
  CH: "瑞士",
  PL: "波兰",
  UA: "乌克兰",
  TR: "土耳其",
  ID: "印度尼西亚",
  VN: "越南",
  TH: "泰国",
  MY: "马来西亚",
  PH: "菲律宾",
  IR: "伊朗",
  IL: "以色列",
  SA: "沙特阿拉伯",
  AE: "阿联酋",
  ZA: "南非",
  EG: "埃及",
  MX: "墨西哥",
  AR: "阿根廷",
  BE: "比利时",
  AT: "奥地利",
  NO: "挪威",
  FI: "芬兰",
  DK: "丹麦",
  IE: "爱尔兰",
  PT: "葡萄牙",
  CZ: "捷克",
  RO: "罗马尼亚",
  PK: "巴基斯坦",
  BD: "孟加拉国",
  NG: "尼日利亚",
  NZ: "新西兰",
};

/**
 * 将 ISO alpha-2 国家代码转换为中文名称。
 *
 * @param code ISO 3166-1 alpha-2 代码（大小写不敏感）
 * @returns 对应中文名；未知代码返回代码本身（大写）
 */
export function countryName(code: string): string {
  if (!code) return "未知";
  const key = code.toUpperCase();
  return COUNTRY_NAMES_ZH[key] ?? key;
}

/**
 * 由 ISO alpha-2 国家代码生成对应国旗 emoji（区域指示符号）。
 *
 * @param code ISO 3166-1 alpha-2 代码（大小写不敏感）
 * @returns 国旗 emoji；非法代码返回地球 emoji
 */
export function countryFlag(code: string): string {
  if (!code || code.length !== 2) return "\u{1F310}";
  const key = code.toUpperCase();
  if (!/^[A-Z]{2}$/.test(key)) return "\u{1F310}";
  const base = 0x1f1e6;
  const a = "A".charCodeAt(0);
  return String.fromCodePoint(base + (key.charCodeAt(0) - a), base + (key.charCodeAt(1) - a));
}
