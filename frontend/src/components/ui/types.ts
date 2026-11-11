/**
 * 状态语义色。
 *
 * 组件只声明语义（成功/警告/危险/信息/中性），
 * 具体色值由各组件按主题映射，避免页面散落硬编码色。
 */
export type StatusTone = "success" | "warning" | "danger" | "info" | "neutral";
