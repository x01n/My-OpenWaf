export const TLS_SNI_PRESENCE_PRESENT = "present"
export const TLS_SNI_PRESENCE_ABSENT = "absent"

/**
 * 把 SNI 单元格的展示值定成「值 / 明确无 SNI 的占位 / 未知」三态。
 *
 * @param sni 日志里的 tls_sni 原文。
 * @param presence 日志里的 tls_sni_presence 原文，可能缺失。
 * @param absentLabel presence 为 absent 时使用的占位文案。
 * @param unknownLabel 既无 SNI 名也无判定依据时使用的占位文案。
 * @returns 可直接渲染的字符串。
 */
export function tlsSniDisplayValue(
  sni: string | undefined | null,
  presence: string | undefined | null,
  absentLabel: string,
  unknownLabel: string
): string {
  const value = (sni ?? "").trim()
  if (value) return value
  return presence === TLS_SNI_PRESENCE_ABSENT ? absentLabel : unknownLabel
}

/**
 * 判断这条日志是否属于「客户端明确没发 SNI 扩展」。
 *
 * @param sni 日志里的 tls_sni 原文。
 * @param presence 日志里的 tls_sni_presence 原文。
 */
export function isClientSentNoSNI(
  sni: string | undefined | null,
  presence: string | undefined | null
): boolean {
  return !(sni ?? "").trim() && presence === TLS_SNI_PRESENCE_ABSENT
}
