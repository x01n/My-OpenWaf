package owasp

import "unicode/utf8"

// binaryTargetRatioThreshold 是判定扫描目标为二进制数据的非文本字符占比阈值。
// 依据 blazehttp 基准实测：正常文本目标（含中文 UTF-8）占比接近 0，
// 而触发误报的压缩流 / PDF 目标占比约 0.54。
const binaryTargetRatioThreshold = 0.30

// binaryTargetMinLen 是启用二进制判定的最小目标长度。
// 短目标（路径、查询参数、头部值）不可能是二进制 body，
// 且样本过小时占比统计不稳定，直接跳过判定。
const binaryTargetMinLen = 256

// binaryTargetMinCmdScore 是二进制目标上命令注入规则被采信所需的单条最低分值。
// 低于该分值的规则（owasp:cmd:002、owasp:cmd:010 等短模式）在随机字节流中
// 碰撞概率过高；反引号紧跟命令词的 owasp:cmd:024 等 5 分规则不受影响。
const binaryTargetMinCmdScore = 5

/**
 * isBinaryScanTarget 判断归一化后的扫描目标是否为二进制数据。
 *
 * 统计无效 UTF-8 序列与 C0 控制字符（\t \n \r 除外）的占比。压缩流、PDF、
 * 图片等二进制 body 中，短模式（如 `';x` 或一对反引号夹带两字母命令词）的
 * 随机碰撞概率极高，此类目标上的低置信度命中不构成攻击证据；而真实注入
 * payload 无论如何编码，解码归一化后仍是可打印文本，占比接近 0。
 *
 * @param s 归一化后的扫描目标
 * @return 目标为二进制数据时返回 true
 */
func isBinaryScanTarget(s string) bool {
	if len(s) < binaryTargetMinLen {
		return false
	}
	bad, total := 0, 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		total++
		switch {
		case r == utf8.RuneError && size == 1:
			bad++
		case r < 0x20 && r != '\t' && r != '\n' && r != '\r':
			bad++
		}
		i += size
	}
	if total == 0 {
		return false
	}
	return float64(bad) >= float64(total)*binaryTargetRatioThreshold
}
