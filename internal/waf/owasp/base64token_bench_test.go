package owasp

import (
	"strings"
	"testing"
)

// BenchmarkBase64TokenScan 对排 forEachBase64TokenIndex 内部谓词的两种实现：
// OldBranch 用剪枝前多分支谓词的静态副本（oldB64Pred），NewTable 用当前
// 256 项查表；b.Run 前的交错暖化落定 I-cache 状态。负载集合覆盖 profile
// 主流的 ASCII 混合串与 base64 token 密集串。结论以配对中位为准，宽度相等
// 或在本机负载（>=12）下不可收敛时撤销数字，不把单次采样当证据：
// 6 轮实测各轮 Old/New 配对差距在 ±20% 内无序翻转（如 NoTokenSparse
// +11%/-6%/+15%、JWTShaped -17%/-21%/-22% 反向等），判定为噪声内不可区分。
func BenchmarkBase64TokenScan(b *testing.B) {
	loads := map[string]string{
		"NoTokenSparse":          "page=2&sort=created_at&order=desc&per_page=20 中文",
		"ShortRuns":              strings.Repeat("abcDEF123abcDEF123!.-_ ", 8),
		"TokenDense":             strings.Repeat("U0VMRUNUIFVOSU9OIFBBU1NXT1JE", 8),
		"IDKWLongishASCIICommon": strings.Repeat("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do ", 12),
		"JWTShaped":              "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDIzNCIsImV4cCI6MTc1MzQ1NjAwMH0",
	}
	for name, src := range loads {
		// 额外零散交替轮暖化 I-cache，随后再进入正式子基准。
		for range 6 {
			sink += oldBase64TokenIndex(src)
			sink += forEachBase64TokenIndexCount(src)
		}
		b.Run(name, func(b *testing.B) {
			b.Run("OldBranch", func(b *testing.B) {
				for b.Loop() {
					sink += oldBase64TokenIndex(src)
				}
			})
			b.Run("NewTable", func(b *testing.B) {
				for b.Loop() {
					sink += forEachBase64TokenIndexCount(src)
				}
			})
		})
	}
}

// BenchmarkDecodeBase64IfSuspiciousTable 仅作 decodeBase64IfSuspicious 热路径
// 的基线观察，不参与剪枝对排（共享代码路径，不做旧/新区分）。
func BenchmarkDecodeBase64IfSuspiciousTable(b *testing.B) {
	inputs := map[string]string{
		"PlainWord":       "Loremipsumdolorsitamet",
		"Base64Decodable": "U0VMRUNUIFVOSU9OIFBBU1NXT1JE",
		"RandomShape":     "8q8q8q8q8q8q8q8q",
	}
	for name, s := range inputs {
		b.Run(name, func(b *testing.B) {
			sink = 0
			for b.Loop() {
				sink += len(decodeBase64IfSuspicious(s))
			}
		})
	}
}

// sink 防内联/消除的包级汇；bench 只把计数与字符串写入它。
var sink int

// oldB64Pred 是剪枝前多分支谓词的静态副本，供对排基准使用。
func oldB64Pred(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
		b == '+' || b == '/' || b == '-' || b == '_'
}

// oldBase64TokenIndex 用旧谓词重放同一个 token 收集循环，返回 token 字节数。
func oldBase64TokenIndex(src string) int {
	n := 0
	for i := 0; i < len(src); {
		for i < len(src) && !oldB64Pred(src[i]) {
			i++
		}
		start := i
		for i < len(src) && oldB64Pred(src[i]) {
			i++
		}
		if i-start < 8 {
			continue
		}
		end := i
		for end < len(src) && end-i < 2 && src[end] == '=' {
			end++
		}
		n += end - start
		if i < len(src) {
			i = end
		}
	}
	return n
}

// forEachBase64TokenIndexCount 与旧循环同构，内部谓词用当前查表实现。
func forEachBase64TokenIndexCount(src string) int {
	n := 0
	forEachBase64TokenIndex(src, -1, func(start, end int) bool {
		n += end - start
		return true
	})
	return n
}
