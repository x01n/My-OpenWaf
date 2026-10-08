package snippet

import (
	"regexp"
	"strings"
)

const (
	// MaxLen 是片段总长上限（字节）。片段可能包含凭据或大段二进制内容，
	// 必须截断后再落库。
	MaxLen = 256
	// ContextLen 是命中区间两侧保留的上下文字节数。仅取正则命中的字面量
	// 会丢失判定依据（例如只保留编码换行而不见紧随的响应头名）。
	ContextLen = 48
	// MaxTargetLen 是参与片段提取的目标串长度上限。
	//
	// 检测层对超长目标串做首尾保留下采样（owasp.maxTargetLen 为 16384，
	// 保留头部与尾部各一份、中间以单个空格连接），因此检测实际搜索过的
	// 最长串是 2*16384+1。上限取同一数量级：既不拒绝检测层真正搜过的串，
	// 也不在荒谬长度的输入上重复执行用户正则。
	MaxTargetLen = 2*16384 + 1
)

/**
 * Around 截取命中区间 [start,end) 及其两侧上下文，并截断到 MaxLen。
 *
 * @param target 命中所在的完整目标串。
 * @param start 命中区间起始字节下标。
 * @param end 命中区间结束字节下标（不含）。
 * @return 截断后的片段；入参越界或为空时返回空字符串。
 */
func Around(target string, start, end int) string {
	if target == "" || len(target) > MaxTargetLen {
		return ""
	}
	if start < 0 || end > len(target) || start >= end {
		return ""
	}
	from := start - ContextLen
	if from < 0 {
		from = 0
	}
	to := end + ContextLen
	if to > len(target) {
		to = len(target)
	}
	out := target[from:to]
	if len(out) > MaxLen {
		out = out[:MaxLen]
	}
	return strings.ToValidUTF8(out, "")
}

/**
 * Extract 用给定正则列表在目标串上寻找首个命中并返回其片段。
 *
 * @param patterns 候选正则，按顺序尝试；nil 元素跳过。
 * @param target 待搜索的目标串。
 * @return 首个命中的片段；全部未命中时返回空字符串。
 */
func Extract(patterns []*regexp.Regexp, target string) string {
	if target == "" || len(target) > MaxTargetLen {
		return ""
	}
	for _, re := range patterns {
		if re == nil {
			continue
		}
		loc := re.FindStringIndex(target)
		if loc == nil {
			continue
		}
		return Around(target, loc[0], loc[1])
	}
	return ""
}
