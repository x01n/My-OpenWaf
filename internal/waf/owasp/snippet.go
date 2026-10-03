package owasp

import (
	"regexp"

	"My-OpenWaf/internal/pkg/snippet"
)

// ruleRegexIndex 由全部 *Patterns 切片构建：规则 ID 到其全部正则的映射。
// 硬编码发射点（path/upload/proto/crlf 等）不在切片中，查不到即为空片段。
var ruleRegexIndex = func() map[string][]*regexp.Regexp {
	index := make(map[string][]*regexp.Regexp, 340)
	for _, group := range allPatternRuleGroups() {
		for _, pattern := range group.patterns {
			if pattern.re == nil {
				continue
			}
			index[pattern.id] = append(index[pattern.id], pattern.re)
		}
	}
	return index
}()

/**
 * ExtractMatchSnippet 提取触发指定规则命中的内容片段。
 *
 * 该函数在收口处调用，每个请求最多执行一次，且只遍历该规则自身的正则
 * （通常一条），不在检测热路径上产生额外扫描。命中位置两侧各保留
 * snippet.ContextLen 字节，整体截断到 snippet.MaxLen；查不到规则正则
 * （硬编码发射点）或目标串为空时返回空字符串。
 *
 * @param ruleID 检测器实际发出的稳定规则 ID。
 * @param target 触发命中的规范化目标串。
 * @return 已截断的匹配片段；不适用时为空字符串。
 */
func ExtractMatchSnippet(ruleID, target string) string {
	if ruleID == "" {
		return ""
	}
	return snippet.Extract(ruleRegexIndex[ruleID], target)
}

/**
 * AttachMatchSnippet 在命中结果上补齐匹配片段，已有片段时保持原值。
 *
 * @param hit 检测层产出的命中结果。
 * @param target 产生该命中的目标串。
 * @return 片段已填充的命中结果。
 */
func AttachMatchSnippet(hit OWASPHit, target string) OWASPHit {
	if hit.Snippet != "" || target == "" {
		return hit
	}
	hit.Snippet = ExtractMatchSnippet(hit.RuleID, target)
	return hit
}
