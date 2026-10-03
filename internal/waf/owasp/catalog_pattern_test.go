package owasp

import (
	"strings"
	"testing"
)

/**
 * TestCollectRulePatternsRegistryParity 校验 pattern 展示快照与运行时注册表
 * 双向一一对应：每个收集到的 ID 必须已注册，each 注册规则也必须在切片
 * 中（或属于 catalog.go 硬编码发射点），且 pattern 目录中不得出现空文本。
 */
func TestCollectRulePatternsRegistryParity(t *testing.T) {
	collected := CollectRulePatterns()
	registry := make(map[string]struct{})
	for _, rule := range DefaultOWASPRegistry.All() {
		registry[rule.ID] = struct{}{}
	}
	for id := range collected {
		if _, ok := registry[id]; !ok {
			t.Errorf("收集到未注册的规则 %q", id)
		}
	}
	for id := range registry {
		if _, ok := collected[id]; !ok {
			t.Errorf("已注册规则 %q 未收集到 pattern", id)
		}
	}
}

/**
 * TestRulePatternEntriesHaveRegexPrefix 校验聚合文本中的每一行都携带
 * `regex=` 与 `score=` 字段且非空：这决定了目录列长正则换行展示的质量。
 */
func TestRulePatternEntriesHaveRegexPrefix(t *testing.T) {
	for id, info := range CollectRulePatterns() {
		for lineNo, line := range strings.Split(strings.TrimSuffix(info.Pattern, "\n"), "\n") {
			if !strings.HasPrefix(line, "regex=") {
				t.Errorf("规则 %q 第 %d 行缺少 regex= 前缀: %q", id, lineNo+1, line)
			}
			if !strings.Contains(line, " score=") {
				t.Errorf("规则 %q 第 %d 行缺少 score= 字段: %q", id, lineNo+1, line)
			}
		}
		if info.Score <= 0 {
			t.Errorf("规则 %q 的 Score=%d 应大于 0", id, info.Score)
		}
	}
}
