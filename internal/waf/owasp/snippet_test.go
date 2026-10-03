package owasp

import (
	"strings"
	"testing"

	"My-OpenWaf/internal/pkg/snippet"
)

// TestAttachMatchSnippetTruncatesAndLocates 守护片段提取的两个关键约束：
// 长度上限（避免把大段请求内容写进安全事件）与命中定位（片段必须包含
// 触发命中的字面量，否则无法解释判定依据）。
func TestAttachMatchSnippetTruncatesAndLocates(t *testing.T) {
	hit, ok := FirstOWASPHitWithThresholds(CompileThresholds("high"), "/x", "id=1+union+select+1,2,3+from+users", nil, nil)
	if !ok {
		t.Fatal("expected sqli hit")
	}
	if hit.RuleID != "owasp:sqli:001" {
		t.Fatalf("rule = %q", hit.RuleID)
	}
	if !strings.Contains(hit.Snippet, "union") {
		t.Fatalf("snippet %q does not contain the matched keyword", hit.Snippet)
	}
	if len(hit.Snippet) > snippet.MaxLen {
		t.Fatalf("snippet length %d exceeds limit %d", len(hit.Snippet), snippet.MaxLen)
	}
}

// TestAttachMatchSnippetTruncatesOverlongTarget 覆盖超长目标串：检测层会做
// 首尾保留下采样（truncateTarget），片段仍应在下采样后的串上定位成功。
func TestAttachMatchSnippetTruncatesOverlongTarget(t *testing.T) {
	query := strings.Repeat("A", 20000) + "+union+select+1,2,3"
	hit, ok := FirstOWASPHitWithThresholds(CompileThresholds("high"), "/x", query, nil, nil)
	if !ok {
		t.Fatal("expected sqli hit on overlong target")
	}
	if hit.Snippet == "" {
		t.Fatal("snippet missing for overlong target")
	}
	if len(hit.Snippet) > snippet.MaxLen {
		t.Fatalf("snippet length %d exceeds limit %d", len(hit.Snippet), snippet.MaxLen)
	}
}

// TestExtractMatchSnippetSkipsRulesWithoutPatterns 记录一个已知边界：
// 硬编码发射点（如 owasp:crlf:005）没有 patterns 切片条目，无正则可回溯，
// 因此片段为空，而不是返回无关的上下文。
func TestExtractMatchSnippetSkipsRulesWithoutPatterns(t *testing.T) {
	hit, ok := FirstOWASPHitWithThresholds(CompileThresholds("high"), "/a%0d%0ab", "", nil, nil)
	if !ok {
		t.Fatal("expected crlf hit")
	}
	if hit.RuleID != "owasp:crlf:005" {
		t.Fatalf("rule = %q", hit.RuleID)
	}
	if hit.Snippet != "" {
		t.Fatalf("hardcoded-emission rule should not produce a snippet, got %q", hit.Snippet)
	}
}
