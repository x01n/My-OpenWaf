package cverules

import (
	"strconv"
	"testing"

	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/cve"
)

// seedToggleGuardRule 写入一条指定来源的 CVE 规则并返回其 ID 字符串。
func seedToggleGuardRule(t *testing.T, repo *repository.CVERuleRepo, source string) (uint, string) {
	t.Helper()
	rule := &cve.CVERuleModel{
		CVEID:    "CVE-2024-TOGGLEGUARD",
		Category: "general",
		Pattern:  "toggle-guard-pattern",
		Target:   "body",
		Severity: "high",
		Action:   "intercept",
		Source:   source,
		Approved: false,
		Enabled:  false,
	}
	if err := repo.Create(rule); err != nil {
		t.Fatalf("seed %s rule: %v", source, err)
	}
	return rule.ID, strconv.FormatUint(uint64(rule.ID), 10)
}

// readToggleGuardState 从数据库回读该规则的 Enabled/Approved，用于断言写库结果。
func readToggleGuardState(t *testing.T, repo *repository.CVERuleRepo, id uint) (bool, bool) {
	t.Helper()
	stored, err := repo.Get(id)
	if err != nil {
		t.Fatalf("read back rule %d: %v", id, err)
	}
	return stored.Enabled, stored.Approved
}

/**
 * TestToggleCVERuleRejectsNonCustomSource 断言本端点拒绝非自定义来源的规则。
 *
 * 该端点挂在 opsGroup（admin + operator），而 UpdateCVERule/DeleteCVERule
 * 只在 adminGroup。缺少来源守卫时，operator 可以把内置/订阅规则置为
 * Enabled=true 并连带写入 Approved=true，从而让未审批规则进入运行时规则集。
 * 断言同时检查 HTTP 状态码与数据库行，避免只挡住响应而实际已落库。
 */
func TestToggleCVERuleRejectsNonCustomSource(t *testing.T) {
	sources := []string{"catalog", "nvd", "github", "auto_generated"}

	for _, source := range sources {
		t.Run(source, func(t *testing.T) {
			repo := newCVERuleRepoForTest(t)
			id, idStr := seedToggleGuardRule(t, repo, source)

			body := []byte(`{"enabled":true}`)
			ctx := invokeCVEHandler(t, ToggleCVERule(repo, nil), "POST", "/api/v1/cve-rules/"+idStr+"/toggle", idStr, body)
			if ctx.Response.StatusCode() != 403 {
				t.Fatalf("source=%s toggle: want 403, got %d: %s", source, ctx.Response.StatusCode(), ctx.Response.Body())
			}

			enabled, approved := readToggleGuardState(t, repo, id)
			if enabled {
				t.Fatalf("source=%s: Enabled was written to true despite rejection", source)
			}
			if approved {
				t.Fatalf("source=%s: Approved was written to true despite rejection", source)
			}
		})
	}
}

/**
 * TestToggleCVERuleRejectsNonCustomSourceOnDisable 断言守卫按既有语义全拦。
 *
 * UpdateCVERule 与 DeleteCVERule 的守卫都不区分方向（不是只拦启用），
 * 本端点必须保持同一口径：即使请求体显式提交 enabled=false 也返回 403，
 * 且不改变库中已有的 Enabled/Approved。
 */
func TestToggleCVERuleRejectsNonCustomSourceOnDisable(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	rule := &cve.CVERuleModel{
		CVEID:    "CVE-2024-TOGGLEGUARDON",
		Category: "general",
		Pattern:  "toggle-guard-enabled-pattern",
		Target:   "body",
		Severity: "high",
		Action:   "intercept",
		Source:   "catalog",
		Approved: true,
		Enabled:  true,
	}
	if err := repo.Create(rule); err != nil {
		t.Fatalf("seed enabled catalog rule: %v", err)
	}
	idStr := strconv.FormatUint(uint64(rule.ID), 10)

	body := []byte(`{"enabled":false}`)
	ctx := invokeCVEHandler(t, ToggleCVERule(repo, nil), "POST", "/api/v1/cve-rules/"+idStr+"/toggle", idStr, body)
	if ctx.Response.StatusCode() != 403 {
		t.Fatalf("disable builtin: want 403, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	enabled, approved := readToggleGuardState(t, repo, rule.ID)
	if !enabled || !approved {
		t.Fatalf("rejected disable must not change the row: enabled=%v approved=%v", enabled, approved)
	}
}

/**
 * TestToggleCVERuleStillFlipsCustomRule 反向断言守卫没有过度收紧。
 *
 * 自定义规则必须仍能被启停，且启用时沿用既有语义把 Approved 置为 true。
 */
func TestToggleCVERuleStillFlipsCustomRule(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	id, idStr := seedToggleGuardRule(t, repo, "custom")

	enableBody := []byte(`{"enabled":true}`)
	ctx := invokeCVEHandler(t, ToggleCVERule(repo, nil), "POST", "/api/v1/cve-rules/"+idStr+"/toggle", idStr, enableBody)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("custom enable: want 200, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	enabled, approved := readToggleGuardState(t, repo, id)
	if !enabled || !approved {
		t.Fatalf("custom enable must persist enabled/approved: enabled=%v approved=%v", enabled, approved)
	}

	disableBody := []byte(`{"enabled":false}`)
	ctx = invokeCVEHandler(t, ToggleCVERule(repo, nil), "POST", "/api/v1/cve-rules/"+idStr+"/toggle", idStr, disableBody)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("custom disable: want 200, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	enabled, approved = readToggleGuardState(t, repo, id)
	if enabled {
		t.Fatalf("custom disable must persist Enabled=false, got %v", enabled)
	}
	if !approved {
		t.Fatalf("disable keeps the previous Approved=true, got %v", approved)
	}
}
