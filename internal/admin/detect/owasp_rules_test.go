package detect

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/owasp"
)

func newSystemSettingsRepoForTest(t *testing.T) *repository.SystemSettingsRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&store.SystemSettings{},
		&store.Policy{},
		&store.OWASPRuleCatalog{},
		&store.PolicyOWASPRuleConfig{},
	); err != nil {
		t.Fatalf("migrate settings: %v", err)
	}
	defaultSlot := uint(1)
	if err := db.Create(&store.Policy{Name: "Default", DefaultSlot: &defaultSlot}).Error; err != nil {
		t.Fatalf("create default policy: %v", err)
	}
	if err := owasp.ReconcileBuiltinCatalog(db); err != nil {
		t.Fatalf("reconcile OWASP catalog: %v", err)
	}
	return repository.NewSystemSettingsRepo(db)
}

func firstOWASPRuleID(t *testing.T) string {
	t.Helper()
	rules := owasp.BuiltinRuleDefinitions()
	if len(rules) == 0 {
		t.Fatalf("expected default OWASP rules")
	}
	for _, rule := range rules {
		if rule.DefaultEnabled {
			return rule.RuleID
		}
	}
	return rules[0].RuleID
}

func invokeOWASPUpdate(t *testing.T, handler app.HandlerFunc, ruleID string, payload map[string]any) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/owasp-rules/" + ruleID + "/update")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(body)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: ruleID}}
	handler(context.Background(), ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestUpdateSingleOWASPRuleClearsActionOverride(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)
	handler := UpdateSingleOWASPRule(repo, func() error { return nil })

	invokeOWASPUpdate(t, handler, ruleID, map[string]any{
		"action":      "intercept",
		"status_code": 403,
		"redirect_to": "https://example.com/blocked",
	})
	var config store.PolicyOWASPRuleConfig
	if err := repo.DB().Where("rule_id = ?", ruleID).First(&config).Error; err != nil {
		t.Fatalf("load override: %v", err)
	}
	if config.Action == nil || *config.Action != "intercept" || config.StatusCode == nil || config.RedirectTo == nil {
		t.Fatalf("expected action override to be set, got %#v", config)
	}

	invokeOWASPUpdate(t, handler, ruleID, map[string]any{
		"action":      "",
		"status_code": 0,
		"redirect_to": "",
	})
	if err := repo.DB().Where("rule_id = ?", ruleID).First(&config).Error; err != nil {
		t.Fatalf("reload override: %v", err)
	}
	if config.Action != nil || config.StatusCode != nil || config.RedirectTo != nil {
		t.Fatalf("expected action fields to be cleared, got %#v", config)
	}
}

func TestUpdateSingleOWASPRuleRejectsRetiredNumericCatalogID(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)
	var catalog store.OWASPRuleCatalog
	if err := repo.DB().Where("rule_id = ?", ruleID).First(&catalog).Error; err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	if err := repo.DB().Model(&catalog).Update("active", false).Error; err != nil {
		t.Fatalf("retire catalog: %v", err)
	}
	handler := UpdateSingleOWASPRule(repo, func() error { return nil })
	ctx := invokeOWASPPost(t, handler, "/api/v1/owasp-rules/"+strconv.FormatUint(uint64(catalog.ID), 10)+"/update", strconv.FormatUint(uint64(catalog.ID), 10), []byte(`{"enabled":false}`))
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("retired numeric catalog id: want 404, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
}

func TestUpdateSingleOWASPRuleSavesSensitivityOverride(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)
	handler := UpdateSingleOWASPRule(repo, func() error { return nil })

	invokeOWASPUpdate(t, handler, ruleID, map[string]any{
		"sensitivity": "strict",
	})

	var config store.PolicyOWASPRuleConfig
	if err := repo.DB().Where("rule_id = ?", ruleID).First(&config).Error; err != nil {
		t.Fatalf("load override: %v", err)
	}
	if config.Sensitivity == nil || *config.Sensitivity != "strict" {
		t.Fatalf("expected sensitivity override to be set, got %#v", config)
	}

	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI("/api/v1/owasp-rules?page_size=500")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ListOWASPRulesFromRegistry(repo)(context.Background(), ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Items []owaspRuleView `json:"items"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	for _, item := range resp.Items {
		if item.ID == ruleID {
			if item.Sensitivity != "strict" {
				t.Fatalf("response sensitivity = %q want strict", item.Sensitivity)
			}
			return
		}
	}
	t.Fatalf("rule %s not found in response", ruleID)
}

func TestUpdateSingleOWASPRuleRejectsEnabledRedirectWithoutTarget(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)
	handler := UpdateSingleOWASPRule(repo, func() error { return nil })

	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/owasp-rules/" + ruleID + "/update")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody([]byte(`{"action":"redirect"}`))
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: ruleID}}
	handler(context.Background(), ctx)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	invokeOWASPUpdate(t, handler, ruleID, map[string]any{
		"enabled":     false,
		"action":      "redirect",
		"redirect_to": "",
	})
}

func TestUpdateSingleOWASPRuleRejectsPartialUpdateThatLeavesInvalidEffectiveConfig(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)
	handler := UpdateSingleOWASPRule(repo, func() error { return nil })

	redirect := "redirect"
	disabled := false
	if err := repo.DB().Create(&store.PolicyOWASPRuleConfig{
		PolicyID: 1,
		RuleID:   ruleID,
		Enabled:  &disabled,
		Action:   &redirect,
	}).Error; err != nil {
		t.Fatalf("seed invalid redirect override: %v", err)
	}
	ctx := invokeOWASPPost(t, handler, "/api/v1/owasp-rules/"+ruleID+"/update", ruleID, []byte(`{"enabled":true}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("enabling redirect without target: want 400, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var config store.PolicyOWASPRuleConfig
	if err := repo.DB().Where("policy_id = ? AND rule_id = ?", 1, ruleID).First(&config).Error; err != nil {
		t.Fatalf("load redirect override: %v", err)
	}
	if config.Enabled == nil || *config.Enabled {
		t.Fatalf("rejected partial update changed enabled state: %#v", config.Enabled)
	}

	intercept := "intercept"
	if err := repo.DB().Model(&config).Updates(map[string]any{
		"enabled": true,
		"action":  intercept,
	}).Error; err != nil {
		t.Fatalf("seed non-captcha override: %v", err)
	}
	ctx = invokeOWASPPost(t, handler, "/api/v1/owasp-rules/"+ruleID+"/update", ruleID, []byte(`{"captcha_type":"slide"}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("captcha type on non-captcha action: want 400, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
}

func TestShouldSkipRuleBoundary(t *testing.T) {
	truePtr := true
	falsePtr := false
	overrides := map[string]owasp.OWASPRuleOverride{
		"owasp:upload:001": {Enabled: &falsePtr, Whitelist: []string{"/admin"}},
		"owasp:upload:003": {Whitelist: []string{"/safe"}},
		"owasp:sqli:003":   {Enabled: &truePtr},
	}

	// disabled rule should skip
	if !owasp.ShouldSkipRule("owasp:upload:001", "/admin", overrides) {
		t.Error("disabled rule should skip")
	}

	// whitelisted path should skip
	if !owasp.ShouldSkipRule("owasp:upload:003", "/safe", overrides) {
		t.Error("whitelisted path should skip")
	}

	// non-whitelisted non-disabled should not skip
	if owasp.ShouldSkipRule("owasp:upload:003", "/admin", overrides) {
		t.Error("non-whitelisted should not skip")
	}

	// enabled rule with no whitelist should not skip
	if owasp.ShouldSkipRule("owasp:sqli:003", "/admin", overrides) {
		t.Error("enabled rule should not skip")
	}

	// test wildcard *
	if !owasp.ShouldSkipRule("owasp:upload:003", "/anything", map[string]owasp.OWASPRuleOverride{"owasp:upload:003": {Whitelist: []string{"*"}}}) {
		t.Error("wildcard whitelist should skip")
	}

	// test exact path match
	exactOverrides := map[string]owasp.OWASPRuleOverride{"owasp:upload:003": {Whitelist: []string{"/exact"}}}
	if !owasp.ShouldSkipRule("owasp:upload:003", "/exact", exactOverrides) {
		t.Error("exact path whitelist should skip")
	}
	if owasp.ShouldSkipRule("owasp:upload:003", "/exact/sub", exactOverrides) {
		t.Error("exact path whitelist should not skip subpath")
	}

	// test prefix match (use /prefix* to indicate wildcard prefix)
	prefixOverrides := map[string]owasp.OWASPRuleOverride{"owasp:upload:003": {Whitelist: []string{"/prefix*"}}}
	if !owasp.ShouldSkipRule("owasp:upload:003", "/prefix/sub", prefixOverrides) {
		t.Error("prefix whitelist should skip subpath")
	}
	if !owasp.ShouldSkipRule("owasp:upload:003", "/prefix", prefixOverrides) {
		t.Error("prefix whitelist should skip exact")
	}

	// 灵敏度覆盖边界：阈值随灵敏度升高而降低（low=7, mid=4, high=3, very_high=2, strict=1）。
	// 命中分数需 >= 阈值才放行到后续判定，因此 score=4 能过 high/mid，过不了 low。
	hit := owasp.OWASPHit{Score: 4, Category: owasp.CatSQLi}
	catSens := map[string]string{}
	if !owasp.HitPassesOverrideSensitivity(hit, owasp.OWASPRuleOverride{Sensitivity: "high"}, catSens) {
		t.Error("score 4 should pass high threshold 3")
	}
	if !owasp.HitPassesOverrideSensitivity(hit, owasp.OWASPRuleOverride{Sensitivity: "mid"}, catSens) {
		t.Error("score 4 should pass mid threshold 4")
	}
	if owasp.HitPassesOverrideSensitivity(hit, owasp.OWASPRuleOverride{Sensitivity: "low"}, catSens) {
		t.Error("score 4 should not pass low threshold 7")
	}
	// off 直接禁用该类别，任何分数都不通过。
	if owasp.HitPassesOverrideSensitivity(hit, owasp.OWASPRuleOverride{Sensitivity: "off"}, catSens) {
		t.Error("sensitivity off should reject every score")
	}
	// 空灵敏度覆盖不参与判定，直接放行。
	if !owasp.HitPassesOverrideSensitivity(hit, owasp.OWASPRuleOverride{}, catSens) {
		t.Error("empty sensitivity override should pass through")
	}
	// catSens 为 nil 时整个灵敏度覆盖短路放行。
	if !owasp.HitPassesOverrideSensitivity(hit, owasp.OWASPRuleOverride{Sensitivity: "strict"}, nil) {
		t.Error("nil category sensitivity map should pass through")
	}
	// 类别级灵敏度优先于覆盖里的默认灵敏度：sqli 显式 off 时应拒绝。
	if owasp.HitPassesOverrideSensitivity(hit, owasp.OWASPRuleOverride{Sensitivity: "strict"}, map[string]string{"sqli": "off"}) {
		t.Error("category sensitivity off should override rule sensitivity")
	}
}

// newBrokenBatchRepo 构建覆盖配置表缺失的内存库：Policy 与
// OWASPRuleCatalog 正常迁移并回过内建目录（目录查询不触碰覆盖配置表），
// 覆盖配置表则完全不迁移。探针实测：该库上 First 返回的错误为
// "SQL logic error: no such table: policy_owasp_rule_configs"（不见于
// 内置路径，故 gorm 不归为 ErrRecordNotFound）——正是 B3 要区分的
// 非 not-found 错误面。
func newBrokenBatchRepo(t *testing.T) *repository.SystemSettingsRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Policy{}, &store.OWASPRuleCatalog{}); err != nil {
		t.Fatalf("migrate catalog: %v", err)
	}
	defaultSlot := uint(1)
	if err := db.Create(&store.Policy{Name: "Default", DefaultSlot: &defaultSlot}).Error; err != nil {
		t.Fatalf("create default policy: %v", err)
	}
	if err := owasp.ReconcileBuiltinCatalog(db); err != nil {
		t.Fatalf("reconcile OWASP catalog: %v", err)
	}
	return repository.NewSystemSettingsRepo(db)
}

// TestBatchUpdateOWASPRulesDBReadErrorAbortsBeforeWrite 验证批量更新中
// 事务内读取覆盖配置的 First 查询遇到非 not-found 错误（覆盖配置表缺失，
// SQLite 返回 no such table 实错，等价 DB 抖动/BUSY 的错误面）时，handler
// 以 400 直返该错误且不触碰 reload（"config applied" 不出现）。注入对
// B3 回归态（吞错继续写，Create 仍弹同源 no such table）无差异，本测试
// 定位为分支状态回归覆盖而不足差分判定。
func TestBatchUpdateOWASPRulesDBReadErrorAbortsBeforeWrite(t *testing.T) {
	repo := newBrokenBatchRepo(t)
	ruleID := firstOWASPRuleID(t)

	body, _ := json.Marshal(map[string]any{
		"rules": []map[string]any{{"id": ruleID, "enabled": false}},
	})
	ctx := invokeOWASPPost(t, BatchUpdateOWASPRules(repo, func() error { return nil }),
		"/api/v1/owasp-rules/batch-update", "", body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("db read error: want 400, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if !strings.Contains(string(ctx.Response.Body()), "no such table") {
		t.Fatalf("response %q does not carry the sqlite read error", string(ctx.Response.Body()))
	}
	if strings.Contains(string(ctx.Response.Body()), "config applied") {
		t.Fatalf("read error must not reach reload, got %s", string(ctx.Response.Body()))
	}
}

// TestBatchUpdateOWASPRulesExistingRowUpdateSemanticsUnchanged 验证吞错修正
// 不改变既有行（First 命中）的覆盖写语义：既有覆盖仍被 patch 合并更新。
func TestBatchUpdateOWASPRulesExistingRowUpdateSemanticsUnchanged(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)
	disabled := false
	if err := repo.DB().Create(&store.PolicyOWASPRuleConfig{
		PolicyID: 1,
		RuleID:   ruleID,
		Enabled:  &disabled,
	}).Error; err != nil {
		t.Fatalf("seed override: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"rules": []map[string]any{{"id": ruleID, "enabled": true}},
	})
	ctx := invokeOWASPPost(t, BatchUpdateOWASPRules(repo, func() error { return nil }),
		"/api/v1/owasp-rules/batch-update", "", body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var config store.PolicyOWASPRuleConfig
	if err := repo.DB().Where("rule_id = ?", ruleID).First(&config).Error; err != nil {
		t.Fatalf("load override: %v", err)
	}
	if config.Enabled == nil || !*config.Enabled {
		t.Fatalf("enabled override = %#v, want true", config.Enabled)
	}
}
