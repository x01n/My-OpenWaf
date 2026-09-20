package snapshot

import (
	"testing"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/cve"
	"My-OpenWaf/internal/waf/owasp"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestRuleCaptchaOverridesReachRuntimeConfig(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&store.PolicyOWASPRuleConfig{},
		&store.CVERuleRecord{},
		&store.CVERuleScopeOverride{},
		&store.Site{},
	); err != nil {
		t.Fatalf("migrate rule overrides: %v", err)
	}

	owaspAction := "captcha_challenge"
	owaspCaptcha := "slide"
	if err := db.Create(&store.PolicyOWASPRuleConfig{
		PolicyID:    1,
		RuleID:      "owasp:sqli:001",
		Action:      &owaspAction,
		CaptchaType: &owaspCaptcha,
	}).Error; err != nil {
		t.Fatalf("seed OWASP override: %v", err)
	}
	owaspConfigs, diagnostics, err := loadPolicyOWASPConfigs(db)
	if err != nil || len(diagnostics) != 0 {
		t.Fatalf("load OWASP overrides: diagnostics=%#v err=%v", diagnostics, err)
	}
	owaspOverride := owasp.ParseOWASPRulesConfig(owaspConfigs[1])["owasp:sqli:001"]
	if owaspOverride.Action != "captcha_challenge" || owaspOverride.CaptchaType != "slide" {
		t.Fatalf("OWASP runtime override=%#v", owaspOverride)
	}

	rule := store.CVERuleRecord{
		CVEID: "CVE-2026-90001", Category: "general", Pattern: "test-pattern",
		Action: "intercept", Enabled: true, Approved: true,
	}
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("seed CVE rule: %v", err)
	}
	cveAction := "captcha_challenge"
	cveCaptcha := "rotate"
	if err := db.Create(&store.CVERuleScopeOverride{
		RuleID: rule.ID, ScopeType: store.CVEScopeGlobal, ScopeID: 0,
		Action: &cveAction, CaptchaType: &cveCaptcha,
	}).Error; err != nil {
		t.Fatalf("seed CVE override: %v", err)
	}
	site := store.Site{Host: "example.test", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":80", Enabled: true}
	if err := db.Create(&site).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}
	cveConfigs, err := loadSiteCVEConfigs(db, []store.Site{site}, 1)
	if err != nil {
		t.Fatalf("load CVE overrides: %v", err)
	}
	cveOverride := cve.ParseCVERuleOverrides(cveConfigs[site.ID])[rule.CVEID]
	if cveOverride.Action != "captcha_challenge" || cveOverride.CaptchaType != "rotate" {
		t.Fatalf("CVE runtime override=%#v", cveOverride)
	}
}

func TestLoadSiteCVEConfigsKeepsDuplicateCVEIDsRuleScoped(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.CVERuleRecord{}, &store.CVERuleScopeOverride{}, &store.Site{}); err != nil {
		t.Fatalf("migrate cve tables: %v", err)
	}

	rules := []store.CVERuleRecord{
		{CVEID: "CVE-2026-DUPLICATE", Category: "general", Pattern: "duplicate-pattern-a", Target: "all", Severity: "high", Action: "intercept", Enabled: true, Approved: true},
		{CVEID: "CVE-2026-DUPLICATE", Category: "general", Pattern: "duplicate-pattern-b", Target: "all", Severity: "high", Action: "intercept", Enabled: true, Approved: true},
	}
	if err := db.Create(&rules).Error; err != nil {
		t.Fatalf("seed duplicate cve rules: %v", err)
	}
	action := "captcha_challenge"
	captchaType := "slide"
	if err := db.Create(&store.CVERuleScopeOverride{
		RuleID: rules[0].ID, ScopeType: store.CVEScopeGlobal, ScopeID: 0,
		Action: &action, CaptchaType: &captchaType,
	}).Error; err != nil {
		t.Fatalf("seed scoped override: %v", err)
	}
	site := store.Site{Host: "duplicate.test", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":80", Enabled: true}
	if err := db.Create(&site).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}

	configs, err := loadSiteCVEConfigs(db, []store.Site{site}, 1)
	if err != nil {
		t.Fatalf("load cve overrides: %v", err)
	}
	overrides := cve.ParseCVERuleOverrides(configs[site.ID])
	if _, ok := overrides["CVE-2026-DUPLICATE"]; ok {
		t.Fatalf("duplicate cve id unexpectedly received an ambiguous compatibility override: %#v", overrides)
	}
	first := overrides["duplicate-pattern-a"]
	if first.Action != "captcha_challenge" || first.CaptchaType != "slide" {
		t.Fatalf("first rule override=%#v, want captcha_challenge/slide", first)
	}
	second := overrides["duplicate-pattern-b"]
	if second.Action != "intercept" || second.CaptchaType != "" {
		t.Fatalf("second rule override=%#v, want its own intercept config", second)
	}
}
