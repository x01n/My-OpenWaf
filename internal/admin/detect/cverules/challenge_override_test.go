package cverules

import (
	"strconv"
	"testing"

	"My-OpenWaf/internal/store/cve"
	"My-OpenWaf/internal/store/repository"
)

func TestCVERuleScopeOverridePersistsAndResolvesCaptchaType(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	rule := seedOneCVERule(t, repo)
	body := []byte(`{"scope":"global","action":"captcha_challenge","captcha_type":"rotate","status_code":0}`)
	ctx := invokeCVEHandler(t, UpdateSingleCVERule(repo, nil), "POST", "/api/v1/cve-rules/"+strconv.FormatUint(uint64(rule.ID), 10)+"/patch", strconv.FormatUint(uint64(rule.ID), 10), body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status=%d body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	views, err := listEffectiveCVERules(repo, cveScopeContext{ScopeType: cve.CVEScopeGlobal}, repository.CVERuleFilter{Query: rule.CVEID})
	if err != nil {
		t.Fatalf("list effective rules: %v", err)
	}
	if len(views) != 1 || views[0].Effective.Action != "captcha_challenge" || views[0].Effective.CaptchaType != "rotate" {
		t.Fatalf("effective views=%#v", views)
	}

	invalid := []byte(`{"scope":"global","captcha_type":"drag"}`)
	bad := invokeCVEHandler(t, UpdateSingleCVERule(repo, nil), "POST", "/api/v1/cve-rules/"+strconv.FormatUint(uint64(rule.ID), 10)+"/patch", strconv.FormatUint(uint64(rule.ID), 10), invalid)
	if bad.Response.StatusCode() != 400 {
		t.Fatalf("invalid captcha status=%d body=%s", bad.Response.StatusCode(), bad.Response.Body())
	}
}

func TestRuleOverridesRejectCaptchaTypeForNonCaptchaAction(t *testing.T) {
	actionValue := "intercept"
	captchaValue := "slide"
	if err := validateCVEScopePatch(&cve.CVERuleScopeOverride{Action: &actionValue, CaptchaType: &captchaValue}); err == nil {
		t.Fatal("CVE scope override accepted captcha_type with intercept action")
	}
}
