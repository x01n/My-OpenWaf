package cve

import (
	"log/slog"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestCVEFeedManagerPreservesDisabledCustomRuleState(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&CVERuleModel{}); err != nil {
		t.Fatalf("migrate cve rules: %v", err)
	}
	rule := CVERuleModel{
		CVEID:       "CVE-2026-DISABLED",
		Category:    "general",
		Pattern:     `disabled-marker`,
		Target:      "body",
		Severity:    "high",
		Action:      "intercept",
		Enabled:     false,
		Description: "disabled custom rule",
		Source:      "custom",
		Approved:    true,
	}
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("create rule: %v", err)
	}
	enabledRule := CVERuleModel{
		CVEID: "CVE-2026-CAPTCHA", Category: "general", Pattern: `captcha-marker`,
		Target: "body", Severity: "high", Action: "captcha_challenge", CaptchaType: "slide",
		Enabled: true, Description: "captcha custom rule", Source: "custom", Approved: true,
	}
	if err := db.Create(&enabledRule).Error; err != nil {
		t.Fatalf("create enabled rule: %v", err)
	}
	detector := NewCVEDetector()
	manager := NewCVEFeedManagerWithFeed(db, detector, time.Hour, "", false, false, slog.Default())
	manager.Start()

	req := BuildCVERequest("/", "", nil, []byte("jndi:disabled-marker"), "text/plain")
	for _, match := range detector.Detect(req) {
		if match.CVEID == rule.CVEID {
			t.Fatalf("disabled custom rule produced a match: %+v", match)
		}
	}
	req = BuildCVERequest("/", "", nil, []byte("jndi:captcha-marker"), "text/plain")
	found := false
	for _, match := range detector.Detect(req) {
		if match.CVEID == enabledRule.CVEID {
			found = true
			if match.CaptchaType != "slide" {
				t.Fatalf("custom CAPTCHA type = %q, want slide", match.CaptchaType)
			}
		}
	}
	if !found {
		t.Fatal("enabled custom CAPTCHA rule did not match")
	}
}

func TestCVEFeedManagerStopIsIdempotent(t *testing.T) {
	m := &CVEFeedManager{feedEnabled: true, stopCh: make(chan struct{})}
	m.Stop()
	m.Stop()
	var zero CVEFeedManager
	zero.Stop()
}
