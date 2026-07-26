package shared

import (
	"encoding/json"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

func newSystemSettingsRepoForTest(t *testing.T) *repository.SystemSettingsRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SystemSettings{}); err != nil {
		t.Fatalf("migrate settings: %v", err)
	}
	return repository.NewSystemSettingsRepo(db)
}

func newCertificateRepoForTest(t *testing.T) *repository.CertificateRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Certificate{}); err != nil {
		t.Fatalf("migrate certificates: %v", err)
	}
	return repository.NewCertificateRepo(db)
}

func TestValidateSiteTLSCertificate(t *testing.T) {
	repo := newCertificateRepoForTest(t)
	cert := store.Certificate{Name: "test", CertPEM: "cert", KeyPEM: "key"}
	if err := repo.Create(&cert); err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	if err := ValidateSiteTLSCertificate(false, nil, repo); err != nil {
		t.Fatalf("disabled TLS should not require certificate: %v", err)
	}
	if err := ValidateSiteTLSCertificate(true, nil, repo); err == nil || err.Error() != "TLS-enabled site requires cert_id" {
		t.Fatalf("expected missing cert_id error, got %v", err)
	}
	missingID := cert.ID + 1
	if err := ValidateSiteTLSCertificate(true, &missingID, repo); err == nil || err.Error() != "certificate not found" {
		t.Fatalf("expected certificate not found error, got %v", err)
	}
	if err := ValidateSiteTLSCertificate(true, &cert.ID, repo); err != nil {
		t.Fatalf("valid certificate should pass: %v", err)
	}
	if err := ValidateSiteTLSCertificate(true, &cert.ID, nil); err != nil {
		t.Fatalf("nil repo should preserve legacy caller behavior: %v", err)
	}
}

func TestSyncBotThresholdToDropPolicyPreservesExistingDropFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	initial := map[string]any{
		"enabled":                false,
		"bot_score_threshold":    80,
		"cve_auto_drop_critical": false,
		"cve_auto_drop_high":     true,
	}
	data, _ := json.Marshal(initial)
	if err := repo.Set("drop_policy", string(data)); err != nil {
		t.Fatalf("seed drop policy: %v", err)
	}

	if err := SyncBotThresholdToDropPolicy(repo, 72); err != nil {
		t.Fatalf("sync bot threshold: %v", err)
	}

	val, err := repo.Get("drop_policy")
	if err != nil {
		t.Fatalf("get drop policy: %v", err)
	}
	var got struct {
		Enabled             bool `json:"enabled"`
		BotScoreThreshold   int  `json:"bot_score_threshold"`
		CVEAutoDropCritical bool `json:"cve_auto_drop_critical"`
		CVEAutoDropHigh     bool `json:"cve_auto_drop_high"`
	}
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode drop policy: %v", err)
	}
	if got.BotScoreThreshold != 72 {
		t.Fatalf("expected bot threshold 72, got %d", got.BotScoreThreshold)
	}
	if got.Enabled || got.CVEAutoDropCritical || !got.CVEAutoDropHigh {
		t.Fatalf("unrelated drop fields changed: %+v", got)
	}
}

func TestSyncBotThresholdToDropPolicyCreatesDefaultPolicy(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := SyncBotThresholdToDropPolicy(repo, 65); err != nil {
		t.Fatalf("sync bot threshold: %v", err)
	}
	val, err := repo.Get("drop_policy")
	if err != nil {
		t.Fatalf("get drop policy: %v", err)
	}
	var got struct {
		Enabled             bool `json:"enabled"`
		BotScoreThreshold   int  `json:"bot_score_threshold"`
		CVEAutoDropCritical bool `json:"cve_auto_drop_critical"`
		CVEAutoDropHigh     bool `json:"cve_auto_drop_high"`
	}
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode drop policy: %v", err)
	}
	if !got.Enabled || got.BotScoreThreshold != 65 || !got.CVEAutoDropCritical || !got.CVEAutoDropHigh {
		t.Fatalf("unexpected default drop policy: %+v", got)
	}
}

func TestSyncDropThresholdToBotSettingsPreservesExistingBotFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	initial := BotSettingsResponse{
		Enabled:           true,
		ScoreThreshold:    60,
		HighRiskCountries: []string{"CN"},
		DatacenterASNs:    []uint32{64512},
		VPNProxyASNs:      []uint32{64513},
		GeoIPDBPath:       "/tmp/GeoLite2.mmdb",
	}
	data, _ := json.Marshal(initial)
	if err := repo.Set("bot_settings", string(data)); err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}

	if err := SyncDropThresholdToBotSettings(repo, 88); err != nil {
		t.Fatalf("sync drop threshold: %v", err)
	}

	val, err := repo.Get("bot_settings")
	if err != nil {
		t.Fatalf("get bot settings: %v", err)
	}
	var got BotSettingsResponse
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode bot settings: %v", err)
	}
	if got.ScoreThreshold != 88 {
		t.Fatalf("expected score threshold 88, got %d", got.ScoreThreshold)
	}
	if !got.Enabled || len(got.HighRiskCountries) != 1 || got.HighRiskCountries[0] != "CN" || len(got.DatacenterASNs) != 1 || got.DatacenterASNs[0] != 64512 || len(got.VPNProxyASNs) != 1 || got.VPNProxyASNs[0] != 64513 || got.GeoIPDBPath != "/tmp/GeoLite2.mmdb" {
		t.Fatalf("unrelated bot fields changed: %+v", got)
	}
}

func TestSyncCVEAutoDropToDropPolicyPreservesBotFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	initial := map[string]any{
		"enabled":                false,
		"bot_score_threshold":    73,
		"cve_auto_drop_critical": true,
		"cve_auto_drop_high":     true,
	}
	data, _ := json.Marshal(initial)
	if err := repo.Set("drop_policy", string(data)); err != nil {
		t.Fatalf("seed drop policy: %v", err)
	}

	if err := SyncCVEAutoDropToDropPolicy(repo, false, false); err != nil {
		t.Fatalf("sync cve auto drop: %v", err)
	}

	val, err := repo.Get("drop_policy")
	if err != nil {
		t.Fatalf("get drop policy: %v", err)
	}
	var got struct {
		Enabled             bool `json:"enabled"`
		BotScoreThreshold   int  `json:"bot_score_threshold"`
		CVEAutoDropCritical bool `json:"cve_auto_drop_critical"`
		CVEAutoDropHigh     bool `json:"cve_auto_drop_high"`
	}
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode drop policy: %v", err)
	}
	if got.Enabled || got.BotScoreThreshold != 73 {
		t.Fatalf("unrelated drop fields changed: %+v", got)
	}
	if got.CVEAutoDropCritical || got.CVEAutoDropHigh {
		t.Fatalf("cve auto drop was not synced: %+v", got)
	}
}

func TestLoadProtectionConfigDefaultOnMissingKey(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := LoadProtectionConfig(repo)
	def := store.DefaultProtectionConfig()
	data1, _ := json.Marshal(cfg)
	data2, _ := json.Marshal(def)
	if string(data1) != string(data2) {
		t.Fatalf("expected default config on missing key, got %s", data1)
	}
}

func TestSaveAndLoadProtectionConfig(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	def := store.DefaultProtectionConfig()
	def.BotDetectionEnabled = !def.BotDetectionEnabled
	if err := SaveProtectionConfig(repo, def); err != nil {
		t.Fatalf("SaveProtectionConfig: %v", err)
	}
	got := LoadProtectionConfig(repo)
	if got.BotDetectionEnabled != def.BotDetectionEnabled {
		t.Fatalf("expected BotDetectionEnabled %v, got %v", def.BotDetectionEnabled, got.BotDetectionEnabled)
	}
}

func TestParseUintParam(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Params = param.Params{{Key: "id", Value: "42"}}
	v, err := ParseUintParam(ctx, "id")
	if err != nil || v != 42 {
		t.Fatalf("ParseUintParam(42) = (%d, %v), want (42, nil)", v, err)
	}
	ctx.Params = param.Params{{Key: "id", Value: "notanumber"}}
	_, err = ParseUintParam(ctx, "id")
	if err == nil {
		t.Fatal("expected error for non-numeric id")
	}
}

func TestValidateRuleAction(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"", "", true},
		{"intercept", "intercept", true},
		{"block", "intercept", true},
		{"observe", "observe", true},
		{"allow", "", false},
		{"tag", "", false},
		{"unknown_xyz", "", false},
	}
	for _, tt := range tests {
		got, ok := ValidateRuleAction(tt.in)
		if ok != tt.ok || got != tt.want {
			t.Errorf("ValidateRuleAction(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestValidateActionWithoutRedirectTarget(t *testing.T) {
	_, ok := ValidateActionWithoutRedirectTarget("redirect")
	if ok {
		t.Fatal("redirect action should be rejected when no redirect target is present")
	}
	got, ok := ValidateActionWithoutRedirectTarget("intercept")
	if !ok || got != "intercept" {
		t.Fatalf("intercept should be valid: got (%q, %v)", got, ok)
	}
	_, ok = ValidateActionWithoutRedirectTarget("")
	if !ok {
		t.Fatal("empty action should be valid (inherits default)")
	}
}

func TestValidateAntiReplayAction(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"", "", true},
		{"intercept", "intercept", true},
		{"challenge", "challenge", true},
		{"captcha_challenge", "captcha_challenge", true},
		{"shield_challenge", "shield_challenge", true},
		{"chain_challenge", "chain_challenge", true},
		{"drop", "", false},
		{"observe", "", false},
		{"allow", "", false},
	}
	for _, tt := range tests {
		got, ok := ValidateAntiReplayAction(tt.in)
		if ok != tt.ok || got != tt.want {
			t.Errorf("ValidateAntiReplayAction(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestValidateBotScoreThreshold(t *testing.T) {
	for _, v := range []int{1, 50, 100} {
		if !ValidateBotScoreThreshold(v) {
			t.Errorf("ValidateBotScoreThreshold(%d) should be true", v)
		}
	}
	for _, v := range []int{0, -1, 101, 200} {
		if ValidateBotScoreThreshold(v) {
			t.Errorf("ValidateBotScoreThreshold(%d) should be false", v)
		}
	}
}

func TestReloadCVERulesNilDoesNotPanic(t *testing.T) {
	ReloadCVERules(nil)
}

func TestSyncBotEnabledToProtection(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := SyncBotEnabledToProtection(repo, true); err != nil {
		t.Fatalf("SyncBotEnabledToProtection(true): %v", err)
	}
	cfg := LoadProtectionConfig(repo)
	if !cfg.BotDetectionEnabled {
		t.Fatal("BotDetectionEnabled should be true after sync")
	}
	if err := SyncBotEnabledToProtection(repo, true); err != nil {
		t.Fatalf("SyncBotEnabledToProtection same value: %v", err)
	}
	if err := SyncBotEnabledToProtection(repo, false); err != nil {
		t.Fatalf("SyncBotEnabledToProtection(false): %v", err)
	}
	cfg = LoadProtectionConfig(repo)
	if cfg.BotDetectionEnabled {
		t.Fatal("BotDetectionEnabled should be false after disabling")
	}
}

func TestSyncCaptchaEnabledToProtection(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := SyncCaptchaEnabledToProtection(repo, true); err != nil {
		t.Fatalf("SyncCaptchaEnabledToProtection(true): %v", err)
	}
	cfg := LoadProtectionConfig(repo)
	if !cfg.CaptchaEnabled {
		t.Fatal("CaptchaEnabled should be true after sync")
	}
	if err := SyncCaptchaEnabledToProtection(repo, true); err != nil {
		t.Fatalf("SyncCaptchaEnabledToProtection same value: %v", err)
	}
}

func TestSyncBrowserSignToProtection(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := SyncBrowserSignToProtection(repo, true, 600, "intercept"); err != nil {
		t.Fatalf("SyncBrowserSignToProtection: %v", err)
	}
	cfg := LoadProtectionConfig(repo)
	if !cfg.BrowserSignEnabled || cfg.BrowserSignTTL != 600 || cfg.BrowserSignAction != "intercept" {
		t.Fatalf("unexpected BrowserSign state: enabled=%v ttl=%d action=%q",
			cfg.BrowserSignEnabled, cfg.BrowserSignTTL, cfg.BrowserSignAction)
	}
	if err := SyncBrowserSignToProtection(repo, true, 600, "intercept"); err != nil {
		t.Fatalf("SyncBrowserSignToProtection same value: %v", err)
	}
}

func TestSyncProtectionBotToSettings(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	initial := BotSettingsResponse{Enabled: false, ScoreThreshold: 75}
	data, _ := json.Marshal(initial)
	_ = repo.Set("bot_settings", string(data))

	if err := SyncProtectionBotToSettings(repo, true); err != nil {
		t.Fatalf("SyncProtectionBotToSettings(true): %v", err)
	}
	val, _ := repo.Get("bot_settings")
	var got BotSettingsResponse
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode bot settings: %v", err)
	}
	if !got.Enabled {
		t.Fatal("Enabled should be true after sync")
	}
	if got.ScoreThreshold != 75 {
		t.Fatalf("unrelated ScoreThreshold changed: got %d", got.ScoreThreshold)
	}
	if err := SyncProtectionBotToSettings(repo, true); err != nil {
		t.Fatalf("SyncProtectionBotToSettings same value: %v", err)
	}
}
