package shared

import (
	"encoding/json"
	"testing"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
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
