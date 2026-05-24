package shared

import (
	"encoding/json"
	"errors"
	"strconv"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/cve"
)

// LoadProtectionConfig reads the protection settings from the system settings repository.
func LoadProtectionConfig(repo *repository.SystemSettingsRepo) store.ProtectionConfig {
	val, err := repo.Get("protection")
	if err != nil {
		return store.DefaultProtectionConfig()
	}
	cfg := store.DefaultProtectionConfig()
	if json.Unmarshal([]byte(val), &cfg) != nil {
		return store.DefaultProtectionConfig()
	}
	return cfg
}

// SaveProtectionConfig writes the protection settings to the system settings repository.
func SaveProtectionConfig(repo *repository.SystemSettingsRepo, cfg store.ProtectionConfig) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return repo.Set("protection", string(data))
}

// ParseUintParam extracts a uint path parameter by name from the request context.
func ParseUintParam(c *app.RequestContext, name string) (uint, error) {
	v, err := strconv.ParseUint(c.Param(name), 10, 64)
	return uint(v), err
}

// ValidateSiteTLSCertificate checks that a TLS-enabled site has a valid certificate reference.
func ValidateSiteTLSCertificate(tlsEnabled bool, certID *uint, certRepo *repository.CertificateRepo) error {
	if !tlsEnabled {
		return nil
	}
	if certID == nil || *certID == 0 {
		return errors.New("TLS-enabled site requires cert_id")
	}
	if certRepo == nil {
		return nil
	}
	if _, err := certRepo.Get(*certID); err != nil {
		return errors.New("certificate not found")
	}
	return nil
}

// ValidateRuleAction normalizes and validates a rule action string.
func ValidateRuleAction(value string) (string, bool) {
	if value == "" {
		return "", true
	}
	act := action.Normalize(action.Type(value))
	if !action.IsValid(act) || act == action.Allow || act == action.Tag {
		return "", false
	}
	return string(act), true
}

// ReloadCVERules triggers a CVE rule reload on the feed manager if it is not nil.
func ReloadCVERules(feedMgr *cve.CVEFeedManager) {
	if feedMgr != nil {
		feedMgr.ReloadRules()
	}
}

// SyncBotEnabledToProtection updates ProtectionConfig.BotDetectionEnabled
// so the engine stays consistent when the bot settings page toggles the flag.
func SyncBotEnabledToProtection(settingsRepo *repository.SystemSettingsRepo, enabled bool) {
	cfg := store.DefaultProtectionConfig()
	if val, err := settingsRepo.Get("protection"); err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), &cfg)
	}
	if cfg.BotDetectionEnabled == enabled {
		return
	}
	cfg.BotDetectionEnabled = enabled
	data, _ := json.Marshal(cfg)
	_ = settingsRepo.Set("protection", string(data))
}

// SyncProtectionBotToSettings updates bot_settings.Enabled so the bot page
// stays consistent when the protection page toggles bot_detection_enabled.
func SyncProtectionBotToSettings(settingsRepo *repository.SystemSettingsRepo, enabled bool) {
	current := BotSettingsResponse{ScoreThreshold: 60}
	if val, err := settingsRepo.Get("bot_settings"); err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), &current)
	}
	if current.Enabled == enabled {
		return
	}
	current.Enabled = enabled
	data, _ := json.Marshal(current)
	_ = settingsRepo.Set("bot_settings", string(data))
}

// BotSettingsResponse represents the bot detection configuration returned by the API.
type BotSettingsResponse struct {
	Enabled           bool     `json:"enabled"`
	ScoreThreshold    int      `json:"score_threshold"`
	HighRiskCountries []string `json:"high_risk_countries"`
	DatacenterASNs    []uint32 `json:"datacenter_asns"`
	VPNProxyASNs      []uint32 `json:"vpn_proxy_asns"`
	GeoIPDBPath       string   `json:"geoip_db_path"`
}
