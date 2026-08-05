package shared

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

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

// ValidateActionWithoutRedirectTarget validates actions for config fields that
// do not carry a redirect_to target.
func ValidateActionWithoutRedirectTarget(value string) (string, bool) {
	normalized, ok := ValidateRuleAction(value)
	if !ok {
		return "", false
	}
	if action.Normalize(action.Type(normalized)) == action.Redirect {
		return "", false
	}
	return normalized, true
}

func ValidateActionWithRedirectTarget(value string, redirectTo *string) (string, bool) {
	normalized, ok := ValidateRuleAction(value)
	if !ok {
		return "", false
	}
	if action.Normalize(action.Type(normalized)) == action.Redirect && (redirectTo == nil || strings.TrimSpace(*redirectTo) == "") {
		return "", false
	}
	return normalized, true
}

// ValidateCCRules validates the shared global/site CC rule JSON contract.
func ValidateCCRules(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var rules []struct {
		Enabled    *bool   `json:"enabled"`
		Name       *string `json:"name"`
		Action     string  `json:"action"`
		Conditions []struct {
			Target   string `json:"target"`
			Operator string `json:"operator"`
			Value    string `json:"value"`
		} `json:"conditions"`
		Window       int    `json:"window"`
		Threshold    int    `json:"threshold"`
		Duration     int    `json:"duration"`
		DurationUnit string `json:"duration_unit"`
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&rules); err != nil {
		return fmt.Errorf("invalid cc rules: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("invalid cc rules: multiple JSON values")
	}
	if rules == nil {
		return errors.New("cc rules must be an array")
	}
	for _, rule := range rules {
		if _, ok := ValidateCCRuleAction(rule.Action); !ok {
			return errors.New("invalid cc rule action")
		}
		if len(rule.Conditions) == 0 {
			return errors.New("cc rule requires conditions")
		}
		if rule.Window <= 0 || rule.Threshold <= 0 {
			return errors.New("cc rule window and threshold must be positive")
		}
		if rule.Duration < 0 {
			return errors.New("cc rule duration must be non-negative")
		}
		if !validCCDurationUnit(rule.DurationUnit) {
			return errors.New("invalid cc rule duration unit")
		}
		for _, condition := range rule.Conditions {
			target := strings.ToLower(strings.TrimSpace(condition.Target))
			op := strings.ToLower(strings.TrimSpace(condition.Operator))
			if strings.TrimSpace(condition.Value) == "" {
				return errors.New("cc rule condition value is required")
			}
			valid := false
			switch target {
			case "url_path":
				valid = op == "equals" || op == "prefix" || op == "contains"
			case "method":
				valid = op == "equals"
			case "header":
				valid = op == "equals" || op == "contains" || op == "prefix"
				if valid {
					name, value := splitCCHeaderValueForValidation(condition.Value)
					valid = name != "" && value != ""
				}
			}
			if !valid {
				return errors.New("invalid cc rule condition")
			}
		}
	}
	return nil
}

// ValidateCCRuleAction validates supported CC actions and legacy aliases.
func ValidateCCRuleAction(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "intercept", "rate_limit", "captcha", "captcha_challenge", "shield_challenge", "chain_challenge", "drop", "observe", "challenge", "block", "log_only":
		return strings.ToLower(strings.TrimSpace(value)), true
	default:
		return "", false
	}
}

func validCCDurationUnit(unit string) bool {
	switch strings.ToLower(strings.TrimSpace(unit)) {
	case "", "seconds", "minutes":
		return true
	default:
		return false
	}
}

func splitCCHeaderValueForValidation(value string) (string, string) {
	for _, separator := range []string{":", "="} {
		if name, headerValue, ok := strings.Cut(value, separator); ok {
			return strings.TrimSpace(name), strings.TrimSpace(headerValue)
		}
	}
	return "", ""
}

// ValidateAntiReplayAction validates the actions preserved by the anti-replay dataplane path.
func ValidateAntiReplayAction(value string) (string, bool) {
	if value == "" {
		return "", true
	}
	act := action.Normalize(action.Type(value))
	switch act {
	case action.Challenge, action.CaptchaChallenge, action.ShieldChallenge, action.ChainChallenge, action.Intercept:
		return string(act), true
	default:
		return "", false
	}
}

// ValidateBotScoreThreshold checks the shared bot/drop threshold range.
func ValidateBotScoreThreshold(value int) bool {
	return value >= 1 && value <= 100
}

// ReloadCVERules triggers a CVE rule reload on the feed manager if it is not nil.
func ReloadCVERules(feedMgr *cve.CVEFeedManager) {
	if feedMgr != nil {
		feedMgr.ReloadRules()
	}
}

// SyncBotEnabledToProtection updates ProtectionConfig.BotDetectionEnabled
// so the engine stays consistent when the bot settings page toggles the flag.
func SyncBotEnabledToProtection(settingsRepo *repository.SystemSettingsRepo, enabled bool) error {
	cfg := store.DefaultProtectionConfig()
	if val, err := settingsRepo.Get("protection"); err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), &cfg)
	}
	if cfg.BotDetectionEnabled == enabled {
		return nil
	}
	cfg.BotDetectionEnabled = enabled
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal protection config: %w", err)
	}
	return settingsRepo.Set("protection", string(data))
}

// SyncCaptchaEnabledToProtection updates ProtectionConfig.CaptchaEnabled
// so the engine stays consistent when the bot settings page toggles the captcha flag.
func SyncCaptchaEnabledToProtection(settingsRepo *repository.SystemSettingsRepo, enabled bool) error {
	cfg := store.DefaultProtectionConfig()
	if val, err := settingsRepo.Get("protection"); err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), &cfg)
	}
	if cfg.CaptchaEnabled == enabled {
		return nil
	}
	cfg.CaptchaEnabled = enabled
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal protection config: %w", err)
	}
	return settingsRepo.Set("protection", string(data))
}

// SyncBrowserSignToProtection 将 bot_settings 中的浏览器签名配置同步到 protection，
// 供引擎 phase 与 proxy HTML 注入读取。
func SyncBrowserSignToProtection(settingsRepo *repository.SystemSettingsRepo, enabled bool, ttl int, action string) error {
	cfg := store.DefaultProtectionConfig()
	if val, err := settingsRepo.Get("protection"); err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), &cfg)
	}
	changed := false
	if cfg.BrowserSignEnabled != enabled {
		cfg.BrowserSignEnabled = enabled
		changed = true
	}
	if ttl > 0 && cfg.BrowserSignTTL != ttl {
		cfg.BrowserSignTTL = ttl
		changed = true
	}
	if action != "" && cfg.BrowserSignAction != action {
		cfg.BrowserSignAction = action
		changed = true
	}
	if !changed {
		return nil
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal protection config: %w", err)
	}
	return settingsRepo.Set("protection", string(data))
}

// SyncBotThresholdToDropPolicy keeps the runtime bot threshold aligned with the bot settings page.
func SyncBotThresholdToDropPolicy(settingsRepo *repository.SystemSettingsRepo, threshold int) error {
	if threshold <= 0 {
		return nil
	}
	current := struct {
		Enabled             bool `json:"enabled"`
		BotScoreThreshold   int  `json:"bot_score_threshold"`
		CVEAutoDropCritical bool `json:"cve_auto_drop_critical"`
		CVEAutoDropHigh     bool `json:"cve_auto_drop_high"`
	}{
		Enabled:             true,
		BotScoreThreshold:   80,
		CVEAutoDropCritical: true,
		CVEAutoDropHigh:     true,
	}
	if val, err := settingsRepo.Get("drop_policy"); err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), &current)
	}
	if current.BotScoreThreshold == threshold {
		return nil
	}
	current.BotScoreThreshold = threshold
	data, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("marshal drop policy: %w", err)
	}
	return settingsRepo.Set("drop_policy", string(data))
}

// SyncCVEAutoDropToDropPolicy keeps CVE auto-drop runtime policy aligned with protection settings.
// SyncDropThresholdToBotSettings updates bot_settings.ScoreThreshold so the bot page
// stays consistent when the drop policy page changes the shared bot threshold.
func SyncDropThresholdToBotSettings(settingsRepo *repository.SystemSettingsRepo, threshold int) error {
	if threshold <= 0 {
		return nil
	}
	current := BotSettingsResponse{ScoreThreshold: 60}
	if val, err := settingsRepo.Get("bot_settings"); err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), &current)
	}
	if current.ScoreThreshold == threshold {
		return nil
	}
	current.ScoreThreshold = threshold
	data, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("marshal bot settings: %w", err)
	}
	return settingsRepo.Set("bot_settings", string(data))
}

func SyncCVEAutoDropToDropPolicy(settingsRepo *repository.SystemSettingsRepo, critical, high bool) error {
	current := struct {
		Enabled             bool `json:"enabled"`
		BotScoreThreshold   int  `json:"bot_score_threshold"`
		CVEAutoDropCritical bool `json:"cve_auto_drop_critical"`
		CVEAutoDropHigh     bool `json:"cve_auto_drop_high"`
	}{
		Enabled:             true,
		BotScoreThreshold:   80,
		CVEAutoDropCritical: true,
		CVEAutoDropHigh:     true,
	}
	if val, err := settingsRepo.Get("drop_policy"); err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), &current)
	}
	if current.CVEAutoDropCritical == critical && current.CVEAutoDropHigh == high {
		return nil
	}
	current.CVEAutoDropCritical = critical
	current.CVEAutoDropHigh = high
	data, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("marshal drop policy: %w", err)
	}
	return settingsRepo.Set("drop_policy", string(data))
}

// SyncProtectionBotToSettings updates bot_settings.Enabled so the bot page
// stays consistent when the protection page toggles bot_detection_enabled.
func SyncProtectionBotToSettings(settingsRepo *repository.SystemSettingsRepo, enabled bool) error {
	current := BotSettingsResponse{ScoreThreshold: 60}
	if val, err := settingsRepo.Get("bot_settings"); err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), &current)
	}
	if current.Enabled == enabled {
		return nil
	}
	current.Enabled = enabled
	data, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("marshal bot settings: %w", err)
	}
	return settingsRepo.Set("bot_settings", string(data))
}

// BotSettingsResponse represents the bot detection configuration returned by the API.
type BotSettingsResponse struct {
	Enabled                  bool     `json:"enabled"`
	ScoreThreshold           int      `json:"score_threshold"`
	HighRiskCountries        []string `json:"high_risk_countries"`
	DatacenterASNs           []uint32 `json:"datacenter_asns"`
	VPNProxyASNs             []uint32 `json:"vpn_proxy_asns"`
	GeoIPDBPath              string   `json:"geoip_db_path"`
	CaptchaEnabled           bool     `json:"captcha_enabled"`
	DynamicProtectionEnabled bool     `json:"dynamic_protection_enabled"`
	HTMLObfuscation          bool     `json:"html_obfuscation"`
	JSObfuscation            bool     `json:"js_obfuscation"`
	ImageWatermark           bool     `json:"image_watermark"`
	AntiReplayEnabled        bool     `json:"anti_replay_enabled"`
	BrowserSignEnabled       bool     `json:"browser_sign_enabled"`
	BrowserSignTTL           int      `json:"browser_sign_ttl"`
	BrowserSignAction        string   `json:"browser_sign_action"`
	JSObfuscationPaths       []string `json:"js_obfuscation_paths,omitempty"`
	JSProtectionMode         string   `json:"js_protection_mode,omitempty"`
	DecryptCacheTTLSeconds   int      `json:"decrypt_cache_ttl_seconds,omitempty"`
	ImageWatermarkPaths      []string `json:"image_watermark_paths,omitempty"`
	WatermarkText            string   `json:"watermark_text,omitempty"`
	ExcludeRecordHeaders     []string `json:"exclude_record_headers,omitempty"`
}
