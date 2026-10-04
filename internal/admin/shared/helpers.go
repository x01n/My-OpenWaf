package shared

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"gorm.io/gorm"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/cve"
)

// LoadProtectionConfig 从系统设置仓库读取防护配置。
// 对无法返回错误的调用方，保留「缺失即用默认值」的既有行为。
func LoadProtectionConfig(repo *repository.SystemSettingsRepo) store.ProtectionConfig {
	cfg, err := LoadProtectionConfigStrict(repo)
	if err != nil {
		return store.DefaultProtectionConfig()
	}
	return cfg
}

// LoadProtectionConfigStrict 读取并校验已持久化的防护配置。
// 配置缺失时使用默认值；数据库错误与 JSON 错误会返回给调用方。
func LoadProtectionConfigStrict(repo *repository.SystemSettingsRepo) (store.ProtectionConfig, error) {
	val, err := repo.Get("protection")
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return store.DefaultProtectionConfig(), nil
		}
		return store.ProtectionConfig{}, fmt.Errorf("load protection config: %w", err)
	}
	cfg := store.DefaultProtectionConfig()
	if err := json.Unmarshal([]byte(val), &cfg); err != nil {
		return store.ProtectionConfig{}, fmt.Errorf("invalid protection config JSON: %w", err)
	}
	if err := cfg.ValidateBasicAuth(); err != nil {
		return store.ProtectionConfig{}, err
	}
	if err := ValidateGlobalCaptchaType(cfg.CaptchaType); err != nil {
		return store.ProtectionConfig{}, err
	}
	return cfg, nil
}

// NormalizeAndValidateBasicAuth 去除配置凭据的首尾空白；若启用了
// Basic Auth，则要求用户名与口令都非空。
func NormalizeAndValidateBasicAuth(cfg *store.ProtectionConfig) error {
	cfg.BasicAuthUsername = strings.TrimSpace(cfg.BasicAuthUsername)
	cfg.BasicAuthPassword = strings.TrimSpace(cfg.BasicAuthPassword)
	return cfg.ValidateBasicAuth()
}

// SaveProtectionConfig 把校验通过的防护配置写入系统设置仓库。
func SaveProtectionConfig(repo *repository.SystemSettingsRepo, cfg store.ProtectionConfig) error {
	if _, err := LoadProtectionConfigStrict(repo); err != nil {
		return err
	}
	if err := NormalizeAndValidateBasicAuth(&cfg); err != nil {
		return err
	}
	if err := ValidateGlobalCaptchaType(cfg.CaptchaType); err != nil {
		return err
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return repo.Set("protection", string(data))
}

// ParseUintParam 按名字从请求上下文中取出一个 uint 路径参数。
func ParseUintParam(c *app.RequestContext, name string) (uint, error) {
	v, err := strconv.ParseUint(c.Param(name), 10, 64)
	return uint(v), err
}

// ValidateSiteTLSCertificate 校验启用了 TLS 的站点确实引用了有效证书。
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

// ValidateRuleAction 归一化并校验规则动作字符串。
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

// ValidateActionWithoutRedirectTarget 校验那些不携带 redirect_to 目标的配置字段所用的动作。
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

// ValidateCaptchaType 校验规则级别的严格 CAPTCHA 覆盖契约。
func ValidateCaptchaType(value string) (string, bool) {
	if value == "" {
		return "", true
	}
	if !challenge.IsValidCaptchaType(challenge.CaptchaType(value)) {
		return "", false
	}
	return value, true
}

// ValidateGlobalCaptchaType 校验已持久化的全局 CAPTCHA 模式。
func ValidateGlobalCaptchaType(value string) error {
	if !challenge.IsValidCaptchaType(challenge.CaptchaType(value)) {
		return fmt.Errorf("captcha_type must be one of: math, click, slide, rotate")
	}
	return nil
}

// ValidateCCRules 校验全局与站点共用的 CC 规则 JSON 契约。
func ValidateCCRules(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var rules []struct {
		Enabled     *bool   `json:"enabled"`
		Name        *string `json:"name"`
		Action      string  `json:"action"`
		CaptchaType string  `json:"captcha_type"`
		Conditions  []struct {
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
		if rule.CaptchaType != "" {
			if _, ok := ValidateCaptchaType(rule.CaptchaType); !ok {
				return errors.New("invalid cc rule captcha_type")
			}
			switch strings.ToLower(strings.TrimSpace(rule.Action)) {
			case "captcha", "captcha_challenge":
			default:
				return errors.New("cc rule captcha_type requires captcha action")
			}
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

// ValidateCCRuleAction 校验受支持的 CC 动作及其 legacy 别名。
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

// ValidateChallengeAction 校验质询动作白名单并归一化。
// 合法集合：challenge / captcha_challenge / shield_challenge / chain_challenge。
// 空串表示「继承」，返回 ("", true)；非法值返回 ("", false)。
func ValidateChallengeAction(value string) (string, bool) {
	if value == "" {
		return "", true
	}
	normalized := action.Normalize(action.Type(value))
	switch normalized {
	case action.Challenge, action.CaptchaChallenge, action.ShieldChallenge, action.ChainChallenge:
		return string(normalized), true
	default:
		return "", false
	}
}

// ValidateGlobalChallengeAction 校验全局质询动作；空串视为默认 challenge，合法。
func ValidateGlobalChallengeAction(value string) bool {
	if value == "" {
		return true
	}
	_, ok := ValidateChallengeAction(value)
	return ok
}

// ValidateAntiReplayAction 校验 anti-replay 数据面路径会保留的动作集合。
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

// ValidateBotScoreThreshold 校验 bot/drop 共用的分值阈值范围。
func ValidateBotScoreThreshold(value int) bool {
	return value >= 1 && value <= 100
}

// ReloadCVERules 在 feed 管理器非空时触发一次 CVE 规则重载。
func ReloadCVERules(feedMgr *cve.CVEFeedManager) {
	if feedMgr != nil {
		feedMgr.ReloadRules()
	}
}

// SyncBotEnabledToProtection 更新 ProtectionConfig.BotDetectionEnabled，
// 使 bot 设置页切换开关时引擎侧保持一致。
func SyncBotEnabledToProtection(settingsRepo *repository.SystemSettingsRepo, enabled bool) error {
	cfg, err := LoadProtectionConfigStrict(settingsRepo)
	if err != nil {
		return err
	}
	if cfg.BotDetectionEnabled == enabled {
		return nil
	}
	cfg.BotDetectionEnabled = enabled
	return SaveProtectionConfig(settingsRepo, cfg)
}

// SyncCaptchaEnabledToProtection 更新 ProtectionConfig.CaptchaEnabled，
// 使 bot 设置页切换 CAPTCHA 开关时引擎侧保持一致。
func SyncCaptchaEnabledToProtection(settingsRepo *repository.SystemSettingsRepo, enabled bool) error {
	cfg, err := LoadProtectionConfigStrict(settingsRepo)
	if err != nil {
		return err
	}
	if cfg.CaptchaEnabled == enabled {
		return nil
	}
	cfg.CaptchaEnabled = enabled
	return SaveProtectionConfig(settingsRepo, cfg)
}

// SyncAntiReplayEnabledToProtection 更新运行时使用的全局 anti-replay 开关。
func SyncAntiReplayEnabledToProtection(settingsRepo *repository.SystemSettingsRepo, enabled bool) error {
	cfg, err := LoadProtectionConfigStrict(settingsRepo)
	if err != nil {
		return err
	}
	if cfg.AntiReplayEnabled == enabled {
		return nil
	}
	cfg.AntiReplayEnabled = enabled
	return SaveProtectionConfig(settingsRepo, cfg)
}

// SyncProtectionCaptchaToSettings 将 protection 中的 CAPTCHA 开关同步到 bot_settings 投影。
//
// @param settingsRepo 系统设置仓库
// @param enabled protection 中的 CAPTCHA 开关
// @return 持久化错误
func SyncProtectionCaptchaToSettings(settingsRepo *repository.SystemSettingsRepo, enabled bool) error {
	current := BotSettingsResponse{ScoreThreshold: 60}
	if val, err := settingsRepo.Get("bot_settings"); err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), &current)
	}
	if current.CaptchaEnabled == enabled {
		return nil
	}
	current.CaptchaEnabled = enabled
	data, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("marshal bot settings: %w", err)
	}
	return settingsRepo.Set("bot_settings", string(data))
}

// SyncProtectionAntiReplayToSettings 把 protection 中的 AntiReplayEnabled 同步到 bot_settings。
func SyncProtectionAntiReplayToSettings(settingsRepo *repository.SystemSettingsRepo, enabled bool) error {
	current := BotSettingsResponse{ScoreThreshold: 60}
	if val, err := settingsRepo.Get("bot_settings"); err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), &current)
	}
	if current.AntiReplayEnabled == enabled {
		return nil
	}
	current.AntiReplayEnabled = enabled
	data, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("marshal bot settings: %w", err)
	}
	return settingsRepo.Set("bot_settings", string(data))
}

// ValidateAntiReplayCookieMode 校验反重放 Cookie 校验模式并返回归一化值。
// 合法值集合为 standard / dual；空串在 allowEmpty 时返回 ("", true) 表示
// 「继承（站点 save 用）」语义，其余非法值返回 false。
func ValidateAntiReplayCookieMode(raw string, allowEmpty bool) (string, bool) {
	mode := strings.TrimSpace(raw)
	switch mode {
	case "":
		return "", allowEmpty
	case "standard", "dual":
		return mode, true
	default:
		return "", false
	}
}

// SyncAntiReplayCookieModeToProtection 更新运行时使用的全局 anti-replay Cookie 模式。
func SyncAntiReplayCookieModeToProtection(settingsRepo *repository.SystemSettingsRepo, mode string) error {
	cfg, err := LoadProtectionConfigStrict(settingsRepo)
	if err != nil {
		return err
	}
	if cfg.AntiReplayCookieMode == mode {
		return nil
	}
	cfg.AntiReplayCookieMode = mode
	return SaveProtectionConfig(settingsRepo, cfg)
}

// SyncProtectionAntiReplayCookieModeToSettings 把 protection 中的 AntiReplayCookieMode 同步到 bot_settings。
func SyncProtectionAntiReplayCookieModeToSettings(settingsRepo *repository.SystemSettingsRepo, mode string) error {
	current := BotSettingsResponse{ScoreThreshold: 60}
	if val, err := settingsRepo.Get("bot_settings"); err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), &current)
	}
	if current.AntiReplayCookieMode == mode {
		return nil
	}
	current.AntiReplayCookieMode = mode
	data, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("marshal bot settings: %w", err)
	}
	return settingsRepo.Set("bot_settings", string(data))
}

// SyncBrowserSignToProtection 将 bot_settings 中的浏览器签名配置同步到 protection，
// 供引擎 phase 与 proxy HTML 注入读取。
func SyncBrowserSignToProtection(settingsRepo *repository.SystemSettingsRepo, enabled bool, ttl int, action string) error {
	cfg, err := LoadProtectionConfigStrict(settingsRepo)
	if err != nil {
		return err
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
	return SaveProtectionConfig(settingsRepo, cfg)
}

// SyncBotThresholdToDropPolicy 让运行时 bot 阈值与 bot 设置页保持一致。
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

// SyncDropThresholdToBotSettings 更新 bot_settings.ScoreThreshold，
// 使 drop policy 页修改共用 bot 阈值时 bot 页保持一致。
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

// SyncCVEAutoDropToDropPolicy 让 CVE 自动 drop 的运行时策略与 protection 设置保持一致。
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

// SyncProtectionBotToSettings 更新 bot_settings.Enabled，
// 使 protection 页切换 bot_detection_enabled 时 bot 页保持一致。
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

// BotSettingsResponse 是 API 返回的 bot 检测配置。
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
	AntiReplayCookieMode     string   `json:"anti_replay_cookie_mode"`
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
