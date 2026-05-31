package store

import (
	"encoding/json"
	"strings"
)

// ProtectionConfig is the global protection configuration stored as JSON in SystemSettings.
type ProtectionConfig struct {
	RequestRateLimitEnabled bool   `json:"request_ratelimit_enabled"`
	RequestRateLimitWindow  int    `json:"request_ratelimit_window"`
	RequestRateLimitMax     int    `json:"request_ratelimit_max"`
	RequestRateLimitAction  string `json:"request_ratelimit_action"`

	ErrorRateLimitEnabled    bool   `json:"error_ratelimit_enabled"`
	ErrorRateLimitWindow     int    `json:"error_ratelimit_window"`
	ErrorRateLimitMax        int    `json:"error_ratelimit_max"`
	ErrorRateLimitCount4xx   bool   `json:"error_ratelimit_count_4xx"`
	ErrorRateLimitCount5xx   bool   `json:"error_ratelimit_count_5xx"`
	ErrorRateLimitCountBlock bool   `json:"error_ratelimit_count_block"`
	ErrorRateLimitAction     string `json:"error_ratelimit_action"`

	OWASPEnabled     bool   `json:"builtin_owasp_enabled"`
	OWASPSensitivity string `json:"builtin_owasp_sensitivity"`
	OWASPAction      string `json:"builtin_owasp_on_hit"`

	MaintenanceGlobalEnabled bool   `json:"maintenance_global_enabled"`
	MaintenanceGlobalHTML    string `json:"maintenance_global_html"`
	MaintenanceGlobalStatus  int    `json:"maintenance_global_status"`

	BotDetectionEnabled bool `json:"bot_detection_enabled"`

	AutoBanEnabled   bool `json:"auto_ban_enabled"`
	AutoBanThreshold int  `json:"auto_ban_threshold"`
	AutoBanWindow    int  `json:"auto_ban_window"`
	AutoBanDuration  int  `json:"auto_ban_duration"`

	WaitingRoomEnabled bool   `json:"waiting_room_enabled"`
	CCUseCustom        bool   `json:"cc_use_custom"`
	CCRules            string `json:"cc_rules,omitempty"`

	OWASPModules string `json:"owasp_modules,omitempty"`

	CVEEnabled          bool   `json:"cve_enabled"`
	CVEAction           string `json:"cve_action"`
	CVEAutoDropCritical bool   `json:"cve_auto_drop_critical"`
	CVEAutoDropHigh     bool   `json:"cve_auto_drop_high"`
	CVERulesConfig      string `json:"cve_rules_config"`

	AutoBanAction string `json:"auto_ban_action" gorm:"default:'intercept'"`

	CategorySensitivity string `json:"category_sensitivity,omitempty" gorm:"column:category_sensitivity;type:text;default:'{}'"`

	OWASPRulesConfig string `json:"owasp_rules_config" gorm:"type:text;default:'{}'"`

	LoginMinPasswordLength int `json:"login_min_password_length"`
	LoginMaxAttempts       int `json:"login_max_attempts"`
	LoginLockoutMinutes    int `json:"login_lockout_minutes"`

	CaptchaEnabled bool   `json:"captcha_enabled"`
	CaptchaType    string `json:"captcha_type"`
	CaptchaTimeout int    `json:"captcha_timeout"`
	CaptchaPassTTL int    `json:"captcha_pass_ttl"`

	ShieldEnabled           bool `json:"shield_enabled"`
	ShieldDifficulty        int  `json:"shield_difficulty"`
	ShieldTimeoutSecs       int  `json:"shield_timeout_secs"`        // 验证超时（秒）
	ShieldAutoStartDelay    int  `json:"shield_auto_start_delay"`    // 自动启动延迟（ms）
	ShieldMaxRetries        int  `json:"shield_max_retries"`         // 最大重试次数
	ShieldEnvStrictness     int  `json:"shield_env_strictness"`      // 环境检测严格度 (0/1/2)
	ShieldRequireHTTP2      bool `json:"shield_require_http2"`       // 要求 HTTP/2
	ShieldRequireHTTP3      bool `json:"shield_require_http3"`       // 要求 HTTP/3
	ShieldAllowHTTP1        bool `json:"shield_allow_http1"`         // 允许 HTTP/1.x
	ShieldEnableWASM        bool `json:"shield_enable_wasm"`         // 启用 WASM PoW
	ShieldEnableJSChallenge bool `json:"shield_enable_js_challenge"` // 启用 JS 挑战
	ShieldEnableEnvCheck    bool `json:"shield_enable_env_check"`    // 启用环境指纹
	ShieldEnableDevTools    bool `json:"shield_enable_devtools"`     // 启用 DevTools 检测

	ChainEnabled bool   `json:"chain_enabled"`
	ChainSteps   string `json:"chain_steps,omitempty"`

	EscalationEnabled    bool   `json:"escalation_enabled"`
	EscalationWindowSecs int    `json:"escalation_window_secs"`
	EscalationSteps      string `json:"escalation_steps,omitempty"`
}

func DefaultProtectionConfig() ProtectionConfig {
	return ProtectionConfig{
		RequestRateLimitWindow:  60,
		RequestRateLimitMax:     300,
		RequestRateLimitAction:  "rate_limit",
		ErrorRateLimitWindow:    300,
		ErrorRateLimitMax:       30,
		ErrorRateLimitAction:    "rate_limit",
		ErrorRateLimitCount4xx:  true,
		ErrorRateLimitCount5xx:  true,
		OWASPSensitivity:        "mid",
		OWASPAction:             "intercept",
		MaintenanceGlobalStatus: 503,
		BotDetectionEnabled:     false,
		AutoBanEnabled:          false,
		AutoBanThreshold:        10,
		AutoBanWindow:           60,
		AutoBanDuration:         3600,
		LoginMinPasswordLength:  8,
		LoginMaxAttempts:        5,
		LoginLockoutMinutes:     30,
		CVEAutoDropCritical:     true,
		CVEAutoDropHigh:         true,
		CaptchaType:             "math",
		CaptchaTimeout:          120,
		CaptchaPassTTL:          120,
		ShieldDifficulty:        4,
		ShieldTimeoutSecs:       30,
		ShieldAutoStartDelay:    800,
		ShieldMaxRetries:        3,
		ShieldEnvStrictness:     1,
		ShieldAllowHTTP1:        true,
		ShieldEnableWASM:        true,
		ShieldEnableJSChallenge: true,
		ShieldEnableEnvCheck:    true,
		ShieldEnableDevTools:    true,
		EscalationWindowSecs:    60,
	}
}

func normalizeProtectionSensitivityLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "off", "none":
		return "off"
	case "low":
		return "low"
	case "medium", "mid":
		return "mid"
	case "high":
		return "high"
	case "very_high", "very-high", "veryhigh":
		return "very_high"
	case "strict":
		return "strict"
	default:
		return ""
	}
}

func normalizeProtectionSensitivityMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for key, level := range m {
		if normalized := normalizeProtectionSensitivityLevel(level); normalized != "" {
			out[key] = normalized
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// GetCategorySensitivity parses the CategorySensitivity JSON field into a map.
func (p *ProtectionConfig) GetCategorySensitivity() map[string]string {
	if p.CategorySensitivity == "" || p.CategorySensitivity == "{}" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(p.CategorySensitivity), &m); err != nil {
		return nil
	}
	return normalizeProtectionSensitivityMap(m)
}

// GetOWASPModules parses the OWASPModules JSON field into a map.
func (p *ProtectionConfig) GetOWASPModules() map[string]string {
	if p.OWASPModules == "" || p.OWASPModules == "{}" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(p.OWASPModules), &m); err != nil {
		return nil
	}
	return normalizeProtectionSensitivityMap(m)
}

// EffectiveCategorySensitivity returns merged per-category overrides for runtime use.
func (p *ProtectionConfig) EffectiveCategorySensitivity() map[string]string {
	base := p.GetCategorySensitivity()
	mods := p.GetOWASPModules()
	if len(base) == 0 && len(mods) == 0 {
		return nil
	}
	out := make(map[string]string, len(base)+len(mods))
	for key, level := range mods {
		out[key] = level
	}
	for key, level := range base {
		out[key] = level
	}
	return out
}

// SetCategorySensitivity serialises the map into the CategorySensitivity JSON field.
func (p *ProtectionConfig) SetCategorySensitivity(m map[string]string) {
	m = normalizeProtectionSensitivityMap(m)
	if len(m) == 0 {
		p.CategorySensitivity = "{}"
		return
	}
	b, err := json.Marshal(m)
	if err != nil {
		p.CategorySensitivity = "{}"
		return
	}
	p.CategorySensitivity = string(b)
}

// GetOWASPRulesConfig parses the OWASPRulesConfig JSON field into a map.
func (p *ProtectionConfig) GetOWASPRulesConfig() map[string]interface{} {
	if p.OWASPRulesConfig == "" || p.OWASPRulesConfig == "{}" {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(p.OWASPRulesConfig), &m); err != nil {
		return nil
	}
	return m
}

// SetOWASPRulesConfig serialises the map into the OWASPRulesConfig JSON field.
func (p *ProtectionConfig) SetOWASPRulesConfig(config map[string]interface{}) {
	if len(config) == 0 {
		p.OWASPRulesConfig = "{}"
		return
	}
	b, err := json.Marshal(config)
	if err != nil {
		p.OWASPRulesConfig = "{}"
		return
	}
	p.OWASPRulesConfig = string(b)
}

// EscalationStepDef is the JSON-friendly step definition stored in ProtectionConfig.
type EscalationStepDef struct {
	Threshold int    `json:"threshold"`
	Action    string `json:"action"`
}

// GetEscalationSteps parses the EscalationSteps JSON field.
func (p *ProtectionConfig) GetEscalationSteps() []EscalationStepDef {
	if p.EscalationSteps == "" || p.EscalationSteps == "[]" {
		return nil
	}
	var steps []EscalationStepDef
	if err := json.Unmarshal([]byte(p.EscalationSteps), &steps); err != nil {
		return nil
	}
	return steps
}

// SetEscalationSteps serialises the steps into the EscalationSteps JSON field.
func (p *ProtectionConfig) SetEscalationSteps(steps []EscalationStepDef) {
	if len(steps) == 0 {
		p.EscalationSteps = "[]"
		return
	}
	b, err := json.Marshal(steps)
	if err != nil {
		p.EscalationSteps = "[]"
		return
	}
	p.EscalationSteps = string(b)
}

// BotProtectionConfig is a per-site bot protection override.
type BotProtectionConfig struct {
	Enabled bool   `json:"enabled"`
	Level   string `json:"level"`  // "low", "medium", "high"
	Action  string `json:"action"` // "intercept", "observe"
}

func DefaultBotProtectionConfig() BotProtectionConfig {
	return BotProtectionConfig{
		Enabled: false,
		Level:   "medium",
		Action:  "intercept",
	}
}

// AttackProtectionConfig is a per-site OWASP/signature protection override.
type AttackProtectionConfig struct {
	OWASPEnabled     bool   `json:"owasp_enabled"`
	OWASPSensitivity string `json:"owasp_sensitivity"`
	OWASPAction      string `json:"owasp_action"`
	SignatureEnabled bool   `json:"signature_enabled"`
	SignatureAction  string `json:"signature_action"`
}

func DefaultAttackProtectionConfig() AttackProtectionConfig {
	return AttackProtectionConfig{
		OWASPEnabled:     true,
		OWASPSensitivity: "mid",
		OWASPAction:      "intercept",
		SignatureEnabled: false,
		SignatureAction:  "intercept",
	}
}
