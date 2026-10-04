package store

import (
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"gorm.io/gorm"
)

const (
	XFFModeStrip      = "strip_all_and_set_remote"
	XFFModeTrustOuter = "trust_outer_waf_cidr_then_take_leftmost"

	ClientIPHeaderXForwardedFor = "x_forwarded_for"
	ClientIPHeaderXRealIP       = "x_real_ip"
	ClientIPHeaderForwarded     = "forwarded"

	SiteProtectionModeProtect = "protect"
	SiteProtectionModeObserve = "observe"
)

// IsClientIPHeader 报告 header 是否可用于可信客户端 IP 提取。
func IsClientIPHeader(header string) bool {
	switch header {
	case ClientIPHeaderXForwardedFor, ClientIPHeaderXRealIP, ClientIPHeaderForwarded:
		return true
	default:
		return false
	}
}

type Site struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Host         string `gorm:"size:255;not null;index" json:"host"`
	UpstreamURLs string `gorm:"type:text;not null" json:"upstream_urls"`
	UpstreamHost string `gorm:"size:255" json:"upstream_host"`

	Bind    string `gorm:"size:255;not null;index" json:"bind"`
	Network string `gorm:"size:16;default:tcp" json:"network"`
	Enabled bool   `gorm:"default:true" json:"enabled"`

	TLSEnabled    bool   `gorm:"default:false" json:"tls_enabled"`
	CertID        *uint  `json:"cert_id,omitempty"`
	MinTLSVersion string `gorm:"size:32" json:"min_tls_version"`
	MaxTLSVersion string `gorm:"size:32" json:"max_tls_version"`
	CipherSuites  string `gorm:"type:text" json:"cipher_suites"`
	ALPN          string `gorm:"size:255" json:"alpn"`

	PolicyID              *uint  `json:"policy_id,omitempty"`
	BotProtectionEnabled  *bool  `gorm:"default:null" json:"bot_protection_enabled,omitempty"`
	BotProtectionLevel    string `gorm:"size:16;default:medium" json:"bot_protection_level"`
	AttackProtectionLevel string `gorm:"size:16;default:medium" json:"attack_protection_level"`

	AntiReplayEnabled *bool  `json:"anti_replay_enabled" gorm:"default:null"`
	AntiReplayTTL     int    `json:"anti_replay_ttl" gorm:"default:300"`
	AntiReplayAction  string `json:"anti_replay_action" gorm:"default:'shield_challenge'"`
	// AntiReplayCookieMode 站点级 Cookie 校验模式三态覆盖；nil = 继承全局 ProtectionConfig。
	AntiReplayCookieMode *string `json:"anti_replay_cookie_mode,omitempty" gorm:"default:null"`

	// 站点级质询策略覆盖（nil = 继承全局 ProtectionConfig）。
	// ChallengeAction 指定命中质询类动作时实际渲染的质询页类型；
	// SiteCaptchaType 指定验证码渲染分支使用的验证码类型（math/click/slide/rotate）。
	ChallengeAction *string `gorm:"default:null" json:"challenge_action,omitempty"`
	SiteCaptchaType *string `gorm:"default:null" json:"captcha_type,omitempty"`

	OWASPEnabled     *bool  `gorm:"default:null" json:"owasp_enabled,omitempty"`
	OWASPSensitivity string `gorm:"size:16" json:"owasp_sensitivity,omitempty"`
	OWASPAction      string `gorm:"size:32" json:"owasp_action,omitempty"`
	CVEEnabled       *bool  `gorm:"default:null" json:"cve_enabled,omitempty"`
	CVEAction        string `gorm:"size:32" json:"cve_action,omitempty"`
	RateLimitEnabled *bool  `gorm:"default:null" json:"rate_limit_enabled,omitempty"`
	RateLimitWindow  int    `gorm:"default:0" json:"rate_limit_window,omitempty"`
	RateLimitMax     int    `gorm:"default:0" json:"rate_limit_max,omitempty"`
	RateLimitAction  string `gorm:"size:32" json:"rate_limit_action,omitempty"`

	// SkipPathByPhase 站点级按 phase 跳过检测的覆盖，语义为三态：
	// nil = 继承全局；"{}" = 覆盖为"本站不跳过任何路径"；非空 JSON = 覆盖为该配置。
	// 必须用 *string 而非 string：空串无法区分"继承"与"覆盖为空"，
	// 后者会把继承态误存成空配置。
	SkipPathByPhase *string `gorm:"column:skip_path_by_phase;type:text" json:"skip_path_by_phase,omitempty"`

	XFFMode              string `gorm:"size:64;default:strip_all_and_set_remote" json:"xff_mode"`
	TrustedCIDR          string `gorm:"type:text" json:"trusted_cidr"`
	ClientIPHeaderOrder  string `gorm:"type:text" json:"client_ip_header_order"`
	PreserveOriginalHost bool   `gorm:"default:false" json:"preserve_original_host"`

	MaxBodyBytes          int64  `gorm:"default:10485760" json:"max_body_bytes"`
	UpstreamTLSSkipVerify bool   `gorm:"default:false" json:"upstream_tls_skip_verify"`
	UpstreamTLSServerName string `gorm:"size:255" json:"upstream_tls_server_name"`

	// 上游 mTLS 客户端证书（PEM 文本，成对配置）：
	// 两者同时 nil/空白 = 不使用客户端证书；同时非空 = TLS 握手时出示客户端证书。
	// 私钥在管理面 API 输出前脱敏（见 internal/admin/site 的 redactUpstreamClientKey）。
	UpstreamTLSClientCertPEM *string           `gorm:"type:text" json:"upstream_tls_client_cert_pem,omitempty"`
	UpstreamTLSClientKeyPEM  *string           `gorm:"type:text" json:"upstream_tls_client_key_pem,omitempty"`
	UpstreamTLSClientCertDER []byte            `gorm:"-" json:"-"`
	UpstreamTLSClientCertKey crypto.PrivateKey `gorm:"-" json:"-"`
	UpstreamTLSClientCertSet bool              `gorm:"-" json:"-"`
	UpstreamTLSClientCertBad bool              `gorm:"-" json:"-"`
	// UpstreamTLSClientCertFP 是证书链 DER 的前 16 字节 SHA-256 十六进制指纹，
	// 构建期与 DER/Key 一并预计算；"badpair" 为不可解析占位，空串为未配置。
	UpstreamTLSClientCertFP string `gorm:"-" json:"-"`

	CacheEnabled    bool   `gorm:"default:false" json:"cache_enabled"`
	CacheDefaultTTL int    `gorm:"default:0" json:"cache_default_ttl"`
	CacheRules      string `gorm:"type:text" json:"cache_rules"`

	MaintenanceEnabled bool   `gorm:"default:false" json:"maintenance_enabled"`
	MaintenanceHTML    string `gorm:"type:text" json:"maintenance_html"`
	MaintenanceStatus  int    `gorm:"default:503" json:"maintenance_status"`

	BlockHTML   string `gorm:"type:text" json:"block_html"`
	BlockStatus int    `gorm:"default:403" json:"block_status"`

	// 不设 DB 默认值：MySQL 禁止 BLOB/TEXT 列带 DEFAULT（Error 1101），
	// 带上会让 AutoMigrate 直接失败。空串与 "{}" 由读取方等价处理
	// （见 GetCustomErrorPages 与 dataplane 的错误页解析）。
	CustomErrorPages string `json:"custom_error_pages" gorm:"type:text"`

	// 动态保护站点级覆盖（nil = 继承全局）
	DynamicProtectionEnabled *bool  `gorm:"column:dynamic_protection_enabled" json:"dynamic_protection_enabled,omitempty"`
	DynamicHTMLEnabled       *bool  `gorm:"column:dynamic_html_enabled" json:"dynamic_html_enabled,omitempty"`
	DynamicJSEnabled         *bool  `gorm:"column:dynamic_js_enabled" json:"dynamic_js_enabled,omitempty"`
	DynamicJSMode            string `gorm:"column:dynamic_js_mode;size:10" json:"dynamic_js_mode,omitempty"`
	DynamicJSPaths           string `gorm:"column:dynamic_js_paths;type:text" json:"dynamic_js_paths,omitempty"`
	DynamicDecryptCacheTTL   *int   `gorm:"column:dynamic_decrypt_cache_ttl" json:"dynamic_decrypt_cache_ttl,omitempty"`

	// 站点级自定义 CC 规则覆盖（nil = 继承全局）
	// CCUseCustom 为 nil 时继承全局 CC 规则；非 nil 时用站点自身的 CCRules。
	CCUseCustom *bool  `gorm:"column:cc_use_custom" json:"cc_use_custom,omitempty"`
	CCRules     string `gorm:"column:cc_rules;type:text" json:"cc_rules,omitempty"`

	// Legacy 字段（已废弃，仅为迁移兼容保留）
	ListenerID          uint  `gorm:"index" json:"listener_id,omitempty"`
	ForwardingProfileID *uint `json:"forwarding_profile_id,omitempty"`
	InheritListenerCert bool  `gorm:"default:false" json:"inherit_listener_cert,omitempty"`
}

// ApplyProtectionModeOverrides 把站点上的紧凑模式同步进运行时防护字段。
func (s *Site) ApplyProtectionModeOverrides() {
	switch s.AttackProtectionLevel {
	case SiteProtectionModeObserve:
		enabled := true
		disabled := false
		s.BotProtectionEnabled = &disabled
		s.OWASPEnabled = &enabled
		if s.OWASPSensitivity == "" {
			s.OWASPSensitivity = "mid"
		}
		s.OWASPAction = string(ActionObserve)
		s.CVEEnabled = &enabled
		s.CVEAction = string(ActionObserve)
		s.RateLimitEnabled = &enabled
		s.RateLimitAction = string(ActionObserve)
	case SiteProtectionModeProtect:
		enabled := true
		s.BotProtectionEnabled = &enabled
		s.OWASPEnabled = &enabled
		if s.OWASPSensitivity == "" {
			s.OWASPSensitivity = "mid"
		}
		s.OWASPAction = string(ActionIntercept)
		s.CVEEnabled = &enabled
		s.CVEAction = string(ActionIntercept)
		s.RateLimitEnabled = &enabled
		s.RateLimitAction = string(ActionRateLimit)
	}
}

func (s *Site) PrepareUpstreamMTLSRuntime() {
	s.UpstreamTLSClientCertFP = ""
	if s.UpstreamTLSClientCertPEM == nil && s.UpstreamTLSClientKeyPEM == nil {
		s.UpstreamTLSClientCertSet = true
		return
	}
	certPEM := ""
	keyPEM := ""
	if s.UpstreamTLSClientCertPEM != nil {
		certPEM = strings.TrimSpace(*s.UpstreamTLSClientCertPEM)
	}
	if s.UpstreamTLSClientKeyPEM != nil {
		keyPEM = strings.TrimSpace(*s.UpstreamTLSClientKeyPEM)
	}
	if certPEM == "" && keyPEM == "" {
		s.UpstreamTLSClientCertSet = true
		s.UpstreamTLSClientCertBad = false
		return
	}
	if certPEM == "" || keyPEM == "" {
		s.UpstreamTLSClientCertBad = true
		s.UpstreamTLSClientCertSet = true
		s.UpstreamTLSClientCertFP = "badpair"
		return
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		s.UpstreamTLSClientCertBad = true
		s.UpstreamTLSClientCertSet = true
		s.UpstreamTLSClientCertFP = "badpair"
		return
	}
	if len(pair.Certificate) > 0 {
		s.UpstreamTLSClientCertDER = pair.Certificate[0]
		sum := sha256.Sum256(pair.Certificate[0])
		s.UpstreamTLSClientCertFP = hex.EncodeToString(sum[0:16])
	}
	s.UpstreamTLSClientCertKey = pair.PrivateKey
	s.UpstreamTLSClientCertBad = false
	s.UpstreamTLSClientCertSet = true
}

func (s *Site) GetCustomErrorPages() map[int]interface{} {
	if s.CustomErrorPages == "" || s.CustomErrorPages == "{}" {
		return nil
	}
	var m map[int]interface{}
	if err := json.Unmarshal([]byte(s.CustomErrorPages), &m); err != nil {
		return nil
	}
	return m
}

// SetCustomErrorPages 把 map 序列化进 CustomErrorPages JSON 字段。
func (s *Site) SetCustomErrorPages(pages map[int]interface{}) {
	if len(pages) == 0 {
		s.CustomErrorPages = "{}"
		return
	}
	b, err := json.Marshal(pages)
	if err != nil {
		s.CustomErrorPages = "{}"
		return
	}
	s.CustomErrorPages = string(b)
}

// SiteListener 表示站点的一个网络端点。
type SiteListener struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	SiteID     uint   `gorm:"index;not null" json:"site_id"`
	Bind       string `gorm:"size:255;not null;index" json:"bind"`
	Network    string `gorm:"size:16;default:tcp" json:"network"`
	TLSEnabled bool   `gorm:"default:false" json:"tls_enabled"`
	CertID     *uint  `json:"cert_id,omitempty"`
	Enabled    bool   `gorm:"default:true" json:"enabled"`
	Note       string `gorm:"size:255" json:"note,omitempty"`
}

// SiteCacheRule 定义存放在 Site.CacheRules 中的一条路径缓存规则。
type SiteCacheRule struct {
	Type            string `json:"type"` // prefix, exact, suffix, contains, regex
	Value           string `json:"value"`
	Path            string `json:"path,omitempty"` // legacy prefix field
	TTL             int    `json:"ttl"`
	CaseInsensitive bool   `json:"case_insensitive,omitempty"`
	IgnoreQuery     bool   `json:"ignore_query,omitempty"`
	Disabled        bool   `json:"disabled,omitempty"`
	Note            string `json:"note,omitempty"`
	StaleIfError    int    `json:"stale_if_error_seconds,omitempty"`
	// Regex 仅在 type 为 "regex" 时于快照构建阶段编译；不持久化、也不出现在 JSON 中。
	Regex *regexp.Regexp `json:"-" gorm:"-"`
}

// SiteForwardingRule 表示把某个子路径映射到专用上游的路径前缀路由规则。
// 以 JSON 形式存放在 Site.ForwardingRules 中。
type SiteForwardingRule struct {
	ID         string   `json:"id,omitempty"`
	Note       string   `json:"note,omitempty"`
	PathPrefix string   `json:"path_prefix"`
	Upstreams  []string `json:"upstreams"`
	Enabled    bool     `json:"enabled"`
}

// SiteHeaderOp 表示施加在上游请求或下游响应上的单次 Header 操作。
// 以 JSON 形式存放在 Site.HeaderOps 中。
type SiteHeaderOp struct {
	ID     string `json:"id,omitempty"`
	Phase  string `json:"phase"`  // "request" | "response"
	Action string `json:"action"` // "add" | "set" | "remove"
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
}
