package store

import (
	"encoding/json"
	"regexp"
	"time"

	"gorm.io/gorm"
)

const (
	XFFModeStrip      = "strip_all_and_set_remote"
	XFFModeTrustOuter = "trust_outer_waf_cidr_then_take_leftmost"
)

// Site holds a virtual host configuration: listener, TLS, protection, forwarding.
type Site struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Host         string `gorm:"size:255;not null;index" json:"host"`
	UpstreamURLs string `gorm:"type:text;not null" json:"upstream_urls"`

	Bind    string `gorm:"size:255;not null;index" json:"bind"`
	Network string `gorm:"size:16;default:tcp" json:"network"`
	Enabled bool   `gorm:"default:true" json:"enabled"`

	TLSEnabled    bool   `gorm:"default:false" json:"tls_enabled"`
	CertID        *uint  `json:"cert_id,omitempty"`
	MinTLSVersion string `gorm:"size:32;default:TLS12" json:"min_tls_version"`
	MaxTLSVersion string `gorm:"size:32;default:TLS13" json:"max_tls_version"`
	CipherSuites  string `gorm:"type:text" json:"cipher_suites"`
	ALPN          string `gorm:"size:255;default:h2,http/1.1" json:"alpn"`

	PolicyID              *uint  `json:"policy_id,omitempty"`
	BotProtectionEnabled  bool   `gorm:"default:false" json:"bot_protection_enabled"`
	BotProtectionLevel    string `gorm:"size:16;default:medium" json:"bot_protection_level"`
	AttackProtectionLevel string `gorm:"size:16;default:medium" json:"attack_protection_level"`

	AntiReplayEnabled bool   `json:"anti_replay_enabled" gorm:"default:false"`
	AntiReplayTTL     int    `json:"anti_replay_ttl" gorm:"default:300"`
	AntiReplayAction  string `json:"anti_replay_action" gorm:"default:'shield_challenge'"`

	OWASPEnabled     *bool  `gorm:"default:null" json:"owasp_enabled,omitempty"`
	OWASPSensitivity string `gorm:"size:16" json:"owasp_sensitivity,omitempty"`
	OWASPAction      string `gorm:"size:32" json:"owasp_action,omitempty"`
	CVEEnabled       *bool  `gorm:"default:null" json:"cve_enabled,omitempty"`
	CVEAction        string `gorm:"size:32" json:"cve_action,omitempty"`
	RateLimitEnabled *bool  `gorm:"default:null" json:"rate_limit_enabled,omitempty"`
	RateLimitWindow  int    `gorm:"default:0" json:"rate_limit_window,omitempty"`
	RateLimitMax     int    `gorm:"default:0" json:"rate_limit_max,omitempty"`
	RateLimitAction  string `gorm:"size:32" json:"rate_limit_action,omitempty"`

	XFFMode              string `gorm:"size:64;default:strip_all_and_set_remote" json:"xff_mode"`
	TrustedCIDR          string `gorm:"type:text" json:"trusted_cidr"`
	PreserveOriginalHost bool   `gorm:"default:false" json:"preserve_original_host"`

	MaxBodyBytes          int64  `gorm:"default:10485760" json:"max_body_bytes"`
	UpstreamTLSSkipVerify bool   `gorm:"default:false" json:"upstream_tls_skip_verify"`
	UpstreamTLSServerName string `gorm:"size:255" json:"upstream_tls_server_name"`

	CacheEnabled    bool   `gorm:"default:false" json:"cache_enabled"`
	CacheDefaultTTL int    `gorm:"default:0" json:"cache_default_ttl"`
	CacheRules      string `gorm:"type:text" json:"cache_rules"`

	MaintenanceEnabled bool   `gorm:"default:false" json:"maintenance_enabled"`
	MaintenanceHTML    string `gorm:"type:text" json:"maintenance_html"`
	MaintenanceStatus  int    `gorm:"default:503" json:"maintenance_status"`

	BlockHTML   string `gorm:"type:text" json:"block_html"`
	BlockStatus int    `gorm:"default:403" json:"block_status"`

	CustomErrorPages string `json:"custom_error_pages" gorm:"type:text;default:'{}'"`

	// Legacy fields (deprecated, kept for migration compatibility)
	ListenerID          uint  `gorm:"index" json:"listener_id,omitempty"`
	ForwardingProfileID *uint `json:"forwarding_profile_id,omitempty"`
	InheritListenerCert bool  `gorm:"default:false" json:"inherit_listener_cert,omitempty"`
}

// GetCustomErrorPages parses the CustomErrorPages JSON field.
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

// SetCustomErrorPages serialises the map into the CustomErrorPages JSON field.
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

// SiteListener represents one network endpoint of a Site.
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

// SiteCacheRule defines a path cache rule stored in Site.CacheRules.
type SiteCacheRule struct {
	Type            string `json:"type"` // prefix, exact, suffix, contains, regex
	Value           string `json:"value"`
	Path            string `json:"path,omitempty"` // legacy prefix field
	TTL             int    `json:"ttl"`
	CaseInsensitive bool   `json:"case_insensitive,omitempty"`
	IgnoreQuery     bool   `json:"ignore_query,omitempty"`
	// Regex is compiled at snapshot build for type "regex" only; not persisted or exposed in JSON.
	Regex *regexp.Regexp `json:"-" gorm:"-"`
}

// SiteForwardingRule represents a path-prefix routing rule that maps a sub-path
// to dedicated upstream targets. Stored as JSON in Site.ForwardingRules.
type SiteForwardingRule struct {
	ID         string   `json:"id,omitempty"`
	Note       string   `json:"note,omitempty"`
	PathPrefix string   `json:"path_prefix"`
	Upstreams  []string `json:"upstreams"`
	Enabled    bool     `json:"enabled"`
}

// SiteHeaderOp represents a single Header operation applied to upstream requests
// or downstream responses. Stored as JSON in Site.HeaderOps.
type SiteHeaderOp struct {
	ID     string `json:"id,omitempty"`
	Phase  string `json:"phase"`  // "request" | "response"
	Action string `json:"action"` // "add" | "set" | "remove"
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
}
