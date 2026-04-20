package store

import (
	"time"

	"gorm.io/gorm"
)

// ─── Listener (DEPRECATED - merged into Site) ─────────────────────
// Kept for migration purposes only

// ─── Certificate ───────────────────────────────────────────────────

type Certificate struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name    string `gorm:"size:128;not null" json:"name"`
	CertPEM string `gorm:"type:text;not null" json:"cert_pem"`
	KeyPEM  string `gorm:"type:text;not null" json:"key_pem"`
}

// ─── ForwardingProfile (DEPRECATED - merged into Site) ────────────
// Kept for migration purposes only

const (
	XFFModeStrip      = "strip_all_and_set_remote"
	XFFModeTrustOuter = "trust_outer_waf_cidr_then_take_leftmost"
)

// ─── Policy & Rules ────────────────────────────────────────────────

type Policy struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name string `gorm:"size:128;not null" json:"name"`
}

type RulePhase string

const (
	PhaseACL       RulePhase = "acl"
	PhaseRateLimit RulePhase = "rate_limit"
	PhaseOWASP     RulePhase = "owasp_default"
	PhaseSignature RulePhase = "signature"
	PhaseCustom    RulePhase = "custom"
)

type RuleAction string

const (
	ActionAllow     RuleAction = "allow"
	ActionIntercept RuleAction = "intercept"
	ActionObserve   RuleAction = "observe"
	ActionDrop      RuleAction = "drop" // TCP connection close, no HTTP response

	// Legacy values for backward compatibility with existing DB rows.
	ActionBlock   RuleAction = "block"
	ActionLogOnly RuleAction = "log_only"
)

// NormalizeAction maps legacy action strings to canonical form.
func NormalizeAction(a RuleAction) RuleAction {
	switch a {
	case ActionBlock:
		return ActionIntercept
	case ActionLogOnly:
		return ActionObserve
	default:
		return a
	}
}

type Rule struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name     string     `gorm:"size:128" json:"name"`
	PolicyID uint       `gorm:"not null;index" json:"policy_id"`
	Phase    RulePhase  `gorm:"size:32;not null;index" json:"phase"`
	Pattern  string     `gorm:"type:text;not null" json:"pattern"`
	Action   RuleAction `gorm:"size:16;not null" json:"action"`
	Priority int        `gorm:"default:100" json:"priority"`
	Enabled  bool       `gorm:"default:true" json:"enabled"`
}

// ─── Site ──────────────────────────────────────────────────────────

type Site struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Basic site info
	Host         string `gorm:"size:255;not null;index" json:"host"`
	UpstreamURLs string `gorm:"type:text;not null" json:"upstream_urls"`

	// Listener configuration (merged from Listener model)
	Bind    string `gorm:"size:255;not null;index" json:"bind"`
	Network string `gorm:"size:16;default:tcp" json:"network"`
	Enabled bool   `gorm:"default:true" json:"enabled"`

	// TLS configuration
	TLSEnabled    bool   `gorm:"default:false" json:"tls_enabled"`
	CertID        *uint  `json:"cert_id,omitempty"`
	MinTLSVersion string `gorm:"size:32;default:TLS12" json:"min_tls_version"`
	MaxTLSVersion string `gorm:"size:32;default:TLS13" json:"max_tls_version"`
	CipherSuites  string `gorm:"type:text" json:"cipher_suites"`
	ALPN          string `gorm:"size:255;default:h2,http/1.1" json:"alpn"`

	// Protection configuration
	PolicyID              *uint  `json:"policy_id,omitempty"`
	BotProtectionEnabled  bool   `gorm:"default:false" json:"bot_protection_enabled"`
	BotProtectionLevel    string `gorm:"size:16;default:medium" json:"bot_protection_level"`
	AttackProtectionLevel string `gorm:"size:16;default:medium" json:"attack_protection_level"`

	// Forwarding configuration (merged from ForwardingProfile)
	XFFMode              string `gorm:"size:64;default:strip_all_and_set_remote" json:"xff_mode"`
	TrustedCIDR          string `gorm:"type:text" json:"trusted_cidr"`
	PreserveOriginalHost bool   `gorm:"default:false" json:"preserve_original_host"`

	// Body and upstream settings
	MaxBodyBytes          int64  `gorm:"default:10485760" json:"max_body_bytes"`
	UpstreamTLSSkipVerify bool   `gorm:"default:false" json:"upstream_tls_skip_verify"`
	UpstreamTLSServerName string `gorm:"size:255" json:"upstream_tls_server_name"`

	// Per-site maintenance mode
	MaintenanceEnabled bool   `gorm:"default:false" json:"maintenance_enabled"`
	MaintenanceHTML    string `gorm:"type:text" json:"maintenance_html"`
	MaintenanceStatus  int    `gorm:"default:503" json:"maintenance_status"`

	// Per-site block page (empty = use global default)
	BlockHTML   string `gorm:"type:text" json:"block_html"`
	BlockStatus int    `gorm:"default:403" json:"block_status"`

	// Legacy fields (deprecated, kept for migration compatibility)
	ListenerID          uint  `gorm:"index" json:"listener_id,omitempty"`
	ForwardingProfileID *uint `json:"forwarding_profile_id,omitempty"`
	InheritListenerCert bool  `gorm:"default:false" json:"inherit_listener_cert,omitempty"`
}

// ─── SystemSettings ────────────────────────────────────────────────

type SystemSettings struct {
	ID    uint   `gorm:"primaryKey" json:"id"`
	Key   string `gorm:"size:128;uniqueIndex;not null" json:"key"`
	Value string `gorm:"type:text" json:"value"`
}

// ─── Admin API Key ─────────────────────────────────────────────────

type AdminAPIKey struct {
	ID         uint           `gorm:"primaryKey" json:"id"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"-"`
	Name       string         `gorm:"size:128" json:"name"`
	TokenHash  string         `gorm:"size:255;not null" json:"-"`
	LastUsedAt *time.Time     `json:"last_used_at,omitempty"`
}

// ─── Admin Account ─────────────────────────────────────────────────

type AdminAccount struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"size:64;uniqueIndex;not null" json:"username"`
	PasswordHash string    `gorm:"size:255;not null" json:"-"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ─── Refresh Token ─────────────────────────────────────────────────

type RefreshToken struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	JTI        string    `gorm:"size:128;uniqueIndex;not null" json:"jti"`
	TokenHash  string    `gorm:"size:255;not null" json:"-"`
	ExpiresAt  time.Time `gorm:"not null" json:"expires_at"`
	Revoked    bool      `gorm:"default:false" json:"revoked"`
	ReplacedBy string    `gorm:"size:128" json:"replaced_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// ─── IP List (Blacklist / Whitelist) ──────────────────────────────

type IPListKind string

const (
	IPListBlack IPListKind = "blacklist"
	IPListWhite IPListKind = "whitelist"
)

type IPListEntry struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Kind    IPListKind `gorm:"size:16;not null;index" json:"kind"`
	Value   string     `gorm:"size:64;not null;index" json:"value"` // IP or CIDR
	Note    string     `gorm:"size:255" json:"note"`
	Enabled bool       `gorm:"default:true" json:"enabled"`
}

// ─── Security Event ────────────────────────────────────────────────

type SecurityEvent struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`

	RequestID string `gorm:"size:64" json:"request_id"`
	ClientIP  string `gorm:"size:45;index" json:"client_ip"`
	Host      string `gorm:"size:255" json:"host"`
	Path      string `gorm:"size:2048" json:"path"`
	Method    string `gorm:"size:16" json:"method"`
	UserAgent string `gorm:"size:512" json:"user_agent"`

	RuleID    uint   `json:"rule_id"`
	RuleIDStr string `gorm:"size:64" json:"rule_id_str"`
	Phase     string `gorm:"size:32" json:"phase"`
	Action    string `gorm:"size:16" json:"action"`
	Category  string `gorm:"size:32;index" json:"category"`
	MatchDesc string `gorm:"size:512" json:"match_desc"`

	GeoCountry string `gorm:"size:2" json:"geo_country"`
	GeoCity    string `gorm:"size:128" json:"geo_city"`

	StatusCode int `gorm:"default:0" json:"status_code"`
}

// ─── Config Revision ───────────────────────────────────────────────

type ConfigRevision struct {
	ID       uint   `gorm:"primaryKey"`
	Revision uint64 `gorm:"not null"`
}

// ─── Protection Config (stored as JSON in SystemSettings) ──────────

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

	// Bot detection
	BotDetectionEnabled bool `json:"bot_detection_enabled"`

	// IP auto-ban (based on violations count within a window)
	AutoBanEnabled   bool `json:"auto_ban_enabled"`
	AutoBanThreshold int  `json:"auto_ban_threshold"`
	AutoBanWindow    int  `json:"auto_ban_window"`   // seconds
	AutoBanDuration  int  `json:"auto_ban_duration"` // seconds

	// CC protection extras
	WaitingRoomEnabled bool   `json:"waiting_room_enabled"`
	CCUseCustom        bool   `json:"cc_use_custom"`
	CCRules            string `json:"cc_rules,omitempty"` // JSON-encoded []CCRule

	// Per-module OWASP sensitivity: map[module_key] -> "off"|"observe"|"mid"|"high"
	OWASPModules string `json:"owasp_modules,omitempty"` // JSON-encoded map[string]string

	// CVE detection
	CVEEnabled bool   `json:"cve_enabled"`
	CVEAction  string `json:"cve_action"` // "intercept" (default), "observe"

	// Login security policy
	LoginMinPasswordLength int `json:"login_min_password_length"`
	LoginMaxAttempts       int `json:"login_max_attempts"`
	LoginLockoutMinutes    int `json:"login_lockout_minutes"`
}

func DefaultProtectionConfig() ProtectionConfig {
	return ProtectionConfig{
		RequestRateLimitWindow:  60,
		RequestRateLimitMax:     300,
		RequestRateLimitAction:  "intercept",
		ErrorRateLimitWindow:    300,
		ErrorRateLimitMax:       30,
		ErrorRateLimitAction:    "intercept",
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
	}
}

// ─── Bot Protection Config ─────────────────────────────────────────

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

// ─── Attack Protection Config ──────────────────────────────────────

type AttackProtectionConfig struct {
	OWASPEnabled     bool   `json:"owasp_enabled"`
	OWASPSensitivity string `json:"owasp_sensitivity"` // "low", "mid", "high"
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

// ─── Token Blacklist ────────────────────────────────────────────────

type TokenBlacklist struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	JTI       string    `gorm:"uniqueIndex;size:64" json:"jti"`
	ExpiresAt time.Time `gorm:"index" json:"expires_at"`
	Reason    string    `gorm:"size:128" json:"reason"` // logout, force_logout, key_rotation
	CreatedAt time.Time `json:"created_at"`
}

// ─── Login Attempt ──────────────────────────────────────────────────

type LoginAttempt struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	Username  string    `gorm:"index;size:64" json:"username"`
	IP        string    `gorm:"index;size:45" json:"ip"`
	Success   bool      `json:"success"`
	UserAgent string    `gorm:"size:256" json:"user_agent"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

// ─── Active Session ─────────────────────────────────────────────────

type ActiveSession struct {
	ID           uint      `gorm:"primarykey" json:"id"`
	Username     string    `gorm:"index;size:64" json:"username"`
	JTI          string    `gorm:"uniqueIndex;size:64" json:"jti"`
	IP           string    `gorm:"size:45" json:"ip"`
	UserAgent    string    `gorm:"size:256" json:"user_agent"`
	DeviceInfo   string    `gorm:"size:128" json:"device_info"`
	LoginAt      time.Time `json:"login_at"`
	LastActiveAt time.Time `json:"last_active_at"`
	ExpiresAt    time.Time `gorm:"index" json:"expires_at"`
}

// ─── RBAC Role Constants ────────────────────────────────────────────

const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleReadonly = "readonly"
)

// ─── Drop Event ─────────────────────────────────────────────────────

// DropEvent records a TCP connection drop (no HTTP response sent).
type DropEvent struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	ClientIP  string    `gorm:"index;size:45" json:"client_ip"`
	Source    string    `gorm:"size:32" json:"source"`   // bot, cve, rule, ip_reputation
	RuleID    string    `gorm:"size:64" json:"rule_id"`
	Detail    string    `gorm:"size:512" json:"detail"`
	Host      string    `gorm:"size:256" json:"host"`
	Path      string    `gorm:"size:512" json:"path"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

// ─── Bot Score Log ──────────────────────────────────────────────────

// BotScoreLog records the result of a bot scoring evaluation.
type BotScoreLog struct {
	ID               uint      `gorm:"primarykey" json:"id"`
	ClientIP         string    `gorm:"index;size:45" json:"client_ip"`
	Host             string    `gorm:"size:256" json:"host"`
	Path             string    `gorm:"size:512" json:"path"`
	TotalScore       int       `gorm:"index" json:"total_score"`
	GeoIPScore       int       `json:"geoip_score"`
	FingerprintScore int       `json:"fingerprint_score"`
	BehaviorScore    int       `json:"behavior_score"`
	IPRepScore       int       `json:"ip_rep_score"`
	IsHighRisk       bool      `json:"is_high_risk"`
	Action           string    `gorm:"size:16" json:"action"` // allow, challenge, block, drop
	Details          string    `gorm:"type:text" json:"details"`
	CreatedAt        time.Time `gorm:"index" json:"created_at"`
}

// ─── Fingerprint Record ─────────────────────────────────────────────

// FingerprintRecord stores aggregated fingerprint statistics.
type FingerprintRecord struct {
	ID          uint      `gorm:"primarykey" json:"id"`
	JA3Hash     string    `gorm:"index;size:64" json:"ja3_hash"`
	Browser     string    `gorm:"size:64" json:"browser"`
	Count       int64     `json:"count"`
	LastSeen    time.Time `json:"last_seen"`
	IsKnownGood bool      `json:"is_known_good"`
}

// ─── CVE Sync Log ───────────────────────────────────────────────────

// CVESyncLog records the result of a CVE feed synchronisation run.
type CVESyncLog struct {
	ID         uint      `gorm:"primarykey" json:"id"`
	Source     string    `gorm:"size:32" json:"source"` // nvd, github
	Status     string    `gorm:"size:16" json:"status"` // success, failed, running
	RulesAdded int       `json:"rules_added"`
	Error      string    `gorm:"size:512" json:"error"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}
