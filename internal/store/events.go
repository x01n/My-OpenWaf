package store

import "time"

// SecurityEvent records every matched WAF event (block/observe/challenge/drop).
type SecurityEvent struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time `gorm:"index:idx_se_created;index:idx_se_site_created" json:"created_at"`

	SiteID      uint   `gorm:"index:idx_se_site_created" json:"site_id"`
	RequestID   string `gorm:"size:64;index:idx_se_request_id" json:"request_id"`
	ClientIP    string `gorm:"size:45;index:idx_se_client_ip" json:"client_ip"`
	Host        string `gorm:"size:255;index:idx_se_host" json:"host"`
	Path        string `gorm:"size:2048" json:"path"`
	QueryString string `gorm:"size:2048" json:"query_string"`
	Method      string `gorm:"size:16" json:"method"`
	UserAgent   string `gorm:"size:512" json:"user_agent"`

	RuleID    uint   `json:"rule_id"`
	RuleIDStr string `gorm:"size:64;index:idx_se_rule_id_str" json:"rule_id_str"`
	Phase     string `gorm:"size:32" json:"phase"`
	Action    string `gorm:"size:32;index:idx_se_action" json:"action"`
	Category  string `gorm:"size:32;index:idx_se_category" json:"category"`
	MatchDesc string `gorm:"size:512" json:"match_desc"`

	RequestHeaders       string `gorm:"type:text" json:"request_headers"`
	RequestBodyPreview   string `gorm:"type:text" json:"request_body_preview"`
	RequestBodyTruncated bool   `gorm:"default:false" json:"request_body_truncated"`
	RequestSize          int64  `gorm:"default:0" json:"request_size"`

	TLSVersion      string `gorm:"size:16" json:"tls_version"`
	TLSSNI          string `gorm:"size:255" json:"tls_sni"`
	TLSALPN         string `gorm:"size:128" json:"tls_alpn"`
	TLSJA3          string `gorm:"size:1024" json:"tls_ja3"`
	TLSJA3Hash      string `gorm:"size:32" json:"tls_ja3_hash"`
	TLSJA4          string `gorm:"size:255" json:"tls_ja4"`
	TLSCipherSuites string `gorm:"type:text" json:"tls_cipher_suites"`
	TLSExtensions   string `gorm:"type:text" json:"tls_extensions"`
	TLSCurves       string `gorm:"type:text" json:"tls_curves"`
	TLSPointFormats string `gorm:"type:text" json:"tls_point_formats"`
	HeaderOrder     string `gorm:"size:1024" json:"header_order"`

	GeoCountry string `gorm:"size:2" json:"geo_country"`
	GeoCity    string `gorm:"size:128" json:"geo_city"`

	StatusCode int `gorm:"default:0" json:"status_code"`
}

// AccessLog records every inbound request outcome for querying and auditing.
type AccessLog struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	CreatedAt   time.Time `gorm:"index:idx_al_created;index:idx_al_site_created" json:"created_at"`
	SiteID      uint      `gorm:"index:idx_al_site_created" json:"site_id"`
	RequestID   string    `gorm:"size:64;index:idx_al_request_id" json:"request_id"`
	ClientIP    string    `gorm:"size:45;index:idx_al_client_ip" json:"client_ip"`
	Host        string    `gorm:"size:255;index:idx_al_host" json:"host"`
	Path        string    `gorm:"size:2048" json:"path"`
	QueryString string    `gorm:"size:2048" json:"query_string"`
	Method      string    `gorm:"size:16" json:"method"`
	StatusCode  int       `gorm:"index:idx_al_status" json:"status_code"`
	WAFAction   string    `gorm:"size:32;index:idx_al_waf_action" json:"waf_action"`
	CacheState  string    `gorm:"size:16" json:"cache_state"`
	Upstream    string    `gorm:"size:512" json:"upstream"`
	UserAgent   string    `gorm:"size:512" json:"user_agent"`

	RequestHeaders       string `gorm:"type:text" json:"request_headers"`
	RequestBodyPreview   string `gorm:"type:text" json:"request_body_preview"`
	RequestBodyTruncated bool   `gorm:"default:false" json:"request_body_truncated"`
	RequestSize          int64  `gorm:"default:0" json:"request_size"`
	ResponseHeaders      string `gorm:"type:text" json:"response_headers"`

	HTTPProtocol         string `gorm:"size:32" json:"http_protocol"`
	UpstreamHTTPProtocol string `gorm:"size:32" json:"upstream_http_protocol"`
	TLSVersion           string `gorm:"size:16" json:"tls_version"`
	TLSSNI               string `gorm:"size:255" json:"tls_sni"`
	TLSALPN              string `gorm:"size:128" json:"tls_alpn"`
	TLSJA3               string `gorm:"size:1024" json:"tls_ja3"`
	TLSJA3Hash           string `gorm:"size:32;index:idx_al_tls_ja3_hash" json:"tls_ja3_hash"`
	TLSJA4               string `gorm:"size:255;index:idx_al_tls_ja4" json:"tls_ja4"`
	TLSCipherSuites      string `gorm:"type:text" json:"tls_cipher_suites"`
	TLSExtensions        string `gorm:"type:text" json:"tls_extensions"`
	TLSCurves            string `gorm:"type:text" json:"tls_curves"`
	TLSPointFormats      string `gorm:"type:text" json:"tls_point_formats"`
	HeaderOrder          string `gorm:"size:1024" json:"header_order"`

	UpstreamLatencyMs int64 `gorm:"default:0" json:"upstream_latency_ms"`
	ResponseSize      int64 `gorm:"default:0" json:"response_size"`
}

// DropEvent records a TCP connection drop (no HTTP response sent).
type DropEvent struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	SiteID    uint      `gorm:"index" json:"site_id"`
	ClientIP  string    `gorm:"index;size:45" json:"client_ip"`
	Source    string    `gorm:"size:32;index:idx_drop_source_created" json:"source"`
	RuleID    string    `gorm:"size:64" json:"rule_id"`
	Detail    string    `gorm:"size:512" json:"detail"`
	Host      string    `gorm:"size:256" json:"host"`
	Path      string    `gorm:"size:512" json:"path"`
	CreatedAt time.Time `gorm:"index;index:idx_drop_source_created" json:"created_at"`
}

// BotScoreLog records the result of a bot scoring evaluation.
type BotScoreLog struct {
	ID               uint      `gorm:"primarykey" json:"id"`
	SiteID           uint      `gorm:"index" json:"site_id"`
	RequestID        string    `gorm:"size:64;index" json:"request_id"`
	ClientIP         string    `gorm:"index;size:45" json:"client_ip"`
	Host             string    `gorm:"size:256" json:"host"`
	Path             string    `gorm:"size:512" json:"path"`
	UserAgent        string    `gorm:"size:512" json:"user_agent"`
	TLSJA3Hash       string    `gorm:"size:32;index" json:"tls_ja3_hash"`
	TLSJA4           string    `gorm:"size:255;index" json:"tls_ja4"`
	TLSVersion       string    `gorm:"size:16" json:"tls_version"`
	TLSSNI           string    `gorm:"size:255" json:"tls_sni"`
	TLSALPN          string    `gorm:"size:128" json:"tls_alpn"`
	HeaderOrder      string    `gorm:"size:1024" json:"header_order"`
	TotalScore       int       `gorm:"index" json:"total_score"`
	GeoIPScore       int       `json:"geoip_score"`
	FingerprintScore int       `json:"fingerprint_score"`
	BehaviorScore    int       `json:"behavior_score"`
	IPRepScore       int       `json:"ip_rep_score"`
	IsHighRisk       bool      `json:"is_high_risk"`
	Action           string    `gorm:"size:32" json:"action"`
	Details          string    `gorm:"type:text" json:"details"`
	CreatedAt        time.Time `gorm:"index" json:"created_at"`
}
