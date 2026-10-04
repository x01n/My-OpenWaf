package store

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"

	"gorm.io/gorm"
)

// SecurityEvent 记录每一次命中的 WAF 事件（intercept/observe/challenge/drop）。
type SecurityEvent struct {
	ID        uint      `gorm:"primaryKey;index:idx_se_site_created_id,priority:3" json:"id"`
	CreatedAt time.Time `gorm:"index:idx_se_created;index:idx_se_site_created;index:idx_se_site_created_id,priority:2" json:"created_at"`

	SiteID      uint   `gorm:"index:idx_se_site_created;index:idx_se_site_created_id,priority:1" json:"site_id"`
	RequestID   string `gorm:"size:64;index:idx_se_request_id" json:"request_id"`
	ClientIP    string `gorm:"size:45;index:idx_se_client_ip" json:"client_ip"`
	Host        string `gorm:"size:255;index:idx_se_host" json:"host"`
	Path        string `gorm:"size:2048" json:"path"`
	QueryString string `gorm:"size:2048" json:"query_string"`
	Method      string `gorm:"size:16" json:"method"`
	UserAgent   string `gorm:"size:512" json:"user_agent"`

	RuleID    uint   `json:"rule_id"`
	RuleIDStr string `gorm:"size:64;index:idx_se_rule_id_str" json:"rule_id_str"`
	// RuleName/RuleDesc 是命中的内置规则名称与说明，来自规则注册表，
	// 用于在安全事件里解释"命中了哪条规则"，而非仅类别级文案。
	RuleName string `gorm:"size:255" json:"rule_name"`
	RuleDesc string `gorm:"size:512" json:"rule_desc"`
	// MatchScore 是 OWASP 命中的累计风险分值；0 表示不适用。
	MatchScore int `gorm:"default:0" json:"match_score"`
	// MatchSnippet 是触发命中的内容片段，已按 snippet.MaxLen 截断并脱敏。
	MatchSnippet string `gorm:"size:256" json:"match_snippet"`
	// MatchPart 是命中部位（url/body/header/cookie/all），CVE 命中时填充。
	MatchPart string `gorm:"size:32" json:"match_part"`
	// Severity 是危险度（critical/high/medium/low），CVE 命中时填充。
	Severity string `gorm:"size:16" json:"severity"`
	// Source 是规则来源（catalog/nvd/github/manual/auto_generated）。
	Source string `gorm:"size:32" json:"source"`
	// CVSSScore/CWEType 是 CVE 规则的危险度明细；References 是参考链接。
	CVSSScore  float64 `gorm:"default:0" json:"cvss_score"`
	CWEType    string  `gorm:"size:32" json:"cwe_type"`
	References string  `gorm:"type:text" json:"references"`

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

// AccessLog 记录每个入站请求的最终结果，供查询与审计使用。
type AccessLog struct {
	ID          uint      `gorm:"primaryKey;index:idx_al_site_created_id,priority:3" json:"id"`
	CreatedAt   time.Time `gorm:"index:idx_al_created;index:idx_al_site_created;index:idx_al_site_created_id,priority:2" json:"created_at"`
	SiteID      uint      `gorm:"index:idx_al_site_created;index:idx_al_site_created_id,priority:1" json:"site_id"`
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
	// FingerprintKey 是九个 TLS 指纹字段的定长摘要，用于避免每次列表查询都对宽文本列做分组。
	// 它不对外暴露；原始字段仍是返回和过滤的权威数据。
	FingerprintKey  string `gorm:"column:fingerprint_key;type:char(64);index:idx_al_fingerprint_key" json:"-"`
	TLSCipherSuites string `gorm:"type:text" json:"tls_cipher_suites"`
	TLSExtensions   string `gorm:"type:text" json:"tls_extensions"`
	TLSCurves       string `gorm:"type:text" json:"tls_curves"`
	TLSPointFormats string `gorm:"type:text" json:"tls_point_formats"`
	HeaderOrder     string `gorm:"size:1024" json:"header_order"`

	VisitorFusionClass              string `gorm:"size:16;index:idx_al_visitor_fusion_window,priority:2" json:"visitor_fusion_class"`
	VisitorFusionScore              int    `gorm:"default:0" json:"visitor_fusion_score"`
	VisitorFusionClientFamily       string `gorm:"size:32" json:"visitor_fusion_client_family"`
	VisitorFusionUAClaim            string `gorm:"size:32" json:"visitor_fusion_ua_claim"`
	VisitorFusionConsistency        string `gorm:"size:32" json:"visitor_fusion_consistency"`
	VisitorFusionEvidenceSufficient bool   `gorm:"default:false;index:idx_al_visitor_fusion_window,priority:1" json:"visitor_fusion_evidence_sufficient"`
	VisitorFusionReasons            string `gorm:"size:1024" json:"visitor_fusion_reasons"`

	UpstreamLatencyMs int64 `gorm:"default:0" json:"upstream_latency_ms"`
	ResponseSize      int64 `gorm:"default:0" json:"response_size"`
}

/**
 * ComputeAccessLogFingerprintKey 生成访问日志九字段指纹的 SHA-256 摘要。
 *
 * 每个字段先写入无符号变长长度，再写入字段字节，避免字段边界或内容导致
 * 拼接歧义。JA3 与 JA4 同时为空时表示没有可聚合的指纹，返回空字符串。
 *
 * @param tlsJA3Hash JA3 哈希。
 * @param tlsJA4 JA4 指纹。
 * @param tlsVersion TLS 版本。
 * @param tlsALPN TLS ALPN。
 * @param tlsSNI TLS SNI。
 * @param tlsCipherSuites TLS cipher suites。
 * @param tlsExtensions TLS extensions。
 * @param tlsCurves TLS curves。
 * @param tlsPointFormats TLS point formats。
 * @return 64 位十六进制摘要，或没有指纹时的空字符串。
 */
func ComputeAccessLogFingerprintKey(tlsJA3Hash, tlsJA4, tlsVersion, tlsALPN, tlsSNI, tlsCipherSuites, tlsExtensions, tlsCurves, tlsPointFormats string) string {
	if tlsJA3Hash == "" && tlsJA4 == "" {
		return ""
	}
	h := sha256.New()
	var encodedLength [binary.MaxVarintLen64]byte
	for _, value := range []string{
		tlsJA3Hash,
		tlsJA4,
		tlsVersion,
		tlsALPN,
		tlsSNI,
		tlsCipherSuites,
		tlsExtensions,
		tlsCurves,
		tlsPointFormats,
	} {
		n := binary.PutUvarint(encodedLength[:], uint64(len(value)))
		_, _ = h.Write(encodedLength[:n])
		_, _ = h.Write([]byte(value))
	}
	return hex.EncodeToString(h.Sum(nil))
}

/**
 * BeforeSave 在访问日志写入或更新前维护指纹摘要。
 *
 * 该钩子覆盖仓储、UnifiedWriter 和直接 GORM CreateInBatches 写入，避免不同
 * 写入路径产生无法参与聚合的空摘要。
 */
func (a *AccessLog) BeforeSave(*gorm.DB) error {
	if a == nil {
		return nil
	}
	a.FingerprintKey = ComputeAccessLogFingerprintKey(
		a.TLSJA3Hash,
		a.TLSJA4,
		a.TLSVersion,
		a.TLSALPN,
		a.TLSSNI,
		a.TLSCipherSuites,
		a.TLSExtensions,
		a.TLSCurves,
		a.TLSPointFormats,
	)
	return nil
}

// DropEvent 记录一次 TCP 连接丢弃（未发出任何 HTTP 响应）。
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

// BotScoreLog 记录一次 Bot 评分判定结果。
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
	UAScore          int       `json:"ua_score"`
	GeoIPScore       int       `json:"geoip_score"`
	FingerprintScore int       `json:"fingerprint_score"`
	BehaviorScore    int       `json:"behavior_score"`
	IPRepScore       int       `json:"ip_rep_score"`
	IsHighRisk       bool      `json:"is_high_risk"`
	Dangerous        bool      `gorm:"default:false" json:"dangerous"`
	DangerReasons    string    `gorm:"size:512" json:"danger_reasons"`
	Action           string    `gorm:"size:32" json:"action"`
	Details          string    `gorm:"type:text" json:"details"`
	CreatedAt        time.Time `gorm:"index" json:"created_at"`
}
