package store

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	"gorm.io/gorm"
)

// Match targets: which part of the HTTP exchange to run the operator against.
const (
	AppRouteTargetRequestHeader       = "request_header"
	AppRouteTargetRequestBody         = "request_body"
	AppRouteTargetResponseBody        = "response_body"
	AppRouteTargetRequestHeadersFull  = "request_headers_full"
	AppRouteTargetResponseHeadersFull = "response_headers_full"
	AppRouteTargetFullHTTPRequest     = "full_http_request"
	AppRouteTargetFullHTTPResponse    = "full_http_response"
	AppRouteTargetRequestMethod       = "request_method"
	AppRouteTargetFingerprint         = "fingerprint"
)

// Match operators.
const (
	AppRouteOpEq          = "eq"
	AppRouteOpNe          = "ne"
	AppRouteOpContains    = "contains"
	AppRouteOpNotContains = "not_contains"
	AppRouteOpPrefix      = "prefix"
	AppRouteOpSuffix      = "suffix"
	AppRouteOpRegex       = "regex"
	AppRouteOpFuzzy       = "fuzzy" // case-insensitive substring
)

// ApplicationRouteRule defines how observed site resources attach historical rule metadata.
// RecordedResource itself is written for observed site traffic; matched rules only enrich the row.
type ApplicationRouteRule struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	SiteID    uint   `gorm:"index;not null" json:"site_id"`
	Name      string `gorm:"size:128" json:"name"`
	Enabled   bool   `gorm:"default:true" json:"enabled"`
	Priority  int    `gorm:"default:0" json:"priority"`
	Target    string `gorm:"size:48;not null" json:"target"`
	Op        string `gorm:"size:24;not null" json:"op"`
	Pattern   string `gorm:"type:text;not null" json:"pattern"`
	HeaderKey string `gorm:"size:128" json:"header_key,omitempty"`
}

func (ApplicationRouteRule) TableName() string { return "application_route_rules" }

// RecordedResource aggregates observed HTTP resources per site.
type RecordedResource struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// 去重键不能直接建在下面五列上：utf8mb4 下 Path+QueryString 各 2048 字符即
	// 16384 字节，加上 Host 远超 MySQL 索引键 3072 字节上限（Error 1071），
	// 而数学上无法在不截断内容的前提下压进该上限。改为把五列摘要成定长
	// DedupKey 列建唯一索引，精度无损且三种方言一致。
	SiteID      uint   `gorm:"not null;index" json:"site_id"`
	Method      string `gorm:"size:16" json:"method"`
	Host        string `gorm:"size:255;index" json:"host"`
	Path        string `gorm:"size:2048" json:"path"`
	QueryString string `gorm:"size:2048" json:"query_string"`

	// DedupKey 是 (SiteID, Method, Host, Path, QueryString) 的 SHA-256 十六进制值，
	// 由 ComputeDedupKey 生成，写入前必须填充。char(64) 在 utf8mb4 下占 256 字节。
	DedupKey       string `gorm:"column:dedup_key;type:char(64);uniqueIndex:ux_recorded_res_dedup" json:"-"`
	ClientIP       string `gorm:"size:45" json:"client_ip"`
	StatusCode     int    `json:"status_code"`
	ContentType    string `gorm:"size:256" json:"content_type"`
	TLSVersion     string `gorm:"size:16" json:"tls_version"`
	TLSSNI         string `gorm:"size:255" json:"tls_sni"`
	TLSALPN        string `gorm:"size:128" json:"tls_alpn"`
	JA3Hash        string `gorm:"size:64" json:"ja3_hash"`
	JA4            string `gorm:"size:255" json:"ja4"`
	UserAgent      string `gorm:"size:512" json:"user_agent"`
	MatchedRuleIDs string `gorm:"size:512" json:"matched_rule_ids"`
	PrimaryRuleID  uint   `gorm:"index" json:"primary_rule_id"`

	RequestHeadersJSON  string `gorm:"type:text" json:"request_headers_json,omitempty"`
	ResponseHeadersJSON string `gorm:"type:text" json:"response_headers_json,omitempty"`
	RequestBodySnippet  string `gorm:"type:text" json:"request_body_snippet,omitempty"`
	ResponseBodySnippet string `gorm:"type:text" json:"response_body_snippet,omitempty"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `gorm:"index" json:"last_seen"`
	HitCount  int64     `json:"hit_count"`
}

func (RecordedResource) TableName() string { return "recorded_resources" }

/**
 * ComputeDedupKey 生成资源去重键。
 *
 * 用 \x00 作分隔符（URL 与 Host 中不会出现），避免相邻字段边界歧义——
 * 例如 host="a" path="/bc" 与 host="ab" path="/c" 必须得到不同的键。
 *
 * @param siteID      站点 ID。
 * @param method      HTTP 方法。
 * @param host        请求 Host。
 * @param path        请求路径。
 * @param queryString 查询串。
 * @return 64 位十六进制的 SHA-256 摘要。
 */
func ComputeDedupKey(siteID uint, method, host, path, queryString string) string {
	h := sha256.New()
	var buf [20]byte
	h.Write(strconv.AppendUint(buf[:0], uint64(siteID), 10))
	for _, part := range []string{method, host, path, queryString} {
		h.Write([]byte{0})
		h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// EnsureDedupKey 在 DedupKey 为空时按当前字段值填充，返回是否发生了填充。
func (r *RecordedResource) EnsureDedupKey() bool {
	if r == nil || r.DedupKey != "" {
		return false
	}
	r.DedupKey = ComputeDedupKey(r.SiteID, r.Method, r.Host, r.Path, r.QueryString)
	return true
}

// BeforeSave 在落库前兜底填充 DedupKey。
//
// dedup_key 上有唯一索引，若留空，多行空串会互相冲突。仅靠调用方记得调用
// EnsureDedupKey 不可靠——任何绕过 repo.Upsert 的直接 db.Create 都会撞索引。
// 放在 GORM 钩子里可覆盖全部写入路径。
func (r *RecordedResource) BeforeSave(*gorm.DB) error {
	r.EnsureDedupKey()
	return nil
}
