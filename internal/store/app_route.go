package store

import (
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

// ApplicationRouteRule defines when to record a resource for a site.
// When any enabled rule matches the live traffic, a row in RecordedResource is upserted.
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

// RecordedResource aggregates observed HTTP resources per site when rules match.
type RecordedResource struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	SiteID         uint   `gorm:"not null;uniqueIndex:ux_recorded_res_key" json:"site_id"`
	Method         string `gorm:"size:16;uniqueIndex:ux_recorded_res_key" json:"method"`
	Host           string `gorm:"size:255;uniqueIndex:ux_recorded_res_key" json:"host"`
	Path           string `gorm:"size:2048;uniqueIndex:ux_recorded_res_key" json:"path"`
	ClientIP       string `gorm:"size:45" json:"client_ip"`
	StatusCode     int    `json:"status_code"`
	ContentType    string `gorm:"size:256" json:"content_type"`
	JA3Hash        string `gorm:"size:64" json:"ja3_hash"`
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
