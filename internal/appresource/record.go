package appresource

import (
	"strconv"
	"strings"

	"My-OpenWaf/internal/store"
)

// BuildRecordedResource builds a persistence row from matched rule ids and material.
func BuildRecordedResource(siteID uint, matched []uint, m *Material) *store.RecordedResource {
	if m == nil {
		return nil
	}
	idsStr := make([]string, 0, len(matched))
	for _, id := range matched {
		idsStr = append(idsStr, strconv.FormatUint(uint64(id), 10))
	}
	var primaryRuleID uint
	if len(matched) > 0 {
		primaryRuleID = matched[0]
	}
	return &store.RecordedResource{
		SiteID:              siteID,
		Method:              m.Method,
		Host:                m.Host,
		Path:                m.Path,
		QueryString:         truncate(m.QueryString, 2048),
		ClientIP:            m.ClientIP,
		StatusCode:          m.StatusCode,
		ContentType:         truncate(m.ContentType, 256),
		TLSVersion:          truncate(m.TLSVersion, 16),
		TLSSNI:              truncate(m.TLSSNI, 255),
		TLSALPN:             truncate(m.TLSALPN, 128),
		JA3Hash:             truncate(m.JA3Hash, 64),
		JA4:                 truncate(m.JA4, 255),
		UserAgent:           truncate(m.UserAgent, 512),
		MatchedRuleIDs:      truncate(strings.Join(idsStr, ","), 512),
		PrimaryRuleID:       primaryRuleID,
		RequestHeadersJSON:  m.RequestHeadersJSON,
		ResponseHeadersJSON: m.ResponseHeadersJSON,
		RequestBodySnippet:  m.RequestBodySnippet,
		ResponseBodySnippet: m.ResponseBodySnippet,
	}
}
