package appresource

import (
	"strconv"
	"strings"

	"My-OpenWaf/internal/store"
)

// BuildRecordedResource builds a persistence row from matched rule ids and material.
func BuildRecordedResource(siteID uint, matched []uint, m *Material) *store.RecordedResource {
	if len(matched) == 0 || m == nil {
		return nil
	}
	idsStr := make([]string, 0, len(matched))
	for _, id := range matched {
		idsStr = append(idsStr, strconv.FormatUint(uint64(id), 10))
	}
	return &store.RecordedResource{
		SiteID:              siteID,
		Method:              m.Method,
		Host:                m.Host,
		Path:                m.Path,
		ClientIP:            m.ClientIP,
		StatusCode:          m.StatusCode,
		ContentType:         truncate(m.ContentType, 256),
		JA3Hash:             truncate(m.JA3Hash, 64),
		UserAgent:           truncate(m.UserAgent, 512),
		MatchedRuleIDs:      truncate(strings.Join(idsStr, ","), 512),
		PrimaryRuleID:       matched[0],
		RequestHeadersJSON:  m.RequestHeadersJSON,
		ResponseHeadersJSON: m.ResponseHeadersJSON,
		RequestBodySnippet:  m.RequestBodySnippet,
		ResponseBodySnippet: m.ResponseBodySnippet,
	}
}
