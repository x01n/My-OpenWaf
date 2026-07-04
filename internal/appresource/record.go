package appresource

import (
	"strconv"
	"strings"

	"My-OpenWaf/internal/store"
)

// Record field length limits aligned with store schema sizes.
const (
	recordQueryStringLimit    = 2048
	recordContentTypeLimit    = 256
	recordTLSVersionLimit     = 16
	recordTLSSNILimit         = 255
	recordTLSALPNLimit        = 128
	recordJA3HashLimit        = 64
	recordJA4Limit            = 255
	recordUserAgentLimit      = 512
	recordMatchedRuleIDsLimit = 512
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
		QueryString:         truncate(m.QueryString, recordQueryStringLimit),
		ClientIP:            m.ClientIP,
		StatusCode:          m.StatusCode,
		ContentType:         truncate(m.ContentType, recordContentTypeLimit),
		TLSVersion:          truncate(m.TLSVersion, recordTLSVersionLimit),
		TLSSNI:              truncate(m.TLSSNI, recordTLSSNILimit),
		TLSALPN:             truncate(m.TLSALPN, recordTLSALPNLimit),
		JA3Hash:             truncate(m.JA3Hash, recordJA3HashLimit),
		JA4:                 truncate(m.JA4, recordJA4Limit),
		UserAgent:           truncate(m.UserAgent, recordUserAgentLimit),
		MatchedRuleIDs:      truncate(strings.Join(idsStr, ","), recordMatchedRuleIDsLimit),
		PrimaryRuleID:       primaryRuleID,
		RequestHeadersJSON:  m.RequestHeadersJSON,
		ResponseHeadersJSON: m.ResponseHeadersJSON,
		RequestBodySnippet:  m.RequestBodySnippet,
		ResponseBodySnippet: m.ResponseBodySnippet,
	}
}
