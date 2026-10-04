package appresource

import (
	"strconv"
	"strings"

	"My-OpenWaf/internal/store"
)

// Record 各字段长度上限，与 store 库表尺寸对齐。
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

/**
 * BuildRecordedResource 由命中的规则 ID 与 material 构建一条落库记录。
 *
 * 命中列表中的首个 ID 另存为 primaryRuleID，便于按主规则归因。
 *
 * @param siteID 站点 ID。
 * @param matched 命中的规则 ID 列表。
 * @param m 请求/响应提取出的 material；为 nil 时返回 nil。
 * @return 待持久化的资源记录。
 */
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
