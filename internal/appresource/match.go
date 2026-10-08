package appresource

import (
	"net/http"
	"strconv"
	"strings"

	"My-OpenWaf/internal/store/approute"
)

// Match 用编译好的规则对目标串求值。
func Match(cr CompiledRule, subject string) bool {
	return applyOp(cr.Op, cr.Pattern, subject, cr.Regex)
}

func applyOp(op, pattern, value string, re interface{ MatchString(string) bool }) bool {
	switch op {
	case approute.AppRouteOpEq:
		return value == pattern
	case approute.AppRouteOpNe:
		return value != pattern
	case approute.AppRouteOpContains:
		return strings.Contains(value, pattern)
	case approute.AppRouteOpNotContains:
		return !strings.Contains(value, pattern)
	case approute.AppRouteOpPrefix:
		return strings.HasPrefix(value, pattern)
	case approute.AppRouteOpSuffix:
		return strings.HasSuffix(value, pattern)
	case approute.AppRouteOpFuzzy:
		return strings.Contains(strings.ToLower(value), strings.ToLower(pattern))
	case approute.AppRouteOpRegex:
		if re == nil {
			return false
		}
		return re.MatchString(value)
	default:
		return false
	}
}

// Subject 从预先构建的 material 中解析出该规则要匹配的字符串。
func Subject(cr CompiledRule, m *Material, reqHeader func(string) string) string {
	if m == nil {
		return ""
	}
	switch cr.Target {
	case approute.AppRouteTargetRequestHeader:
		if cr.HeaderKeyLower != "" {
			return reqHeader(cr.HeaderKeyLower)
		}
		if cr.HeaderKey != "" {
			return reqHeader(cr.HeaderKey)
		}
		return ""
	case approute.AppRouteTargetRequestBody:
		return m.RequestBody
	case approute.AppRouteTargetResponseBody:
		return m.ResponseBody
	case approute.AppRouteTargetRequestHeadersFull:
		return m.RequestHeadersFull
	case approute.AppRouteTargetResponseHeadersFull:
		return m.ResponseHeadersFull
	case approute.AppRouteTargetFullHTTPRequest:
		if m.FullHTTPRequest == "" {
			m.FullHTTPRequest = m.Method + " " + m.Path + "\n" + m.RequestHeadersFull + "\n\n" + m.RequestBody
		}
		return m.FullHTTPRequest
	case approute.AppRouteTargetFullHTTPResponse:
		if m.FullHTTPResponse == "" {
			m.FullHTTPResponse = strconv.Itoa(m.StatusCode) + " " + http.StatusText(m.StatusCode) + "\n" + m.ResponseHeadersFull + "\n\n" + m.ResponseBody
		}
		return m.FullHTTPResponse
	case approute.AppRouteTargetRequestMethod:
		return m.Method
	case approute.AppRouteTargetFingerprint:
		if m.Fingerprint == "" && (m.JA3Hash != "" || m.UserAgent != "") {
			var fp strings.Builder
			fp.WriteString(m.JA3Hash)
			fp.WriteByte('\t')
			fp.WriteString(m.UserAgent)
			m.Fingerprint = truncate(fp.String(), maxFingerprintString)
		}
		return m.Fingerprint
	default:
		return ""
	}
}

/**
 * MatchedRuleIDs 返回 material 命中的全部规则 ID。
 *
 * 单阶段：需要响应字段时由调用方负责提供。
 *
 * @param rules 编译后的规则列表。
 * @param m 请求/响应提取出的 material。
 * @param reqHeader 请求头取值函数（大小写不敏感）。
 * @return 命中的规则 ID 列表；无命中时返回 nil。
 */
func MatchedRuleIDs(rules []CompiledRule, m *Material, reqHeader func(string) string) []uint {
	var ids []uint
	for _, cr := range rules {
		sub := Subject(cr, m, reqHeader)
		if Match(cr, sub) {
			ids = append(ids, cr.ID)
		}
	}
	return ids
}
