package appresource

import (
	"net/http"
	"strconv"
	"strings"

	"My-OpenWaf/internal/store"
)

// Match evaluates a compiled rule against a subject string.
func Match(cr CompiledRule, subject string) bool {
	return applyOp(cr.Op, cr.Pattern, subject, cr.Regex)
}

func applyOp(op, pattern, value string, re interface{ MatchString(string) bool }) bool {
	switch op {
	case store.AppRouteOpEq:
		return value == pattern
	case store.AppRouteOpNe:
		return value != pattern
	case store.AppRouteOpContains:
		return strings.Contains(value, pattern)
	case store.AppRouteOpNotContains:
		return !strings.Contains(value, pattern)
	case store.AppRouteOpPrefix:
		return strings.HasPrefix(value, pattern)
	case store.AppRouteOpSuffix:
		return strings.HasSuffix(value, pattern)
	case store.AppRouteOpFuzzy:
		return strings.Contains(strings.ToLower(value), strings.ToLower(pattern))
	case store.AppRouteOpRegex:
		if re == nil {
			return false
		}
		return re.MatchString(value)
	default:
		return false
	}
}

// Subject resolves the string to match for a rule from pre-built material.
func Subject(cr CompiledRule, m *Material, reqHeader func(string) string) string {
	if m == nil {
		return ""
	}
	switch cr.Target {
	case store.AppRouteTargetRequestHeader:
		if cr.HeaderKeyLower != "" {
			return reqHeader(cr.HeaderKeyLower)
		}
		if cr.HeaderKey != "" {
			return reqHeader(cr.HeaderKey)
		}
		return ""
	case store.AppRouteTargetRequestBody:
		return m.RequestBody
	case store.AppRouteTargetResponseBody:
		return m.ResponseBody
	case store.AppRouteTargetRequestHeadersFull:
		return m.RequestHeadersFull
	case store.AppRouteTargetResponseHeadersFull:
		return m.ResponseHeadersFull
	case store.AppRouteTargetFullHTTPRequest:
		if m.FullHTTPRequest == "" {
			m.FullHTTPRequest = m.Method + " " + m.Path + "\n" + m.RequestHeadersFull + "\n\n" + m.RequestBody
		}
		return m.FullHTTPRequest
	case store.AppRouteTargetFullHTTPResponse:
		if m.FullHTTPResponse == "" {
			m.FullHTTPResponse = strconv.Itoa(m.StatusCode) + " " + http.StatusText(m.StatusCode) + "\n" + m.ResponseHeadersFull + "\n\n" + m.ResponseBody
		}
		return m.FullHTTPResponse
	case store.AppRouteTargetRequestMethod:
		return m.Method
	case store.AppRouteTargetFingerprint:
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

// MatchedRuleIDs returns all rule IDs that match the material (single phase: caller must supply response fields when needed).
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
