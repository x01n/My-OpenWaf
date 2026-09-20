package shared

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"text/template"

	"My-OpenWaf/internal/security"
	"My-OpenWaf/internal/upstream"
)

var (
	errSiteUpstreamsRequired           = errors.New("upstream_urls is required")
	errSiteUpstreamsInvalidList        = errors.New("upstream_urls must be a string array or comma-separated string")
	errSiteUpstreamsInvalidURL         = errors.New("upstream_urls contains invalid URL")
	errSiteUpstreamsUnsupportedScheme  = errors.New("upstream_urls supports only http, https, h2c, h3, tls, grpc, grpcs, grpc+tls, grpc+https")
	errSiteUpstreamHostInvalidTemplate = errors.New("upstream_host contains invalid template")
	errSiteUpstreamHostInvalidHost     = errors.New("upstream_host contains invalid host")
)

// ValidateSiteUpstreamURLs validates site upstream URL syntax and supported schemes.
func ValidateSiteUpstreamURLs(raw string) error {
	upstreams, err := parseSiteUpstreamURLsForValidation(raw)
	if err != nil {
		return err
	}
	if len(upstreams) == 0 {
		return errSiteUpstreamsRequired
	}
	for _, upstream := range upstreams {
		u, err := url.Parse(upstream)
		if err != nil || u.Scheme == "" {
			return errSiteUpstreamsInvalidURL
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "h2c", "h3":
			// 标准 scheme 必须带非空主机；别名 scheme 无法被 url.Parse 识别
			// 出 Host，由下方兜底分支校验。
			if u.Host == "" {
				return errSiteUpstreamsInvalidURL
			}
		case "tls", "grpc", "grpcs", "grpc+tls", "grpc+https":
			if u.Host == "" && !siteUpstreamRPCURLHasAuthority(upstream) {
				return errSiteUpstreamsInvalidURL
			}
		default:
			return errSiteUpstreamsUnsupportedScheme
		}
	}
	return nil
}

func parseSiteUpstreamURLsForValidation(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if strings.HasPrefix(raw, "[") {
		var values []string
		if err := json.Unmarshal([]byte(raw), &values); err != nil {
			return nil, errSiteUpstreamsInvalidList
		}
		return trimNonEmptyStrings(values), nil
	}
	return trimNonEmptyStrings(strings.Split(raw, ",")), nil
}

func trimNonEmptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

// siteUpstreamRPCURLHasAuthority 判定带 RPC 别名前缀的 upstream 是否包含
// 非空 authority。url.Parse 无法从 tls://、grpc:// 等未知 scheme 中解析出
// Host，因此复用 proxy 的归一逻辑：归一后仍以 "scheme://" 开头且其后内容
// 非空、且不属于它自身的 scheme-only 形态时视为有效。
func siteUpstreamRPCURLHasAuthority(raw string) bool {
	if _, rest, ok := upstream.RPCUpstreamAliasForURL(raw); ok {
		// 截取 authority 部分（到首个 / ? # 为止）判定非空；
		// grpc:///path 这类无主机输入会被拒绝。
		host := rest
		if i := strings.IndexAny(host, "/?#"); i >= 0 {
			host = host[:i]
		}
		return host != ""
	}
	return true
}
func ValidateSiteUpstreamHost(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if strings.Contains(raw, "{{") || strings.Contains(raw, "}}") {
		if _, err := template.New("upstream_host").Option("missingkey=error").Parse(raw); err != nil {
			return errSiteUpstreamHostInvalidTemplate
		}
		return nil
	}
	if _, err := security.NormalizeHostHeaderValue(raw); err != nil {
		return errSiteUpstreamHostInvalidHost
	}
	return nil
}
