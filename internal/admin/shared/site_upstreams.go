package shared

import (
	"encoding/json"
	"errors"
	"net/url"
	"text/template"
	"strings"

	"My-OpenWaf/internal/security"
)

var (
	errSiteUpstreamsRequired          = errors.New("upstream_urls is required")
	errSiteUpstreamsInvalidList       = errors.New("upstream_urls must be a string array or comma-separated string")
	errSiteUpstreamsInvalidURL        = errors.New("upstream_urls contains invalid URL")
	errSiteUpstreamsUnsupportedScheme = errors.New("upstream_urls supports only http, https, h2c, h3")
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
		if err != nil || u.Scheme == "" || u.Host == "" {
			return errSiteUpstreamsInvalidURL
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "h2c", "h3":
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

// ValidateSiteUpstreamHost validates the optional upstream Host override.
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
