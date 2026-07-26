package shared

import (
	"testing"
)

// --- ValidateSiteUpstreamURLs ---

func TestValidateSiteUpstreamURLsValid(t *testing.T) {
	cases := []string{
		"http://backend:8080",
		"https://api.example.com",
		"h2c://grpc-service:9000",
		"h3://fast-backend:443",
		`["http://a:8080","https://b:443"]`,
		"http://a:8080, https://b:443",
	}
	for _, c := range cases {
		if err := ValidateSiteUpstreamURLs(c); err != nil {
			t.Errorf("ValidateSiteUpstreamURLs(%q) returned error: %v", c, err)
		}
	}
}

func TestValidateSiteUpstreamURLsEmpty(t *testing.T) {
	err := ValidateSiteUpstreamURLs("")
	if err != errSiteUpstreamsRequired {
		t.Errorf("expected errSiteUpstreamsRequired, got %v", err)
	}
}

func TestValidateSiteUpstreamURLsWhitespaceOnly(t *testing.T) {
	err := ValidateSiteUpstreamURLs("   ")
	if err != errSiteUpstreamsRequired {
		t.Errorf("expected errSiteUpstreamsRequired for whitespace, got %v", err)
	}
}

func TestValidateSiteUpstreamURLsInvalidScheme(t *testing.T) {
	err := ValidateSiteUpstreamURLs("ftp://backend:21")
	if err != errSiteUpstreamsUnsupportedScheme {
		t.Errorf("expected errSiteUpstreamsUnsupportedScheme, got %v", err)
	}
}

func TestValidateSiteUpstreamURLsNoScheme(t *testing.T) {
	err := ValidateSiteUpstreamURLs("backend:8080")
	if err == nil {
		t.Error("missing scheme should return error")
	}
}

func TestValidateSiteUpstreamURLsInvalidURL(t *testing.T) {
	err := ValidateSiteUpstreamURLs("http://")
	if err == nil {
		t.Error("URL with no host should return error")
	}
}

func TestValidateSiteUpstreamURLsInvalidJSONList(t *testing.T) {
	err := ValidateSiteUpstreamURLs("[not valid json")
	if err != errSiteUpstreamsInvalidList {
		t.Errorf("expected errSiteUpstreamsInvalidList, got %v", err)
	}
}

func TestValidateSiteUpstreamURLsJSONListEmpty(t *testing.T) {
	err := ValidateSiteUpstreamURLs("[]")
	if err != errSiteUpstreamsRequired {
		t.Errorf("empty JSON array should return errSiteUpstreamsRequired, got %v", err)
	}
}

func TestValidateSiteUpstreamURLsSchemesCaseInsensitive(t *testing.T) {
	cases := []string{"HTTP://a:8080", "HTTPS://a:443", "H2C://a:80", "H3://a:443"}
	for _, c := range cases {
		if err := ValidateSiteUpstreamURLs(c); err != nil {
			t.Errorf("ValidateSiteUpstreamURLs(%q) should accept uppercase scheme, got %v", c, err)
		}
	}
}

// --- ValidateSiteUpstreamHost ---

func TestValidateSiteUpstreamHostEmpty(t *testing.T) {
	if err := ValidateSiteUpstreamHost(""); err != nil {
		t.Errorf("empty host should be valid, got %v", err)
	}
}

func TestValidateSiteUpstreamHostWhitespace(t *testing.T) {
	if err := ValidateSiteUpstreamHost("   "); err != nil {
		t.Errorf("whitespace-only host should be valid (treated as empty), got %v", err)
	}
}

func TestValidateSiteUpstreamHostValidPlain(t *testing.T) {
	cases := []string{"example.com", "api.example.com", "backend:8080", "localhost"}
	for _, c := range cases {
		if err := ValidateSiteUpstreamHost(c); err != nil {
			t.Errorf("ValidateSiteUpstreamHost(%q) should be valid, got %v", c, err)
		}
	}
}

func TestValidateSiteUpstreamHostValidTemplate(t *testing.T) {
	// Go 模板语法应该被接受
	if err := ValidateSiteUpstreamHost("{{.Host}}"); err != nil {
		t.Errorf("valid template should be accepted, got %v", err)
	}
}

func TestValidateSiteUpstreamHostInvalidTemplate(t *testing.T) {
	err := ValidateSiteUpstreamHost("{{.Host}")
	if err != errSiteUpstreamHostInvalidTemplate {
		t.Errorf("invalid template should return errSiteUpstreamHostInvalidTemplate, got %v", err)
	}
}

func TestValidateSiteUpstreamHostInvalidHost(t *testing.T) {
	err := ValidateSiteUpstreamHost("not a valid\x00host")
	if err != errSiteUpstreamHostInvalidHost {
		t.Errorf("invalid host should return errSiteUpstreamHostInvalidHost, got %v", err)
	}
}

// --- trimNonEmptyStrings (内部) ---

func TestTrimNonEmptyStrings(t *testing.T) {
	got := trimNonEmptyStrings([]string{"a", "  ", "b", ""})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("expected [a b], got %v", got)
	}
}

func TestTrimNonEmptyStringsAllEmpty(t *testing.T) {
	got := trimNonEmptyStrings([]string{"", "  ", "\t"})
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %v", got)
	}
}
