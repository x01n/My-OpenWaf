package repository

import "testing"

func TestNormalizeTLSVersionFilterKnownToken(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"TLS 1.3", "TLS13"},
		{"tls1.3", "TLS13"},
		{"TLS13", "TLS13"},
		{"TLS 1.2", "TLS12"},
		{"tls12", "TLS12"},
		{"TLS 1.1", "TLS11"},
		{"TLS 1.0", "TLS10"},
	}
	for _, tc := range cases {
		got := normalizeTLSVersionFilter(tc.input)
		if got != tc.want {
			t.Errorf("normalizeTLSVersionFilter(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestNormalizeTLSVersionFilterUnknownPassesThrough(t *testing.T) {
	raw := "UNKNOWN_VERSION"
	got := normalizeTLSVersionFilter(raw)
	if got != raw {
		t.Errorf("normalizeTLSVersionFilter(%q) = %q, want passthrough %q", raw, got, raw)
	}
}

func TestNormalizeTLSVersionFilterEmpty(t *testing.T) {
	got := normalizeTLSVersionFilter("")
	if got != "" {
		t.Errorf("normalizeTLSVersionFilter('') = %q, want ''", got)
	}
}

func TestNormalizeAccessLogFilterTLSVersion(t *testing.T) {
	f := AccessLogFilter{TLSVersion: "tls1.3"}
	out := normalizeAccessLogFilter(f)
	if out.TLSVersion != "TLS13" {
		t.Errorf("normalizeAccessLogFilter TLSVersion = %q, want TLS13", out.TLSVersion)
	}
}

func TestNormalizeSecurityEventFilterTLSVersion(t *testing.T) {
	f := SecurityEventFilter{TLSVersion: "tls12"}
	out := normalizeSecurityEventFilter(f)
	if out.TLSVersion != "TLS12" {
		t.Errorf("normalizeSecurityEventFilter TLSVersion = %q, want TLS12", out.TLSVersion)
	}
}

func TestNormalizeFingerprintFilterTLSVersion(t *testing.T) {
	f := FingerprintFilter{TLSVersion: "TLS13"}
	out := normalizeFingerprintFilter(f)
	if out.TLSVersion != "TLS13" {
		t.Errorf("normalizeFingerprintFilter TLSVersion = %q, want TLS13", out.TLSVersion)
	}
}

func TestNormalizeRecordedResourceFilterTLSVersion(t *testing.T) {
	f := RecordedResourceFilter{TLSVersion: "tls1.2"}
	out := normalizeRecordedResourceFilter(f)
	if out.TLSVersion != "TLS12" {
		t.Errorf("normalizeRecordedResourceFilter TLSVersion = %q, want TLS12", out.TLSVersion)
	}
}
