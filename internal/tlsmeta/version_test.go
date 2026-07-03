package tlsmeta

import (
	"crypto/tls"
	"testing"
)

func TestParseVersionSupportsAliasesAndWireValues(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  uint16
	}{
		{name: "canonical ssl3", input: "SSL3", want: versionSSL30},
		{name: "ssl with dot", input: "ssl 3.0", want: versionSSL30},
		{name: "canonical tls13", input: "TLS13", want: tls.VersionTLS13},
		{name: "short tls13", input: "1.3", want: tls.VersionTLS13},
		{name: "tls with space", input: "TLS 1.2", want: tls.VersionTLS12},
		{name: "tlsv format", input: "tlsv1.1", want: tls.VersionTLS11},
		{name: "hex wire value", input: "0x0304", want: tls.VersionTLS13},
		{name: "decimal wire value", input: "772", want: tls.VersionTLS13},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseVersion(tt.input); got != tt.want {
				t.Fatalf("ParseVersion(%q) = %#x, want %#x", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeVersionTokenReturnsCanonicalTokens(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "SSL3", want: "SSL3"},
		{input: "0x0300", want: "SSL3"},
		{input: "1.0", want: "TLS10"},
		{input: "tls 1.1", want: "TLS11"},
		{input: "TLSv1.2", want: "TLS12"},
		{input: "772", want: "TLS13"},
		{input: "unknown", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := NormalizeVersionToken(tt.input); got != tt.want {
				t.Fatalf("NormalizeVersionToken(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCanonicalVersionNameSupportsSSL3(t *testing.T) {
	if got := CanonicalVersionName(versionSSL30); got != "SSL3" {
		t.Fatalf("CanonicalVersionName(SSL30) = %q, want %q", got, "SSL3")
	}
}

func TestNormalizeRuntimeVersionTokenRejectsSSLVersions(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "TLS10", want: "TLS10"},
		{input: "TLS 1.1", want: "TLS11"},
		{input: "1.2", want: "TLS12"},
		{input: "0x0304", want: "TLS13"},
		{input: "SSL3", want: ""},
		{input: "SSL2", want: ""},
		{input: "SSL1", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := NormalizeRuntimeVersionToken(tt.input); got != tt.want {
				t.Fatalf("NormalizeRuntimeVersionToken(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRuntimeVersionRangeValid(t *testing.T) {
	tests := []struct {
		name string
		min  string
		max  string
		want bool
	}{
		{name: "ascending", min: "TLS10", max: "TLS13", want: true},
		{name: "equal", min: "TLS 1.2", max: "0x0303", want: true},
		{name: "inherited min", min: "", max: "TLS13", want: true},
		{name: "inherited max", min: "TLS12", max: "", want: true},
		{name: "descending", min: "TLS13", max: "TLS12", want: false},
		{name: "ssl min", min: "SSL3", max: "TLS12", want: false},
		{name: "unknown max", min: "TLS12", max: "TLS14", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RuntimeVersionRangeValid(tt.min, tt.max); got != tt.want {
				t.Fatalf("RuntimeVersionRangeValid(%q, %q) = %v, want %v", tt.min, tt.max, got, tt.want)
			}
		})
	}
}
