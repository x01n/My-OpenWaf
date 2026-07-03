package tlsmeta

import (
	"crypto/tls"
	"testing"
)

func TestNormalizeCipherSuiteTokenRecognizesAliases(t *testing.T) {
	cases := map[string]string{
		"4865":                     "TLS_AES_128_GCM_SHA256",
		"0x1302":                   "TLS_AES_256_GCM_SHA384",
		"TLS_AES_128_GCM_SHA256":   "TLS_AES_128_GCM_SHA256",
		"AES_128_GCM_SHA256":       "TLS_AES_128_GCM_SHA256",
		"UNKNOWN_SUITE_EXAMPLE":    "UNKNOWN_SUITE_EXAMPLE",
		"  tls_aes_256_gcm_sha384": "TLS_AES_256_GCM_SHA384",
	}
	for input, want := range cases {
		if got := NormalizeCipherSuiteToken(input); got != want {
			t.Fatalf("NormalizeCipherSuiteToken(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestFormatCipherSuitesUsesCanonicalNames(t *testing.T) {
	got := FormatCipherSuites([]uint16{4865, 4866, 0x9999})
	want := "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,0x9999"
	if got != want {
		t.Fatalf("FormatCipherSuites() = %q, want %q", got, want)
	}
}

func TestParseCipherSuitesRecognizesIDsAliasesAndDeduplicates(t *testing.T) {
	got := ParseCipherSuites("4865,0x1302,TLS_AES_128_GCM_SHA256,AES_128_GCM_SHA256,4865")
	want := []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
	}
	if len(got) != len(want) {
		t.Fatalf("ParseCipherSuites() = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ParseCipherSuites()[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestParseTLSConfigCipherSuitesExcludesTLS13Suites(t *testing.T) {
	got := ParseTLSConfigCipherSuites("TLS_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,0x1301")
	if len(got) != 1 {
		t.Fatalf("ParseTLSConfigCipherSuites() = %#v, want one suite", got)
	}
	if got[0] != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("ParseTLSConfigCipherSuites()[0] = %v, want %v", got[0], tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	}
}

func TestIsTLSConfigCipherSuiteToken(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{input: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", want: true},
		{input: "ECDHE_RSA_WITH_AES_128_GCM_SHA256", want: true},
		{input: "0xc02f", want: true},
		{input: "TLS_AES_128_GCM_SHA256", want: false},
		{input: "0x1301", want: false},
		{input: "UNKNOWN_SUITE_EXAMPLE", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IsTLSConfigCipherSuiteToken(tt.input); got != tt.want {
				t.Fatalf("IsTLSConfigCipherSuiteToken(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestInvalidTLSConfigCipherSuiteToken(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "", want: ""},
		{input: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,0xc030", want: ""},
		{input: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_AES_128_GCM_SHA256", want: "TLS_AES_128_GCM_SHA256"},
		{input: "UNKNOWN_SUITE_EXAMPLE,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", want: "UNKNOWN_SUITE_EXAMPLE"},
		{input: ",", want: ","},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := InvalidTLSConfigCipherSuiteToken(tt.input); got != tt.want {
				t.Fatalf("InvalidTLSConfigCipherSuiteToken(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
