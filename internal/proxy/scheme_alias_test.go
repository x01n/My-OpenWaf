package proxy

import (
	"strings"
	"testing"

	"My-OpenWaf/internal/snapshot"
)

func TestNormalizeUpstreamURLRPCAliases(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "tls://svc:443/a", want: "https://svc:443/a"},
		{raw: "grpcs://svc:443/a", want: "https://svc:443/a"},
		{raw: "grpc+tls://svc:443/a", want: "https://svc:443/a"},
		{raw: "grpc+https://svc:443/a", want: "https://svc:443/a"},
		{raw: "GRPCS://svc:443/a", want: "https://svc:443/a"},
		{raw: "grpc://svc:9000/a", want: "http://svc:9000/a"},
		{raw: "GRPC://svc:9000/a", want: "http://svc:9000/a"},
		{raw: "h2c://svc:9000/a", want: "http://svc:9000/a"},
		{raw: "h3://svc:443/a", want: "https://svc:443/a"},
		{raw: "https://svc:443/a", want: "https://svc:443/a"},
		{raw: "http://svc:80/a", want: "http://svc:80/a"},
		{raw: "", want: ""},
	}
	for _, tt := range tests {
		if got := NormalizeUpstreamURL(tt.raw); got != tt.want {
			t.Fatalf("NormalizeUpstreamURL(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestShouldUseHertzUpstreamRPCAliases(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{raw: "h2c://svc:9000", want: true},
		{raw: "grpc://svc:9000", want: true},
		{raw: "GRPC://svc:9000", want: true},
		{raw: "https://svc:443", want: false},
		{raw: "grpcs://svc:443", want: false},
		{raw: "http://svc:80", want: false},
	}
	for _, tt := range tests {
		if got := shouldUseHertzUpstream(tt.raw); got != tt.want {
			t.Fatalf("shouldUseHertzUpstream(%q) = %v, want %v", tt.raw, got, tt.want)
		}
	}
}

func TestIsHTTPSUpstreamBaseRPCAliases(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{raw: "https://svc:443", want: true},
		{raw: "tls://svc:443", want: true},
		{raw: "grpcs://svc:443", want: true},
		{raw: "grpc+tls://svc:443", want: true},
		{raw: "grpc+https://svc:443", want: true},
		{raw: "GRPCS://svc:443", want: true},
		{raw: "grpc://svc:9000", want: false},
		{raw: "http://svc:80", want: false},
	}
	for _, tt := range tests {
		if got := isHTTPSUpstreamBase(tt.raw); got != tt.want {
			t.Fatalf("isHTTPSUpstreamBase(%q) = %v, want %v", tt.raw, got, tt.want)
		}
	}
}

func TestHTTPProtoForBaseRPCAliases(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "h2c://svc:9000", want: "HTTP/2.0"},
		{raw: "grpc://svc:9000", want: "HTTP/2.0"},
		{raw: "https://svc:443", want: "HTTP/2.0"},
		{raw: "grpcs://svc:443", want: "HTTP/2.0"},
		{raw: "tls://svc:443", want: "HTTP/2.0"},
		{raw: "http://svc:80", want: "HTTP/1.1"},
	}
	for _, tt := range tests {
		if got := httpProtoForBase(tt.raw); got != tt.want {
			t.Fatalf("httpProtoForBase(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestTransportKeyForUpstreamRPCAliases(t *testing.T) {
	tests := []struct {
		raw          string
		wantHTTPS    bool
		wantH2CPrior bool
	}{
		{raw: "https://svc:443", wantHTTPS: true},
		{raw: "grpcs://svc:443", wantHTTPS: true},
		{raw: "tls://svc:443", wantHTTPS: true},
		{raw: "grpc+https://svc:443", wantHTTPS: true},
		{raw: "grpc://svc:9000", wantH2CPrior: true},
		{raw: "http://svc:80", wantHTTPS: false, wantH2CPrior: false},
	}
	for _, tt := range tests {
		key := transportKeyForUpstream(tt.raw, snapshot.SiteRuntime{})
		if key.isHTTPS != tt.wantHTTPS {
			t.Fatalf("transportKeyForUpstream(%q).isHTTPS = %v, want %v", tt.raw, key.isHTTPS, tt.wantHTTPS)
		}
		if key.h2cPrior != tt.wantH2CPrior {
			t.Fatalf("transportKeyForUpstream(%q).h2cPrior = %v, want %v", tt.raw, key.h2cPrior, tt.wantH2CPrior)
		}
	}
}

func TestUpstreamRoundTripperForBaseRPCAliases(t *testing.T) {
	rt := snapshot.SiteRuntime{}
	for raw, want := range map[string]string{
		"grpcs://svc:443/base":      "https://svc:443/base",
		"tls://svc:443/base":        "https://svc:443/base",
		"grpc+https://svc:443/base": "https://svc:443/base",
		"grpc://svc:9000/base":      "http://svc:9000/base",
	} {
		tr, normalizedBase := UpstreamRoundTripperForBase(rt, raw)
		if tr == nil {
			t.Fatalf("UpstreamRoundTripperForBase(%q) returned nil transport", raw)
		}
		if normalizedBase != want {
			t.Fatalf("UpstreamRoundTripperForBase(%q) normalizedBase = %q, want %q", raw, normalizedBase, want)
		}
		if !strings.HasPrefix(normalizedBase, "http") {
			t.Fatalf("UpstreamRoundTripperForBase(%q) normalizedBase = %q, want http(s) prefix", raw, normalizedBase)
		}
	}
}

func TestResolveUpstreamBaseMilliContract(t *testing.T) {
	rt := snapshot.SiteRuntime{}
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "tls://svc:443/a", want: "https://svc:443/a"},
		{raw: "grpcs://svc:443/a", want: "https://svc:443/a"},
		{raw: "grpc+tls://svc:443/a", want: "https://svc:443/a"},
		{raw: "grpc+https://svc:443/a", want: "https://svc:443/a"},
		{raw: "GRPCS://svc:443/a", want: "https://svc:443/a"},
		{raw: "grpc://svc:9000/a", want: "http://svc:9000/a"},
		{raw: "GRPC://svc:9000/a", want: "http://svc:9000/a"},
		{raw: "h2c://svc:9000/a", want: "http://svc:9000/a"},
		{raw: "h3://svc:443/a", want: "https://svc:443/a"},
		{raw: "https://svc:443/a", want: "https://svc:443/a"},
		{raw: "http://svc:80/a", want: "http://svc:80/a"},
		{raw: "", want: ""},
		{raw: "h2c://127.0.0.1:8080/base", want: "http://127.0.0.1:8080/base"},
		{raw: "h3://127.0.0.1:8443/base", want: "https://127.0.0.1:8443/base"},
		{raw: "HTTPS://svc:443/a", want: "HTTPS://svc:443/a"},
		{raw: "grpc+https://svc:443/base", want: "https://svc:443/base"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			res := resolveUpstreamBase(rt, tt.raw)
			if got := NormalizeUpstreamURL(tt.raw); got != tt.want {
				t.Fatalf("NormalizeUpstreamURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
			if res.normalized != tt.want {
				t.Fatalf("resolveUpstreamBase(%q).normalized = %q, want %q", tt.raw, res.normalized, tt.want)
			}
			tr, normalizedBase := UpstreamRoundTripperForBase(rt, tt.raw)
			if tr == nil {
				t.Fatalf("UpstreamRoundTripperForBase(%q) returned nil transport", tt.raw)
			}
			if normalizedBase != tt.want || tr != res.transport {
				t.Fatalf("UpstreamRoundTripperForBase(%q) = (%p, %q), resolver = (%p, %q)", tt.raw, tr, normalizedBase, res.transport, res.normalized)
			}
			if got := shouldUseHertzUpstream(tt.raw); got != res.hertzH2C {
				t.Fatalf("resolver hertzH2C = %v, shouldUseHertzUpstream = %v", res.hertzH2C, got)
			}
		})
	}
}
