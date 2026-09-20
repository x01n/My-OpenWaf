package schemealias

import "testing"

func TestScheme(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "http", want: "http"},
		{in: "https", want: "https"},
		{in: "h2c", want: "h2c"},
		{in: "h3", want: "h3"},
		{in: "tls", want: "https"},
		{in: "grpcs", want: "https"},
		{in: "grpc+tls", want: "https"},
		{in: "grpc+https", want: "https"},
		{in: "grpc", want: "h2c"},
		{in: "TLS", want: "https"},
		{in: "GRPCS", want: "https"},
		{in: "GRPC", want: "h2c"},
		{in: "GrPc+TlS", want: "https"},
		{in: "ftp", want: "ftp"},
		{in: "", want: ""},
	}
	for _, tt := range tests {
		if got := Scheme(tt.in); got != tt.want {
			t.Fatalf("Scheme(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIsRPCScheme(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{in: "grpc", want: true},
		{in: "grpc://", want: true},
		{in: "GRPCS", want: true},
		{in: "grpc+tls", want: true},
		{in: "grpc+https", want: true},
		{in: "tls", want: true},
		{in: "https", want: false},
		{in: "http", want: false},
		{in: "h2c", want: false},
		{in: "h3", want: false},
		{in: "", want: false},
	}
	for _, tt := range tests {
		if got := IsRPCScheme(tt.in); got != tt.want {
			t.Fatalf("IsRPCScheme(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestAliasForURL(t *testing.T) {
	tests := []struct {
		raw       string
		transport string
		rest      string
		ok        bool
	}{
		{raw: "tls://svc:443/a", transport: "https", rest: "svc:443/a", ok: true},
		{raw: "TLS://svc:443/a", transport: "https", rest: "svc:443/a", ok: true},
		{raw: "grpcs://svc:443", transport: "https", rest: "svc:443", ok: true},
		{raw: "grpc+tls://svc:443", transport: "https", rest: "svc:443", ok: true},
		{raw: "grpc+https://svc:443", transport: "https", rest: "svc:443", ok: true},
		{raw: "grpc://svc:9000/rpc", transport: "h2c", rest: "svc:9000/rpc", ok: true},
		{raw: "GRPC://svc:9000/rpc", transport: "h2c", rest: "svc:9000/rpc", ok: true},
		{raw: "https://svc:443", ok: false},
		{raw: "h2c://svc:9000", ok: false},
		{raw: "http://svc:80", ok: false},
		{raw: "h3://svc:443", ok: false},
		{raw: "ftp://svc:21", ok: false},
		{raw: "not a url", ok: false},
		{raw: "", ok: false},
	}
	for _, tt := range tests {
		transport, rest, ok := AliasForURL(tt.raw)
		if ok != tt.ok || transport != tt.transport || rest != tt.rest {
			t.Fatalf("AliasForURL(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.raw, transport, rest, ok, tt.transport, tt.rest, tt.ok)
		}
	}
}

func TestNormalizeURLPrefix(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "tls://svc:443/a", want: "https://svc:443/a"},
		{raw: "GRPCS://svc:443/a", want: "https://svc:443/a"},
		{raw: "grpc+tls://svc:443/a", want: "https://svc:443/a"},
		{raw: "grpc+https://svc:443/a", want: "https://svc:443/a"},
		{raw: "grpc://svc:9000/a", want: "h2c://svc:9000/a"},
		// 旧四前缀不做大小写折叠，保持原样。
		{raw: "HTTP://svc:80/a", want: "HTTP://svc:80/a"},
		{raw: "h2c://svc:9000/a", want: "h2c://svc:9000/a"},
		{raw: "h3://svc:443/a", want: "h3://svc:443/a"},
		{raw: "ftp://svc:21/a", want: "ftp://svc:21/a"},
		{raw: "no prefix at all", want: "no prefix at all"},
		{raw: "", want: ""},
	}
	for _, tt := range tests {
		if got := NormalizeURLPrefix(tt.raw); got != tt.want {
			t.Fatalf("NormalizeURLPrefix(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}
