package upstream

import (
	"strings"
	"testing"
)

func TestNormalizeUpstreamScheme(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "http", in: "http", want: "http"},
		{name: "https", in: "https", want: "https"},
		{name: "h2c", in: "h2c", want: "h2c"},
		{name: "h3", in: "h3", want: "h3"},
		{name: "tls", in: "tls", want: "https"},
		{name: "grpcs", in: "grpcs", want: "https"},
		{name: "grpc+tls", in: "grpc+tls", want: "https"},
		{name: "grpc+https", in: "grpc+https", want: "https"},
		{name: "grpc", in: "grpc", want: "h2c"},
		{name: "upper_tls", in: "TLS", want: "https"},
		{name: "upper_grpcs", in: "GRPCS", want: "https"},
		{name: "upper_grpc", in: "GRPC", want: "h2c"},
		{name: "mixed_grpc_plus_tls", in: "GrPc+TlS", want: "https"},
		{name: "unknown", in: "ftp", want: "ftp"},
		{name: "empty", in: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeUpstreamScheme(tt.in); got != tt.want {
				t.Fatalf("normalizeUpstreamScheme(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsRPCUpstreamScheme(t *testing.T) {
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
		if got := IsRPCUpstreamScheme(tt.in); got != tt.want {
			t.Fatalf("IsRPCUpstreamScheme(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestRPCUpstreamAliasForURL(t *testing.T) {
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
		transport, rest, ok := RPCUpstreamAliasForURL(tt.raw)
		if ok != tt.ok || transport != tt.transport || rest != tt.rest {
			t.Fatalf("RPCUpstreamAliasForURL(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.raw, transport, rest, ok, tt.transport, tt.rest, tt.ok)
		}
	}
}

func TestNormalizeUpstreamURLPrefix(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "tls://svc:443/a", want: "https://svc:443/a"},
		{raw: "GRPCS://svc:443/a", want: "https://svc:443/a"},
		{raw: "grpc+tls://svc:443/a", want: "https://svc:443/a"},
		{raw: "grpc+https://svc:443/a", want: "https://svc:443/a"},
		{raw: "grpc://svc:9000/a", want: "h2c://svc:9000/a"},
		// 旧四前缀原样保留（这里是前缀改写函数，不做大小写折叠）。
		{raw: "HTTP://svc:80/a", want: "HTTP://svc:80/a"},
		{raw: "h2c://svc:9000/a", want: "h2c://svc:9000/a"},
		{raw: "h3://svc:443/a", want: "h3://svc:443/a"},
		{raw: "weird-scheme://svc:1/a", want: "weird-scheme://svc:1/a"},
		{raw: "no prefix at all", want: "no prefix at all"},
		{raw: "", want: ""},
	}
	for _, tt := range tests {
		if got := NormalizeUpstreamURLPrefix(tt.raw); got != tt.want {
			t.Fatalf("NormalizeUpstreamURLPrefix(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestUpstreamURLInfoNormalizesAliases(t *testing.T) {
	tests := []struct {
		raw       string
		scheme    string
		probeHost string
	}{
		// 四个 TLS 别名与 https 同语义：host 解析、scheme 归一、探针同为 https。
		{raw: "tls://svc:443/api", scheme: "https", probeHost: "https://svc:443/api"},
		{raw: "grpcs://svc:443/api", scheme: "https", probeHost: "https://svc:443/api"},
		{raw: "grpc+tls://svc:443/api", scheme: "https", probeHost: "https://svc:443/api"},
		{raw: "grpc+https://svc:443/api", scheme: "https", probeHost: "https://svc:443/api"},
		// grpc 与 h2c 同语义：探针同为 http 明文。
		{raw: "grpc://svc:9000/rpc", scheme: "h2c", probeHost: "http://svc:9000/rpc"},
		// 旧四前缀行为不变。
		{raw: "https://svc:443/api", scheme: "https", probeHost: "https://svc:443/api"},
		{raw: "h2c://svc:9000/rpc", scheme: "h2c", probeHost: "http://svc:9000/rpc"},
		{raw: "h3://svc:443/api", scheme: "h3", probeHost: "https://svc:443/api"},
		{raw: "http://svc:80/api", scheme: "http", probeHost: "http://svc:80/api"},
	}
	for _, tt := range tests {
		info := parseUpstreamURL(tt.raw)
		if !info.valid() {
			t.Fatalf("parseUpstreamURL(%q) invalid", tt.raw)
		}
		if info.scheme != tt.scheme {
			t.Fatalf("parseUpstreamURL(%q).scheme = %q, want %q", tt.raw, info.scheme, tt.scheme)
		}
		if got := info.probeTarget(); got != tt.probeHost {
			t.Fatalf("parseUpstreamURL(%q).probeTarget() = %q, want %q", tt.raw, got, tt.probeHost)
		}
	}
}

func TestParseUpstreamStateKeyAliases(t *testing.T) {
	if got := parseUpstreamStateKey("grpcs://svc:443"); got.scheme != upstreamStateSchemeHTTPS {
		t.Fatalf("parseUpstreamStateKey(grpcs) scheme = %v, want %v", got.scheme, upstreamStateSchemeHTTPS)
	}
	if got := parseUpstreamStateKey("TCPTLS://svc:443"); got.scheme != upstreamStateSchemeInvalid {
		// tls:// 才是别名；陌生 scheme 仍归 Invalid。
		t.Fatalf("parseUpstreamStateKey(tcptls) scheme = %v, want invalid", got.scheme)
	}
}

func TestRPCUpstreamAliases(t *testing.T) {
	for _, alias := range []string{"tls", "grpcs", "grpc+tls", "grpc+https"} {
		info := parseUpstreamURL(alias + "://host:1")
		if !info.valid() {
			t.Fatalf("alias %s:// should normalize to a parseable URL", alias)
		}
		if info.scheme != "https" {
			t.Fatalf("alias %s:// normalized to scheme %q, want https", alias, info.scheme)
		}
		if !info.isHTTPS() {
			t.Fatalf("alias %s:// should be classified as HTTPS", alias)
		}
	}
	info := parseUpstreamURL("grpc://host:1")
	if !info.valid() || info.scheme != "h2c" || !info.isExplicitH2C() {
		t.Fatalf("grpc:// should normalize to h2c")
	}
}

func TestConfiguredProtocolAliases(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "tls://a:1", want: "https"},
		{raw: "grpcs://a:1", want: "https"},
		{raw: "grpc+tls://a:1", want: "https"},
		{raw: "grpc+https://a:1", want: "https"},
		{raw: "grpc://a:1", want: "h2c"},
		{raw: "GRPCS://a:1/path", want: "https"},
	}
	for _, tt := range tests {
		if got := ConfiguredProtocol(tt.raw); got != tt.want {
			t.Fatalf("ConfiguredProtocol(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestProtocolPreferenceAliases(t *testing.T) {
	tests := []struct {
		raw  string
		want int
	}{
		// 层级：h3(3) > h2c/grpc(2) > https/tls/grpcs(1) > 其余(0)。
		{raw: "h3://a:1", want: 3},
		{raw: "grpc://a:1", want: 2},
		{raw: "h2c://a:1", want: 2},
		{raw: "tls://a:1", want: 1},
		{raw: "grpcs://a:1", want: 1},
		{raw: "grpc+tls://a:1", want: 1},
		{raw: "GRPC+HTTPS://a:1", want: 1},
		{raw: "https://a:1", want: 1},
		{raw: "http://a:1", want: 0},
		{raw: "ftp://a:1", want: 0},
	}
	for _, tt := range tests {
		if got := protocolPreference(tt.raw); got != tt.want {
			t.Fatalf("protocolPreference(%q) = %d, want %d", tt.raw, got, tt.want)
		}
	}
}

func TestGroupURLsByProtocolPreferenceAliases(t *testing.T) {
	urls := []string{
		"tls://a:1",
		"grpc://b:2",
		"h3://c:3",
		"http://d:4",
	}
	groups := GroupURLsByProtocolPreference(urls)
	// 顺序：h3 组、h2c/grpc 组、https/tls 组、其余。
	if got := strings.Join(groups[0], ","); got != "h3://c:3" {
		t.Fatalf("groups[0] = %q, want h3", got)
	}
	if got := strings.Join(groups[1], ","); got != "grpc://b:2" {
		t.Fatalf("groups[1] = %q, want grpc", got)
	}
	if got := strings.Join(groups[2], ","); got != "tls://a:1" {
		t.Fatalf("groups[2] = %q, want tls", got)
	}
	if got := strings.Join(groups[3], ","); got != "http://d:4" {
		t.Fatalf("groups[3] = %q, want http", got)
	}
}

func TestPickByProtocolPreferenceAliases(t *testing.T) {
	got, ok := PickByProtocolPreference(
		[]string{"grpc://b:2", "grpcs://s:1", "h3://q:3", "http://p:0"}, nil,
		func(uint32) uint32 { return 0 })
	if !ok || got != "h3://q:3" {
		t.Fatalf("got %q ok=%v, want h3 first", got, ok)
	}

	got, ok = PickByProtocolPreference(
		[]string{"grpc://b:2", "grpcs://s:1", "http://p:0"}, nil,
		func(uint32) uint32 { return 0 })
	if !ok || got != "grpc://b:2" {
		t.Fatalf("got %q ok=%v, want grpc before grpcs", got, ok)
	}

	// grpc://（h2c 层）：同层比较时仍按 latency 选最优，这里只验证能选中。
	got, ok = PickByProtocolPreference(
		[]string{"tls://a:1", "http://p:0"}, nil,
		func(uint32) uint32 { return 0 })
	if !ok || got != "tls://a:1" {
		t.Fatalf("got %q ok=%v, want tls before http", got, ok)
	}
}

func TestStateKeyStringAliases(t *testing.T) {
	// 归一后状态键回显为归一后的 scheme（配置字符串回显）。
	if got := parseUpstreamStateKey("grpcs://svc:443").String(); got != "https://svc:443" {
		t.Fatalf("grpcs state key String() = %q, want https://svc:443", got)
	}
	if got := parseUpstreamStateKey("grpc://svc:9000").String(); got != "h2c://svc:9000" {
		t.Fatalf("grpc state key String() = %q, want h2c://svc:9000", got)
	}
	// 同一上游不同别名应共享状态键。
	grpcs := parseUpstreamStateKey("grpcs://svc:443")
	https := parseUpstreamStateKey("https://svc:443")
	if grpcs != https {
		t.Fatalf("grpcs and https should share the same state key: %+v vs %+v", grpcs, https)
	}
}
