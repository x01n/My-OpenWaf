package dataplane

import (
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/waf/bot"
)

type stringAddrForTest string

func (a stringAddrForTest) Network() string { return "tcp" }
func (a stringAddrForTest) String() string  { return string(a) }

func populateRequestCtxHeadersLegacy(reqCtx *pipeline.RequestCtx, c *app.RequestContext) {
	c.Request.Header.VisitAll(func(k, v []byte) {
		key := string(k)
		value := string(v)
		reqCtx.Headers[key] = value
		if lower := strings.ToLower(key); lower != key {
			reqCtx.Headers[lower] = value
		}
		reqCtx.AppendHeaderKey(key)
	})
}

func newHeaderPopulateBenchContext() *app.RequestContext {
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.Header.SetHost("bench.example.com")
	ctx.Request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8")
	ctx.Request.Header.Set("Accept-Encoding", "gzip, deflate, br")
	ctx.Request.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	ctx.Request.Header.Set("Cache-Control", "max-age=0")
	ctx.Request.Header.Set("Connection", "keep-alive")
	ctx.Request.Header.Set("Cookie", "__waf_passed=bench; sessionid=abc123; csrftoken=xyz")
	ctx.Request.Header.Set("Pragma", "no-cache")
	ctx.Request.Header.Set("Referer", "https://bench.example.com/console?q=1")
	ctx.Request.Header.Set("Sec-Ch-Ua", "\"Chromium\";v=\"136\", \"Not.A/Brand\";v=\"99\"")
	ctx.Request.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	ctx.Request.Header.Set("Sec-Ch-Ua-Platform", "\"Windows\"")
	ctx.Request.Header.Set("Sec-Fetch-Dest", "document")
	ctx.Request.Header.Set("Sec-Fetch-Mode", "navigate")
	ctx.Request.Header.Set("Sec-Fetch-Site", "same-origin")
	ctx.Request.Header.Set("Sec-Fetch-User", "?1")
	ctx.Request.Header.Set("Upgrade-Insecure-Requests", "1")
	ctx.Request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/136.0 Safari/537.36")
	ctx.Request.Header.Set("X-Forwarded-For", "203.0.113.10")
	ctx.Request.Header.Set("X-Forwarded-Proto", "https")
	ctx.Request.Header.Set("X-Request-Id", "req-bench")
	ctx.Request.Header.Set("X-Custom-Token", "bench-token")
	return ctx
}

func hasHeaderKey(keys []string, want string) bool {
	for i := range keys {
		if keys[i] == want {
			return true
		}
	}
	return false
}

func TestPopulateRequestCtxHeadersStoresLowercaseKeysOnly(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.Header.Set("User-Agent", "bench-agent")
	ctx.Request.Header.Set("X-Custom-Token", "bench-token")

	reqCtx := pipeline.AcquireCtx()
	defer pipeline.ReleaseCtx(reqCtx)

	populateRequestCtxHeaders(reqCtx, ctx)

	if !reqCtx.HeadersLowercase {
		t.Fatal("request headers should be marked as lowercase")
	}
	if got := reqCtx.Headers["user-agent"]; got != "bench-agent" {
		t.Fatalf("lowercase user-agent = %q, want bench-agent", got)
	}
	if got := reqCtx.Headers["x-custom-token"]; got != "bench-token" {
		t.Fatalf("lowercase x-custom-token = %q, want bench-token", got)
	}
	if _, ok := reqCtx.Headers["User-Agent"]; ok {
		t.Fatalf("original-case key should not be duplicated: %#v", reqCtx.Headers)
	}
	if _, ok := reqCtx.Headers["X-Custom-Token"]; ok {
		t.Fatalf("original-case key should not be duplicated: %#v", reqCtx.Headers)
	}
	if !hasHeaderKey(reqCtx.HeaderKeys, "User-Agent") || !hasHeaderKey(reqCtx.HeaderKeys, "X-Custom-Token") {
		t.Fatalf("header order keys should preserve original case, got %#v", reqCtx.HeaderKeys)
	}
}

func TestLowerRequestHeaderNameMatchesStringsToLower(t *testing.T) {
	inputs := []string{
		"Accept",
		"Accept-Encoding",
		"Accept-Language",
		"Authorization",
		"Cache-Control",
		"Connection",
		"Content-Length",
		"Content-Type",
		"Cookie",
		"DNT",
		"Host",
		"If-Modified-Since",
		"If-None-Match",
		"Origin",
		"Pragma",
		"Referer",
		"Sec-Ch-Ua",
		"Sec-Ch-Ua-Arch",
		"Sec-Ch-Ua-Bitness",
		"Sec-Ch-Ua-Full-Version",
		"Sec-Ch-Ua-Full-Version-List",
		"Sec-Ch-Ua-Mobile",
		"Sec-Ch-Ua-Model",
		"Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Platform-Version",
		"Sec-Fetch-Dest",
		"Sec-Fetch-Mode",
		"Sec-Fetch-Site",
		"Sec-Fetch-User",
		"TE",
		"Upgrade",
		"Upgrade-Insecure-Requests",
		"User-Agent",
		"X-Client-Data",
		"X-Forwarded-For",
		"X-Forwarded-Proto",
		"X-Request-Id",
		"x-custom-token",
		"X-Custom-Token",
		"X-OWAF-TLS-SNI",
		"X-Trace-\u7f16\u53f7",
	}
	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			if got, want := lowerRequestHeaderName(input), strings.ToLower(input); got != want {
				t.Fatalf("lowerRequestHeaderName(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

func BenchmarkPopulateRequestCtxHeadersBrowserHeaders(b *testing.B) {
	ctx := newHeaderPopulateBenchContext()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reqCtx := pipeline.AcquireCtx()
		populateRequestCtxHeaders(reqCtx, ctx)
		pipeline.ReleaseCtx(reqCtx)
	}
}

func BenchmarkPopulateRequestCtxHeadersLegacyBrowserHeaders(b *testing.B) {
	ctx := newHeaderPopulateBenchContext()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reqCtx := pipeline.AcquireCtx()
		populateRequestCtxHeadersLegacy(reqCtx, ctx)
		pipeline.ReleaseCtx(reqCtx)
	}
}

func TestApplyInternalHTTP3RequestMetadataCachesTLSFingerprintAndStripsHeaders(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := app.NewContext(0)
	ctx.Request.Header.Set(InternalHTTP3ProtoHeader, "h3")
	ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
	ctx.Request.Header.Set(InternalHTTP3TLSVersionHeader, "TLS13")
	ctx.Request.Header.Set(InternalHTTP3TLSSNIHeader, "client.example")
	ctx.Request.Header.Set(InternalHTTP3TLSALPNHeader, "h3")
	ctx.Request.Header.Set(InternalHTTP3TLSJA3Header, "771,4865-4866,0-16-43,29,0")
	ctx.Request.Header.Set(InternalHTTP3TLSJA3HashHeader, "0123456789abcdef0123456789abcdef")
	ctx.Request.Header.Set(InternalHTTP3TLSJA4Header, "q13d0511h3_fea09b2e4d67_1234567890ab")
	ctx.Request.Header.Set(InternalHTTP3TLSCipherSuitesHeader, "4865,4866")
	ctx.Request.Header.Set(InternalHTTP3TLSExtensionsHeader, "0,16,43")
	ctx.Request.Header.Set(InternalHTTP3TLSCurvesHeader, "29,23")
	ctx.Request.Header.Set(InternalHTTP3TLSPointFormatsHeader, "0")
	ctx.SetConn(&loopbackHertzConn{
		Conn:       &testHertzConn{Conn: server},
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	})

	applyInternalHTTP3RequestMetadata(ctx)

	if !isInternalHTTP3Request(ctx) {
		t.Fatal("expected request to be marked as internal HTTP/3")
	}
	if got := string(ctx.GetHeader(InternalHTTP3ProtoHeader)); got != "" {
		t.Fatalf("internal proto header should be stripped, got %q", got)
	}
	if got := string(ctx.GetHeader(InternalHTTP3TLSVersionHeader)); got != "" {
		t.Fatalf("internal tls version header should be stripped, got %q", got)
	}
	if got := string(ctx.GetHeader(InternalHTTP3TLSSNIHeader)); got != "" {
		t.Fatalf("internal tls sni header should be stripped, got %q", got)
	}
	if got := string(ctx.GetHeader(InternalHTTP3TLSALPNHeader)); got != "" {
		t.Fatalf("internal tls alpn header should be stripped, got %q", got)
	}
	if got := string(ctx.GetHeader(InternalHTTP3TLSJA3Header)); got != "" {
		t.Fatalf("internal tls ja3 header should be stripped, got %q", got)
	}
	if got := string(ctx.GetHeader(InternalHTTP3TLSJA3HashHeader)); got != "" {
		t.Fatalf("internal tls ja3 hash header should be stripped, got %q", got)
	}
	if got := string(ctx.GetHeader(InternalHTTP3TLSJA4Header)); got != "" {
		t.Fatalf("internal tls ja4 header should be stripped, got %q", got)
	}
	if got := string(ctx.GetHeader(InternalHTTP3TLSCipherSuitesHeader)); got != "" {
		t.Fatalf("internal tls cipher suites header should be stripped, got %q", got)
	}
	if got := string(ctx.GetHeader(InternalHTTP3TLSExtensionsHeader)); got != "" {
		t.Fatalf("internal tls extensions header should be stripped, got %q", got)
	}
	if got := string(ctx.GetHeader(InternalHTTP3TLSCurvesHeader)); got != "" {
		t.Fatalf("internal tls curves header should be stripped, got %q", got)
	}
	if got := string(ctx.GetHeader(InternalHTTP3TLSPointFormatsHeader)); got != "" {
		t.Fatalf("internal tls point formats header should be stripped, got %q", got)
	}

	fp, ok := tlsFingerprintFromRequestContext(ctx)
	if !ok {
		t.Fatal("expected cached TLS fingerprint metadata")
	}
	if fp.TLSVersion != "TLS13" || fp.SNI != "client.example" {
		t.Fatalf("unexpected TLS fingerprint metadata: %+v", fp)
	}
	if len(fp.ALPN) != 1 || fp.ALPN[0] != "h3" {
		t.Fatalf("unexpected ALPN metadata: %+v", fp.ALPN)
	}
	if fp.JA3 != "771,4865-4866,0-16-43,29,0" || fp.JA3Hash != "0123456789abcdef0123456789abcdef" || fp.JA4 != "q13d0511h3_fea09b2e4d67_1234567890ab" {
		t.Fatalf("unexpected JA3/JA4 metadata: %+v", fp)
	}
	if !reflect.DeepEqual(fp.CipherSuites, []uint16{4865, 4866}) {
		t.Fatalf("unexpected cipher suites: %+v", fp.CipherSuites)
	}
	if !reflect.DeepEqual(fp.Extensions, []uint16{0, 16, 43}) {
		t.Fatalf("unexpected extensions: %+v", fp.Extensions)
	}
	if !reflect.DeepEqual(fp.Curves, []uint16{29, 23}) {
		t.Fatalf("unexpected curves: %+v", fp.Curves)
	}
	if !reflect.DeepEqual(fp.PointFormats, []uint8{0}) {
		t.Fatalf("unexpected point formats: %+v", fp.PointFormats)
	}
}

func TestTLSFingerprintFromRequestContextSkipsProxyConnForInternalHTTP3(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := app.NewContext(0)
	ctx.Request.Header.Set(InternalHTTP3ProtoHeader, "h3")
	ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
	ctx.SetConn(&loopbackHertzConn{
		Conn: &testHertzConn{Conn: bot.WrapFingerprintConn(server, bot.TLSClientFingerprint{
			TLSVersion: "TLS13",
			JA3Hash:    "proxy-ja3",
			JA4:        "proxy-ja4",
		})},
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	})

	applyInternalHTTP3RequestMetadata(ctx)

	if _, ok := tlsFingerprintFromRequestContext(ctx); ok {
		t.Fatal("internal HTTP/3 request without explicit metadata should not fall back to proxy TLS fingerprint")
	}
}

func TestApplyInternalHTTP3RequestMetadataDoesNotMergeProxyTLSFingerprint(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.Header.Set(InternalHTTP3ProtoHeader, "h3")
	ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
	ctx.Request.Header.Set(InternalHTTP3TLSVersionHeader, "TLS13")
	ctx.Request.Header.Set(InternalHTTP3TLSSNIHeader, "client.example")
	ctx.Request.Header.Set(InternalHTTP3TLSALPNHeader, "h3")
	ctx.Set(tlsFingerprintContextKey, bot.TLSClientFingerprint{
		TLSVersion: "TLS13",
		SNI:        "proxy.example",
		ALPN:       []string{"h2"},
		JA3Hash:    "proxy-ja3-hash",
		JA4:        "t13i2511h2_b78ed14e2fd0_ab7e3b40a677",
	})
	ctx.SetConn(&loopbackHertzConn{
		Conn:       &testHertzConn{},
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	})

	applyInternalHTTP3RequestMetadata(ctx)

	fp, ok := tlsFingerprintFromRequestContext(ctx)
	if !ok {
		t.Fatal("expected cached HTTP/3 TLS metadata")
	}
	if fp.TLSVersion != "TLS13" || fp.SNI != "client.example" || len(fp.ALPN) != 1 || fp.ALPN[0] != "h3" {
		t.Fatalf("unexpected HTTP/3 TLS metadata: %+v", fp)
	}
	if fp.JA3Hash != "" || fp.JA4 != "" {
		t.Fatalf("HTTP/3 metadata should not retain proxy JA3/JA4: %+v", fp)
	}
}

func TestIsLoopbackNetAddrRecognizesConcreteAddrTypes(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want bool
	}{
		{name: "tcp loopback", addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}, want: true},
		{name: "udp loopback", addr: &net.UDPAddr{IP: net.ParseIP("::1"), Port: 443}, want: true},
		{name: "ipaddr loopback", addr: &net.IPAddr{IP: net.ParseIP("127.0.0.1")}, want: true},
		{name: "string fallback loopback", addr: stringAddrForTest("127.0.0.1:443"), want: true},
		{name: "tcp non-loopback", addr: &net.TCPAddr{IP: net.ParseIP("198.51.100.10"), Port: 443}, want: false},
		{name: "empty addr", addr: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLoopbackNetAddr(tt.addr); got != tt.want {
				t.Fatalf("isLoopbackNetAddr(%T %v) = %v, want %v", tt.addr, tt.addr, got, tt.want)
			}
		})
	}
}

func BenchmarkApplyInternalHTTP3RequestMetadataUntrusted(b *testing.B) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := app.NewContext(0)
	ctx.SetConn(&loopbackHertzConn{
		Conn:       &testHertzConn{Conn: server},
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.10"), Port: 12345},
	})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.Request.Header.Set(InternalHTTP3ProtoHeader, "h3")
		ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
		ctx.Request.Header.Set(InternalHTTP3TLSVersionHeader, "TLS13")
		ctx.Request.Header.Set(InternalHTTP3TLSSNIHeader, "client.example")
		ctx.Request.Header.Set(InternalHTTP3TLSALPNHeader, "h3")
		ctx.Request.Header.Set(InternalHTTP3TLSJA3Header, "771,4865-4866,0-16-43,29,0")
		ctx.Request.Header.Set(InternalHTTP3TLSJA3HashHeader, "0123456789abcdef0123456789abcdef")
		ctx.Request.Header.Set(InternalHTTP3TLSJA4Header, "q13d0511h3_fea09b2e4d67_1234567890ab")
		ctx.Request.Header.Set(InternalHTTP3TLSCipherSuitesHeader, "4865,4866")
		ctx.Request.Header.Set(InternalHTTP3TLSExtensionsHeader, "0,16,43")
		ctx.Request.Header.Set(InternalHTTP3TLSCurvesHeader, "29,23")
		ctx.Request.Header.Set(InternalHTTP3TLSPointFormatsHeader, "0")
		applyInternalHTTP3RequestMetadata(ctx)
	}
}
