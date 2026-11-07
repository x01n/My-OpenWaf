package proxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/snapshot"
)

/*
本文件覆盖 upstream_request_guard.go 的两个净化器。

背景：datacon2025 语料里 85 条 502 由本仓库自身造成，两条根因分别是
「hertz 收下的非法头名/头值被 net/http 整条拒绝」与「path 里的裸 '%' 让
url.Parse 失败」。这里的用例同时锁住两件事：畸形输入能发出去，以及
合法输入一个字节都不变。
*/

// resetUpstreamGuardCounters 把净化器计数器归零，便于按增量断言。
func resetUpstreamGuardCounters(t *testing.T) {
	t.Helper()
	reset := func() {
		upstreamHeaderNameDroppedCounter.Store(0)
		upstreamHeaderValueDroppedCounter.Store(0)
		upstreamPathSanitizedCounter.Store(0)
		upstreamSecurityHeaderDroppedCounter.Store(0)
	}
	reset()
	t.Cleanup(reset)
}

/*
TestBuildUpstreamRequestDropsInvalidHeaderName 覆盖根因 A 的主路径。

`Token;` 里的分号不是 RFC 7230 的 tchar，hertz 的 HTTP/1 解析器照收，
而 net/http 出站前会用它自己的 httpguts 判据拒绝整个 Header——整条请求
因此变成 502。这里断言的是「非法头被丢掉、请求仍然构建成功、同一个请求
里的合法头一个不少」。
*/
func TestBuildUpstreamRequestDropsInvalidHeaderName(t *testing.T) {
	resetUpstreamGuardCounters(t)

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource")
	ctx.Request.Header.Set("Token;", "abc")
	ctx.Request.Header.Set(",Accept", "text/html")
	ctx.Request.Header.Set("X@t", "v")
	ctx.Request.Header.Set("X-Kept", "kept")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}

	for _, name := range []string{"Token;", ",Accept", "X@t"} {
		if got := req.Header.Get(name); got != "" {
			t.Fatalf("非法头名 %q 未被丢弃，值 = %q", name, got)
		}
	}
	if got := req.Header.Get("X-Kept"); got != "kept" {
		t.Fatalf("合法头 X-Kept 受影响，值 = %q", got)
	}
	if got := UpstreamRequestGuardSnapshot().DroppedHeaderNames; got != 3 {
		t.Fatalf("DroppedHeaderNames = %d, want 3", got)
	}
}

/*
TestBuildUpstreamRequestHeaderGuardKeepsLegalNamesIntact 是根因 A 的反向断言。

合法头名走 addUpstreamHeader 的大小写快速路径，其取值必须逐条保留，
包括重复出现的同名头——净化器按「字段」判定，合法字段的多个取值都要留下。
*/
func TestBuildUpstreamRequestHeaderGuardKeepsLegalNamesIntact(t *testing.T) {
	resetUpstreamGuardCounters(t)

	legalNames := []string{
		"Accept", "Accept-Encoding", "Accept-Language", "Cache-Control", "Content-Type",
		"Cookie", "If-Modified-Since", "Origin", "Pragma", "Referer", "Sec-Ch-Ua",
		"Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform", "Sec-Fetch-Dest", "Sec-Fetch-Mode",
		"Sec-Fetch-Site", "Upgrade-Insecure-Requests", "User-Agent", "X-Client-Data",
		"X-Requested-With", "X-Tingyun-Id", "X-Test", "x-lowercase", "X-MiXeD",
		// token 里的合法标点
		"X-We!rd#$%&'*+-.^_`|~Name",
	}

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource")
	for _, name := range legalNames {
		ctx.Request.Header.Set(name, "v-"+name)
	}
	ctx.Request.Header.Add("X-Repeat", "one")
	ctx.Request.Header.Add("X-Repeat", "two")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}

	for _, name := range legalNames {
		if got := req.Header.Get(name); got != "v-"+name {
			t.Fatalf("合法头 %q = %q, want %q", name, got, "v-"+name)
		}
	}
	if got := req.Header.Values("X-Repeat"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("重复合法头 X-Repeat = %#v, want [one two]", got)
	}
	if got := UpstreamRequestGuardSnapshot(); got.DroppedHeaderNames != 0 || got.DroppedHeaderValues != 0 {
		t.Fatalf("合法请求触发了丢弃计数: %+v", got)
	}
}

/*
TestBuildUpstreamRequestDropsInvalidHeaderValue 覆盖头值侧的同一判据。

net/http 的 validateHeaders 同时校验 name 与 value，而 hertz 的 HTTP/1
解析器会先挡掉控制字节——所以这条防线针对的不是网络入站，而是**服务端自己
注入的头**：桌面端请求头改写（applyJSMutationPlan）走的是 hertz 的
Header.Set，它只拦 CR/LF，VT/FF/DEL 能一路写进请求头，随后同样让整条请求
在 net/http 处变成 502。实测（本机 hertz v0.10.6）：Set 一个含 0x0b 的值，
Peek 原样取回；经过 buildUpstreamRequest 后该头已被丢弃。
*/
func TestBuildUpstreamRequestDropsInvalidHeaderValue(t *testing.T) {
	resetUpstreamGuardCounters(t)

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource")
	ctx.Request.Header.Set("X-Vt", "a\x0bb")
	ctx.Request.Header.Set("X-Del", "a\x7fb")
	ctx.Request.Header.Set("X-Ff", "a\x0cb")
	ctx.Request.Header.Set("X-Kept", "a b\tc")
	// 高位字节在 net/http 的判据里是合法的（非 CTL），必须原样保留：
	// 真实浏览器与语料里都有 UTF-8 头值，误丢会改变转发语义。
	ctx.Request.Header.Set("X-Utf8", "中文")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}

	for _, name := range []string{"X-Vt", "X-Del", "X-Ff"} {
		if got := req.Header.Get(name); got != "" {
			t.Fatalf("非法头值 %q 未被丢弃，值 = %q", name, got)
		}
	}
	if got := req.Header.Get("X-Kept"); got != "a b\tc" {
		t.Fatalf("合法头值 X-Kept = %q, want %q", got, "a b\tc")
	}
	if got := req.Header.Get("X-Utf8"); got != "中文" {
		t.Fatalf("UTF-8 头值 X-Utf8 = %q, want %q", got, "中文")
	}
	if got := UpstreamRequestGuardSnapshot().DroppedHeaderValues; got != 3 {
		t.Fatalf("DroppedHeaderValues = %d, want 3", got)
	}
}

/*
TestBuildUpstreamRequestDropsOnlyIllegalValueOfRepeatedHeader 锁住粒度。

头值按「取值」而不是按「字段」判定：一个字段的多个取值互不牵连，
丢弃其中非法的一个不应连带丢掉同一个头里的合法取值。
*/
func TestBuildUpstreamRequestDropsOnlyIllegalValueOfRepeatedHeader(t *testing.T) {
	resetUpstreamGuardCounters(t)

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource")
	ctx.Request.Header.Add("X-Multi", "good-one")
	ctx.Request.Header.Add("X-Multi", "bad\x0bvalue")
	ctx.Request.Header.Add("X-Multi", "good-two")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}

	got := req.Header.Values("X-Multi")
	if len(got) != 2 || got[0] != "good-one" || got[1] != "good-two" {
		t.Fatalf("X-Multi = %#v, want [good-one good-two]", got)
	}
	if n := UpstreamRequestGuardSnapshot().DroppedHeaderValues; n != 1 {
		t.Fatalf("DroppedHeaderValues = %d, want 1", n)
	}
}

/*
TestBuildUpstreamRequestDropsIllegalForwardedIdentityHeader 覆盖收尾位置的必要性。

出站 Header 的写入者有三个：hertz 入站头的拷贝、TE、security 重建的转发身份头。
放在收尾处才能一次覆盖全部；这条用例专门打第三个写入者——入站的
X-Forwarded-Host 会被 security 无条件删除并按 origHost 重建，而重建只在
preserveOriginalHost 为真时发生。因此必须同时打开该开关并把 origHost 本身
构造成非法值，才能证明收尾位置确实管住了第三个写入者。
*/
func TestBuildUpstreamRequestDropsIllegalForwardedIdentityHeader(t *testing.T) {
	resetUpstreamGuardCounters(t)

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource")
	// 入站自带的 X-Forwarded-Host 无论如何都会被 security 删掉重建，
	// 先放一个合法值，确保最终被丢的是重建出来的那一个。
	ctx.Request.Header.Set("X-Forwarded-Host", "client.example")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "bad\x0bhost", true)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}

	if got := req.Header.Get("X-Forwarded-Host"); got != "" {
		t.Fatalf("非法 X-Forwarded-Host 未被丢弃，值 = %q", got)
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("合法 X-Forwarded-Proto 受影响，值 = %q", got)
	}
	if n := UpstreamRequestGuardSnapshot().DroppedHeaderValues; n != 1 {
		t.Fatalf("DroppedHeaderValues = %d, want 1", n)
	}
}

/*
TestBuildUpstreamRequestDropsSecurityRelevantHeader 覆盖「丢弃安全头」这条副作用的
可观测性，而不是可避免性。

结论先说：**丢弃安全相关头在本实现里不可达**，因为 hertz 只在 Cookie 头合法时
才把它物化进 Header map（`internal/proxy/proxy.go` 头拷贝循环只会看到 hertz
物化过的头）。但这是 hertz 的内部行为、不在本仓库的控制之内，一旦某天它变了，
「上游看到匿名身份」这种事故不会有任何外部信号。因此对 Authorization / Cookie /
X-Forwarded-* 等头单独计数并在整体丢弃时升到 WARN。

为什么不改成「值非法则拒绝整个请求」：拒绝路径把畸形头变成了对本 WAF 自身的
可用性武器——一个畸形 Cookie 就能让该请求从可转发降级为 5xx；而丢弃只是让上游
看到与「客户端本来就没发这个头」完全相同的请求，且现在有 WARN 与计数器可追。
保留 2xx 并显著告警，比把它升级成 5xx 更符合「局部补救而非整条失败」的既定原则。
*/
func TestBuildUpstreamRequestDropsSecurityRelevantHeader(t *testing.T) {
	resetUpstreamGuardCounters(t)

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource")
	// 直接写进 http.Header 的等价物：用一个 hertz 会原样物化的安全头，
	// 再把值构造成非法。Authorization 不在 hertz 的 Cookie 特判里。
	ctx.Request.Header.Set("Authorization", "Bearer a\x0bb")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("非法 Authorization 未被丢弃，值 = %q", got)
	}
	if n := UpstreamRequestGuardSnapshot().DroppedSecurityHeaderNames; n != 1 {
		t.Fatalf("DroppedSecurityHeaderNames = %d, want 1（安全头整体丢弃必须被单独计数）", n)
	}
}

/*
TestSecurityRelevantOutboundHeaderClassification 锁住分类表本身。

分类错了会让上面那条 WARN 永远不触发，而这类「永远不会响的报警器」在测试里
看不出来。表里同时锁一个反例（普通业务头不得进入该表），避免有人把判据放宽成
「所有头」。
*/
func TestSecurityRelevantOutboundHeaderClassification(t *testing.T) {
	for _, name := range []string{
		"Authorization", "authorization", "Cookie", "cookie",
		"Proxy-Authorization", "X-Forwarded-For", "x-forwarded-for",
		"X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip", "Client-Ip", "Forwarded",
	} {
		if !isSecurityRelevantOutboundHeader(name) {
			t.Fatalf("isSecurityRelevantOutboundHeader(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"X-Test", "User-Agent", "Accept", "Content-Type", "", "X-Forwarded-Forr"} {
		if isSecurityRelevantOutboundHeader(name) {
			t.Fatalf("isSecurityRelevantOutboundHeader(%q) = true, want false", name)
		}
	}
}

// startRawCaptureUpstream 起一个把请求行与头部原样回传的上游，供逐字节对照。
//
// @param t 测试句柄。
// @return 上游地址与「取回下一条请求行」的函数。
func startRawCaptureUpstream(t *testing.T) (string, func() string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw upstream: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	lines := make(chan string, 32)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				first, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				lines <- strings.TrimRight(first, "\r\n")
				for {
					line, err := reader.ReadString('\n')
					if err != nil || strings.TrimRight(line, "\r\n") == "" {
						break
					}
				}
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			}(conn)
		}
	}()

	return ln.Addr().String(), func() string {
		select {
		case line := <-lines:
			return line
		case <-time.After(3 * time.Second):
			t.Fatal("raw upstream did not receive a request")
			return ""
		}
	}
}

/*
TestForwardHTTPUpstreamRequestLineBytes 是「合法 path 转发字节不变」的对照。

表里两个期望值分别锁住两条通道：
  - 不含裸 '%' 的 path 必须逐字节原样出现在 request-line 里（这是净化器的
    零分配快路径保证的）；
  - 含裸 '%' 的 path 只把裸 '%' 换成 "%25"，其余字节（含既有的合法转义
    与大小写）一个不动。
*/
func TestForwardHTTPUpstreamRequestLineBytes(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		want string
		// wantSanitized 是该 path 是否应当触发裸 '%' 转义计数。
		wantSanitized uint64
	}{
		{name: "plain path", uri: "/resource", want: "GET /resource HTTP/1.1"},
		{name: "empty path", uri: "", want: "GET / HTTP/1.1"},
		{name: "root path", uri: "/", want: "GET / HTTP/1.1"},
		{name: "escaped slash and space", uri: "/assets/a%2Fb%20c.js", want: "GET /assets/a%2Fb%20c.js HTTP/1.1"},
		{name: "lowercase hex preserved", uri: "/a%2fB", want: "GET /a%2fB HTTP/1.1"},
		{name: "encoded percent preserved", uri: "/%25", want: "GET /%25 HTTP/1.1"},
		{name: "utf8 escapes preserved", uri: "/%E4%B8%AD%E6%96%87", want: "GET /%E4%B8%AD%E6%96%87 HTTP/1.1"},
		{name: "plus and semicolon", uri: "/a+b;c", want: "GET /a+b;c HTTP/1.1"},
		{name: "query preserved", uri: "/resource%20x?x=1&y=two", want: "GET /resource%20x?x=1&y=two HTTP/1.1"},
		{name: "truncated escape escaped", uri: "/abc%", want: "GET /abc%25 HTTP/1.1", wantSanitized: 1},
		{name: "single hex digit escaped", uri: "/abc%2", want: "GET /abc%252 HTTP/1.1", wantSanitized: 1},
		{name: "double percent", uri: "/a%%27b", want: "GET /a%25%27b HTTP/1.1", wantSanitized: 1},
		{name: "non hex after percent", uri: "/abc%zz", want: "GET /abc%25zz HTTP/1.1", wantSanitized: 1},
		{
			name:          "corpus absolute-form with truncated escape",
			uri:           "/http://x.test/%E2%80%",
			want:          "GET /http://x.test/%E2%80%25 HTTP/1.1",
			wantSanitized: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetUpstreamGuardCounters(t)
			addr, nextLine := startRawCaptureUpstream(t)

			ctx := app.NewContext(0)
			ctx.Request.SetMethod("GET")
			ctx.Request.SetRequestURI(tc.uri)

			if err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, "http://"+addr, nil, "example.test"); err != nil {
				t.Fatalf("ForwardHTTP returned error: %v", err)
			}
			if got := ctx.Response.StatusCode(); got != http.StatusOK {
				t.Fatalf("status = %d, want 200", got)
			}
			if got := nextLine(); got != tc.want {
				t.Fatalf("upstream request-line = %q, want %q", got, tc.want)
			}

			wantSanitized := tc.wantSanitized
			if got := UpstreamRequestGuardSnapshot().SanitizedPaths; got != wantSanitized {
				t.Fatalf("SanitizedPaths = %d, want %d", got, wantSanitized)
			}
		})
	}
}

/*
TestBuildUpstreamRequestWithBarePercentStillSucceeds 覆盖根因 B 的构建阶段。

裸 '%' 曾经让 url.Parse 直接报 invalid URL escape，请求根本没发出去。
这两条断言的是「能构建出请求」与「URL 结构正确」。
*/
func TestBuildUpstreamRequestWithBarePercentStillSucceeds(t *testing.T) {
	resetUpstreamGuardCounters(t)

	for _, uri := range []string{"/%E2%80%", "/a%%27b", "/abc%", "/abc%2", "/abc%zz"} {
		ctx := app.NewContext(0)
		ctx.Request.SetMethod("GET")
		ctx.Request.SetRequestURI(uri)

		req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
		if err != nil {
			t.Fatalf("path %q: buildUpstreamRequest returned error: %v", uri, err)
		}
		if req.URL.Scheme != "http" || req.URL.Host != "127.0.0.1:8800" {
			t.Fatalf("path %q: URL = %s, want http://127.0.0.1:8800/...", uri, req.URL)
		}
		if got := req.URL.EscapedPath(); !strings.Contains(got, "%25") {
			t.Fatalf("path %q: EscapedPath = %q, want it to contain %%25", uri, got)
		}
	}
}

/*
TestBuildUpstreamRequestLegalPathEscapedPathUnchanged 是「合法 path 逐字节不变」的
单元级对照：合法输入下 EscapedPath 与 RawQuery 必须与净化前完全一致。
*/
func TestBuildUpstreamRequestLegalPathEscapedPathUnchanged(t *testing.T) {
	cases := []struct {
		uri         string
		wantPath    string
		wantRawPath string
	}{
		{uri: "/resource", wantPath: "/resource", wantRawPath: "x=1"},
		{uri: "/assets/a%2Fb%20c.js", wantPath: "/assets/a%2Fb%20c.js", wantRawPath: "x=a%2Fb&y=two"},
		{uri: "/%E4%B8%AD%E6%96%87", wantPath: "/%E4%B8%AD%E6%96%87", wantRawPath: ""},
		{uri: "/%25", wantPath: "/%25", wantRawPath: ""},
		{uri: "/a%2fB", wantPath: "/a%2fB", wantRawPath: ""},
	}

	for _, tc := range cases {
		t.Run(tc.uri, func(t *testing.T) {
			resetUpstreamGuardCounters(t)

			uri := tc.uri
			if uri == "/resource" {
				uri = "/resource?x=1"
			} else if strings.Contains(uri, "a%2Fb") {
				uri = "/assets/a%2Fb%20c.js?x=a%2Fb&y=two"
			}

			ctx := app.NewContext(0)
			ctx.Request.SetMethod("GET")
			ctx.Request.SetRequestURI(uri)

			req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
			if err != nil {
				t.Fatalf("buildUpstreamRequest returned error: %v", err)
			}
			if got := req.URL.EscapedPath(); got != tc.wantPath {
				t.Fatalf("EscapedPath = %q, want %q", got, tc.wantPath)
			}
			if req.URL.RawQuery != tc.wantRawPath {
				t.Fatalf("RawQuery = %q, want %q", req.URL.RawQuery, tc.wantRawPath)
			}
			if got := UpstreamRequestGuardSnapshot().SanitizedPaths; got != 0 {
				t.Fatalf("合法 path 触发了路径净化计数: %d", got)
			}
		})
	}
}

/*
TestSanitizeRawPercentEscapesFastPathReturnsNil 锁住零分配快路径。

「合法 path 转发字节不变」是靠「不改动」实现的，而不是靠改回去：预扫没有
裸 '%' 时必须返回 nil，让调用方继续用原始切片。
*/
func TestSanitizeRawPercentEscapesFastPathReturnsNil(t *testing.T) {
	for _, path := range []string{
		"", "/", "/resource", "/assets/a%2Fb%20c.js", "/%E4%B8%AD%E6%96%87",
		"/%25", "/a%2fB", "/a+b", "/a'b", "/a;b", "/a%2Fb%25c",
	} {
		if got := sanitizeRawPercentEscapes([]byte(path)); got != nil {
			t.Fatalf("sanitizeRawPercentEscapes(%q) = %q, want nil（零分配快路径）", path, got)
		}
	}
}
