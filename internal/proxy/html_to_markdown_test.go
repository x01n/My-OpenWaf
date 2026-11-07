package proxy

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol/consts"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/dynamic"
)

// markdownTestHTML 是覆盖标题、强调、链接、列表、表格、删除线与图片的样例文档。
const markdownTestHTML = `<html><body><h1>标题</h1><p>这是<strong>加粗</strong>与<a href="https://example.com">链接</a>。</p>` +
	`<ul><li>项目一</li><li>项目二</li></ul>` +
	`<table><tr><th>A</th><th>B</th></tr><tr><td>1</td><td>2</td></tr></table>` +
	`<del>删除</del><img src="/x.png" alt="pic"></body></html>`

// newMarkdownTestContext 构造一个带指定 Accept 的请求上下文，响应状态码固定 200。
//
// @param accept Accept 头原值。
// @param contentType 上游响应 Content-Type。
// @return 已初始化的 Hertz 上下文。
func newMarkdownTestContext(accept string, contentType string) *app.RequestContext {
	c := app.NewContext(0)
	c.Request.Header.SetMethod(consts.MethodGet)
	c.Request.SetRequestURI("/index.html")
	if accept != "" {
		c.Request.Header.Set("Accept", accept)
	}
	if contentType != "" {
		c.Response.Header.SetContentType(contentType)
	}
	c.Response.SetStatusCode(consts.StatusOK)
	return c
}

// markdownTestRuntime 构造启用 HTML→Markdown 协商的最小站点运行时。
//
// @param enabled 全局开关取值。
// @return 站点运行时。
func markdownTestRuntime(enabled bool) snapshot.SiteRuntime {
	return snapshot.SiteRuntime{
		Site:                  store.Site{ID: 1},
		Bind:                  ":80",
		HTMLToMarkdownEnabled: enabled,
	}
}

// TestHTMLToMarkdownNegotiationConvertsExplicitlyAcceptedHTML 覆盖验收点：
// Accept: text/markdown 时响应 Content-Type 变为 text/markdown; charset=utf-8，
// 且输出是可读 Markdown（表格、删除线等结构保留）。
func TestHTMLToMarkdownNegotiationConvertsExplicitlyAcceptedHTML(t *testing.T) {
	c := newMarkdownTestContext("text/markdown", "text/html; charset=utf-8")
	rt := markdownTestRuntime(true)

	body, changed, err := transformIdentityResponseBody(c, consts.StatusOK, []byte(markdownTestHTML),
		responseEntityTransformerForSiteAndClient(rt, c, net.IPv4(127, 0, 0, 1)), net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatalf("unexpected transform error: %v", err)
	}
	if !changed {
		t.Fatal("markdown conversion must report the response as changed")
	}
	if got := string(c.Response.Header.ContentType()); got != MarkdownContentType {
		t.Fatalf("content type = %q, want %q", got, MarkdownContentType)
	}
	text := string(body)
	for _, want := range []string{"# 标题", "**加粗**", "[链接](https://example.com)", "- 项目一", "| A | B |", "~~删除~~", "![pic](/x.png)"} {
		if !strings.Contains(text, want) {
			t.Fatalf("markdown output missing %q; got:\n%s", want, text)
		}
	}
	if strings.Contains(text, "<html") || strings.Contains(text, "<h1>") {
		t.Fatalf("markdown output still carries html tags:\n%s", text)
	}
}

// TestHTMLToMarkdownNotTriggeredByWildcardOrHTMLAccept 覆盖验收点：
// `*/*` 与 `text/html` 都不触发转换，响应保持 HTML。
func TestHTMLToMarkdownNotTriggeredByWildcardOrHTMLAccept(t *testing.T) {
	for _, accept := range []string{"*/*", "text/html", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "application/json", ""} {
		t.Run(accept, func(t *testing.T) {
			c := newMarkdownTestContext(accept, "text/html; charset=utf-8")
			rt := markdownTestRuntime(true)

			body, changed, err := transformIdentityResponseBody(c, consts.StatusOK, []byte(markdownTestHTML),
				responseEntityTransformerForSiteAndClient(rt, c, net.IPv4(127, 0, 0, 1)), net.IPv4(127, 0, 0, 1))
			if err != nil {
				t.Fatalf("unexpected transform error: %v", err)
			}
			if changed {
				t.Fatal("response must not be transformed for this Accept value")
			}
			if string(body) != markdownTestHTML {
				t.Fatal("html body must pass through untouched")
			}
			if got := string(c.Response.Header.ContentType()); got != "text/html; charset=utf-8" {
				t.Fatalf("content type = %q, want the original html content type", got)
			}
		})
	}
}

// TestHTMLToMarkdownDisabledByGlobalSwitch 覆盖验收点：全局开关关闭时不转换。
func TestHTMLToMarkdownDisabledByGlobalSwitch(t *testing.T) {
	c := newMarkdownTestContext("text/markdown", "text/html; charset=utf-8")
	rt := markdownTestRuntime(false)

	body, changed, err := transformIdentityResponseBody(c, consts.StatusOK, []byte(markdownTestHTML),
		responseEntityTransformerForSiteAndClient(rt, c, net.IPv4(127, 0, 0, 1)), net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatalf("unexpected transform error: %v", err)
	}
	if changed || string(body) != markdownTestHTML {
		t.Fatal("switch disabled must leave the html response untouched")
	}
}

// TestHTMLToMarkdownSetsVaryAccept 覆盖验收点：转换后的响应设置 Vary: Accept，
// 且与上游已有的 Vary 值合并而非覆盖。
func TestHTMLToMarkdownSetsVaryAccept(t *testing.T) {
	c := newMarkdownTestContext("text/markdown", "text/html; charset=utf-8")
	c.Response.Header.Set("Vary", "Accept-Encoding")
	rt := markdownTestRuntime(true)

	_, changed, err := transformIdentityResponseBody(c, consts.StatusOK, []byte(markdownTestHTML),
		responseEntityTransformerForSiteAndClient(rt, c, net.IPv4(127, 0, 0, 1)), net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatalf("unexpected transform error: %v", err)
	}
	if !changed {
		t.Fatal("expected a converted response")
	}
	if got := string(c.Response.Header.Peek("Vary")); got != "Accept-Encoding, Accept" {
		t.Fatalf("vary = %q, want %q", got, "Accept-Encoding, Accept")
	}
	// Vary: Accept 必须让该响应退出共享缓存（varyDisallowsCaching 只放行 accept-encoding）。
	if !varyDisallowsCaching(string(c.Response.Header.Peek("Vary"))) {
		t.Fatal("Vary: Accept must disqualify the response from the shared cache")
	}
	// Markdown 响应不得被标成动态变体：那会附带 Cache-Control: no-store 与 Vary: Cookie。
	if got := string(c.Response.Header.Peek("Cache-Control")); got != "" {
		t.Fatalf("cache-control = %q, want empty on the markdown path", got)
	}
}

// TestHTMLToMarkdownSetsVaryAcceptWhenAbsent 覆盖 Vary 头缺失时的取值。
func TestHTMLToMarkdownSetsVaryAcceptWhenAbsent(t *testing.T) {
	c := newMarkdownTestContext("text/markdown", "text/html; charset=utf-8")
	rt := markdownTestRuntime(true)

	_, _, err := transformIdentityResponseBody(c, consts.StatusOK, []byte(markdownTestHTML),
		responseEntityTransformerForSiteAndClient(rt, c, net.IPv4(127, 0, 0, 1)), net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatalf("unexpected transform error: %v", err)
	}
	if got := string(c.Response.Header.Peek("Vary")); got != "Accept" {
		t.Fatalf("vary = %q, want %q", got, "Accept")
	}
}

// TestHTMLToMarkdownWinsOverHTMLObfuscation 覆盖验收点：站点启用 HTML 混淆时
// Markdown 优先，输出必须是可读 Markdown 而不是密文；对照组（Accept: text/html）
// 证明该站点确实处于混淆生效状态。
func TestHTMLToMarkdownWinsOverHTMLObfuscation(t *testing.T) {
	challenge.SetChallengeSecret([]byte("markdown-test-secret-32-bytes-ok!!"))
	rt := markdownTestRuntime(true)
	rt.DynamicProtection = dynamic.ProtectionConfig{
		HTMLObfuscationEnabled: true,
		EncryptionKeyBase:      bytes.Repeat([]byte{7}, 32),
	}

	// 对照组：HTML 客户端拿到混淆后的密文。
	htmlCtx := newMarkdownTestContext("text/html", "text/html; charset=utf-8")
	obfuscated, changed, err := transformIdentityResponseBody(htmlCtx, consts.StatusOK, []byte(markdownTestHTML),
		responseEntityTransformerForSiteAndClient(rt, htmlCtx, net.IPv4(127, 0, 0, 1)), net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatalf("unexpected obfuscation error: %v", err)
	}
	if !changed || bytes.Contains(obfuscated, []byte("<h1>")) || bytes.Contains(obfuscated, []byte("# 标题")) {
		t.Fatalf("control group must be obfuscated, got:\n%s", string(obfuscated))
	}

	// 实验组：显式要 Markdown 的客户端拿到明文 Markdown。
	mdCtx := newMarkdownTestContext("text/markdown", "text/html; charset=utf-8")
	mdBody, changed, err := transformIdentityResponseBody(mdCtx, consts.StatusOK, []byte(markdownTestHTML),
		responseEntityTransformerForSiteAndClient(rt, mdCtx, net.IPv4(127, 0, 0, 1)), net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatalf("unexpected transform error: %v", err)
	}
	if !changed {
		t.Fatal("markdown conversion must win over html obfuscation")
	}
	if !strings.Contains(string(mdBody), "# 标题") || !strings.Contains(string(mdBody), "| A | B |") {
		t.Fatalf("markdown must be readable, got:\n%s", string(mdBody))
	}
	if bytes.Equal(mdBody, obfuscated) {
		t.Fatal("markdown output must differ from the obfuscated output")
	}
	if got := string(mdCtx.Response.Header.ContentType()); got != MarkdownContentType {
		t.Fatalf("content type = %q, want %q", got, MarkdownContentType)
	}
}

// TestHTMLToMarkdownShortCircuitsScriptRewriteChain 覆盖验收点：命中 Markdown 时
// 返回的是转换器本体，而不是 dynamic/JS/Lua 的组合变换器（证明短路生效）。
func TestHTMLToMarkdownShortCircuitsScriptRewriteChain(t *testing.T) {
	rt := markdownTestRuntime(true)
	rt.DynamicProtection = dynamic.ProtectionConfig{
		HTMLObfuscationEnabled: true,
		EncryptionKeyBase:      bytes.Repeat([]byte{7}, 32),
	}
	rt.AccessControl = nil

	c := newMarkdownTestContext("text/markdown", "text/html; charset=utf-8")
	transformer := responseEntityTransformerForSiteAndClient(rt, c, net.IPv4(127, 0, 0, 1))
	if _, ok := transformer.(htmlToMarkdownTransformer); !ok {
		t.Fatalf("transformer = %T, want htmlToMarkdownTransformer", transformer)
	}

	// 未协商时仍返回原组合变换器（dynamic 生效），证明短路只在命中时发生。
	plainCtx := newMarkdownTestContext("text/html", "text/html; charset=utf-8")
	if _, ok := responseEntityTransformerForSiteAndClient(rt, plainCtx, net.IPv4(127, 0, 0, 1)).(htmlToMarkdownTransformer); ok {
		t.Fatal("html clients must not receive the markdown transformer")
	}
}

// TestHTMLToMarkdownConversionFailureFallsBackToHTML 覆盖验收点：转换失败时
// 原样直通 HTML，绝不产生 502 网关错误。
func TestHTMLToMarkdownConversionFailureFallsBackToHTML(t *testing.T) {
	original := htmlToMarkdownConvert
	htmlToMarkdownConvert = func([]byte) ([]byte, error) {
		return nil, errors.New("synthetic conversion failure")
	}
	defer func() { htmlToMarkdownConvert = original }()

	c := newMarkdownTestContext("text/markdown", "text/html; charset=utf-8")
	rt := markdownTestRuntime(true)

	body, changed, err := transformIdentityResponseBody(c, consts.StatusOK, []byte(markdownTestHTML),
		responseEntityTransformerForSiteAndClient(rt, c, net.IPv4(127, 0, 0, 1)), net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatalf("conversion failure must not surface as an error: %v", err)
	}
	if changed {
		t.Fatal("failed conversion must leave the response unchanged")
	}
	if string(body) != markdownTestHTML {
		t.Fatal("failed conversion must pass the original html through")
	}
	if got := c.Response.StatusCode(); got != consts.StatusOK {
		t.Fatalf("status = %d, want 200 (never 502 from this path)", got)
	}
	if got := string(c.Response.Header.ContentType()); got != "text/html; charset=utf-8" {
		t.Fatalf("content type = %q, want the original html content type", got)
	}
}

// TestHTMLToMarkdownEmptyConversionFallsBackToHTML 覆盖空结果的降级：
// 转换成功但产出空字符串时同样直通 HTML，避免把响应换成空体。
func TestHTMLToMarkdownEmptyConversionFallsBackToHTML(t *testing.T) {
	original := htmlToMarkdownConvert
	htmlToMarkdownConvert = func([]byte) ([]byte, error) { return nil, nil }
	defer func() { htmlToMarkdownConvert = original }()

	c := newMarkdownTestContext("text/markdown", "text/html; charset=utf-8")
	rt := markdownTestRuntime(true)

	body, changed, err := transformIdentityResponseBody(c, consts.StatusOK, []byte(markdownTestHTML),
		responseEntityTransformerForSiteAndClient(rt, c, net.IPv4(127, 0, 0, 1)), net.IPv4(127, 0, 0, 1))
	if err != nil || changed || string(body) != markdownTestHTML {
		t.Fatalf("empty conversion must pass html through: err=%v changed=%v", err, changed)
	}
}

// TestHTMLToMarkdownSkipsNonHTMLResponses 覆盖验收点：非 HTML 响应不转换。
func TestHTMLToMarkdownSkipsNonHTMLResponses(t *testing.T) {
	for _, ct := range []string{"application/json", "image/png", "text/plain; charset=utf-8", "application/javascript"} {
		t.Run(ct, func(t *testing.T) {
			c := newMarkdownTestContext("text/markdown", ct)
			rt := markdownTestRuntime(true)
			payload := []byte(`{"ok":true}`)

			body, changed, err := transformIdentityResponseBody(c, consts.StatusOK, payload,
				responseEntityTransformerForSiteAndClient(rt, c, net.IPv4(127, 0, 0, 1)), net.IPv4(127, 0, 0, 1))
			if err != nil {
				t.Fatalf("unexpected transform error: %v", err)
			}
			if changed || !bytes.Equal(body, payload) {
				t.Fatal("non-html responses must not be converted")
			}
			if got := string(c.Response.Header.ContentType()); got != ct {
				t.Fatalf("content type = %q, want %q", got, ct)
			}
		})
	}
}

// TestHTMLToMarkdownXHTMLIsConverted 覆盖 application/xhtml+xml：与 isHTMLContentType
// 的既有口径一致，同样参与协商。
func TestHTMLToMarkdownXHTMLIsConverted(t *testing.T) {
	c := newMarkdownTestContext("text/markdown", "application/xhtml+xml")
	rt := markdownTestRuntime(true)

	_, changed, err := transformIdentityResponseBody(c, consts.StatusOK, []byte(markdownTestHTML),
		responseEntityTransformerForSiteAndClient(rt, c, net.IPv4(127, 0, 0, 1)), net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatalf("unexpected transform error: %v", err)
	}
	if !changed {
		t.Fatal("xhtml responses are html and must participate in the negotiation")
	}
}

// TestHTMLToMarkdownRespectsExplicitRejection 覆盖 q=0：显式拒绝压过通配符。
func TestHTMLToMarkdownRespectsExplicitRejection(t *testing.T) {
	for _, accept := range []string{"text/markdown;q=0, text/html", "text/markdown;q=0.000, */*", "text/markdown;q=0"} {
		t.Run(accept, func(t *testing.T) {
			c := newMarkdownTestContext(accept, "text/html; charset=utf-8")
			rt := markdownTestRuntime(true)

			body, changed, err := transformIdentityResponseBody(c, consts.StatusOK, []byte(markdownTestHTML),
				responseEntityTransformerForSiteAndClient(rt, c, net.IPv4(127, 0, 0, 1)), net.IPv4(127, 0, 0, 1))
			if err != nil {
				t.Fatalf("unexpected transform error: %v", err)
			}
			if changed || string(body) != markdownTestHTML {
				t.Fatal("explicit q=0 rejection must not be converted")
			}
		})
	}
}

// TestHTMLToMarkdownAcceptsUppercaseAndParameters 覆盖大小写与参数：
// 媒体类型按 ASCII 大小写不敏感匹配，q 之外的参数被忽略。
func TestHTMLToMarkdownAcceptsUppercaseAndParameters(t *testing.T) {
	for _, accept := range []string{"TEXT/MARKDOWN", "text/markdown; charset=utf-8", "text/html;q=0.9, text/markdown", " text/markdown ; q=0.5"} {
		t.Run(accept, func(t *testing.T) {
			c := newMarkdownTestContext(accept, "text/html; charset=utf-8")
			rt := markdownTestRuntime(true)

			_, changed, err := transformIdentityResponseBody(c, consts.StatusOK, []byte(markdownTestHTML),
				responseEntityTransformerForSiteAndClient(rt, c, net.IPv4(127, 0, 0, 1)), net.IPv4(127, 0, 0, 1))
			if err != nil {
				t.Fatalf("unexpected transform error: %v", err)
			}
			if !changed {
				t.Fatal("explicit markdown accept must convert")
			}
		})
	}
}

// TestHTMLToMarkdownEmptyBodyIsNotConverted 覆盖空响应体：无可转换内容时不动响应。
func TestHTMLToMarkdownEmptyBodyIsNotConverted(t *testing.T) {
	c := newMarkdownTestContext("text/markdown", "text/html; charset=utf-8")
	rt := markdownTestRuntime(true)

	_, changed, err := transformIdentityResponseBody(c, consts.StatusOK, nil,
		responseEntityTransformerForSiteAndClient(rt, c, net.IPv4(127, 0, 0, 1)), net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatalf("unexpected transform error: %v", err)
	}
	if changed {
		t.Fatal("empty bodies must not be converted")
	}
}

// TestParseAcceptMediaTypes 覆盖通用 Accept 解析器：分档存储与 q 值优先级。
func TestParseAcceptMediaTypes(t *testing.T) {
	m := parseAcceptMediaTypes([]byte("text/html, text/markdown;q=0.8, application/json;q=0.5, text/*;q=0.3, */*;q=0.1"))
	if q := m.q("text/html"); q != 1 {
		t.Fatalf("text/html q = %v, want 1", q)
	}
	if q := m.q("text/markdown"); q != 0.8 {
		t.Fatalf("text/markdown q = %v, want 0.8", q)
	}
	if q := m.q("application/json"); q != 0.5 {
		t.Fatalf("application/json q = %v, want 0.5", q)
	}
	// text/xml 只被 text/* 命中。
	if q := m.q("text/xml"); q != 0.3 {
		t.Fatalf("text/xml q = %v, want 0.3", q)
	}
	// application/xml 落到 */*。
	if q := m.q("application/xml"); q != 0.1 {
		t.Fatalf("application/xml q = %v, want 0.1", q)
	}
	// 精确匹配优先于类型通配。
	empty := parseAcceptMediaTypes(nil)
	if q := empty.q("text/markdown"); q != 0 {
		t.Fatalf("empty accept q = %v, want 0", q)
	}
	if empty.explicitlyAccepts("text/markdown") {
		t.Fatal("empty accept must not explicitly accept markdown")
	}
	// 通配符永不构成显式接受。
	wildcardOnly := parseAcceptMediaTypes([]byte("*/*"))
	if wildcardOnly.explicitlyAccepts("text/markdown") {
		t.Fatal("wildcard must not count as an explicit accept")
	}
	// 重复出现时后者覆盖前者。
	dup := parseAcceptMediaTypes([]byte("text/markdown, text/markdown;q=0"))
	if dup.explicitlyAccepts("text/markdown") {
		t.Fatal("later duplicate entry must win")
	}
}

// TestHTMLToMarkdownTransformerForRequiresExplicitAccept 覆盖判定入口：
// 开关、Accept、以及 nil 上下文的边界。
func TestHTMLToMarkdownTransformerForRequiresExplicitAccept(t *testing.T) {
	if htmlToMarkdownTransformerFor(nil, markdownTestRuntime(true)) != nil {
		t.Fatal("nil context must not produce a transformer")
	}
	c := newMarkdownTestContext("text/markdown", "text/html; charset=utf-8")
	if htmlToMarkdownTransformerFor(c, markdownTestRuntime(false)) != nil {
		t.Fatal("disabled switch must not produce a transformer")
	}
	if htmlToMarkdownTransformerFor(c, markdownTestRuntime(true)) == nil {
		t.Fatal("explicit markdown accept with the switch on must produce a transformer")
	}
	c2 := newMarkdownTestContext("*/*", "text/html; charset=utf-8")
	if htmlToMarkdownTransformerFor(c2, markdownTestRuntime(true)) != nil {
		t.Fatal("wildcard accept must not produce a transformer")
	}
}
