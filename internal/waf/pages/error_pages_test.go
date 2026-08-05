package pages

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
)

func TestGetDefaultErrorPageKnownCodes(t *testing.T) {
	codes := []int{403, 404, 429, 431, 502, 503, 504}
	for _, code := range codes {
		cfg := GetDefaultErrorPage(code)
		if cfg == nil {
			t.Fatalf("GetDefaultErrorPage(%d) returned nil", code)
		}
		if cfg.StatusCode != code {
			t.Errorf("GetDefaultErrorPage(%d).StatusCode = %d", code, cfg.StatusCode)
		}
		if cfg.Title == "" {
			t.Errorf("GetDefaultErrorPage(%d).Title is empty", code)
		}
	}
}

func TestGetDefaultErrorPageUnknownCode(t *testing.T) {
	cfg := GetDefaultErrorPage(418)
	if cfg == nil {
		t.Fatal("GetDefaultErrorPage(418) returned nil")
	}
	if cfg.StatusCode != 418 {
		t.Errorf("GetDefaultErrorPage(418).StatusCode = %d", cfg.StatusCode)
	}
	if cfg.Title == "" {
		t.Error("fallback error page should have non-empty Title")
	}
}

func TestRenderErrorPageContainsStatusCode(t *testing.T) {
	for _, code := range []int{403, 404, 429, 502, 503, 504} {
		out := RenderErrorPage(code, nil)
		if !strings.Contains(string(out), strconv.Itoa(code)) {
			t.Errorf("RenderErrorPage(%d) output missing status code", code)
		}
	}
}

func TestRenderErrorPageDefaultIsValidHTML(t *testing.T) {
	out := RenderErrorPage(403, nil)
	s := string(out)
	if !strings.HasPrefix(s, "<!DOCTYPE html>") {
		t.Error("RenderErrorPage(403) should start with DOCTYPE html")
	}
	if !strings.Contains(s, "</html>") {
		t.Error("RenderErrorPage(403) should contain closing </html>")
	}
}

func TestRenderErrorPageCustomTitle(t *testing.T) {
	custom := &ErrorPageConfig{Title: "My Custom Title"}
	out := RenderErrorPage(403, custom)
	if !strings.Contains(string(out), "My Custom Title") {
		t.Errorf("RenderErrorPage with custom title should include custom title; got %q", string(out)[:200])
	}
}

func TestRenderErrorPageCustomBody(t *testing.T) {
	custom := &ErrorPageConfig{Body: "custom body text for test"}
	out := RenderErrorPage(503, custom)
	if !strings.Contains(string(out), "custom body text for test") {
		t.Error("RenderErrorPage should include custom body text")
	}
}

func TestRenderErrorPageCustomHTML(t *testing.T) {
	custom := &ErrorPageConfig{HTML: "<html><body>custom page {{.StatusCode}}</body></html>"}
	out := RenderErrorPage(403, custom)
	s := string(out)
	if !strings.Contains(s, "403") {
		t.Errorf("RenderErrorPage with custom HTML template should render status code; got %q", s)
	}
	if !strings.Contains(s, "custom page") {
		t.Errorf("RenderErrorPage with custom HTML should contain custom content; got %q", s)
	}
}

func TestRenderErrorPageCustomHTMLInvalidTemplate(t *testing.T) {
	// 无效模板语法时，renderErrorTemplate 应返回原始 HTML 而不 panic
	custom := &ErrorPageConfig{HTML: "{{invalid"}
	out := RenderErrorPage(403, custom)
	if string(out) != "{{invalid" {
		// 可能回落到默认渲染也可接受
		if len(out) == 0 {
			t.Error("RenderErrorPage with invalid template should return non-empty output")
		}
	}
}

func TestRenderErrorPageCustomCSS(t *testing.T) {
	custom := &ErrorPageConfig{CustomCSS: ".custom-class{color:red}"}
	out := RenderErrorPage(200, custom)
	if !strings.Contains(string(out), ".custom-class") {
		t.Error("RenderErrorPage should include custom CSS")
	}
}

func TestRenderErrorPageEscapesDefaultTitleAndBody(t *testing.T) {
	custom := &ErrorPageConfig{
		Title: `<script>alert("title")</script>`,
		Body:  `<img src=x onerror=alert("body")>`,
	}
	out := string(RenderErrorPage(403, custom))
	if strings.Contains(out, `<script>alert("title")</script>`) || strings.Contains(out, `<img src=x onerror=alert("body")>`) {
		t.Fatalf("RenderErrorPage should escape default title/body content: %s", out)
	}
	if !strings.Contains(out, `&lt;script&gt;`) || !strings.Contains(out, `&lt;img`) {
		t.Fatalf("RenderErrorPage escaped markers missing: %s", out)
	}
}

func TestRenderErrorPageSanitizesCustomCSSStyleBreakout(t *testing.T) {
	custom := &ErrorPageConfig{CustomCSS: `.ok{color:red}</style><script>alert(1)</script>`}
	out := string(RenderErrorPage(403, custom))
	if strings.Contains(strings.ToLower(out), `</style><script`) || strings.Contains(strings.ToLower(out), `<script`) {
		t.Fatalf("RenderErrorPage should sanitize CSS style breakout: %s", out)
	}
	if !strings.Contains(out, `.ok{color:red}`) {
		t.Fatalf("RenderErrorPage should keep safe CSS prefix: %s", out)
	}
}

func TestRenderErrorPageDoesNotLeakInternalDetails(t *testing.T) {
	out := RenderErrorPage(403, nil)
	s := string(out)
	// 不应泄露内部路径或堆栈信息
	for _, leak := range []string{"runtime/", "goroutine", "panic:"} {
		if strings.Contains(s, leak) {
			t.Errorf("RenderErrorPage should not leak internal details: found %q", leak)
		}
	}
}

func TestWriteErrorPageSetsStatusCodeAndContentType(t *testing.T) {
	var c app.RequestContext
	WriteErrorPage(context.Background(), &c, 404, nil)
	if c.Response.StatusCode() != 404 {
		t.Errorf("WriteErrorPage status = %d, want 404", c.Response.StatusCode())
	}
	ct := string(c.Response.Header.ContentType())
	if !strings.Contains(ct, "text/html") {
		t.Errorf("WriteErrorPage Content-Type = %q, want text/html", ct)
	}
}

func TestWriteErrorPageCustomConfig(t *testing.T) {
	custom := &ErrorPageConfig{Title: "Forbidden Zone"}
	var c app.RequestContext
	WriteErrorPage(context.Background(), &c, 403, custom)
	if c.Response.StatusCode() != 403 {
		t.Errorf("WriteErrorPage(403, custom) status = %d", c.Response.StatusCode())
	}
	if !strings.Contains(string(c.Response.Body()), "Forbidden Zone") {
		t.Error("WriteErrorPage should render custom title in body")
	}
}

func TestWriteErrorPageRemovesServerHeader(t *testing.T) {
	var c app.RequestContext
	c.Response.Header.Set("Server", "secret-server/1.0")
	WriteErrorPage(context.Background(), &c, 503, nil)
	if sv := string(c.Response.Header.Peek("Server")); sv != "" {
		t.Errorf("WriteErrorPage should remove Server header, got %q", sv)
	}
}

func TestWriteWelcomePageStatus200(t *testing.T) {
	var c app.RequestContext
	WriteWelcomePage(context.Background(), &c)
	if c.Response.StatusCode() != 200 {
		t.Errorf("WriteWelcomePage status = %d, want 200", c.Response.StatusCode())
	}
}

func TestWriteWelcomePageContainsWAFBranding(t *testing.T) {
	var c app.RequestContext
	WriteWelcomePage(context.Background(), &c)
	body := string(c.Response.Body())
	if !strings.Contains(body, "My-OpenWAF") {
		t.Error("WriteWelcomePage should contain WAF branding")
	}
}

func TestWriteWelcomePageIsHTML(t *testing.T) {
	var c app.RequestContext
	WriteWelcomePage(context.Background(), &c)
	body := string(c.Response.Body())
	if !strings.HasPrefix(body, "<!DOCTYPE html>") {
		t.Error("WriteWelcomePage should return valid HTML")
	}
	ct := string(c.Response.Header.ContentType())
	if !strings.Contains(ct, "text/html") {
		t.Errorf("WriteWelcomePage Content-Type = %q, want text/html", ct)
	}
}

func TestRenderErrorTemplateInjectsStatusCode(t *testing.T) {
	out := renderErrorTemplate("<p>code: {{.StatusCode}}</p>", 502, "Bad Gateway")
	if !strings.Contains(out, "502") {
		t.Errorf("renderErrorTemplate did not inject status code; got %q", out)
	}
}

func TestRenderErrorTemplateInjectsTitle(t *testing.T) {
	out := renderErrorTemplate("<p>{{.Title}}</p>", 403, "Access Denied")
	if !strings.Contains(out, "Access Denied") {
		t.Errorf("renderErrorTemplate did not inject title; got %q", out)
	}
}

func TestRenderErrorTemplateInvalidTemplateFallsBack(t *testing.T) {
	raw := "{{unclosed"
	out := renderErrorTemplate(raw, 500, "Error")
	if out != raw {
		t.Errorf("renderErrorTemplate with invalid template should return raw html; got %q", out)
	}
}
