package admin

import (
	"context"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"

	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/snapshot"
)

// newMiddlewareCtx 构造带指定 URI 与请求头的上下文。
func newMiddlewareCtx(uri string, headers map[string]string) *app.RequestContext {
	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI(uri)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	return ctx
}

// holderWith 返回持有指定快照的 Holder。
func holderWith(sn *snapshot.Snapshot) *snapshot.Holder {
	h := &snapshot.Holder{}
	h.Store(sn)
	return h
}

// ---- RequireRole ----

func TestRequireRoleDeniesWhenNoRoleSet(t *testing.T) {
	ctx := newMiddlewareCtx("/api/v1/sites", nil)
	RequireRole(auth.RoleAdmin)(context.Background(), ctx)
	if ctx.Response.StatusCode() != 403 {
		t.Fatalf("no role: want 403, got %d", ctx.Response.StatusCode())
	}
}

func TestRequireRoleDeniesInsufficientRole(t *testing.T) {
	ctx := newMiddlewareCtx("/api/v1/sites", nil)
	ctx.Set("auth_role", auth.RoleReadonly)
	RequireRole(auth.RoleAdmin, auth.RoleOperator)(context.Background(), ctx)
	if ctx.Response.StatusCode() != 403 {
		t.Fatalf("readonly against admin/operator route: want 403, got %d", ctx.Response.StatusCode())
	}
}

func TestRequireRoleAllowsMatchingRole(t *testing.T) {
	for _, role := range []string{auth.RoleAdmin, auth.RoleOperator} {
		ctx := newMiddlewareCtx("/api/v1/sites", nil)
		ctx.Set("auth_role", role)
		RequireRole(auth.RoleAdmin, auth.RoleOperator)(context.Background(), ctx)
		if ctx.Response.StatusCode() == 403 {
			t.Errorf("role %q should be allowed, got 403", role)
		}
	}
}

// TestRequireRoleDeniesNonStringRoleValue 验证 auth_role 被写入非字符串时按拒绝处理。
func TestRequireRoleDeniesNonStringRoleValue(t *testing.T) {
	ctx := newMiddlewareCtx("/api/v1/sites", nil)
	ctx.Set("auth_role", 42)
	RequireRole(auth.RoleAdmin)(context.Background(), ctx)
	if ctx.Response.StatusCode() != 403 {
		t.Fatalf("non-string role: want 403, got %d", ctx.Response.StatusCode())
	}
}

// ---- AuthMiddleware 白名单与请求头校验 ----

// TestAuthMiddlewareSkipsWhitelistedPaths 验证健康检查与认证端点不需要 Authorization。
func TestAuthMiddlewareSkipsWhitelistedPaths(t *testing.T) {
	for _, path := range []string{
		"/api/v1/health",
		"/api/v1/auth/login",
		"/api/v1/auth/refresh",
		"/api/v1/auth/logout",
	} {
		ctx := newMiddlewareCtx(path, nil)
		AuthMiddleware(nil, nil, nil)(context.Background(), ctx)
		if ctx.Response.StatusCode() == 401 {
			t.Errorf("whitelisted path %q must not require auth", path)
		}
	}
}

func TestAuthMiddlewareRejectsMissingHeader(t *testing.T) {
	ctx := newMiddlewareCtx("/api/v1/sites", nil)
	AuthMiddleware(nil, nil, nil)(context.Background(), ctx)
	if ctx.Response.StatusCode() != 401 {
		t.Fatalf("missing Authorization: want 401, got %d", ctx.Response.StatusCode())
	}
}

// TestAuthMiddlewareRejectsNonBearerFormat 验证非 Bearer 前缀的凭据被拒绝。
func TestAuthMiddlewareRejectsNonBearerFormat(t *testing.T) {
	for _, header := range []string{
		"Basic dXNlcjpwYXNz",
		"sometoken",
		"bearer lowercase-prefix",
	} {
		ctx := newMiddlewareCtx("/api/v1/sites", map[string]string{"Authorization": header})
		AuthMiddleware(nil, nil, nil)(context.Background(), ctx)
		if ctx.Response.StatusCode() != 401 {
			t.Errorf("header %q: want 401, got %d", header, ctx.Response.StatusCode())
		}
	}
}

// ---- adminRequestProtocol ----

func TestAdminRequestProtocol(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		headers map[string]string
		want    string
	}{
		{"forwarded proto wins", "http://example.com/x", map[string]string{"X-Forwarded-Proto": "https"}, "https"},
		{"forwarded proto lowercased", "http://example.com/x", map[string]string{"X-Forwarded-Proto": "HTTPS"}, "https"},
		{"forwarded h3", "http://example.com/x", map[string]string{"X-Forwarded-Proto": "h3"}, "h3"},
		{"scheme fallback https", "https://example.com/x", nil, "https"},
		{"scheme fallback http", "http://example.com/x", nil, "http"},
	}
	for _, tt := range tests {
		ctx := newMiddlewareCtx(tt.uri, tt.headers)
		if got := adminRequestProtocol(ctx); got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
}

// ---- SecurityHeaders 基础头 ----

func TestSecurityHeadersAlwaysSetsBaselineHeaders(t *testing.T) {
	ctx := newMiddlewareCtx("http://example.com/api/v1/sites", nil)
	SecurityHeaders(nil)(context.Background(), ctx)

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}
	for name, value := range want {
		if got := string(ctx.Response.Header.Peek(name)); got != value {
			t.Errorf("header %s = %q, want %q", name, got, value)
		}
	}
	if csp := string(ctx.Response.Header.Peek("Content-Security-Policy")); csp == "" {
		t.Error("Content-Security-Policy must be set")
	}
}

// TestSecurityHeadersNilHolderSkipsConditionalHeaders 验证无 snapshot 时不写入条件安全头。
func TestSecurityHeadersNilHolderSkipsConditionalHeaders(t *testing.T) {
	ctx := newMiddlewareCtx("https://example.com/api/v1/sites", nil)
	SecurityHeaders(nil)(context.Background(), ctx)

	for _, name := range []string{
		adminXSSHeaderName,
		adminHSTSHeaderName,
		adminHPKPHeaderName,
		adminHPKPReportOnlyHeaderName,
	} {
		if got := string(ctx.Response.Header.Peek(name)); got != "" {
			t.Errorf("nil holder must not set %s, got %q", name, got)
		}
	}
}

// ---- X-XSS-Protection ----

func TestXSSProtectionHeaderWrittenWhenEnabled(t *testing.T) {
	ctx := newMiddlewareCtx("http://example.com/api/v1/sites", nil)
	SecurityHeaders(holderWith(&snapshot.Snapshot{XSSProtectionEnabled: true}))(context.Background(), ctx)
	if got := string(ctx.Response.Header.Peek(adminXSSHeaderName)); got != adminXSSHeaderValue {
		t.Fatalf("%s = %q, want %q", adminXSSHeaderName, got, adminXSSHeaderValue)
	}
}

func TestXSSProtectionHeaderSkippedWhenDisabled(t *testing.T) {
	ctx := newMiddlewareCtx("http://example.com/api/v1/sites", nil)
	SecurityHeaders(holderWith(&snapshot.Snapshot{XSSProtectionEnabled: false}))(context.Background(), ctx)
	if got := string(ctx.Response.Header.Peek(adminXSSHeaderName)); got != "" {
		t.Fatalf("disabled XSS protection must not write header, got %q", got)
	}
}

// TestXSSProtectionHeaderPreservesExistingValue 验证已有值不被覆盖。
func TestXSSProtectionHeaderPreservesExistingValue(t *testing.T) {
	ctx := newMiddlewareCtx("http://example.com/api/v1/sites", nil)
	ctx.Response.Header.Set(adminXSSHeaderName, "0")
	SecurityHeaders(holderWith(&snapshot.Snapshot{XSSProtectionEnabled: true}))(context.Background(), ctx)
	if got := string(ctx.Response.Header.Peek(adminXSSHeaderName)); got != "0" {
		t.Fatalf("existing header must be preserved, got %q", got)
	}
}

// ---- HSTS ----

// TestHSTSHeaderWrittenOnlyOverSecureProtocols 验证 HSTS 仅在 https/h3 下写入。
func TestHSTSHeaderWrittenOnlyOverSecureProtocols(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		headers map[string]string
		want    bool
	}{
		{"https scheme", "https://example.com/x", nil, true},
		{"forwarded https", "http://example.com/x", map[string]string{"X-Forwarded-Proto": "https"}, true},
		{"forwarded h3", "http://example.com/x", map[string]string{"X-Forwarded-Proto": "h3"}, true},
		{"plain http", "http://example.com/x", nil, false},
		{"forwarded http", "https://example.com/x", map[string]string{"X-Forwarded-Proto": "http"}, false},
	}
	for _, tt := range tests {
		ctx := newMiddlewareCtx(tt.uri, tt.headers)
		SecurityHeaders(holderWith(&snapshot.Snapshot{HSTSEnabled: true}))(context.Background(), ctx)
		got := string(ctx.Response.Header.Peek(adminHSTSHeaderName))
		if tt.want && got != adminHSTSHeaderValue {
			t.Errorf("%s: %s = %q, want %q", tt.name, adminHSTSHeaderName, got, adminHSTSHeaderValue)
		}
		if !tt.want && got != "" {
			t.Errorf("%s: %s should be empty, got %q", tt.name, adminHSTSHeaderName, got)
		}
	}
}

func TestHSTSHeaderSkippedWhenDisabled(t *testing.T) {
	ctx := newMiddlewareCtx("https://example.com/api/v1/sites", nil)
	SecurityHeaders(holderWith(&snapshot.Snapshot{HSTSEnabled: false}))(context.Background(), ctx)
	if got := string(ctx.Response.Header.Peek(adminHSTSHeaderName)); got != "" {
		t.Fatalf("disabled HSTS must not write header, got %q", got)
	}
}

// ---- HPKP ----

func TestHPKPHeaderWrittenWhenEnabledOverHTTPS(t *testing.T) {
	ctx := newMiddlewareCtx("https://example.com/api/v1/sites", nil)
	SecurityHeaders(holderWith(&snapshot.Snapshot{
		HPKPEnabled: true,
		HPKPValue:   `pin-sha256="abc"; max-age=5184000`,
	}))(context.Background(), ctx)
	if got := string(ctx.Response.Header.Peek(adminHPKPHeaderName)); got != `pin-sha256="abc"; max-age=5184000` {
		t.Fatalf("%s = %q", adminHPKPHeaderName, got)
	}
}

// TestHPKPHeaderSkippedWhenValueBlank 验证启用但未配置 pin 值时不写空头。
func TestHPKPHeaderSkippedWhenValueBlank(t *testing.T) {
	for _, value := range []string{"", "   "} {
		ctx := newMiddlewareCtx("https://example.com/api/v1/sites", nil)
		SecurityHeaders(holderWith(&snapshot.Snapshot{
			HPKPEnabled: true,
			HPKPValue:   value,
		}))(context.Background(), ctx)
		if got := string(ctx.Response.Header.Peek(adminHPKPHeaderName)); got != "" {
			t.Errorf("blank HPKP value %q must not write header, got %q", value, got)
		}
	}
}

func TestHPKPHeaderSkippedOverPlainHTTP(t *testing.T) {
	ctx := newMiddlewareCtx("http://example.com/api/v1/sites", nil)
	SecurityHeaders(holderWith(&snapshot.Snapshot{
		HPKPEnabled: true,
		HPKPValue:   `pin-sha256="abc"`,
	}))(context.Background(), ctx)
	if got := string(ctx.Response.Header.Peek(adminHPKPHeaderName)); got != "" {
		t.Fatalf("HPKP must not be written over plain http, got %q", got)
	}
}

func TestHPKPReportOnlyHeaderWrittenWhenEnabled(t *testing.T) {
	ctx := newMiddlewareCtx("https://example.com/api/v1/sites", nil)
	SecurityHeaders(holderWith(&snapshot.Snapshot{
		HPKPReportOnlyEnabled: true,
		HPKPReportOnlyValue:   `pin-sha256="xyz"; report-uri="https://example.com/r"`,
	}))(context.Background(), ctx)
	got := string(ctx.Response.Header.Peek(adminHPKPReportOnlyHeaderName))
	if got != `pin-sha256="xyz"; report-uri="https://example.com/r"` {
		t.Fatalf("%s = %q", adminHPKPReportOnlyHeaderName, got)
	}
}

func TestHPKPReportOnlyHeaderSkippedWhenValueBlank(t *testing.T) {
	ctx := newMiddlewareCtx("https://example.com/api/v1/sites", nil)
	SecurityHeaders(holderWith(&snapshot.Snapshot{
		HPKPReportOnlyEnabled: true,
		HPKPReportOnlyValue:   "  ",
	}))(context.Background(), ctx)
	if got := string(ctx.Response.Header.Peek(adminHPKPReportOnlyHeaderName)); got != "" {
		t.Fatalf("blank report-only value must not write header, got %q", got)
	}
}

// TestSecurityHeadersAllEnabledOverHTTPS 验证全部启用时四个条件头同时写入。
func TestSecurityHeadersAllEnabledOverHTTPS(t *testing.T) {
	ctx := newMiddlewareCtx("https://example.com/api/v1/sites", nil)
	SecurityHeaders(holderWith(&snapshot.Snapshot{
		XSSProtectionEnabled:  true,
		HSTSEnabled:           true,
		HPKPEnabled:           true,
		HPKPValue:             `pin-sha256="a"`,
		HPKPReportOnlyEnabled: true,
		HPKPReportOnlyValue:   `pin-sha256="b"`,
	}))(context.Background(), ctx)

	for _, name := range []string{
		adminXSSHeaderName,
		adminHSTSHeaderName,
		adminHPKPHeaderName,
		adminHPKPReportOnlyHeaderName,
	} {
		if got := string(ctx.Response.Header.Peek(name)); got == "" {
			t.Errorf("header %s should be set when enabled over https", name)
		}
	}
}

// ---- splitRefreshCookie ----

func TestSplitRefreshCookie(t *testing.T) {
	tests := []struct {
		in      string
		wantJTI string
		wantRaw string
		wantOK  bool
	}{
		{"jti123:rawtoken", "jti123", "rawtoken", true},
		{"jti:with:colons", "jti", "with:colons", true},
		{":emptyjti", "", "emptyjti", true},
		{"trailing:", "trailing", "", true},
		{"nocolon", "", "", false},
		{"", "", "", false},
	}
	for _, tt := range tests {
		jti, raw, ok := splitRefreshCookie(tt.in)
		if jti != tt.wantJTI || raw != tt.wantRaw || ok != tt.wantOK {
			t.Errorf("splitRefreshCookie(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.in, jti, raw, ok, tt.wantJTI, tt.wantRaw, tt.wantOK)
		}
	}
}

// ---- recordLoginAttempt ----

// TestRecordLoginAttemptNilDBIsNoop 验证 db 为 nil 时静默返回而非 panic。
func TestRecordLoginAttemptNilDBIsNoop(t *testing.T) {
	recordLoginAttempt(nil, "alice", "1.2.3.4", "curl/8.0", false)
}
