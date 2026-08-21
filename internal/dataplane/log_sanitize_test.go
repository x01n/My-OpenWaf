package dataplane

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"My-OpenWaf/internal/observability"
	"My-OpenWaf/internal/store"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type panicResponseBodyReader struct{}

func (panicResponseBodyReader) Read(_ []byte) (int, error) {
	panic("response body stream should not be read")
}

func TestSanitizeQueryStringRedactsSensitiveValues(t *testing.T) {
	got := sanitizeQueryString("page=1&token=abc123&password=secret&name=alice")
	if strings.Contains(got, "abc123") || strings.Contains(got, "secret") {
		t.Fatalf("sensitive query values leaked: %s", got)
	}
	if !strings.Contains(got, "token=%5Bredacted%5D") || !strings.Contains(got, "password=%5Bredacted%5D") {
		t.Fatalf("sensitive query values were not redacted: %s", got)
	}
	if !strings.Contains(got, "name=alice") {
		t.Fatalf("non-sensitive query value should be preserved: %s", got)
	}
}

func TestSanitizeQueryStringRedactsMalformedEncodedSensitiveKey(t *testing.T) {
	got := sanitizeQueryString("pass%77ord=secret&bad=%zz")
	if strings.Contains(got, "secret") {
		t.Fatalf("malformed query leaked sensitive value: %s", got)
	}
	if got != "[redacted]" {
		t.Fatalf("malformed query = %q, want [redacted]", got)
	}
}

func TestRequestBodyPreviewRedactsJSONAndFormSecrets(t *testing.T) {
	jsonCtx := app.NewContext(0)
	jsonCtx.Request.Header.Set("Content-Type", "application/json")
	jsonCtx.Request.SetBody([]byte(`{"username":"alice","password":"secret","nested":{"api_key":"token"}}`))
	preview, _, _ := requestBodyPreview(jsonCtx)
	if strings.Contains(preview, "secret") || strings.Contains(preview, "token") {
		t.Fatalf("json body secret leaked: %s", preview)
	}
	if !strings.Contains(preview, `"password":"[redacted]"`) || !strings.Contains(preview, `"api_key":"[redacted]"`) {
		t.Fatalf("json body secrets were not redacted: %s", preview)
	}

	formCtx := app.NewContext(0)
	formCtx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	formCtx.Request.SetBody([]byte("username=alice&password=secret&token=token"))
	preview, _, _ = requestBodyPreview(formCtx)
	if strings.Contains(preview, "secret") || strings.Contains(preview, "token=token") {
		t.Fatalf("form body secret leaked: %s", preview)
	}
	if got := sanitizeQueryString("pass%77ord=secret&bad=%zz"); got != "[redacted]" {
		t.Fatalf("malformed form = %q, want [redacted]", got)
	}
}

func TestRequestBodyPreviewRedactsHeaderLikePlaintext(t *testing.T) {
	body := "Authorization: Bearer auth-secret\r\n continuation-secret\r\n" +
		"Proxy-Authorization: Basic proxy-secret\r\n" +
		"Cookie: sid=cookie-secret\r\n" +
		"Set-Cookie: refresh=response-secret; HttpOnly\r\n"
	cases := []struct {
		name        string
		contentType string
		body        string
		truncated   bool
	}{
		{name: "plain text", contentType: "text/plain", body: body},
		{name: "malformed JSON", contentType: "application/json", body: "{\"unterminated\":\n" + body},
		{name: "truncated", contentType: "text/plain", body: body + strings.Repeat("x", logBodyPreviewLimit), truncated: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := app.NewContext(0)
			ctx.Request.Header.Set("Content-Type", tc.contentType)
			ctx.Request.SetBody([]byte(tc.body))

			preview, truncated, _ := requestBodyPreview(ctx)
			if truncated != tc.truncated {
				t.Fatalf("truncated = %v, want %v", truncated, tc.truncated)
			}
			for _, secret := range []string{"auth-secret", "continuation-secret", "proxy-secret", "cookie-secret", "response-secret"} {
				if strings.Contains(preview, secret) {
					t.Fatalf("request body preview leaked %q: %s", secret, preview)
				}
			}
			for _, field := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie"} {
				if !strings.Contains(preview, field+": [redacted]") {
					t.Fatalf("request body preview did not retain redacted %s field: %s", field, preview)
				}
			}
		})
	}
}

func TestRequestBodyPreviewRedactsMalformedNestedEnv(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		truncated bool
	}{
		{
			name: "malformed JSON",
			body: `{"env":{"nested":"env-secret"}`,
		},
		{
			name:      "truncated JSON",
			body:      `{"env":{"nested":"env-secret"},` + strings.Repeat("x", logBodyPreviewLimit),
			truncated: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := app.NewContext(0)
			ctx.Request.Header.Set("Content-Type", "application/json")
			ctx.Request.SetBody([]byte(tc.body))

			preview, truncated, _ := requestBodyPreview(ctx)
			if truncated != tc.truncated {
				t.Fatalf("truncated = %v, want %v", truncated, tc.truncated)
			}
			if strings.Contains(preview, "env-secret") {
				t.Fatalf("malformed JSON leaked nested env secret: %s", preview)
			}
			if !strings.Contains(preview, "[redacted]") {
				t.Fatalf("malformed JSON did not contain redaction marker: %s", preview)
			}
		})
	}
}

func TestDynamicProtectionRequestBodyPreviewRedactsTicketKeyAndEnv(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetRequestURI(dynamicProtectionKeyPath)
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.SetBody([]byte(`{"ticket":"ticket-secret","key":"key-secret","env":{"nested":{"fingerprint":"env-secret"}},"票据":"unicode-secret"}`))

	preview, truncated, size := requestBodyPreview(ctx)
	if preview != "[redacted]" {
		t.Fatalf("dynamic protection request body was not redacted as a whole: %s", preview)
	}
	if truncated {
		t.Fatal("short dynamic protection request body should not be marked truncated")
	}
	if size != int64(len(ctx.Request.Body())) {
		t.Fatalf("request body size = %d, want %d", size, len(ctx.Request.Body()))
	}
	for _, secret := range []string{"ticket-secret", "key-secret", "env-secret", "unicode-secret"} {
		if strings.Contains(preview, secret) {
			t.Fatalf("dynamic protection secret leaked in request body preview: %s", preview)
		}
	}
}

func TestDynamicProtectionMalformedRequestBodyPreviewRedactsTicketAndEnv(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetRequestURI(dynamicProtectionKeyPath)
	ctx.Request.Header.Set("Content-Type", "text/plain")
	ctx.Request.SetBody([]byte(`{"ticket":"ticket-secret","env":{"nested":"env-secret"}`))

	preview, truncated, _ := requestBodyPreview(ctx)
	if preview != "[redacted]" {
		t.Fatalf("dynamic protection body with unexpected content type was not redacted as a whole: %s", preview)
	}
	if truncated {
		t.Fatal("malformed dynamic protection request body should not be marked truncated")
	}
	for _, secret := range []string{"ticket-secret", "env-secret"} {
		if strings.Contains(preview, secret) {
			t.Fatalf("malformed dynamic protection secret leaked: %s", preview)
		}
	}
}

func TestRecordDynamicProtectionAccessLogPersistsRedactedBody(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetRequestURI(dynamicProtectionKeyPath)
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.SetBody([]byte(`{"ticket":"ticket-secret","key":"key-secret","env":{"fingerprint":"env-secret"}}`))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.AccessLog{}); err != nil {
		t.Fatalf("migrate access logs: %v", err)
	}

	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	recordAccessLog(ctx, Options{Writer: writer}, accessLogInfo{
		SiteID:     1,
		WAFAction:  "dynamic_key_error",
		StatusCode: 400,
	})
	writer.Close()

	var entry store.AccessLog
	if err := db.First(&entry).Error; err != nil {
		t.Fatalf("load access log: %v", err)
	}
	if entry.RequestBodyPreview != "[redacted]" {
		t.Fatalf("persisted dynamic protection request body was not redacted as a whole: %s", entry.RequestBodyPreview)
	}
	for _, secret := range []string{"ticket-secret", "key-secret", "env-secret"} {
		if strings.Contains(entry.RequestBodyPreview, secret) {
			t.Fatalf("persisted request body preview leaked %q: %s", secret, entry.RequestBodyPreview)
		}
	}
}

func TestRecordAccessLogRedactsHeaderLikePlaintextBody(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.Header.Set("Content-Type", "text/plain")
	ctx.Request.SetBody([]byte("Authorization: Bearer auth-secret\r\nCookie: sid=cookie-secret\r\n"))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.AccessLog{}); err != nil {
		t.Fatalf("migrate access logs: %v", err)
	}

	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	recordAccessLog(ctx, Options{Writer: writer}, accessLogInfo{
		SiteID:     1,
		WAFAction:  "intercept",
		StatusCode: 403,
	})
	writer.Close()

	var entry store.AccessLog
	if err := db.First(&entry).Error; err != nil {
		t.Fatalf("load access log: %v", err)
	}
	for _, secret := range []string{"auth-secret", "cookie-secret"} {
		if strings.Contains(entry.RequestBodyPreview, secret) {
			t.Fatalf("persisted request body preview leaked %q: %s", secret, entry.RequestBodyPreview)
		}
	}
	for _, field := range []string{"Authorization", "Cookie"} {
		if !strings.Contains(entry.RequestBodyPreview, field+": [redacted]") {
			t.Fatalf("persisted request body preview did not retain redacted %s field: %s", field, entry.RequestBodyPreview)
		}
	}
}

func TestRecordSecurityEventRedactsHeaderLikePlaintextBody(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.SetBody([]byte("{\"unterminated\":\nAuthorization: Bearer auth-secret\r\nSet-Cookie: refresh=response-secret\r\n"))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SecurityEvent{}); err != nil {
		t.Fatalf("migrate security events: %v", err)
	}

	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	recordSecurityEvent(ctx, Options{Writer: writer}, store.SecurityEvent{
		SiteID:     1,
		Action:     "intercept",
		StatusCode: 403,
	})
	writer.Close()

	var entry store.SecurityEvent
	if err := db.First(&entry).Error; err != nil {
		t.Fatalf("load security event: %v", err)
	}
	for _, secret := range []string{"auth-secret", "response-secret"} {
		if strings.Contains(entry.RequestBodyPreview, secret) {
			t.Fatalf("persisted security-event body preview leaked %q: %s", secret, entry.RequestBodyPreview)
		}
	}
	for _, field := range []string{"Authorization", "Set-Cookie"} {
		if !strings.Contains(entry.RequestBodyPreview, field+": [redacted]") {
			t.Fatalf("persisted security-event body preview did not retain redacted %s field: %s", field, entry.RequestBodyPreview)
		}
	}
}

func TestRecordSecurityEventRedactsPrefilledHeaderLikePlaintext(t *testing.T) {
	ctx := app.NewContext(0)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SecurityEvent{}); err != nil {
		t.Fatalf("migrate security events: %v", err)
	}

	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	recordSecurityEvent(ctx, Options{Writer: writer}, store.SecurityEvent{
		SiteID:             1,
		Action:             "intercept",
		StatusCode:         403,
		RequestHeaders:     `{"Authorization":"Bearer header-secret"}`,
		RequestBodyPreview: "Proxy-Authorization: Basic proxy-secret\r\n",
		RequestSize:        1,
	})
	writer.Close()

	var entry store.SecurityEvent
	if err := db.First(&entry).Error; err != nil {
		t.Fatalf("load security event: %v", err)
	}
	for _, secret := range []string{"header-secret", "proxy-secret"} {
		if strings.Contains(entry.RequestHeaders, secret) || strings.Contains(entry.RequestBodyPreview, secret) {
			t.Fatalf("prefilled security-event fields leaked %q: %+v", secret, entry)
		}
	}
}

func TestDynamicProtectionTruncatedJSONRequestBodyPreviewRedactsWholeBody(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetRequestURI(dynamicProtectionKeyPath)
	ctx.Request.Header.Set("Content-Type", "application/json")
	body := `{"ticket":"ticket-secret","key":"key-secret","env":{"nested":"env-secret"},` + strings.Repeat("x", logBodyPreviewLimit)
	ctx.Request.SetBody([]byte(body))

	preview, truncated, size := requestBodyPreview(ctx)
	if preview != "[redacted]" {
		t.Fatalf("truncated dynamic protection JSON was not redacted as a whole: %s", preview)
	}
	if !truncated {
		t.Fatal("oversized dynamic protection request body should be marked truncated")
	}
	if size != int64(len(body)) {
		t.Fatalf("request body size = %d, want %d", size, len(body))
	}
	for _, secret := range []string{"ticket-secret", "key-secret", "env-secret"} {
		if strings.Contains(preview, secret) {
			t.Fatalf("truncated dynamic protection secret leaked: %s", preview)
		}
	}
}

func TestBuildAccessLogEntryRedactsPrefilledDynamicProtectionBody(t *testing.T) {
	ctx := app.NewContext(0)
	entry := buildAccessLogEntry(ctx, accessLogInfo{
		Path:               dynamicProtectionKeyPath,
		RequestBodyPreview: `{"ticket":"ticket-secret","key":"key-secret","env":{"nested":"env-secret"}}`,
		RequestSize:        1,
		WAFAction:          "dynamic_key_error",
		StatusCode:         400,
	})
	if entry.RequestBodyPreview != "[redacted]" {
		t.Fatalf("prefilled dynamic protection request body was not redacted as a whole: %s", entry.RequestBodyPreview)
	}
}

func TestBuildAccessLogEntryRedactsPrefilledHeaderLikePlaintext(t *testing.T) {
	ctx := app.NewContext(0)
	entry := buildAccessLogEntry(ctx, accessLogInfo{
		RequestBodyPreview: "Authorization: Bearer auth-secret\r\nCookie: sid=cookie-secret\r\n",
		RequestHeaders:     `{"Authorization":"Bearer header-secret"}`,
		ResponseHeaders:    `{"Set-Cookie":"refresh=response-secret"}`,
		RequestSize:        1,
	})
	for _, secret := range []string{"auth-secret", "cookie-secret", "header-secret", "response-secret"} {
		if strings.Contains(entry.RequestBodyPreview, secret) || strings.Contains(entry.RequestHeaders, secret) || strings.Contains(entry.ResponseHeaders, secret) {
			t.Fatalf("prefilled access-log fields leaked %q: %+v", secret, entry)
		}
	}
}

func TestRecordAccessLogDoesNotPersistUpstreamUserinfo(t *testing.T) {
	ctx := app.NewContext(0)
	const upstream = "https://upstream-user:upstream-password@origin.example.test:9443/base?x=1"

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.AccessLog{}); err != nil {
		t.Fatalf("migrate access logs: %v", err)
	}

	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	recordAccessLog(ctx, Options{Writer: writer}, accessLogInfo{
		SiteID:     1,
		Upstream:   upstream,
		WAFAction:  "intercept",
		StatusCode: 403,
	})
	writer.Close()

	var entry store.AccessLog
	if err := db.First(&entry).Error; err != nil {
		t.Fatalf("load access log: %v", err)
	}
	if got, want := entry.Upstream, "https://origin.example.test:9443/base?x=1"; got != want {
		t.Fatalf("persisted upstream = %q, want %q", got, want)
	}
	for _, secret := range []string{"upstream-user", "upstream-password"} {
		if strings.Contains(entry.Upstream, secret) {
			t.Fatalf("persisted upstream leaked %q: %q", secret, entry.Upstream)
		}
	}
}

func TestRequestHeadersJSONRedactsSensitiveHeadersAndTruncates(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.Header.Set("Authorization", "Bearer secret")
	ctx.Request.Header.Set("X-CSRF-Token", "csrf-token")
	ctx.Request.Header.Set("X-Trace", strings.Repeat("a", logHeaderValueLimit+16))

	got := requestHeadersJSON(ctx)
	if strings.Contains(got, "secret") || strings.Contains(got, "csrf-token") {
		t.Fatalf("sensitive header leaked: %s", got)
	}
	if !strings.Contains(got, "[redacted]") {
		t.Fatalf("sensitive headers were not redacted: %s", got)
	}
	if !strings.Contains(got, "...[truncated]") {
		t.Fatalf("large header was not truncated: %s", got)
	}
}

func TestResponseHeadersJSONRedactsSensitiveHeadersAndTruncates(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Response.Header.Set("Set-Cookie", "sid=secret")
	ctx.Response.Header.Set("X-Session-ID", "sid")
	ctx.Response.Header.Set("X-Trace", strings.Repeat("b", logHeaderValueLimit+16))

	got := responseHeadersJSON(ctx)
	if strings.Contains(got, "secret") || strings.Contains(got, "sid") {
		t.Fatalf("sensitive response header leaked: %s", got)
	}
	if !strings.Contains(got, "[redacted]") {
		t.Fatalf("sensitive response headers were not redacted: %s", got)
	}
	if !strings.Contains(got, "...[truncated]") {
		t.Fatalf("large response header was not truncated: %s", got)
	}
}

func TestRequestHeadersSnapshotSharesOrderAndJSON(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.Header.Add("X-First", "one")
	ctx.Request.Header.Add("Authorization", "Bearer secret")
	ctx.Request.Header.Add("X-First", "two")

	order := requestHeaderOrder(ctx)
	if len(order) != 3 {
		t.Fatalf("requestHeaderOrder() length = %d want 3", len(order))
	}
	if order[0] != "X-First" || order[1] != "Authorization" || order[2] != "X-First" {
		t.Fatalf("requestHeaderOrder() = %#v", order)
	}

	got := requestHeadersJSON(ctx)
	if strings.Contains(got, "secret") {
		t.Fatalf("sensitive header leaked: %s", got)
	}
	if !strings.Contains(got, `[redacted]`) {
		t.Fatalf("sensitive header was not redacted: %s", got)
	}
	if !strings.Contains(got, `"X-First"`) {
		t.Fatalf("expected header key missing from json: %s", got)
	}
}
func TestBuildAccessLogEntrySkipsDetailedFieldsForSampledPass(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.Header.Set("Authorization", "Bearer secret")
	ctx.Request.SetBody([]byte(`{"password":"secret"}`))
	ctx.Response.Header.Set("Set-Cookie", "sid=secret")

	entry := buildAccessLogEntry(ctx, accessLogInfo{SiteID: 1, WAFAction: "none", StatusCode: 200})
	if entry.RequestHeaders != "" || entry.RequestBodyPreview != "" || entry.ResponseHeaders != "" || entry.RequestSize != 0 {
		t.Fatalf("sampled pass access log should skip detailed fields: %+v", entry)
	}
}

func TestBuildAccessLogEntryKeepsDetailedFieldsForBlockedRequest(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.Header.Set("Authorization", "Bearer secret")
	ctx.Request.SetBody([]byte(`{"password":"secret"}`))

	entry := buildAccessLogEntry(ctx, accessLogInfo{SiteID: 1, WAFAction: "intercept", StatusCode: 403, Detailed: true})
	if entry.RequestHeaders == "" || entry.RequestBodyPreview == "" || entry.RequestSize == 0 {
		t.Fatalf("blocked access log should keep detailed fields: %+v", entry)
	}
}

func TestBuildAccessLogEntryUsesResponseBodyLengthWhenMissing(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Response.SetBody([]byte("blocked"))

	entry := buildAccessLogEntry(ctx, accessLogInfo{SiteID: 1, WAFAction: "intercept", StatusCode: 403, Detailed: true})
	if entry.ResponseSize != int64(len("blocked")) {
		t.Fatalf("response_size = %d want %d", entry.ResponseSize, len("blocked"))
	}
}

func TestBuildAccessLogEntryUsesStreamContentLengthWithoutReadingBody(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Response.SetBodyStream(panicResponseBodyReader{}, 16)

	entry := buildAccessLogEntry(ctx, accessLogInfo{SiteID: 1, WAFAction: "intercept", StatusCode: 403, Detailed: true})
	if entry.ResponseSize != 16 {
		t.Fatalf("response_size = %d want %d", entry.ResponseSize, 16)
	}
}

func TestShouldRecordAccessLogSupportsZeroSamplingDisable(t *testing.T) {
	if shouldRecordAccessLog(accessLogInfo{WAFAction: "none", StatusCode: 200}, 0) {
		t.Fatal("sampled pass access log should be disabled when rate is zero")
	}
	if !shouldRecordAccessLog(accessLogInfo{WAFAction: "intercept", StatusCode: 403}, 0) {
		t.Fatal("blocked access log should still be recorded when sampling is disabled")
	}
}

// TestIsClientGoneForPlainAccessLogOnlySkipsPlainPass 守护「客户端断开跳过访问日志」的边界。
//
// 采样率默认为 1 后，客户端在响应交付途中 RST_STREAM 的请求会带着上游给的 200 走到
// 代理完成记录点。跳过它是为了不虚增流量，但这个跳过绝不能扩大到 observe：那是误报
// 排查的唯一依据。intercept/challenge/drop 走别的记录点，此处一并断言不受影响。
func TestIsClientGoneForPlainAccessLogOnlySkipsPlainPass(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	if !isClientGoneForPlainAccessLog(canceled, "none") {
		t.Fatal("客户端已断开的正常访问应跳过记录")
	}
	for _, act := range []string{"observe", "intercept", "challenge", "drop", "redirect"} {
		if isClientGoneForPlainAccessLog(canceled, act) {
			t.Errorf("waf_action=%q 即使客户端断开也必须记录", act)
		}
	}
	if isClientGoneForPlainAccessLog(context.Background(), "none") {
		t.Fatal("客户端未断开的正常访问必须记录")
	}
	if isClientGoneForPlainAccessLog(nil, "none") {
		t.Fatal("ctx 为 nil 时不得跳过记录")
	}
}

func TestRecordAccessLogRecordsSampledPassWithoutDetailedFields(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Response.SetBodyStream(strings.NewReader("ok"), 2)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.AccessLog{}); err != nil {
		t.Fatalf("migrate access logs: %v", err)
	}

	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	recordAccessLog(ctx, Options{Writer: writer, AccessLogSamplingRate: 1}, accessLogInfo{
		SiteID:     1,
		WAFAction:  "none",
		StatusCode: 200,
	})
	writer.Close()

	var entry store.AccessLog
	if err := db.First(&entry).Error; err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if entry.SiteID != 1 || entry.StatusCode != 200 {
		t.Fatalf("access log = %+v, want normal 2xx request", entry)
	}
	if entry.RequestHeaders != "" || entry.RequestBodyPreview != "" || entry.ResponseHeaders != "" {
		t.Fatalf("normal pass should not retain detailed fields: %+v", entry)
	}
}

func TestRecordAccessLogSkipsResponseBodyReadWhenPassSamplingDisabled(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Response.SetBodyStream(panicResponseBodyReader{}, 16)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.AccessLog{}); err != nil {
		t.Fatalf("migrate access logs: %v", err)
	}

	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	recordAccessLog(ctx, Options{Writer: writer, AccessLogSamplingRate: 0}, accessLogInfo{
		SiteID:     1,
		WAFAction:  "none",
		StatusCode: 200,
	})
	writer.Close()

	var count int64
	if err := db.Model(&store.AccessLog{}).Count(&count).Error; err != nil {
		t.Fatalf("count access logs: %v", err)
	}
	if count != 0 {
		t.Fatalf("recorded access logs = %d want 0", count)
	}
}

func TestShouldRecordDetailedSecurityEventOnlyForTerminal(t *testing.T) {
	if shouldRecordDetailedSecurityEvent(store.SecurityEvent{Action: "observe", StatusCode: 200}) {
		t.Fatal("observe event should skip detailed fields on hot path")
	}
	if !shouldRecordDetailedSecurityEvent(store.SecurityEvent{Action: "intercept", StatusCode: 403}) {
		t.Fatal("terminal intercept event should keep detailed fields")
	}
	if !shouldRecordDetailedSecurityEvent(store.SecurityEvent{Action: "observe", StatusCode: 500}) {
		t.Fatal("error status event should keep detailed fields")
	}
}
