package dataplane

import (
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
	formCtx.Request.SetBody([]byte("username=alice&csrf=nonce&session_id=sid"))
	preview, _, _ = requestBodyPreview(formCtx)
	if strings.Contains(preview, "nonce") || strings.Contains(preview, "sid") {
		t.Fatalf("form body secret leaked: %s", preview)
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
