package dataplane

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/observability"
	"My-OpenWaf/internal/store"
)

/**
 * 缓存槽移除后，无 reqCtx 可用的记录点回退到 requestHeaderOrder（VisitAll）
 * 枚举。本测试锁定该回退的 HeaderOrder 输出字节不变，且访问日志与安全事件
 * 共享同一顺序字符串（两条路径各自枚举一次，值必须一致）。
 */
func TestHeaderOrderFallbackSharedBetweenAccessAndSecurity(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.Default())

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/order-eq")
	ctx.Request.Header.SetHost("order.example")
	ctx.Request.Header.Set("X-B", "1")
	ctx.Request.Header.Set("X-A", "2")

	recordSecurityEvent(ctx, Options{Writer: writer}, store.SecurityEvent{
		SiteID: 1, RequestID: "order-eq", ClientIP: "127.0.0.1", Host: "order.example",
		Path: "/order-eq", Method: http.MethodGet, UserAgent: "order-eq-test",
		RuleIDStr: "owasp:sqli:001", Phase: "owasp_default", Action: "intercept",
		Category: "sqli", MatchDesc: "SQL injection signals", StatusCode: 403,
	})
	recordAccessLog(ctx, Options{Writer: writer}, accessLogInfo{
		SiteID: 1, RequestID: "order-eq", ClientIP: "127.0.0.1", Host: "order.example",
		Path: "/order-eq", QueryString: "", Method: http.MethodGet, UserAgent: "order-eq-test",
		StatusCode: 403, WAFAction: "intercept", CacheState: "bypass",
	})
	writer.Close()

	const want = "Host,X-B,X-A"
	var ev store.SecurityEvent
	if err := db.Where("request_id = ?", "order-eq").First(&ev).Error; err != nil {
		t.Fatalf("read security event: %v", err)
	}
	if ev.HeaderOrder != want {
		t.Fatalf("security event HeaderOrder = %q, want %q", ev.HeaderOrder, want)
	}
	var al store.AccessLog
	if err := db.Where("request_id = ?", "order-eq").First(&al).Error; err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if al.HeaderOrder != want {
		t.Fatalf("access log HeaderOrder = %q, want %q", al.HeaderOrder, want)
	}
}
