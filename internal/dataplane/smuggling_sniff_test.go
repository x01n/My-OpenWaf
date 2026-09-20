package dataplane

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/observability"
	"My-OpenWaf/internal/store"
)

// smugglingHeaderRaw 构造带标准请求行的原始头片段，供字节向量测试使用。
func smugglingHeaderRaw(headers ...string) []byte {
	return []byte("POST / HTTP/1.1\r\nHost: example.test\r\n" + strings.Join(headers, "\r\n") + "\r\n\r\nbody")
}

// TestSmugglingSniffVectors 覆盖五类走私判定与合法请求 0 误报的字节向量矩阵。
func TestSmugglingSniffVectors(t *testing.T) {
	cases := []struct {
		name     string
		raw      []byte
		wantHit  bool
		wantRule string
	}{
		{name: "te_cl_coexist", raw: smugglingHeaderRaw("Content-Length: 4", "Transfer-Encoding: chunked"), wantHit: true, wantRule: "owaf.smuggle.te_cl_coexist"},
		{name: "te_cl_coexist_mixed_case_keys", raw: smugglingHeaderRaw("content-length: 4", "TRANSFER-ENCODING: CHUNKED"), wantHit: true, wantRule: "owaf.smuggle.te_cl_coexist"},
		{name: "te_cl_coexist_te_first", raw: smugglingHeaderRaw("Transfer-Encoding: chunked", "Content-Length: 4"), wantHit: true, wantRule: "owaf.smuggle.te_cl_coexist"},
		{name: "cl_mismatch", raw: smugglingHeaderRaw("Content-Length: 4", "Content-Length: 5"), wantHit: true, wantRule: "owaf.smuggle.cl_mismatch"},
		{name: "cl_duplicate_identical_is_ok", raw: smugglingHeaderRaw("Content-Length: 4", "Content-Length: 4"), wantHit: false},
		{name: "te_multi_lines", raw: smugglingHeaderRaw("Transfer-Encoding: chunked", "Transfer-Encoding: chunked"), wantHit: true, wantRule: "owaf.smuggle.te_multi"},
		{name: "te_repeated_coding_in_one_line", raw: smugglingHeaderRaw("Transfer-Encoding: chunked, chunked"), wantHit: true, wantRule: "owaf.smuggle.te_bad_value"},
		{name: "te_non_chunked", raw: smugglingHeaderRaw("Transfer-Encoding: gzip"), wantHit: true, wantRule: "owaf.smuggle.te_bad_value"},
		{name: "te_empty_value", raw: smugglingHeaderRaw("Transfer-Encoding:"), wantHit: true, wantRule: "owaf.smuggle.te_bad_value"},
		{name: "cl_non_numeric", raw: smugglingHeaderRaw("Content-Length: abc"), wantHit: true, wantRule: "owaf.smuggle.cl_bad_value"},
		{name: "cl_negative", raw: smugglingHeaderRaw("Content-Length: -1"), wantHit: true, wantRule: "owaf.smuggle.cl_bad_value"},
		{name: "cl_overflow", raw: smugglingHeaderRaw("Content-Length: 18446744073709551616"), wantHit: true, wantRule: "owaf.smuggle.cl_bad_value"},
		{name: "cl_fractional", raw: smugglingHeaderRaw("Content-Length: 4.0"), wantHit: true, wantRule: "owaf.smuggle.cl_bad_value"},
		{name: "legit_cl_only", raw: smugglingHeaderRaw("Content-Length: 4"), wantHit: false},
		{name: "legit_chunked_only", raw: smugglingHeaderRaw("Transfer-Encoding: chunked"), wantHit: false},
		{name: "legit_get_no_body", raw: []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"), wantHit: false},
		{name: "legit_te_chunked_ows", raw: smugglingHeaderRaw("Transfer-Encoding:  chunked "), wantHit: false},
		{name: "empty_bytes", raw: nil, wantHit: false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			res := SmugglingSniff(tt.raw)
			if res.Detected != tt.wantHit {
				t.Fatalf("detected = %v, want %v (res=%+v)", res.Detected, tt.wantHit, res)
			}
			if tt.wantRule == "" {
				if res.RuleID != "" || res.Severity != "" || res.Category != "" {
					t.Fatalf("non-hit must have empty fields, got %+v", res)
				}
				return
			}
			if res.RuleID != tt.wantRule {
				t.Fatalf("rule = %q, want %q", res.RuleID, tt.wantRule)
			}
			if res.Category != smugglingCatProtoViol {
				t.Fatalf("category = %q, want %q", res.Category, smugglingCatProtoViol)
			}
		})
	}
}

// TestRequestSmugglingSniffParsedResidualWritesEvent 覆盖解析层残留形态的
// 事件断言：hertz Set("Content-Length", <非法>) 会把非法值静默吞掉（CL 归 0、
// 行不枚举），VisitAll 无法重现该类残留；因此以 TE 畸形值这一残留模拟验证
// 接线与写入。真实线上这些形态同样会被解析层拒绝，测试只证明「若漏入
// handler 必留下审计证据」这一兜底契约。
func TestRequestSmugglingSniffParsedResidualWritesEvent(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate logs: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	metrics := NewMetrics()

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodPost)
	ctx.Request.SetRequestURI("/")
	ctx.Request.Header.SetHost("example.test")
	// 解析层残留模拟：非 chunked 的 TE 值。注意 hertz 的 Set/Add 会把 TE
	// 特殊字段吞掉（automatic managed），必须走 SetArgBytes 才能向普通
	// 头区注入可见的畸形 TE 行。
	ctx.Request.Header.SetArgBytes([]byte("Transfer-Encoding"), []byte("gzip"), false)

	requestSmugglingSniff(ctx, Options{Writer: writer, Metrics: metrics}, 1, "rid-te", "example.test", "1.2.3.4")
	writer.Close()

	var ev store.SecurityEvent
	if err := db.Where("rule_id_str = ? AND phase = ?", smugglingRuleIDs[3], smugglingCatProtoViol).First(&ev).Error; err != nil {
		t.Fatalf("read te_bad_value security event: %v", err)
	}
	if ev.Action != string(action.Observe) {
		t.Fatalf("action = %q, want observe", ev.Action)
	}
	if got := metrics.WAFObserves.Load(); got != 1 {
		t.Fatalf("WAFObserves = %d, want 1", got)
	}
}

// TestRequestSmugglingSniffLegitNoHit 保证合法请求（普通 CL 头）0 误报。
func TestRequestSmugglingSniffLegitNoHit(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate logs: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	metrics := NewMetrics()

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodPost)
	ctx.Request.SetRequestURI("/")
	ctx.Request.Header.SetHost("example.test")
	ctx.Request.Header.Set("Content-Length", "4")

	requestSmugglingSniff(ctx, Options{Writer: writer, Metrics: metrics}, 1, "rid-legit", "example.test", "1.2.3.4")
	writer.Close()

	var count int64
	db.Model(&store.SecurityEvent{}).Where("phase = ?", smugglingCatProtoViol).Count(&count)
	if count != 0 {
		t.Fatalf("legit CL-only request produced %d events", count)
	}
	if got := metrics.WAFObserves.Load(); got != 0 {
		t.Fatalf("legit request incremented WAFObserves to %d", got)
	}
}

// TestRequestSmugglingSniffNoWriterNoPanic 保证 Writer 为 nil 时安全返回。
func TestRequestSmugglingSniffNoWriterNoPanic(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodPost)
	ctx.Request.SetRequestURI("/")
	ctx.Request.Header.SetHost("example.test")
	requestSmugglingSniff(ctx, Options{Writer: nil}, 1, "rid-none", "example.test", "1.2.3.4")
}
