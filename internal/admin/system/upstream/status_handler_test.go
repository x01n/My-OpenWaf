package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"

	"My-OpenWaf/internal/upstream"
)

func invokeUpstreamHandler(t *testing.T, handler app.HandlerFunc, method, uri string) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI(uri)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}

func TestUpstreamStatusHandlerReturnsSortedItems(t *testing.T) {
	pool := upstream.NewPool()
	pool.MarkResult("http://b.example.test", nil, 20*time.Millisecond)
	pool.MarkResult("http://a.example.test", assertErr{}, 80*time.Millisecond)

	ctx := invokeUpstreamHandler(t, UpstreamStatus(pool), "GET", "/api/v1/upstream-status")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("upstream status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp struct {
		Items []struct {
			URL           string `json:"url"`
			FailCount     int    `json:"fail_count"`
			LastError     string `json:"last_error"`
			LastSuccessAt string `json:"last_success_at"`
			LastLatencyMs int64  `json:"last_latency_ms"`
		} `json:"items"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode upstream status: %v", err)
	}
	if resp.Total != 2 || len(resp.Items) != 2 {
		t.Fatalf("upstream status = total %d len %d, want 2", resp.Total, len(resp.Items))
	}
	if resp.Items[0].URL != "http://a.example.test" || resp.Items[1].URL != "http://b.example.test" {
		t.Fatalf("upstream items not sorted by url: %#v", resp.Items)
	}
	// 单次失败只累加 FailCount，健康标记由 Pool 的失败阈值决定，此处不做断言。
	if resp.Items[0].FailCount != 1 || resp.Items[0].LastError != "err" {
		t.Fatalf("first upstream should record the failure: %#v", resp.Items[0])
	}
	if resp.Items[0].LastSuccessAt != "" {
		t.Fatalf("first upstream must not report a success timestamp: %#v", resp.Items[0])
	}
	if resp.Items[1].FailCount != 0 || resp.Items[1].LastError != "" {
		t.Fatalf("second upstream should be clean: %#v", resp.Items[1])
	}
	if resp.Items[1].LastLatencyMs != 20 {
		t.Fatalf("second upstream last_latency_ms = %d, want 20", resp.Items[1].LastLatencyMs)
	}
}

func TestUpstreamStatusHandlerWithEmptyPool(t *testing.T) {
	ctx := invokeUpstreamHandler(t, UpstreamStatus(upstream.NewPool()), "GET", "/api/v1/upstream-status")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("upstream status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if !bytes.Contains(ctx.Response.Body(), []byte(`"total":0`)) {
		t.Fatalf("empty pool body = %s, want total 0", bytes.TrimSpace(ctx.Response.Body()))
	}
	if !bytes.Contains(ctx.Response.Body(), []byte(`"items":[]`)) {
		t.Fatalf("empty pool body = %s, want an empty items array", bytes.TrimSpace(ctx.Response.Body()))
	}
}
