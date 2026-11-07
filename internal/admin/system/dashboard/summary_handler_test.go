package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"

	dpmetrics "My-OpenWaf/internal/dataplane/metrics"
)

func invokeDashboardHandler(t *testing.T, handler app.HandlerFunc, method, uri string, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI(uri)
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}

func TestDashboardSummaryHandlerServesSnapshot(t *testing.T) {
	deps := &DashboardDeps{
		Metrics:  dpmetrics.NewMetrics(),
		ConfigDB: newDashboardConfigDBForTest(t),
		LogDB:    newDashboardLogDBForTest(t),
	}

	ctx := invokeDashboardHandler(t, DashboardSummary(deps), "GET", "/api/v1/dashboard", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("dashboard status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode dashboard summary: %v", err)
	}
	for _, key := range []string{"qps_1s", "requests_total", "waf_blocks", "revision", "bot_total_24h", "cve_by_type_24h", "drop_by_source_24h"} {
		if _, ok := resp[key]; !ok {
			t.Fatalf("dashboard summary missing key %q", key)
		}
	}
	sources, ok := resp["drop_by_source_24h"].(map[string]any)
	if !ok {
		t.Fatalf("drop_by_source_24h = %T, want an object", resp["drop_by_source_24h"])
	}
	for _, source := range []string{"bot", "cve", "rule", "ip_reputation"} {
		if _, ok := sources[source]; !ok {
			t.Fatalf("drop_by_source_24h missing source %q", source)
		}
	}
}
