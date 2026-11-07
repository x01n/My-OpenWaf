package observability

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
)

// TestPrometheusBodyIncludesImageTransformStats 验证图像转换指标出现在 /metrics 输出里。
//
// 重点断言 openwaf_imagery_webp_dynamic_available：它存在与否决定了「部署镜像
// 漏装 libwebp」这件事能不能被看见，所以必须逐字确认它以 0/1 的样本行出现，
// 而不是只在某种「可用」状态下才输出。
func TestPrometheusBodyIncludesImageTransformStats(t *testing.T) {
	m := NewMetrics()
	m.SetImageTransformStatsProvider(func() ImageTransformStatsSnapshot {
		return ImageTransformStatsSnapshot{
			WebPDynamicAvailable: true,
			Applied:              7,
			Skipped:              3,
			TimedOut:             1,
			GateLimit:            8,
			GateInUse:            2,
			GateSkipped:          5,
		}
	})

	body := PrometheusBody(m)
	for _, want := range []string{
		"openwaf_imagery_webp_dynamic_available 1",
		"openwaf_imagery_applied_total 7",
		"openwaf_imagery_skipped_total 3",
		"openwaf_imagery_timed_out_total 1",
		"openwaf_imagery_gate_limit 8",
		"openwaf_imagery_gate_in_use 2",
		"openwaf_imagery_gate_skipped_total 5",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("PrometheusBody() missing %q\nbody:\n%s", want, body)
		}
	}
}

// TestPrometheusImageTransformReportsUnavailableAsZero 回退状态下必须是 0 而不是缺席。
//
// 这是 P0-3 的核心验收点：漏装共享库时 gauge 为 0。若实现改成「不可用就不输出」，
// 报警器就失效了，这条断言会拦住那种改法。
func TestPrometheusImageTransformReportsUnavailableAsZero(t *testing.T) {
	m := NewMetrics()
	m.SetImageTransformStatsProvider(func() ImageTransformStatsSnapshot {
		return ImageTransformStatsSnapshot{WebPDynamicAvailable: false}
	})
	body := PrometheusBody(m)
	if !strings.Contains(body, "openwaf_imagery_webp_dynamic_available 0") {
		t.Fatalf("unavailable state must render as 0\nbody:\n%s", body)
	}
	if strings.Contains(body, "openwaf_imagery_webp_dynamic_available 1") {
		t.Fatalf("unavailable state rendered as 1\nbody:\n%s", body)
	}
}

// TestPrometheusBodyOmitsImageTransformStatsWithoutProvider 未接线时不输出空头。
//
// 与既有 TestPrometheusBodyOmitsLuaScriptStatsWhenEmpty 同一口径：没有 provider
// 就不该出现 HELP/TYPE 头，避免看板把「未接线」误读成「值为 0」。
func TestPrometheusBodyOmitsImageTransformStatsWithoutProvider(t *testing.T) {
	m := NewMetrics()
	if body := PrometheusBody(m); strings.Contains(body, "openwaf_imagery_") {
		t.Fatalf("unwired metrics must not appear\nbody:\n%s", body)
	}
}

// TestPrometheusHandlerServesImageTransformStats 走真实 handler，证明它确实出现在端点响应里。
//
// 前三条测试直接调 PrometheusBody；这一条构造 Hertz 处理函数并真正调用一次，
// 断言响应体与 Content-Type，覆盖「handler 是否真的把这个 body 写出去」这一段。
func TestPrometheusHandlerServesImageTransformStats(t *testing.T) {
	m := NewMetrics()
	m.SetImageTransformStatsProvider(func() ImageTransformStatsSnapshot {
		return ImageTransformStatsSnapshot{WebPDynamicAvailable: true, Applied: 42}
	})

	handler := PrometheusHandler(m)
	c := app.NewContext(0)
	handler(context.Background(), c)

	if got := c.Response.StatusCode(); got != 200 {
		t.Fatalf("status = %d, want 200", got)
	}
	if ct := string(c.Response.Header.ContentType()); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain...", ct)
	}
	body := string(c.Response.Body())
	for _, want := range []string{
		"openwaf_imagery_webp_dynamic_available 1",
		"openwaf_imagery_applied_total 42",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("handler response missing %q\nbody:\n%s", want, body)
		}
	}
	// 样本行格式自检：每个 openwaf_imagery_ 行都必须是合法 Prometheus 样本。
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "openwaf_imagery_") {
			continue
		}
		if strings.Contains(line, "  ") || strings.HasSuffix(line, " ") {
			t.Errorf("malformed sample line %q", line)
		}
	}
	_ = protocol.Args{}
}
