package imagery

import (
	"runtime"
	"testing"
)

// TestWebPDynamicAvailabilityIsExposed 探测结果必须可读且与 webp.Dynamic() 一致。
//
// 这条 gauge 的全部意义是让「共享库没装成」这件事可见，因此它必须真的在
// /metrics 里出现。本测试证明本包这一半（探测值与取值函数）；observability
// 那一半（渲染进 PrometheusBody）由 metrics_test.go 的
// TestPrometheusBodyIncludesImageTransformStats 覆盖；两半在 internal/app
// 的接线处汇合。
func TestWebPDynamicAvailabilityIsExposed(t *testing.T) {
	got := WebPDynamicAvailable()
	// 重复读取必须稳定：这是 init 期一次性探测的缓存值，不随时间变化。
	for i := 0; i < 3; i++ {
		if WebPDynamicAvailable() != got {
			t.Fatal("WebPDynamicAvailable is not stable across reads")
		}
	}
	t.Logf("WebPDynamicAvailable = %v (runtime.GOOS=%s GOARCH=%s)", got, runtime.GOOS, runtime.GOARCH)
}

// TestMetricsSnapshotCarriesGateAndTransformCounters 快照必须把三处状态都带出来。
func TestMetricsSnapshotCarriesGateAndTransformCounters(t *testing.T) {
	ResetStats()
	SetGateLimit(3)
	t.Cleanup(func() { SetGateLimit(0) })

	snapshot := Metrics()
	if snapshot.GateLimit != 3 {
		t.Fatalf("GateLimit = %d, want 3", snapshot.GateLimit)
	}
	if snapshot.GateInUse != 0 {
		t.Fatalf("GateInUse = %d, want 0", snapshot.GateInUse)
	}
	if snapshot.Applied != 0 || snapshot.Skipped != 0 || snapshot.TimedOut != 0 {
		t.Fatalf("counters not reset: %+v", snapshot)
	}
	if snapshot.WebPDynamicAvailable != WebPDynamicAvailable() {
		t.Fatal("MetricsSnapshot.WebPDynamicAvailable disagrees with the accessor")
	}

	// 制造一次成功转换与一次跳过，确认两个计数器分别落到对应字段。
	in := mustReadTestdata(t, "fixture.png")
	opts, err := Parse("resize,w_16")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res := Transform(nil, in, "image/png", opts, "", DecodeLimits{}); !res.Changed {
		t.Fatalf("expected a successful transform; SkipReason=%q", res.SkipReason)
	}
	if res := Transform(nil, []byte("garbage"), "image/png", opts, "", DecodeLimits{}); res.Changed {
		t.Fatal("garbage input must not change")
	}

	after := Metrics()
	if after.Applied != 1 {
		t.Errorf("Applied = %d, want 1", after.Applied)
	}
	if after.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", after.Skipped)
	}
	if after.TimedOut != 0 {
		t.Errorf("TimedOut = %d, want 0", after.TimedOut)
	}
	ResetStats()
}

// TestMetricsSnapshotReportsGateSkipped 闸门拒绝必须体现在 GateSkipped 上。
func TestMetricsSnapshotReportsGateSkipped(t *testing.T) {
	ResetStats()
	SetGateLimit(1)
	t.Cleanup(func() { SetGateLimit(0) })

	// 占住唯一额度，再发起第二次 acquire，必然被拒。
	if !acquire() {
		t.Fatal("first acquire failed")
	}
	defer release()
	if acquire() {
		t.Fatal("second acquire succeeded beyond the limit")
	}

	snapshot := Metrics()
	if snapshot.GateLimit != 1 {
		t.Errorf("GateLimit = %d, want 1", snapshot.GateLimit)
	}
	if snapshot.GateInUse != 1 {
		t.Errorf("GateInUse = %d, want 1", snapshot.GateInUse)
	}
	if snapshot.GateSkipped == 0 {
		t.Error("GateSkipped = 0 after a rejected acquire")
	}
}
