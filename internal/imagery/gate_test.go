package imagery

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestGateRejectsBeyondLimit 闸门超限时必须放弃转换而不是排队。
func TestGateRejectsBeyondLimit(t *testing.T) {
	SetGateLimit(1)
	defer SetGateLimit(0)

	// 占住唯一额度。
	if !acquire() {
		t.Fatal("first acquire failed")
	}
	defer release()

	opts, err := Parse("format,webp")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	res := TransformGuarded(context.Background(), mustReadTestdata(t, "fixture.png"), "image/png", opts, "", DecodeLimits{}, time.Second)
	if res.Changed {
		t.Fatal("TransformGuarded ran despite the gate being saturated")
	}
	if res.SkipReason != "concurrency limit" {
		t.Fatalf("SkipReason = %q, want %q", res.SkipReason, "concurrency limit")
	}
}

// TestGateReleasesOnCompletion 正常路径必须归还额度。
func TestGateReleasesOnCompletion(t *testing.T) {
	SetGateLimit(2)
	defer SetGateLimit(0)

	opts, err := Parse("format,webp")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	before := SnapshotGateStats().InUse
	for i := 0; i < 5; i++ {
		_ = TransformGuarded(context.Background(), mustReadTestdata(t, "fixture.png"), "image/png", opts, "", DecodeLimits{}, time.Second)
	}
	if got := SnapshotGateStats().InUse; got != before {
		t.Fatalf("InUse = %d after 5 runs, want %d", got, before)
	}
}

// TestTransformGuardedConcurrent 并发调用不产生数据竞争、不泄漏额度。
func TestTransformGuardedConcurrent(t *testing.T) {
	SetGateLimit(4)
	defer SetGateLimit(0)

	opts, err := Parse("resize,w_32/format,webp")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	data := mustReadTestdata(t, "fixture.png")

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = TransformGuarded(context.Background(), data, "image/png", opts, "", DecodeLimits{}, time.Second)
		}()
	}
	wg.Wait()

	if got := SnapshotGateStats().InUse; got != 0 {
		t.Fatalf("InUse = %d after concurrent run, want 0", got)
	}
}

// TestTransformGuardedTimeoutBudget 覆盖墙钟预算：已过期的 context 必须
// 立即放弃，且计入 TimedOut。
func TestTransformGuardedTimeoutBudget(t *testing.T) {
	ResetStats()
	SetGateLimit(2)
	defer SetGateLimit(0)

	opts, err := Parse("format,webp")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res := TransformGuarded(ctx, mustReadTestdata(t, "fixture.png"), "image/png", opts, "", DecodeLimits{}, time.Second)
	if res.Changed {
		t.Fatal("TransformGuarded ran with an already-cancelled context")
	}
	if got := SnapshotStats().TimedOut; got == 0 {
		t.Fatal("TimedOut counter did not increment")
	}
}

// TestTransformGuardedZeroTimeoutUsesDefault 零超时取默认预算而不是立即超时。
func TestTransformGuardedZeroTimeoutUsesDefault(t *testing.T) {
	SetGateLimit(2)
	defer SetGateLimit(0)

	opts, err := Parse("format,webp")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	res := TransformGuarded(context.Background(), mustReadTestdata(t, "fixture.png"), "image/png", opts, "", DecodeLimits{}, 0)
	if !res.Changed {
		t.Fatalf("zero timeout should fall back to DefaultOpTimeout; SkipReason=%q", res.SkipReason)
	}
	if DefaultOpTimeout <= 0 {
		t.Fatal("DefaultOpTimeout must be positive")
	}
}

// TestStatsCountersMove 统计计数在成功与跳过路径上都要变化。
func TestStatsCountersMove(t *testing.T) {
	ResetStats()
	opts, err := Parse("format,png")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_ = Transform(context.Background(), mustReadTestdata(t, "fixture.jpg"), "image/jpeg", opts, "", DecodeLimits{})
	if SnapshotStats().Applied == 0 {
		t.Fatal("Applied counter did not increment")
	}

	ResetStats()
	_ = Transform(context.Background(), []byte("garbage"), "image/png", opts, "", DecodeLimits{})
	if SnapshotStats().Skipped == 0 {
		t.Fatal("Skipped counter did not increment")
	}
	if LastSkipReason() == "" {
		t.Fatal("LastSkipReason is empty after a skip")
	}
}
