package observability

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestDefaultOptionsMatchLegacyConstants 守护「可配置化不改变既有行为」：
// 两个 Default*Options 必须逐项等于参数化之前的硬编码常量。
func TestDefaultOptionsMatchLegacyConstants(t *testing.T) {
	uw := DefaultUnifiedWriterOptions()
	if uw.EventBufferSize != 16384 {
		t.Errorf("EventBufferSize = %d, want 16384", uw.EventBufferSize)
	}
	if uw.DropBufferSize != 8192 {
		t.Errorf("DropBufferSize = %d, want 8192", uw.DropBufferSize)
	}
	if uw.BatchSize != 512 {
		t.Errorf("BatchSize = %d, want 512", uw.BatchSize)
	}
	if uw.FlushInterval != 3*time.Second {
		t.Errorf("FlushInterval = %s, want 3s", uw.FlushInterval)
	}

	wq := DefaultWriteQueueOptions()
	if wq.Capacity != 256 {
		t.Errorf("Capacity = %d, want 256", wq.Capacity)
	}
	if wq.BatchSize != 64 {
		t.Errorf("BatchSize = %d, want 64", wq.BatchSize)
	}
	if wq.BatchInterval != 50*time.Millisecond {
		t.Errorf("BatchInterval = %s, want 50ms", wq.BatchInterval)
	}
}

// TestNewUnifiedWriterMatchesLegacyRuntimeValues 断言默认构造路径落到运行时字段上的
// 值与硬编码时期一致：通道容量、批大小、drainLimit(4×BatchSize=2048)、flush 周期。
func TestNewUnifiedWriterMatchesLegacyRuntimeValues(t *testing.T) {
	w := NewUnifiedWriter(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(w.Close)

	if got := cap(w.eventCh); got != 16384 {
		t.Errorf("cap(eventCh) = %d, want 16384", got)
	}
	if got := cap(w.accessCh); got != 16384 {
		t.Errorf("cap(accessCh) = %d, want 16384", got)
	}
	if got := cap(w.dropCh); got != 8192 {
		t.Errorf("cap(dropCh) = %d, want 8192", got)
	}
	if got := cap(w.botScoreCh); got != 8192 {
		t.Errorf("cap(botScoreCh) = %d, want 8192", got)
	}
	if w.batchSize != 512 {
		t.Errorf("batchSize = %d, want 512", w.batchSize)
	}
	// 原 unifiedWriterDrainLimit = 2048，参数化后按 4×BatchSize 推导。
	if w.drainLimit != 2048 {
		t.Errorf("drainLimit = %d, want 2048", w.drainLimit)
	}
	if w.flushInterval != 3*time.Second {
		t.Errorf("flushInterval = %s, want 3s", w.flushInterval)
	}
}

// TestNewWriteQueueMatchesLegacyRuntimeValues 断言默认构造路径的 WriteQueue 运行时
// 字段与硬编码时期一致。
func TestNewWriteQueueMatchesLegacyRuntimeValues(t *testing.T) {
	wq := NewWriteQueue(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(wq.Close)

	if got := cap(wq.ch); got != 256 {
		t.Errorf("cap(ch) = %d, want 256", got)
	}
	if wq.maxBatchSize != 64 {
		t.Errorf("maxBatchSize = %d, want 64", wq.maxBatchSize)
	}
	if wq.batchInterval != 50*time.Millisecond {
		t.Errorf("batchInterval = %s, want 50ms", wq.batchInterval)
	}
}

// TestNewUnifiedWriterAppliesOptions 校验合法 options 真正生效，而不是被默认值覆盖。
func TestNewUnifiedWriterAppliesOptions(t *testing.T) {
	w := NewUnifiedWriterWithOptions(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), UnifiedWriterOptions{
		EventBufferSize: 64,
		DropBufferSize:  32,
		BatchSize:       16,
		FlushInterval:   250 * time.Millisecond,
	})
	t.Cleanup(w.Close)

	if got := cap(w.eventCh); got != 64 {
		t.Errorf("cap(eventCh) = %d, want 64", got)
	}
	if got := cap(w.dropCh); got != 32 {
		t.Errorf("cap(dropCh) = %d, want 32", got)
	}
	if w.batchSize != 16 {
		t.Errorf("batchSize = %d, want 16", w.batchSize)
	}
	// BatchSize 收紧时 drainLimit 必须跟着收，否则单批事务会超出批阈值。
	if w.drainLimit != 64 {
		t.Errorf("drainLimit = %d, want 64", w.drainLimit)
	}
	if w.flushInterval != 250*time.Millisecond {
		t.Errorf("flushInterval = %s, want 250ms", w.flushInterval)
	}
}

// TestNewWriteQueueAppliesOptions 校验合法 options 真正生效。
func TestNewWriteQueueAppliesOptions(t *testing.T) {
	wq := NewWriteQueueWithOptions(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), WriteQueueOptions{
		Capacity:      512,
		BatchSize:     128,
		BatchInterval: 10 * time.Millisecond,
	})
	t.Cleanup(wq.Close)

	if got := cap(wq.ch); got != 512 {
		t.Errorf("cap(ch) = %d, want 512", got)
	}
	if wq.maxBatchSize != 128 {
		t.Errorf("maxBatchSize = %d, want 128", wq.maxBatchSize)
	}
	if wq.batchInterval != 10*time.Millisecond {
		t.Errorf("batchInterval = %s, want 10ms", wq.batchInterval)
	}
}

// TestClampUnifiedWriterOptionsBounds 覆盖下界（0/负数）与上界，逐项断言回退值与告警。
func TestClampUnifiedWriterOptionsBounds(t *testing.T) {
	tests := []struct {
		name  string
		in    UnifiedWriterOptions
		check func(*testing.T, UnifiedWriterOptions)
	}{
		{
			name: "zero value falls back to every default",
			in:   UnifiedWriterOptions{},
			check: func(t *testing.T, got UnifiedWriterOptions) {
				if got != DefaultUnifiedWriterOptions() {
					t.Errorf("got %+v, want %+v", got, DefaultUnifiedWriterOptions())
				}
			},
		},
		{
			name: "negative capacity falls back",
			in:   UnifiedWriterOptions{EventBufferSize: -1, DropBufferSize: -1, BatchSize: -1, FlushInterval: -time.Second},
			check: func(t *testing.T, got UnifiedWriterOptions) {
				if got != DefaultUnifiedWriterOptions() {
					t.Errorf("got %+v, want %+v", got, DefaultUnifiedWriterOptions())
				}
			},
		},
		{
			name: "above hard limits gets clamped",
			in: UnifiedWriterOptions{
				EventBufferSize: unifiedWriterMaxChannelCapacity + 1,
				DropBufferSize:  unifiedWriterMaxChannelCapacity * 2,
				BatchSize:       unifiedWriterMaxBatchSize + 1,
				FlushInterval:   unifiedWriterMaxFlushInterval + time.Minute,
			},
			check: func(t *testing.T, got UnifiedWriterOptions) {
				if got.EventBufferSize != unifiedWriterMaxChannelCapacity {
					t.Errorf("EventBufferSize = %d, want %d", got.EventBufferSize, unifiedWriterMaxChannelCapacity)
				}
				if got.DropBufferSize != unifiedWriterMaxChannelCapacity {
					t.Errorf("DropBufferSize = %d, want %d", got.DropBufferSize, unifiedWriterMaxChannelCapacity)
				}
				if got.BatchSize != unifiedWriterMaxBatchSize {
					t.Errorf("BatchSize = %d, want %d", got.BatchSize, unifiedWriterMaxBatchSize)
				}
				if got.FlushInterval != unifiedWriterMaxFlushInterval {
					t.Errorf("FlushInterval = %s, want %s", got.FlushInterval, unifiedWriterMaxFlushInterval)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, warns := clampUnifiedWriterOptions(tt.in)
			tt.check(t, got)
			// 四个字段全部越界，钳制不得静默。
			if len(warns) != 4 {
				t.Errorf("warnings = %d (%v), want 4", len(warns), warns)
			}
		})
	}
}

// TestClampWriteQueueOptionsBounds 同上，覆盖 WriteQueue 的三个旋钮。
func TestClampWriteQueueOptionsBounds(t *testing.T) {
	got, warns := clampWriteQueueOptions(WriteQueueOptions{})
	if got != DefaultWriteQueueOptions() {
		t.Errorf("zero value → %+v, want %+v", got, DefaultWriteQueueOptions())
	}
	if len(warns) != 3 {
		t.Errorf("warnings = %d (%v), want 3", len(warns), warns)
	}

	got, warns = clampWriteQueueOptions(WriteQueueOptions{
		Capacity:      writeQueueMaxChannelCapacity + 1,
		BatchSize:     writeQueueMaxBatchSize + 1,
		BatchInterval: -time.Second,
	})
	if got.Capacity != writeQueueMaxChannelCapacity {
		t.Errorf("Capacity = %d, want %d", got.Capacity, writeQueueMaxChannelCapacity)
	}
	if got.BatchSize != writeQueueMaxBatchSize {
		t.Errorf("BatchSize = %d, want %d", got.BatchSize, writeQueueMaxBatchSize)
	}
	if got.BatchInterval != DefaultWriteQueueOptions().BatchInterval {
		t.Errorf("BatchInterval = %s, want %s", got.BatchInterval, DefaultWriteQueueOptions().BatchInterval)
	}
	if len(warns) != 3 {
		t.Errorf("warnings = %d (%v), want 3", len(warns), warns)
	}
}

// TestDefaultOptionsProduceNoClampWarnings 保证默认值本身不触发告警，
// 否则每次正常启动都会刷出无意义的 WARN。
func TestDefaultOptionsProduceNoClampWarnings(t *testing.T) {
	if _, warns := clampUnifiedWriterOptions(DefaultUnifiedWriterOptions()); len(warns) != 0 {
		t.Errorf("unified writer defaults produced warnings: %v", warns)
	}
	if _, warns := clampWriteQueueOptions(DefaultWriteQueueOptions()); len(warns) != 0 {
		t.Errorf("write queue defaults produced warnings: %v", warns)
	}
}

// TestConstructorsLogClampWarnings 断言越界构造会真正打出 WARN，而不是只在
// 返回值里携带告警。
func TestConstructorsLogClampWarnings(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	w := NewUnifiedWriterWithOptions(nil, log, UnifiedWriterOptions{BatchSize: -1})
	t.Cleanup(w.Close)

	if !strings.Contains(buf.String(), "UnifiedWriterOptions.BatchSize") {
		t.Errorf("log missing BatchSize warning:\n%s", buf.String())
	}

	buf.Reset()
	wq := NewWriteQueueWithOptions(nil, log, WriteQueueOptions{Capacity: -1})
	t.Cleanup(wq.Close)

	if !strings.Contains(buf.String(), "WriteQueueOptions.Capacity") {
		t.Errorf("log missing Capacity warning:\n%s", buf.String())
	}
}

// TestConstructorsTolerateNilLogger 守护无 logger 的构造路径：告警本身不能成为
// panic 源。测试与嵌入场景会走这条路径。
func TestConstructorsTolerateNilLogger(t *testing.T) {
	w := NewUnifiedWriterWithOptions(nil, nil, UnifiedWriterOptions{EventBufferSize: -1})
	t.Cleanup(w.Close)

	if got := cap(w.eventCh); got != DefaultUnifiedWriterOptions().EventBufferSize {
		t.Errorf("cap(eventCh) = %d, want %d", got, DefaultUnifiedWriterOptions().EventBufferSize)
	}
}
