package observability

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"My-OpenWaf/internal/store"
)

// 慢速日志宽限（SlowLogGrace）的行为用例。
//
// 背景：UnifiedWriter 的入队原本是非阻塞的——队列满即丢弃并计入
// openwaf_writer_dropped_total。实测在 128 并发下丢弃率 45-56%，而请求日志
// 不允许丢。SlowLogGrace > 0 时改为「队列满先滚动等待，只有持续为满超过宽限
// 才退回丢弃」。这里守护三件不可退化的事：
//  1. 宽限关闭时语义与参数化之前逐字节一致；
//  2. 宽限开启且消费者能腾出空位时，记录必须入队而不是被丢；
//  3. 持续过载与关停两种情况下都不得把调用方无限期挂住。

// newGraceWriter 构造一个不启动 loop 的 writer，由用例自己扮演消费者。
func newGraceWriter(grace time.Duration, capacity int) *UnifiedWriter {
	w := &UnifiedWriter{
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		accessCh:     make(chan store.AccessLog, capacity),
		eventCh:      make(chan store.SecurityEvent, capacity),
		dropCh:       make(chan store.DropEvent, capacity),
		botScoreCh:   make(chan store.BotScoreLog, capacity),
		stopCh:       make(chan struct{}),
		slowLogGrace: grace,
	}
	if grace > 0 {
		w.abortWaitCh = make(chan struct{})
	}
	return w
}

// TestSlowLogGraceWaitsForConsumerInsteadOfDropping 守护宽限的核心收益：
// 队列满时等待消费者腾位，记录最终入队且不计入丢弃。
func TestSlowLogGraceWaitsForConsumerInsteadOfDropping(t *testing.T) {
	w := newGraceWriter(2*time.Second, 1)
	w.accessCh <- store.AccessLog{RequestID: "occupant"}

	returned := make(chan struct{})
	go func() {
		w.RecordAccessLog(store.AccessLog{RequestID: "waiting"})
		close(returned)
	}()

	// 消费者尚未腾位时，入队必须仍在等待（而不是已经丢弃返回）。
	select {
	case <-returned:
		t.Fatal("RecordAccessLog returned while the queue was still full and the grace window had not elapsed")
	case <-time.After(100 * time.Millisecond):
	}

	// 扮演 loop：取走占位记录，腾出一个空位。
	if got := (<-w.accessCh).RequestID; got != "occupant" {
		t.Fatalf("drained request id = %q, want %q", got, "occupant")
	}

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("RecordAccessLog did not return after the consumer freed a slot")
	}

	if got := w.Stats().AccessLogDropped; got != 0 {
		t.Fatalf("AccessLogDropped = %d, want 0 when the record was delivered within the grace window", got)
	}
	if got := (<-w.accessCh).RequestID; got != "waiting" {
		t.Fatalf("queued request id = %q, want %q", got, "waiting")
	}
}

// TestSlowLogGraceExpiresIntoDrop 守护过载上界：连续为满超过宽限后立刻退回丢弃，
// 且同一轮连续满状态内后续调用不再重复等待（否则入队延迟会无上界叠加）。
func TestSlowLogGraceExpiresIntoDrop(t *testing.T) {
	const grace = 150 * time.Millisecond
	w := newGraceWriter(grace, 1)
	w.accessCh <- store.AccessLog{RequestID: "occupant"}

	start := time.Now()
	w.RecordAccessLog(store.AccessLog{RequestID: "first-after-full"})
	waited := time.Since(start)

	if waited < grace/2 {
		t.Fatalf("first blocked enqueue returned after %s, want at least ~%s of grace", waited, grace)
	}
	if waited > 5*time.Second {
		t.Fatalf("first blocked enqueue returned after %s, want it bounded by the grace window", waited)
	}
	if got := w.Stats().AccessLogDropped; got != 1 {
		t.Fatalf("AccessLogDropped = %d, want 1 after the grace window expired", got)
	}

	// 队列仍然满且连续满状态未复位：下一条必须立刻丢弃，不再等第二个宽限窗口。
	start = time.Now()
	w.RecordAccessLog(store.AccessLog{RequestID: "second-after-full"})
	if elapsed := time.Since(start); elapsed > grace/2 {
		t.Fatalf("second blocked enqueue waited %s, want an immediate drop while the saturation flag is latched", elapsed)
	}
	if got := w.Stats().AccessLogDropped; got != 2 {
		t.Fatalf("AccessLogDropped = %d, want 2", got)
	}

	// 消费者腾位并成功入队一条之后，连续满状态复位，重新获得完整宽限。
	<-w.accessCh
	w.RecordAccessLog(store.AccessLog{RequestID: "after-drain"})
	if got := w.Stats().AccessLogDropped; got != 2 {
		t.Fatalf("AccessLogDropped = %d, want 2 (the post-drain record must be delivered, not dropped)", got)
	}
	if got := w.blockedSinceAccess.Load(); got != 0 {
		t.Fatalf("blockedSinceAccess = %d, want 0 after a successful enqueue", got)
	}
}

// TestSlowLogGraceDisabledKeepsLegacyDropSemantics 守护显式关闭时的既有语义：
// 队列满即丢弃，调用方不等待。关闭由 slowLogGrace=0 表示（生产路径由
// SlowLogGraceDisabled 得出，见 TestClampUnifiedWriterSlowLogGrace）。
func TestSlowLogGraceDisabledKeepsLegacyDropSemantics(t *testing.T) {
	w := newGraceWriter(0, 1)
	w.accessCh <- store.AccessLog{RequestID: "occupant"}

	start := time.Now()
	w.RecordAccessLog(store.AccessLog{RequestID: "dropped"})
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("RecordAccessLog with grace disabled waited %s, want an immediate drop", elapsed)
	}
	if got := w.Stats().AccessLogDropped; got != 1 {
		t.Fatalf("AccessLogDropped = %d, want 1", got)
	}
	if got := w.blockedSinceAccess.Load(); got != 0 {
		t.Fatalf("blockedSinceAccess = %d, want 0 when grace is disabled", got)
	}
}

// TestSlowLogGraceAbortsOnClose 守护关停不被拖住：Close 关闭 abortWaitCh 后，
// 处于等待中的入队必须立刻退回丢弃而不是等满宽限窗口。
func TestSlowLogGraceAbortsOnClose(t *testing.T) {
	// 宽限远大于关停预算：若 Close 不能打断等待，本用例会超时失败。
	w := newGraceWriter(time.Hour, 1)
	w.accessCh <- store.AccessLog{RequestID: "occupant"}

	returned := make(chan struct{})
	go func() {
		w.RecordAccessLog(store.AccessLog{RequestID: "blocked-at-close"})
		close(returned)
	}()

	select {
	case <-returned:
		t.Fatal("RecordAccessLog returned before Close was called")
	case <-time.After(100 * time.Millisecond):
	}

	closed := make(chan struct{})
	go func() {
		w.Close()
		close(closed)
	}()

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not release the blocked enqueue")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return while an enqueue was blocked on a full queue")
	}
	if got := w.Stats().AccessLogDropped; got != 1 {
		t.Fatalf("AccessLogDropped = %d, want 1 for the record abandoned at close", got)
	}
}

// TestSlowLogGraceWaitsForEveryRecordType 守护四类记录共用同一套等待语义。
func TestSlowLogGraceWaitsForEveryRecordType(t *testing.T) {
	w := newGraceWriter(2*time.Second, 1)

	t.Run("security_event", func(t *testing.T) {
		w.eventCh <- store.SecurityEvent{RequestID: "occupant"}
		go func() {
			time.Sleep(50 * time.Millisecond)
			<-w.eventCh
		}()
		w.RecordEvent(store.SecurityEvent{RequestID: "waited"})
		if got := (<-w.eventCh).RequestID; got != "waited" {
			t.Fatalf("event request id = %q, want %q", got, "waited")
		}
		if got := w.Stats().SecurityEventDropped; got != 0 {
			t.Fatalf("SecurityEventDropped = %d, want 0", got)
		}
	})

	t.Run("drop_event", func(t *testing.T) {
		w.dropCh <- store.DropEvent{Detail: "occupant"}
		go func() {
			time.Sleep(50 * time.Millisecond)
			<-w.dropCh
		}()
		w.RecordDropEvent(store.DropEvent{Detail: "waited"})
		if got := (<-w.dropCh).Detail; got != "waited" {
			t.Fatalf("drop event detail = %q, want %q", got, "waited")
		}
		if got := w.Stats().DropEventDropped; got != 0 {
			t.Fatalf("DropEventDropped = %d, want 0", got)
		}
	})

	t.Run("bot_score", func(t *testing.T) {
		w.botScoreCh <- store.BotScoreLog{RequestID: "occupant"}
		go func() {
			time.Sleep(50 * time.Millisecond)
			<-w.botScoreCh
		}()
		w.RecordBotScore(store.BotScoreLog{RequestID: "waited"})
		if got := (<-w.botScoreCh).RequestID; got != "waited" {
			t.Fatalf("bot score request id = %q, want %q", got, "waited")
		}
		if got := w.Stats().BotScoreDropped; got != 0 {
			t.Fatalf("BotScoreDropped = %d, want 0", got)
		}
	})
}

// TestClampUnifiedWriterSlowLogGrace 守护宽限旋钮的钳制口径：只做上界截断与负数
// 归零，0 原样保留（它是「未配置」的表示，运行时由 effectiveSlowLogGrace 折算成
// defaultSlowLogGrace）；显式关闭走 SlowLogGraceDisabled。
func TestClampUnifiedWriterSlowLogGrace(t *testing.T) {
	cases := []struct {
		name  string
		in    time.Duration
		want  time.Duration
		warns bool
	}{
		{"zero stays zero", 0, 0, false},
		{"positive kept", 30 * time.Second, 30 * time.Second, false},
		{"negative becomes zero", -time.Second, 0, true},
		{"over limit clamped", 10 * time.Minute, unifiedWriterMaxSlowLogGrace, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := DefaultUnifiedWriterOptions()
			opts.SlowLogGrace = tc.in
			got, warns := clampUnifiedWriterOptions(opts)
			if got.SlowLogGrace != tc.want {
				t.Fatalf("SlowLogGrace = %s, want %s", got.SlowLogGrace, tc.want)
			}
			if (len(warns) > 0) != tc.warns {
				t.Fatalf("warns = %v, want warns=%v", warns, tc.warns)
			}
		})
	}

	// 请求路径不得为可观测性背压阻塞：未配置时折算为 0（满即丢弃并计数）。
	if got := effectiveSlowLogGrace(0, false); got != 0 {
		t.Fatalf("effectiveSlowLogGrace(0,false) = %s, want 0 (non-blocking)", got)
	}
	if got := effectiveSlowLogGrace(0, true); got != 0 {
		t.Fatalf("effectiveSlowLogGrace(0,true) = %s, want 0 (disabled)", got)
	}
	if got := effectiveSlowLogGrace(-time.Second, false); got != defaultSlowLogGrace {
		t.Fatalf("effectiveSlowLogGrace(-1s,false) = %s, want %s", got, defaultSlowLogGrace)
	}
	if got := effectiveSlowLogGrace(time.Minute, false); got != time.Minute {
		t.Fatalf("effectiveSlowLogGrace(1m,false) = %s, want 1m", got)
	}

	// 未配置的 options 必须真的让运行时生效值为正：这条把「默认不丢」钉在构造环节。
	// 用 nil db 构造，loop 会因 flushBuffered 的 db==nil 分支跳过写入。
	w := NewUnifiedWriterWithOptions(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), UnifiedWriterOptions{})
	t.Cleanup(w.Close)
	if w.slowLogGrace != defaultSlowLogGrace {
		t.Fatalf("runtime slowLogGrace = %s, want %s when options carry no grace", w.slowLogGrace, defaultSlowLogGrace)
	}

	// 显式关闭：值被归零，且不与「未配置」共用告警口径。
	t.Run("explicit disable", func(t *testing.T) {
		opts := DefaultUnifiedWriterOptions()
		opts.SlowLogGraceDisabled = true
		got, warns := clampUnifiedWriterOptions(opts)
		if got.SlowLogGrace != 0 {
			t.Fatalf("SlowLogGrace = %s, want 0 when disabled", got.SlowLogGrace)
		}
		if len(warns) != 0 {
			t.Fatalf("warns = %v, want none for a clean explicit disable", warns)
		}
	})
}
