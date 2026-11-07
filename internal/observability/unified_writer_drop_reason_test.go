package observability

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"My-OpenWaf/internal/store"
)

// warnTestWriter 造一个只用于观察告警文案的写入器：缓冲区容量 1，flush 周期极长，
// 保证记录只会走「队列满」或「关停闸门」两条丢弃路径，不会真的落库。
func warnTestWriter(buf *bytes.Buffer) *UnifiedWriter {
	return &UnifiedWriter{
		log:        slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})),
		eventCh:    make(chan store.SecurityEvent, 1),
		accessCh:   make(chan store.AccessLog, 1),
		dropCh:     make(chan store.DropEvent, 1),
		botScoreCh: make(chan store.BotScoreLog, 1),
	}
}

// expireDropWarnWindow 让下一次告警不被 unifiedWriterDropWarnInterval 限流挡掉。
func expireDropWarnWindow(w *UnifiedWriter) {
	w.lastDropWarnUnixNano.Store(time.Now().Add(-2 * unifiedWriterDropWarnInterval).UnixNano())
}

// TestUnifiedWriterDropReasonMessagesDiffer 守护两种丢弃原因各用各的文案。
//
// 缺陷形态：关停期丢弃（closed 闸门已落下）与队列满丢弃共用
// "observability queue full, record dropped"。运维看到这行字只会去查队列容量，
// 而关停期的丢失根本不是背压，那是已经无法挽回的损失，二者动作完全不同。
//
// 同时钉住限流语义：两种原因共用同一个 lastDropWarnUnixNano 闸门，同一窗口内只
// 留一条 WARN（拆成两个闸会在关停阶段把队列满的告警挤掉，或反之）。
func TestUnifiedWriterDropReasonMessagesDiffer(t *testing.T) {
	var buf bytes.Buffer
	writer := warnTestWriter(&buf)

	// 队列满：第一条填满缓冲区，第二条走 default 分支被丢弃。
	writer.RecordAccessLog(store.AccessLog{})
	writer.RecordAccessLog(store.AccessLog{})

	if got := strings.Count(buf.String(), "observability queue full"); got != 1 {
		t.Fatalf("队列满告警 = %d 条, want 1\nlog:\n%s", got, buf.String())
	}
	if got := strings.Count(buf.String(), "observability writer closed"); got != 0 {
		t.Fatalf("队列满丢弃不应出现关停文案\nlog:\n%s", buf.String())
	}
	if got := writer.Stats().AccessLogDropped; got != 1 {
		t.Fatalf("AccessLogDropped = %d, want 1", got)
	}

	// 同一限流窗口内：关停闸门落下也不该补一条新告警。
	writer.closed.Store(true)
	writer.RecordAccessLog(store.AccessLog{})
	if got := strings.Count(buf.String(), "observability writer closed"); got != 0 {
		t.Fatalf("同一限流窗口内关停丢弃不应额外告警\nlog:\n%s", buf.String())
	}
	if got := writer.Stats().AccessLogDropped; got != 2 {
		t.Fatalf("AccessLogDropped = %d, want 2（计数不受限流影响）", got)
	}

	// 窗口过期后：关停期丢弃必须打出与队列满不同的文案与字段。
	buf.Reset()
	expireDropWarnWindow(writer)
	writer.RecordAccessLog(store.AccessLog{})

	log := buf.String()
	if got := strings.Count(log, "observability writer closed, record dropped"); got != 1 {
		t.Fatalf("关停期丢弃告警 = %d 条, want 1\nlog:\n%s", got, log)
	}
	if strings.Contains(log, "observability queue full") {
		t.Fatalf("关停期丢弃误用了队列满文案，运维会去查容量而不是核对损失\nlog:\n%s", log)
	}
	if !strings.Contains(log, "type=access_log") || !strings.Contains(log, "dropped_total=3") {
		t.Fatalf("关停期丢弃告警缺少定位字段\nlog:\n%s", log)
	}
	if unifiedWriterQueueFullMessage == unifiedWriterClosedDropMessage {
		t.Fatal("两种丢弃原因的文案常量相同")
	}
}

// TestUnifiedWriterDropWarningStillRateLimitedAcrossReasons 钉住限流闸只有一把。
//
// 共用一把闸是有意的：丢弃本身才是运维要看的信号，原因只是它的属性。若拆成两把，
// 一次关停期丢弃会紧接着把队列满的告警放出来，在磁盘压力最大的关停阶段反而多打日志。
func TestUnifiedWriterDropWarningStillRateLimitedAcrossReasons(t *testing.T) {
	var buf bytes.Buffer
	writer := warnTestWriter(&buf)

	writer.RecordAccessLog(store.AccessLog{})
	writer.RecordAccessLog(store.AccessLog{}) // 队列满 → 第 1 条 WARN

	writer.closed.Store(true)
	for i := 0; i < 5; i++ {
		writer.RecordAccessLog(store.AccessLog{}) // 关停期丢弃 → 被同一把闸挡住
	}

	if got := strings.Count(buf.String(), "level=WARN"); got != 1 {
		t.Fatalf("WARN 条数 = %d, want 1（两种原因共用一把限流闸）\nlog:\n%s", got, buf.String())
	}
	if got := writer.Stats().AccessLogDropped; got != 6 {
		t.Fatalf("AccessLogDropped = %d, want 6", got)
	}
}
