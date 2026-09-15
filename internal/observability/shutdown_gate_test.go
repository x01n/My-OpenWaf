package observability

import (
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"My-OpenWaf/internal/store"
	"gorm.io/gorm"
)

// TestUnifiedWriterCloseWaitsForInFlightRecord 验证关闭不会越过正在发送的记录。
func TestUnifiedWriterCloseWaitsForInFlightRecord(t *testing.T) {
	db := newLogTestDB(t)
	opts := DefaultUnifiedWriterOptions()
	opts.EventBufferSize = 1
	opts.FlushInterval = time.Hour
	writer := NewUnifiedWriterWithOptions(db, slog.New(slog.NewTextHandler(io.Discard, nil)), opts)

	writer.submitMu.RLock()
	closed := make(chan struct{})
	go func() {
		writer.Close()
		close(closed)
	}()

	select {
	case <-closed:
		t.Fatal("Close returned while a record submission held the gate")
	case <-time.After(20 * time.Millisecond):
	}

	// 发送发生在关闭闸门仍由读锁保护的窗口内，随后 Close 才能发布 stopCh。
	writer.eventCh <- store.SecurityEvent{RequestID: "in-flight"}
	writer.submitMu.RUnlock()

	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not return after the submission gate was released")
	}
	if !writer.closed.Load() {
		t.Fatal("Close did not mark the writer closed")
	}
	var persisted int64
	if err := db.Model(&store.SecurityEvent{}).Where("request_id = ?", "in-flight").Count(&persisted).Error; err != nil {
		t.Fatalf("count in-flight event: %v", err)
	}
	if persisted != 1 {
		t.Fatalf("persisted in-flight events = %d, want 1", persisted)
	}
	writer.RecordEvent(store.SecurityEvent{RequestID: "after-close"})
	if got := writer.Stats().SecurityEventDropped; got != 1 {
		t.Fatalf("SecurityEventDropped = %d, want 1 after close", got)
	}
}

// TestWriteQueueCloseWaitsForInFlightSubmit 验证关闭与入队之间没有悬空任务窗口。
func TestWriteQueueCloseWaitsForInFlightSubmit(t *testing.T) {
	db := newLogTestDB(t)
	opts := DefaultWriteQueueOptions()
	opts.Capacity = 1
	opts.BatchInterval = time.Hour
	queue := NewWriteQueueWithOptions(db, slog.New(slog.NewTextHandler(io.Discard, nil)), opts)

	queue.submitMu.RLock()
	closed := make(chan struct{})
	go func() {
		queue.Close()
		close(closed)
	}()

	select {
	case <-closed:
		t.Fatal("Close returned while a submission held the gate")
	case <-time.After(20 * time.Millisecond):
	}

	var executed atomic.Int64
	queue.ch <- writeQueueJob{fn: func(_ *gorm.DB) error {
		executed.Add(1)
		return nil
	}}
	queue.submitMu.RUnlock()

	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not return after the submission gate was released")
	}
	if !queue.closed.Load() {
		t.Fatal("Close did not mark the queue closed")
	}
	if got := executed.Load(); got != 1 {
		t.Fatalf("executed in-flight jobs = %d, want 1", got)
	}
	queue.Submit(func(_ *gorm.DB) error {
		executed.Add(1)
		return nil
	})
	if got := len(queue.ch); got != 0 {
		t.Fatalf("queued jobs after Close = %d, want 0", got)
	}
	if got := executed.Load(); got != 1 {
		t.Fatalf("executed jobs after Close = %d, want 1", got)
	}
	if err := queue.SubmitWait(func(_ *gorm.DB) error { return nil }); err != ErrWriteQueueClosed {
		t.Fatalf("SubmitWait after Close error = %v, want ErrWriteQueueClosed", err)
	}
	if err := queue.SubmitPriority(func(_ *gorm.DB) error { return nil }); err != ErrWriteQueueClosed {
		t.Fatalf("SubmitPriority after Close error = %v, want ErrWriteQueueClosed", err)
	}
	queue.Close()
}
