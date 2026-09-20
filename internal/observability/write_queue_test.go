package observability

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

func TestWriteQueueStatsTracksFullAndClosedDrops(t *testing.T) {
	queue := &WriteQueue{
		ch:     make(chan writeQueueJob, 1),
		stopCh: make(chan struct{}),
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	fn := func(*gorm.DB) error { return nil }

	queue.Submit(fn)
	queue.Submit(fn)
	stats := queue.Stats()
	if stats.SubmittedTotal != 2 || stats.EnqueuedTotal != 1 {
		t.Fatalf("submission stats = %+v, want submitted=2 enqueued=1", stats)
	}
	if stats.DroppedFullTotal != 1 || stats.DroppedClosedTotal != 0 {
		t.Fatalf("drop stats before close = %+v, want full=1 closed=0", stats)
	}

	queue.Close()
	queue.Submit(fn)
	stats = queue.Stats()
	if !stats.Closed {
		t.Fatal("queue did not report closed state")
	}
	if stats.DroppedClosedTotal != 1 {
		t.Fatalf("DroppedClosedTotal = %d, want 1", stats.DroppedClosedTotal)
	}
}

func TestWriteQueueFlushBatchUsesSavepointsAndReportsFailures(t *testing.T) {
	db := newLogTestDB(t)
	queue := &WriteQueue{
		db:  db,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	wantErr := errors.New("expected callback failure")
	firstDone := make(chan error, 1)
	failingDone := make(chan error, 1)
	lastDone := make(chan error, 1)
	queue.flushBatch([]writeQueueJob{
		{
			fn: func(tx *gorm.DB) error {
				return tx.Create(&store.AccessLog{RequestID: "wq-first", Host: "wq.test", Path: "/first"}).Error
			},
			doneCh: firstDone,
		},
		{
			fn: func(tx *gorm.DB) error {
				if err := tx.Create(&store.AccessLog{RequestID: "wq-rollback", Host: "wq.test", Path: "/rollback"}).Error; err != nil {
					return err
				}
				return wantErr
			},
			doneCh: failingDone,
		},
		{
			fn: func(tx *gorm.DB) error {
				return tx.Create(&store.SecurityEvent{RequestID: "wq-last", Host: "wq.test", Path: "/last"}).Error
			},
			doneCh: lastDone,
		},
	})

	var first, rollback, last int64
	if err := db.Model(&store.AccessLog{}).Where("request_id = ?", "wq-first").Count(&first).Error; err != nil {
		t.Fatalf("count first access log: %v", err)
	}
	if err := db.Model(&store.AccessLog{}).Where("request_id = ?", "wq-rollback").Count(&rollback).Error; err != nil {
		t.Fatalf("count rolled back access log: %v", err)
	}
	if err := db.Model(&store.SecurityEvent{}).Where("request_id = ?", "wq-last").Count(&last).Error; err != nil {
		t.Fatalf("count last security event: %v", err)
	}
	if first != 1 || rollback != 0 || last != 1 {
		t.Fatalf("persisted rows first=%d rollback=%d last=%d, want 1/0/1", first, rollback, last)
	}

	if err := <-firstDone; err != nil {
		t.Fatalf("first callback result = %v, want nil", err)
	}
	if err := <-lastDone; err != nil {
		t.Fatalf("last callback result = %v, want nil", err)
	}
	if err := <-failingDone; !errors.Is(err, wantErr) {
		t.Fatalf("failing callback result = %v, want %v", err, wantErr)
	}

	stats := queue.Stats()
	if stats.BatchesTotal != 1 || stats.LastBatchJobs != 3 {
		t.Fatalf("batch stats = %+v, want one batch of three", stats)
	}
	if stats.ExecutedTotal != 3 || stats.SucceededTotal != 2 || stats.FailedJobsTotal != 1 {
		t.Fatalf("job stats = %+v, want executed=3 succeeded=2 failed=1", stats)
	}
	if stats.LastBatchSucceeded != 2 || stats.LastBatchFailed != 1 || stats.TransactionErrorsTotal != 0 {
		t.Fatalf("last batch stats = %+v, want succeeded=2 failed=1 tx_errors=0", stats)
	}
}

func TestWriteQueueFlushBatchRecoversPanics(t *testing.T) {
	db := newLogTestDB(t)
	queue := &WriteQueue{db: db, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	queue.flushBatch([]writeQueueJob{
		{fn: func(*gorm.DB) error { panic("bad observability callback") }},
		{fn: func(tx *gorm.DB) error {
			return tx.Create(&store.AccessLog{RequestID: "wq-after-panic", Host: "wq.test", Path: "/ok"}).Error
		}},
	})

	var count int64
	if err := db.Model(&store.AccessLog{}).Where("request_id = ?", "wq-after-panic").Count(&count).Error; err != nil {
		t.Fatalf("count post-panic access log: %v", err)
	}
	if count != 1 {
		t.Fatalf("post-panic access logs = %d, want 1", count)
	}
	stats := queue.Stats()
	if stats.ExecutedTotal != 2 || stats.SucceededTotal != 1 || stats.FailedJobsTotal != 1 {
		t.Fatalf("panic stats = %+v, want executed=2 succeeded=1 failed=1", stats)
	}
}

func TestWriteQueueFlushBatchReportsTransactionFailure(t *testing.T) {
	db := newLogTestDB(t)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sqlite db: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close sqlite db: %v", err)
	}

	doneA := make(chan error, 1)
	doneB := make(chan error, 1)
	queue := &WriteQueue{db: db, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	queue.flushBatch([]writeQueueJob{
		{fn: func(tx *gorm.DB) error {
			return tx.Create(&store.AccessLog{RequestID: "wq-tx-a", Host: "wq-tx.test", Path: "/a"}).Error
		}, doneCh: doneA},
		{fn: func(tx *gorm.DB) error {
			return tx.Create(&store.AccessLog{RequestID: "wq-tx-b", Host: "wq-tx.test", Path: "/b"}).Error
		}, doneCh: doneB},
	})
	if err := <-doneA; err == nil {
		t.Fatal("first transaction-failed callback returned nil")
	}
	if err := <-doneB; err == nil {
		t.Fatal("second transaction-failed callback returned nil")
	}
	stats := queue.Stats()
	if stats.ExecutedTotal != 0 || stats.SucceededTotal != 0 || stats.FailedJobsTotal != 2 {
		t.Fatalf("transaction failure stats = %+v, want executed=0 succeeded=0 failed=2", stats)
	}
	if stats.TransactionErrorsTotal != 1 || stats.LastBatchFailed != 2 {
		t.Fatalf("transaction failure counters = %+v, want tx_errors=1 last_failed=2", stats)
	}
}

func TestWriteQueueSubmitWaitFullUsesSynchronousFallback(t *testing.T) {
	db := newLogTestDB(t)
	queue := &WriteQueue{
		db:            db,
		ch:            make(chan writeQueueJob, 1),
		stopCh:        make(chan struct{}),
		batchInterval: time.Hour,
		maxBatchSize:  1,
		log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	queue.ch <- writeQueueJob{fn: func(*gorm.DB) error { return nil }}
	if err := queue.SubmitWait(func(tx *gorm.DB) error {
		return tx.Create(&store.AccessLog{RequestID: "wq-sync", Host: "wq.test", Path: "/sync"}).Error
	}); err != nil {
		t.Fatalf("SubmitWait fallback: %v", err)
	}
	<-queue.ch

	var count int64
	if err := db.Model(&store.AccessLog{}).Where("request_id = ?", "wq-sync").Count(&count).Error; err != nil {
		t.Fatalf("count synchronous access log: %v", err)
	}
	if count != 1 {
		t.Fatalf("synchronous access logs = %d, want 1", count)
	}
	stats := queue.Stats()
	if stats.SyncFallbackTotal != 1 || stats.ExecutedTotal != 1 || stats.SucceededTotal != 1 {
		t.Fatalf("fallback stats = %+v, want fallback=1 executed=1 succeeded=1", stats)
	}
	queue.Close()
}

func TestWriteQueueCloseDrainsInBoundedBatches(t *testing.T) {
	db := newLogTestDB(t)
	options := DefaultWriteQueueOptions()
	options.Capacity = 8
	options.BatchSize = 2
	options.BatchInterval = time.Hour
	queue := NewWriteQueueWithOptions(db, slog.New(slog.NewTextHandler(io.Discard, nil)), options)
	for i := 0; i < 5; i++ {
		requestID := "wq-close-" + string(rune('0'+i))
		queue.Submit(func(tx *gorm.DB) error {
			return tx.Create(&store.AccessLog{RequestID: requestID, Host: "wq-close.test", Path: "/close"}).Error
		})
	}
	queue.Close()

	var count int64
	if err := db.Model(&store.AccessLog{}).Where("host = ?", "wq-close.test").Count(&count).Error; err != nil {
		t.Fatalf("count close-drained access logs: %v", err)
	}
	if count != 5 {
		t.Fatalf("close-drained access logs = %d, want 5", count)
	}
	if stats := queue.Stats(); stats.BatchesTotal < 3 {
		t.Fatalf("close drain batches = %d, want at least 3 for batch size 2", stats.BatchesTotal)
	}
}
