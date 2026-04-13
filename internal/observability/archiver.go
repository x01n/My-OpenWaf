package observability

import (
	"log/slog"
	"sync"
	"time"

	"My-OpenWaf/internal/store/repository"
)

// Archiver periodically deletes security events older than the retention period.
type Archiver struct {
	repo      *repository.SecurityEventRepo
	log       *slog.Logger
	retention time.Duration
	interval  time.Duration
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

func NewArchiver(repo *repository.SecurityEventRepo, log *slog.Logger, retentionDays int) *Archiver {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	a := &Archiver{
		repo:      repo,
		log:       log,
		retention: time.Duration(retentionDays) * 24 * time.Hour,
		interval:  1 * time.Hour,
		stopCh:    make(chan struct{}),
	}
	a.wg.Add(1)
	go a.loop()
	return a
}

func (a *Archiver) Close() {
	close(a.stopCh)
	a.wg.Wait()
}

func (a *Archiver) loop() {
	defer a.wg.Done()
	// Run once on startup.
	a.cleanup()

	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.cleanup()
		case <-a.stopCh:
			return
		}
	}
}

func (a *Archiver) cleanup() {
	cutoff := time.Now().Add(-a.retention)
	deleted, err := a.repo.DeleteOlderThan(cutoff)
	if err != nil {
		a.log.Error("archiver: failed to delete old events", slog.Any("err", err))
		return
	}
	if deleted > 0 {
		a.log.Info("archiver: cleaned old security events",
			slog.Int64("deleted", deleted),
			slog.String("older_than", cutoff.Format(time.RFC3339)))
	}
}
