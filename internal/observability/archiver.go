package observability

import (
	"log/slog"
	"sync"
	"time"

	"My-OpenWaf/internal/store/repository"
)

// Archiver periodically deletes security events and drop events older than the retention period.
type Archiver struct {
	repo       *repository.SecurityEventRepo
	accessRepo *repository.AccessLogRepo
	dropRepo   *repository.DropEventRepo
	log        *slog.Logger
	retention  time.Duration
	interval   time.Duration
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

func NewArchiver(repo *repository.SecurityEventRepo, accessRepo *repository.AccessLogRepo, dropRepo *repository.DropEventRepo, log *slog.Logger, retentionDays int) *Archiver {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	a := &Archiver{
		repo:       repo,
		accessRepo: accessRepo,
		dropRepo:   dropRepo,
		log:        log,
		retention:  time.Duration(retentionDays) * 24 * time.Hour,
		interval:   1 * time.Hour,
		stopCh:     make(chan struct{}),
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

	// Clean security events.
	deleted, err := a.repo.DeleteOlderThan(cutoff)
	if err != nil {
		a.log.Error("archiver: failed to delete old security events", slog.Any("err", err))
	} else if deleted > 0 {
		a.log.Info("archiver: cleaned old security events",
			slog.Int64("deleted", deleted),
			slog.String("older_than", cutoff.Format(time.RFC3339)))
	}

	// Clean access logs.
	if a.accessRepo != nil {
		accessDeleted, err := a.accessRepo.DeleteOlderThan(cutoff)
		if err != nil {
			a.log.Error("archiver: failed to delete old access logs", slog.Any("err", err))
		} else if accessDeleted > 0 {
			a.log.Info("archiver: cleaned old access logs",
				slog.Int64("deleted", accessDeleted),
				slog.String("older_than", cutoff.Format(time.RFC3339)))
		}
	}

	// Clean drop events.
	if a.dropRepo != nil {
		dropDeleted, err := a.dropRepo.DeleteOlderThan(cutoff)
		if err != nil {
			a.log.Error("archiver: failed to delete old drop events", slog.Any("err", err))
		} else if dropDeleted > 0 {
			a.log.Info("archiver: cleaned old drop events",
				slog.Int64("deleted", dropDeleted),
				slog.String("older_than", cutoff.Format(time.RFC3339)))
		}
	}
}
