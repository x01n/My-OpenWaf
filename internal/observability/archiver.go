package observability

import (
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"My-OpenWaf/internal/store/repository"
)

// RetentionConfig holds per-data-type retention periods in days.
// 0 means never clean (keep forever).
type RetentionConfig struct {
	SecurityEventDays int `json:"security_event_retention_days"`
	AccessLogDays     int `json:"access_log_retention_days"`
	DropEventDays     int `json:"drop_event_retention_days"`
	StatsDays         int `json:"stats_retention_days"`
}

func DefaultRetentionConfig() RetentionConfig {
	return RetentionConfig{
		SecurityEventDays: 30,
		AccessLogDays:     30,
		DropEventDays:     30,
		StatsDays:         7,
	}
}

// Archiver periodically deletes security events, access logs and drop events older than the retention period.
type Archiver struct {
	repo         *repository.SecurityEventRepo
	accessRepo   *repository.AccessLogRepo
	dropRepo     *repository.DropEventRepo
	settingsRepo *repository.SystemSettingsRepo
	log          *slog.Logger
	retention    atomic.Value // RetentionConfig
	interval     time.Duration
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

func NewArchiver(repo *repository.SecurityEventRepo, accessRepo *repository.AccessLogRepo, dropRepo *repository.DropEventRepo, log *slog.Logger, retentionDays int) *Archiver {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	cfg := RetentionConfig{
		SecurityEventDays: retentionDays,
		AccessLogDays:     retentionDays,
		DropEventDays:     retentionDays,
		StatsDays:         7,
	}
	a := &Archiver{
		repo:       repo,
		accessRepo: accessRepo,
		dropRepo:   dropRepo,
		log:        log,
		interval:   1 * time.Hour,
		stopCh:     make(chan struct{}),
	}
	a.retention.Store(cfg)
	a.wg.Add(1)
	go a.loop()
	return a
}

// SetSettingsRepo allows the archiver to read dynamic retention config from DB.
func (a *Archiver) SetSettingsRepo(repo *repository.SystemSettingsRepo) {
	a.settingsRepo = repo
}

// SetRetention updates the retention config dynamically.
func (a *Archiver) SetRetention(cfg RetentionConfig) {
	a.retention.Store(cfg)
}

func (a *Archiver) Close() {
	close(a.stopCh)
	a.wg.Wait()
}

func (a *Archiver) loop() {
	defer a.wg.Done()
	a.refreshRetentionFromDB()
	a.cleanup()

	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.refreshRetentionFromDB()
			a.cleanup()
		case <-a.stopCh:
			return
		}
	}
}

func (a *Archiver) refreshRetentionFromDB() {
	if a.settingsRepo == nil {
		return
	}
	val, err := a.settingsRepo.Get("retention_config")
	if err != nil || val == "" {
		return
	}
	var cfg RetentionConfig
	if json.Unmarshal([]byte(val), &cfg) == nil {
		a.retention.Store(cfg)
	}
}

func (a *Archiver) cleanup() {
	cfg := a.retention.Load().(RetentionConfig)

	if cfg.SecurityEventDays > 0 {
		cutoff := time.Now().Add(-time.Duration(cfg.SecurityEventDays) * 24 * time.Hour)
		deleted, err := a.repo.DeleteOlderThan(cutoff)
		if err != nil {
			a.log.Error("archiver: failed to delete old security events", slog.Any("err", err))
		} else if deleted > 0 {
			a.log.Info("archiver: cleaned old security events",
				slog.Int64("deleted", deleted),
				slog.String("older_than", cutoff.Format(time.RFC3339)))
		}
	}

	if cfg.AccessLogDays > 0 && a.accessRepo != nil {
		cutoff := time.Now().Add(-time.Duration(cfg.AccessLogDays) * 24 * time.Hour)
		accessDeleted, err := a.accessRepo.DeleteOlderThan(cutoff)
		if err != nil {
			a.log.Error("archiver: failed to delete old access logs", slog.Any("err", err))
		} else if accessDeleted > 0 {
			a.log.Info("archiver: cleaned old access logs",
				slog.Int64("deleted", accessDeleted),
				slog.String("older_than", cutoff.Format(time.RFC3339)))
		}
	}

	if cfg.DropEventDays > 0 && a.dropRepo != nil {
		cutoff := time.Now().Add(-time.Duration(cfg.DropEventDays) * 24 * time.Hour)
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
