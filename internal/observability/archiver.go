package observability

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"My-OpenWaf/internal/store/repository"

	"gorm.io/gorm"
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
// After cleanup it optimizes the database (VACUUM for SQLite, OPTIMIZE TABLE for MySQL, VACUUM ANALYZE for PostgreSQL).
type Archiver struct {
	repo         *repository.SecurityEventRepo
	accessRepo   *repository.AccessLogRepo
	dropRepo     *repository.DropEventRepo
	syncLogRepo  *repository.ThreatIntelSyncLogRepo
	settingsRepo *repository.SystemSettingsRepo
	db           *gorm.DB
	log          *slog.Logger
	retention    atomic.Value // RetentionConfig
	interval     atomic.Int64 // cleanup interval in seconds
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

func NewArchiver(db *gorm.DB, repo *repository.SecurityEventRepo, accessRepo *repository.AccessLogRepo, dropRepo *repository.DropEventRepo, log *slog.Logger, retentionDays int) *Archiver {
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
		db:         db,
		repo:       repo,
		accessRepo: accessRepo,
		dropRepo:   dropRepo,
		log:        log,
		stopCh:     make(chan struct{}),
	}
	a.retention.Store(cfg)
	a.interval.Store(int64(24 * time.Hour / time.Second)) // default: 24 hours
	a.wg.Add(1)
	go a.loop()
	return a
}

// SetSettingsRepo allows the archiver to read dynamic retention config from DB.
func (a *Archiver) SetSettingsRepo(repo *repository.SystemSettingsRepo) {
	a.settingsRepo = repo
}

// SetSyncLogRepo 注入威胁情报同步日志仓库，启用同步历史保留清理。
// 保留天数复用 DropEventDays（同类"运维辅助日志"通常一致）。
func (a *Archiver) SetSyncLogRepo(repo *repository.ThreatIntelSyncLogRepo) {
	a.syncLogRepo = repo
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

	for {
		intervalSec := a.interval.Load()
		timer := time.NewTimer(time.Duration(intervalSec) * time.Second)
		select {
		case <-timer.C:
			a.refreshRetentionFromDB()
			a.cleanup()
			a.optimizeDB()
		case <-a.stopCh:
			timer.Stop()
			return
		}
	}
}

func (a *Archiver) refreshRetentionFromDB() {
	if a.settingsRepo == nil {
		return
	}
	// Refresh retention config.
	val, err := a.settingsRepo.Get("retention_config")
	if err == nil && val != "" {
		var cfg RetentionConfig
		if json.Unmarshal([]byte(val), &cfg) == nil {
			a.retention.Store(cfg)
		}
	}

	// Also read individual settings keys for retention days.
	if v, e := a.settingsRepo.Get("security_event_retention_days"); e == nil && v != "" {
		if days, pe := strconv.Atoi(v); pe == nil {
			cfg := a.retention.Load().(RetentionConfig)
			cfg.SecurityEventDays = days
			a.retention.Store(cfg)
		}
	}
	if v, e := a.settingsRepo.Get("access_log_retention_days"); e == nil && v != "" {
		if days, pe := strconv.Atoi(v); pe == nil {
			cfg := a.retention.Load().(RetentionConfig)
			cfg.AccessLogDays = days
			a.retention.Store(cfg)
		}
	}

	// Refresh cleanup interval from DB setting (in hours).
	if iv, e := a.settingsRepo.Get("db_optimize_interval_hours"); e == nil && iv != "" {
		if hours, pe := strconv.Atoi(iv); pe == nil && hours > 0 {
			a.interval.Store(int64(hours) * 3600)
		}
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

	// 威胁情报同步日志复用 DropEventDays 的保留期（同类"运维辅助日志"）。
	if cfg.DropEventDays > 0 && a.syncLogRepo != nil {
		cutoff := time.Now().Add(-time.Duration(cfg.DropEventDays) * 24 * time.Hour)
		syncDeleted, err := a.syncLogRepo.DeleteOlderThan(cutoff)
		if err != nil {
			a.log.Error("archiver: failed to delete old threat-intel sync logs", slog.Any("err", err))
		} else if syncDeleted > 0 {
			a.log.Info("archiver: cleaned old threat-intel sync logs",
				slog.Int64("deleted", syncDeleted),
				slog.String("older_than", cutoff.Format(time.RFC3339)))
		}
	}
}

// optimizeDB reclaims space and updates statistics for the database after cleanup.
// Supports SQLite (VACUUM + PRAGMA optimize), MySQL (OPTIMIZE TABLE), and PostgreSQL (VACUUM ANALYZE).
func (a *Archiver) optimizeDB() {
	if a.db == nil {
		return
	}

	start := time.Now()
	driver := detectDriver(a.db)

	var err error
	switch driver {
	case "sqlite":
		err = a.optimizeSQLite()
	case "mysql":
		err = a.optimizeMySQL()
	case "postgres":
		err = a.optimizePostgres()
	default:
		a.log.Warn("archiver: unknown DB driver, skip optimization", slog.String("driver", driver))
		return
	}

	if err != nil {
		a.log.Error("archiver: database optimization failed", slog.Any("err", err), slog.String("driver", driver))
	} else {
		a.log.Info("archiver: database optimized",
			slog.String("driver", driver),
			slog.Duration("elapsed", time.Since(start)))
	}
}

func (a *Archiver) optimizeSQLite() error {
	// Run PRAGMA optimize to update query planner statistics.
	if err := a.db.Exec("PRAGMA optimize").Error; err != nil {
		a.log.Warn("archiver: PRAGMA optimize failed", slog.Any("err", err))
	}
	// Run incremental_vacuum first (lighter operation for WAL mode).
	if err := a.db.Exec("PRAGMA incremental_vacuum(1000)").Error; err != nil {
		a.log.Warn("archiver: incremental_vacuum failed", slog.Any("err", err))
	}
	// Run WAL checkpoint to keep WAL file size reasonable.
	if err := a.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)").Error; err != nil {
		a.log.Warn("archiver: wal_checkpoint failed", slog.Any("err", err))
	}
	// VACUUM to fully reclaim space (only if large amount was deleted).
	return a.db.Exec("VACUUM").Error
}

func (a *Archiver) optimizeMySQL() error {
	tables := []string{"security_events", "access_logs", "drop_events", "bot_score_logs"}
	for _, t := range tables {
		if err := a.db.Exec(fmt.Sprintf("OPTIMIZE TABLE `%s`", t)).Error; err != nil {
			a.log.Warn("archiver: OPTIMIZE TABLE failed", slog.String("table", t), slog.Any("err", err))
		}
	}
	// Update table statistics for better query planning.
	for _, t := range tables {
		if err := a.db.Exec(fmt.Sprintf("ANALYZE TABLE `%s`", t)).Error; err != nil {
			a.log.Warn("archiver: ANALYZE TABLE failed", slog.String("table", t), slog.Any("err", err))
		}
	}
	return nil
}

func (a *Archiver) optimizePostgres() error {
	tables := []string{"security_events", "access_logs", "drop_events", "bot_score_logs"}
	for _, t := range tables {
		if err := a.db.Exec(fmt.Sprintf("VACUUM ANALYZE %s", t)).Error; err != nil {
			a.log.Warn("archiver: VACUUM ANALYZE failed", slog.String("table", t), slog.Any("err", err))
		}
	}
	return nil
}

// detectDriver determines the database driver type from the GORM dialector name.
func detectDriver(db *gorm.DB) string {
	name := db.Dialector.Name()
	switch {
	case strings.Contains(name, "sqlite"):
		return "sqlite"
	case strings.Contains(name, "mysql"):
		return "mysql"
	case strings.Contains(name, "postgres"):
		return "postgres"
	default:
		return name
	}
}
