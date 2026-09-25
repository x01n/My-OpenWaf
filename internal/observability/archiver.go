package observability

import (
	"context"
	"encoding/json"
	"errors"
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

// Archiver periodically deletes security events, access logs and drop events older than the retention period.
// After cleanup it runs lightweight SQLite planner/WAL maintenance or the native server-database optimizer.
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
	closeOnce    sync.Once
}

const (
	defaultArchiverRetentionDays = 30
	defaultArchiverStatsDays     = 7
	// 文档与系统设置均以小时表达清理间隔；默认值保持为现有运行时的 24 小时。
	defaultArchiverIntervalSeconds int64 = int64(24 * time.Hour / time.Second)

	// RetentionConfig 最终会转换成 time.Duration。上限取 Duration 能表示的整天数，
	// 防止恶意或损坏的设置在 cutoff 计算时发生整数溢出。
	maxArchiverRetentionDays = int((int64(1<<63 - 1)) / int64(24*time.Hour))
	// interval 同样以秒存储；该上限保证转换为 time.Duration 时不会溢出。
	maxArchiverIntervalSeconds = (int64(1<<63 - 1)) / int64(time.Second)
	maxArchiverIntervalHours   = maxArchiverIntervalSeconds / 3600

	// 数据库维护由归档后台执行，必须有上界，避免驱动不响应时阻塞进程关停。
	// 驱动支持 context 时会在期限到达后返回；不支持的驱动仍由其自身超时策略负责。
	archiverMaintenanceTimeout = 30 * time.Second
)

// logger 返回归档器可用的日志器。归档路径属于后台尽力执行能力，
// 即使嵌入方未提供 logger，也不能因为记录诊断信息反过来触发 panic。
func (a *Archiver) logger() *slog.Logger {
	if a == nil || a.log == nil {
		return slog.Default()
	}
	return a.log
}

// currentRetention 读取当前快照；对零值 Archiver 或尚未初始化的 atomic.Value
// 返回空配置，避免后台维护因类型断言 panic 而退出。
func (a *Archiver) currentRetention() RetentionConfig {
	if a == nil {
		return RetentionConfig{}
	}
	value := a.retention.Load()
	cfg, ok := value.(RetentionConfig)
	if !ok {
		return RetentionConfig{}
	}
	return cfg
}

func normalizeRetentionDays(name string, days int, warnings *[]string) int {
	if days < 0 {
		*warnings = append(*warnings, fmt.Sprintf("%s=%d is invalid, falling back to 0 (keep forever)", name, days))
		return 0
	}
	if days > maxArchiverRetentionDays {
		*warnings = append(*warnings, fmt.Sprintf("%s=%d exceeds the duration limit, clamped to %d", name, days, maxArchiverRetentionDays))
		return maxArchiverRetentionDays
	}
	return days
}

func normalizeRetentionConfig(cfg RetentionConfig) (RetentionConfig, []string) {
	var warnings []string
	cfg.SecurityEventDays = normalizeRetentionDays("RetentionConfig.SecurityEventDays", cfg.SecurityEventDays, &warnings)
	cfg.AccessLogDays = normalizeRetentionDays("RetentionConfig.AccessLogDays", cfg.AccessLogDays, &warnings)
	cfg.DropEventDays = normalizeRetentionDays("RetentionConfig.DropEventDays", cfg.DropEventDays, &warnings)
	cfg.StatsDays = normalizeRetentionDays("RetentionConfig.StatsDays", cfg.StatsDays, &warnings)
	return cfg, warnings
}

func normalizeArchiverIntervalSeconds(seconds int64) (int64, bool) {
	if seconds <= 0 {
		return defaultArchiverIntervalSeconds, seconds != defaultArchiverIntervalSeconds
	}
	if seconds > maxArchiverIntervalSeconds {
		return maxArchiverIntervalSeconds, true
	}
	return seconds, false
}

func normalizeArchiverIntervalHours(hours int64) (int64, []string) {
	if hours <= 0 {
		return defaultArchiverIntervalSeconds, []string{fmt.Sprintf("db_optimize_interval_hours=%d is invalid, falling back to %d hours", hours, defaultArchiverIntervalSeconds/3600)}
	}
	if hours > maxArchiverIntervalHours {
		return maxArchiverIntervalSeconds, []string{fmt.Sprintf("db_optimize_interval_hours=%d exceeds the duration limit, clamped to %d hours", hours, maxArchiverIntervalHours)}
	}
	return hours * 3600, nil
}

// runArchiverDelete 把仓库实现或测试替身中的 panic 转成普通错误，
// 确保单个日志表异常不会杀死整个归档循环。
func runArchiverDelete(fn func() (int64, error)) (deleted int64, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("archiver delete panic: %v", recovered)
		}
	}()
	return fn()
}

func NewArchiver(db *gorm.DB, repo *repository.SecurityEventRepo, accessRepo *repository.AccessLogRepo, dropRepo *repository.DropEventRepo, log *slog.Logger, retentionDays int) *Archiver {
	if retentionDays <= 0 {
		retentionDays = defaultArchiverRetentionDays
	}
	cfg := RetentionConfig{
		SecurityEventDays: retentionDays,
		AccessLogDays:     retentionDays,
		DropEventDays:     retentionDays,
		StatsDays:         defaultArchiverStatsDays,
	}
	cfg, clampWarnings := normalizeRetentionConfig(cfg)
	if log == nil {
		log = slog.Default()
	}
	for _, warning := range clampWarnings {
		log.Warn(warning)
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
	a.interval.Store(defaultArchiverIntervalSeconds)
	a.wg.Add(1)
	go a.loop()
	return a
}

// SetSettingsRepo allows the archiver to read dynamic retention config from DB.
func (a *Archiver) SetSettingsRepo(repo *repository.SystemSettingsRepo) {
	if a == nil {
		return
	}
	a.settingsRepo = repo
}

// SetSyncLogRepo 注入威胁情报同步日志仓库，启用同步历史保留清理。
// 保留天数复用 DropEventDays（同类"运维辅助日志"通常一致）。
func (a *Archiver) SetSyncLogRepo(repo *repository.ThreatIntelSyncLogRepo) {
	if a == nil {
		return
	}
	a.syncLogRepo = repo
}

// SetRetention updates the retention config dynamically.
func (a *Archiver) SetRetention(cfg RetentionConfig) {
	if a == nil {
		return
	}
	cfg, warnings := normalizeRetentionConfig(cfg)
	a.retention.Store(cfg)
	for _, warning := range warnings {
		a.logger().Warn(warning)
	}
}

func (a *Archiver) Close() {
	if a == nil {
		return
	}
	a.closeOnce.Do(func() {
		if a.stopCh != nil {
			close(a.stopCh)
		}
	})
	a.wg.Wait()
}

func (a *Archiver) loop() {
	defer a.wg.Done()

	for {
		rawIntervalSec := a.interval.Load()
		intervalSec, clamped := normalizeArchiverIntervalSeconds(rawIntervalSec)
		if clamped {
			a.interval.Store(intervalSec)
			a.logger().Warn("archiver: invalid cleanup interval, using a safe value",
				slog.Int64("interval_seconds", rawIntervalSec),
				slog.Int64("effective_interval_seconds", intervalSec))
		}
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
	if a == nil || a.settingsRepo == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			a.logger().Error("archiver: failed to refresh settings", slog.Any("err", fmt.Errorf("settings refresh panic: %v", recovered)))
		}
	}()

	// Refresh retention config.
	val, err := a.settingsRepo.Get("retention_config")
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			a.logger().Warn("archiver: failed to read retention_config", slog.Any("err", err))
		}
	} else if val != "" {
		var cfg RetentionConfig
		if unmarshalErr := json.Unmarshal([]byte(val), &cfg); unmarshalErr == nil {
			var warnings []string
			cfg, warnings = normalizeRetentionConfig(cfg)
			a.retention.Store(cfg)
			for _, warning := range warnings {
				a.logger().Warn(warning)
			}
		} else {
			a.logger().Warn("archiver: invalid retention_config, keeping the previous value", slog.Any("err", unmarshalErr))
		}
	}

	// Also read individual settings keys for retention days. Individual keys
	// intentionally override only their corresponding field in the JSON object.
	applyDaysSetting := func(key string, assign func(*RetentionConfig, int)) {
		value, readErr := a.settingsRepo.Get(key)
		if readErr != nil {
			if !errors.Is(readErr, gorm.ErrRecordNotFound) {
				a.logger().Warn("archiver: failed to read retention setting", slog.String("key", key), slog.Any("err", readErr))
			}
			return
		}
		if value == "" {
			return
		}
		days, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil {
			a.logger().Warn("archiver: invalid retention setting", slog.String("key", key), slog.String("value", value), slog.Any("err", parseErr))
			return
		}
		if days > int64(maxArchiverRetentionDays) {
			days = int64(maxArchiverRetentionDays)
		}
		if days < int64(-maxArchiverRetentionDays) {
			days = -int64(maxArchiverRetentionDays)
		}
		cfg := a.currentRetention()
		assign(&cfg, int(days))
		cfg, warnings := normalizeRetentionConfig(cfg)
		a.retention.Store(cfg)
		for _, warning := range warnings {
			a.logger().Warn(warning)
		}
	}
	applyDaysSetting("security_event_retention_days", func(cfg *RetentionConfig, days int) {
		cfg.SecurityEventDays = days
	})
	applyDaysSetting("access_log_retention_days", func(cfg *RetentionConfig, days int) {
		cfg.AccessLogDays = days
	})

	// Refresh cleanup interval from DB setting (in hours).
	if iv, e := a.settingsRepo.Get("db_optimize_interval_hours"); e != nil {
		if !errors.Is(e, gorm.ErrRecordNotFound) {
			a.logger().Warn("archiver: failed to read cleanup interval", slog.Any("err", e))
		}
	} else if iv != "" {
		hours, pe := strconv.ParseInt(iv, 10, 64)
		if pe != nil {
			a.logger().Warn("archiver: invalid cleanup interval", slog.String("value", iv), slog.Any("err", pe))
		} else {
			seconds, warnings := normalizeArchiverIntervalHours(hours)
			a.interval.Store(seconds)
			for _, warning := range warnings {
				a.logger().Warn(warning)
			}
		}
	}
}

func (a *Archiver) cleanup() {
	if a == nil {
		return
	}
	cfg, warnings := normalizeRetentionConfig(a.currentRetention())
	for _, warning := range warnings {
		a.logger().Warn(warning)
	}

	if cfg.SecurityEventDays > 0 {
		cutoff := time.Now().Add(-time.Duration(cfg.SecurityEventDays) * 24 * time.Hour)
		if a.repo == nil {
			a.logger().Warn("archiver: security event repository is nil, skipping cleanup")
		} else {
			deleted, err := runArchiverDelete(func() (int64, error) {
				return a.repo.DeleteOlderThan(cutoff)
			})
			if err != nil {
				a.logger().Error("archiver: failed to delete old security events", slog.Any("err", err))
			} else if deleted > 0 {
				a.logger().Info("archiver: cleaned old security events",
					slog.Int64("deleted", deleted),
					slog.String("older_than", cutoff.Format(time.RFC3339)))
			}
		}
	}

	if cfg.AccessLogDays > 0 && a.accessRepo != nil {
		cutoff := time.Now().Add(-time.Duration(cfg.AccessLogDays) * 24 * time.Hour)
		accessDeleted, err := runArchiverDelete(func() (int64, error) {
			return a.accessRepo.DeleteOlderThan(cutoff)
		})
		if err != nil {
			a.logger().Error("archiver: failed to delete old access logs", slog.Any("err", err))
		} else if accessDeleted > 0 {
			a.logger().Info("archiver: cleaned old access logs",
				slog.Int64("deleted", accessDeleted),
				slog.String("older_than", cutoff.Format(time.RFC3339)))
		}
	}

	if cfg.DropEventDays > 0 && a.dropRepo != nil {
		cutoff := time.Now().Add(-time.Duration(cfg.DropEventDays) * 24 * time.Hour)
		dropDeleted, err := runArchiverDelete(func() (int64, error) {
			return a.dropRepo.DeleteOlderThan(cutoff)
		})
		if err != nil {
			a.logger().Error("archiver: failed to delete old drop events", slog.Any("err", err))
		} else if dropDeleted > 0 {
			a.logger().Info("archiver: cleaned old drop events",
				slog.Int64("deleted", dropDeleted),
				slog.String("older_than", cutoff.Format(time.RFC3339)))
		}
	}

	// 威胁情报同步日志复用 DropEventDays 的保留期（同类"运维辅助日志"）。
	if cfg.DropEventDays > 0 && a.syncLogRepo != nil {
		cutoff := time.Now().Add(-time.Duration(cfg.DropEventDays) * 24 * time.Hour)
		syncDeleted, err := runArchiverDelete(func() (int64, error) {
			return a.syncLogRepo.DeleteOlderThan(cutoff)
		})
		if err != nil {
			a.logger().Error("archiver: failed to delete old threat-intel sync logs", slog.Any("err", err))
		} else if syncDeleted > 0 {
			a.logger().Info("archiver: cleaned old threat-intel sync logs",
				slog.Int64("deleted", syncDeleted),
				slog.String("older_than", cutoff.Format(time.RFC3339)))
		}
	}
}

// optimizeDB updates planner/storage state after cleanup.
// SQLite uses PRAGMA optimize plus a non-blocking passive WAL checkpoint; MySQL and PostgreSQL use their native maintenance commands.
func (a *Archiver) optimizeDB() {
	if a == nil || a.db == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			a.logger().Error("archiver: database optimization panicked", slog.Any("err", fmt.Errorf("optimization panic: %v", recovered)))
		}
	}()

	start := time.Now()
	driver := detectDriver(a.db)
	ctx, cancel := context.WithTimeout(context.Background(), archiverMaintenanceTimeout)
	defer cancel()

	var err error
	switch driver {
	case "sqlite":
		err = a.optimizeSQLiteContext(ctx)
	case "mysql":
		err = a.optimizeMySQLContext(ctx)
	case "postgres":
		err = a.optimizePostgresContext(ctx)
	default:
		a.logger().Warn("archiver: unknown DB driver, skip optimization", slog.String("driver", driver))
		return
	}

	if err != nil {
		a.logger().Error("archiver: database optimization failed", slog.Any("err", err), slog.String("driver", driver))
	} else {
		a.logger().Info("archiver: database optimized",
			slog.String("driver", driver),
			slog.Duration("elapsed", time.Since(start)))
	}
}

func (a *Archiver) optimizeSQLite() error {
	return a.optimizeSQLiteContext(context.Background())
}

func (a *Archiver) optimizeSQLiteContext(ctx context.Context) error {
	if a == nil || a.db == nil {
		return nil
	}
	db := a.db.WithContext(ctx)
	var errs []error
	// PRAGMA optimize updates planner statistics only when SQLite determines it is useful.
	if err := db.Exec("PRAGMA optimize").Error; err != nil {
		a.logger().Warn("archiver: PRAGMA optimize failed", slog.Any("err", err))
		errs = append(errs, fmt.Errorf("PRAGMA optimize: %w", err))
	}
	// PASSIVE checkpoints completed WAL frames without blocking active readers or writers.
	// Deleted pages remain reusable by SQLite; shrinking the whole database requires an
	// explicit maintenance operation instead of an unconditional daily VACUUM.
	if err := db.Exec("PRAGMA wal_checkpoint(PASSIVE)").Error; err != nil {
		a.logger().Warn("archiver: wal_checkpoint(PASSIVE) failed", slog.Any("err", err))
		errs = append(errs, fmt.Errorf("wal_checkpoint(PASSIVE): %w", err))
	}
	// TRUNCATE 在常规 checkpoint 后将 WAL 文件截断归零：本归档器仅作用于 LogDB，
	// 该库只新增（insert）不更新，长尾 WAL 页已 checkpoint 后可安全回收，
	// 防止 WAL 体积随写入持续增长而放大后续 flush 的页活动。
	if err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)").Error; err != nil {
		a.logger().Warn("archiver: wal_checkpoint(TRUNCATE) failed", slog.Any("err", err))
		errs = append(errs, fmt.Errorf("wal_checkpoint(TRUNCATE): %w", err))
	}
	return errors.Join(errs...)
}

func (a *Archiver) optimizeMySQL() error {
	return a.optimizeMySQLContext(context.Background())
}

func (a *Archiver) optimizeMySQLContext(ctx context.Context) error {
	if a == nil || a.db == nil {
		return nil
	}
	db := a.db.WithContext(ctx)
	tables := []string{"security_events", "access_logs", "drop_events", "bot_score_logs"}
	var errs []error
	for _, t := range tables {
		if err := db.Exec(fmt.Sprintf("OPTIMIZE TABLE `%s`", t)).Error; err != nil {
			a.logger().Warn("archiver: OPTIMIZE TABLE failed", slog.String("table", t), slog.Any("err", err))
			errs = append(errs, fmt.Errorf("OPTIMIZE TABLE %s: %w", t, err))
		}
	}
	// Update table statistics for better query planning.
	for _, t := range tables {
		if err := db.Exec(fmt.Sprintf("ANALYZE TABLE `%s`", t)).Error; err != nil {
			a.logger().Warn("archiver: ANALYZE TABLE failed", slog.String("table", t), slog.Any("err", err))
			errs = append(errs, fmt.Errorf("ANALYZE TABLE %s: %w", t, err))
		}
	}
	return errors.Join(errs...)
}

func (a *Archiver) optimizePostgres() error {
	return a.optimizePostgresContext(context.Background())
}

func (a *Archiver) optimizePostgresContext(ctx context.Context) error {
	if a == nil || a.db == nil {
		return nil
	}
	db := a.db.WithContext(ctx)
	tables := []string{"security_events", "access_logs", "drop_events", "bot_score_logs"}
	var errs []error
	for _, t := range tables {
		if err := db.Exec(fmt.Sprintf("VACUUM ANALYZE %s", t)).Error; err != nil {
			a.logger().Warn("archiver: VACUUM ANALYZE failed", slog.String("table", t), slog.Any("err", err))
			errs = append(errs, fmt.Errorf("VACUUM ANALYZE %s: %w", t, err))
		}
	}
	return errors.Join(errs...)
}

// detectDriver determines the database driver type from the GORM dialector name.
func detectDriver(db *gorm.DB) string {
	if db == nil || db.Dialector == nil {
		return ""
	}
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
