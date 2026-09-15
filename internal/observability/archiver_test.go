package observability

import (
	"bytes"
	"log/slog"
	"sync"
	"testing"
	"time"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestArchiverDoesNotCleanupImmediatelyOnStart(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	archiver := NewArchiver(db, nil, nil, nil, slog.Default(), 30)
	defer archiver.Close()

	select {
	case <-archiver.stopCh:
		t.Fatal("archiver stopped unexpectedly")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestArchiverCloseIsIdempotentAndAcceptsNilLogger(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	archiver := NewArchiver(db, nil, nil, nil, nil, 30)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			archiver.Close()
		}()
	}
	wg.Wait()
	// 第二轮调用不得因重复关闭 stopCh 而 panic。
	archiver.Close()
	if archiver.log == nil {
		t.Fatal("NewArchiver did not install a fallback logger")
	}
}

func TestArchiverCleanupAndOptimizeAreSafeForZeroValueAndNilDependencies(t *testing.T) {
	var zero Archiver
	zero.cleanup()
	zero.optimizeDB()
	zero.Close()

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	archiver := &Archiver{log: log}
	archiver.retention.Store(RetentionConfig{SecurityEventDays: 1, AccessLogDays: 1, DropEventDays: 1})
	archiver.cleanup()
	if !bytes.Contains(buf.Bytes(), []byte("security event repository is nil")) {
		t.Fatalf("cleanup did not report nil security repository: %s", buf.String())
	}
}

func TestArchiverRetentionConfigClampsUnsafeValues(t *testing.T) {
	var buf bytes.Buffer
	archiver := &Archiver{log: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))}
	archiver.SetRetention(RetentionConfig{
		SecurityEventDays: -1,
		AccessLogDays:     maxArchiverRetentionDays + 1,
		DropEventDays:     0,
		StatsDays:         -2,
	})
	cfg := archiver.currentRetention()
	if cfg.SecurityEventDays != 0 || cfg.AccessLogDays != maxArchiverRetentionDays || cfg.DropEventDays != 0 || cfg.StatsDays != 0 {
		t.Fatalf("normalized retention = %+v", cfg)
	}
	if !bytes.Contains(buf.Bytes(), []byte("RetentionConfig.SecurityEventDays")) || !bytes.Contains(buf.Bytes(), []byte("RetentionConfig.AccessLogDays")) {
		t.Fatalf("retention clamp warnings missing: %s", buf.String())
	}
}

func TestArchiverIntervalNormalizationPreventsOverflow(t *testing.T) {
	if got, _ := normalizeArchiverIntervalSeconds(0); got != defaultArchiverIntervalSeconds {
		t.Fatalf("zero interval = %d, want %d", got, defaultArchiverIntervalSeconds)
	}
	if got, _ := normalizeArchiverIntervalSeconds(-1); got != defaultArchiverIntervalSeconds {
		t.Fatalf("negative interval = %d, want %d", got, defaultArchiverIntervalSeconds)
	}
	if got, clamped := normalizeArchiverIntervalSeconds(maxArchiverIntervalSeconds + 1); got != maxArchiverIntervalSeconds || !clamped {
		t.Fatalf("overflow interval = %d, clamped=%v", got, clamped)
	}
	if got, warnings := normalizeArchiverIntervalHours(0); got != defaultArchiverIntervalSeconds || len(warnings) == 0 {
		t.Fatalf("zero hours = %d, warnings=%v", got, warnings)
	}
	if got, warnings := normalizeArchiverIntervalHours(maxArchiverIntervalHours + 1); got != maxArchiverIntervalSeconds || len(warnings) == 0 {
		t.Fatalf("overflow hours = %d, warnings=%v", got, warnings)
	}
}

func TestArchiverRefreshSettingsClampsInvalidValues(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SystemSettings{}); err != nil {
		t.Fatalf("migrate settings: %v", err)
	}
	settings := repository.NewSystemSettingsRepo(db)
	if err := settings.Set("retention_config", `{"security_event_retention_days":-3,"access_log_retention_days":999999999,"drop_event_retention_days":0,"stats_retention_days":7}`); err != nil {
		t.Fatalf("set retention config: %v", err)
	}
	if err := settings.Set("db_optimize_interval_hours", "0"); err != nil {
		t.Fatalf("set interval: %v", err)
	}
	var buf bytes.Buffer
	archiver := &Archiver{
		log:          slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})),
		settingsRepo: settings,
	}
	archiver.retention.Store(RetentionConfig{SecurityEventDays: 30, AccessLogDays: 30, DropEventDays: 30, StatsDays: 7})
	archiver.interval.Store(123)
	archiver.refreshRetentionFromDB()
	if cfg := archiver.currentRetention(); cfg.SecurityEventDays != 0 || cfg.AccessLogDays != maxArchiverRetentionDays || cfg.DropEventDays != 0 || cfg.StatsDays != 7 {
		t.Fatalf("refreshed retention = %+v", cfg)
	}
	if got := archiver.interval.Load(); got != defaultArchiverIntervalSeconds {
		t.Fatalf("refreshed interval = %d, want %d", got, defaultArchiverIntervalSeconds)
	}
	if !bytes.Contains(buf.Bytes(), []byte("invalid")) || !bytes.Contains(buf.Bytes(), []byte("clamped")) {
		t.Fatalf("refresh warnings missing: %s", buf.String())
	}
}

func TestRunArchiverDeleteConvertsPanicToError(t *testing.T) {
	_, err := runArchiverDelete(func() (int64, error) {
		panic("broken repository")
	})
	if err == nil {
		t.Fatal("runArchiverDelete returned nil error for panic")
	}
}

func TestArchiverOptimizeSQLiteDoesNotPanicWithNilLogger(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	archiver := &Archiver{db: db}
	archiver.optimizeDB()
}
