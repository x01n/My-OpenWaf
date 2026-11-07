package core

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

/**
 * newConfigOverrideDBForTest 建立仅含系统设置表的内存库。
 */
func newConfigOverrideDBForTest(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SystemSettings{}); err != nil {
		t.Fatalf("migrate system settings: %v", err)
	}
	return db
}

/**
 * TestApplyStoredConfigOverridesAppliesQueueAndCacheKeys 断言「启动固化」一档的键
 * 在启动期真的被读进 Config。
 *
 * 这条断言是端点 restart_required=true 的对偶：端点声称「写进覆盖表、下次重启用上」，
 * 若 ApplyStoredConfigOverrides 不读它们，那次重启读到的仍是环境变量，界面上的
 * 保存就被静默丢弃了。
 */
func TestApplyStoredConfigOverridesAppliesQueueAndCacheKeys(t *testing.T) {
	db := newConfigOverrideDBForTest(t)
	const raw = `{
		"queue_event_buffer_size":{"value":4096,"set":true},
		"queue_drop_buffer_size":{"value":2048,"set":true},
		"queue_batch_size":{"value":512,"set":true},
		"queue_flush_interval":{"value":"7s","set":true},
		"queue_write_batch_size":{"value":128,"set":true},
		"queue_write_capacity":{"value":512,"set":true},
		"queue_write_interval":{"value":"25ms","set":true},
		"response_cache_mb":{"value":128,"set":true},
		"response_cache_ttl_sec":{"value":300,"set":true},
		"request_decompress_limit_bytes":{"value":1048576,"set":true},
		"response_decompress_limit_bytes":{"value":2097152,"set":true},
		"admin_static_dir":{"value":"/srv/dist","set":true},
		"captcha_dir":{"value":"/srv/captcha","set":true},
		"accesslog_sampling":{"value":10,"set":true},
		"trace_enabled":{"value":true,"set":true},
		"trace_level":{"value":"base","set":true},
		"log_color":{"value":"on","set":true}
	}`
	if err := db.Create(&store.SystemSettings{Key: store.SettingKeyRuntimeConfigOverrides, Value: raw}).Error; err != nil {
		t.Fatalf("seed overrides: %v", err)
	}

	got, warns := ApplyStoredConfigOverrides(db, LoadConfigFromEnv())
	if len(warns) != 0 {
		t.Fatalf("warnings = %#v, want none for a clean table", warns)
	}

	if got.Queue.EventBufferSize != 4096 {
		t.Errorf("Queue.EventBufferSize = %d, want 4096", got.Queue.EventBufferSize)
	}
	if got.Queue.DropBufferSize != 2048 {
		t.Errorf("Queue.DropBufferSize = %d, want 2048", got.Queue.DropBufferSize)
	}
	if got.Queue.BatchSize != 512 {
		t.Errorf("Queue.BatchSize = %d, want 512", got.Queue.BatchSize)
	}
	if got.Queue.FlushInterval != 7*time.Second {
		t.Errorf("Queue.FlushInterval = %s, want 7s", got.Queue.FlushInterval)
	}
	if got.Queue.WriteQueueBatchSize != 128 {
		t.Errorf("Queue.WriteQueueBatchSize = %d, want 128", got.Queue.WriteQueueBatchSize)
	}
	if got.Queue.WriteQueueCapacity != 512 {
		t.Errorf("Queue.WriteQueueCapacity = %d, want 512", got.Queue.WriteQueueCapacity)
	}
	if got.Queue.WriteQueueInterval != 25*time.Millisecond {
		t.Errorf("Queue.WriteQueueInterval = %s, want 25ms", got.Queue.WriteQueueInterval)
	}
	if got.ResponseCacheMB != 128 {
		t.Errorf("ResponseCacheMB = %d, want 128", got.ResponseCacheMB)
	}
	if got.ResponseCacheTTLSec != 300 {
		t.Errorf("ResponseCacheTTLSec = %d, want 300", got.ResponseCacheTTLSec)
	}
	if got.RequestDecompressionMaxBytes != 1048576 {
		t.Errorf("RequestDecompressionMaxBytes = %d, want 1048576", got.RequestDecompressionMaxBytes)
	}
	if got.ResponseDecompressionMaxBytes != 2097152 {
		t.Errorf("ResponseDecompressionMaxBytes = %d, want 2097152", got.ResponseDecompressionMaxBytes)
	}
	if got.AdminStaticDir != "/srv/dist" {
		t.Errorf("AdminStaticDir = %q, want /srv/dist", got.AdminStaticDir)
	}
	if got.CaptchaDir != "/srv/captcha" {
		t.Errorf("CaptchaDir = %q, want /srv/captcha", got.CaptchaDir)
	}
	if got.AccessLogSamplingRate != 10 {
		t.Errorf("AccessLogSamplingRate = %d, want 10", got.AccessLogSamplingRate)
	}
	if !got.HTTPTrace.Enabled {
		t.Error("HTTPTrace.Enabled = false, want the overridden true")
	}
	if got.HTTPTrace.Level != "base" {
		t.Errorf("HTTPTrace.Level = %q, want base", got.HTTPTrace.Level)
	}
	if got.LogColor != "on" {
		t.Errorf("LogColor = %q, want on", got.LogColor)
	}
}

/**
 * TestApplyStoredConfigOverridesLeavesUnlistedKeysAlone 断言局部覆盖不会把未列出的键
 * 按零值写下去。
 */
func TestApplyStoredConfigOverridesLeavesUnlistedKeysAlone(t *testing.T) {
	db := newConfigOverrideDBForTest(t)
	if err := db.Create(&store.SystemSettings{
		Key:   store.SettingKeyRuntimeConfigOverrides,
		Value: `{"queue_batch_size":{"value":512,"set":true}}`,
	}).Error; err != nil {
		t.Fatalf("seed overrides: %v", err)
	}

	base := LoadConfigFromEnv()
	got, _ := ApplyStoredConfigOverrides(db, base)
	if got.Queue.BatchSize != 512 {
		t.Fatalf("Queue.BatchSize = %d, want 512", got.Queue.BatchSize)
	}
	if got.Queue.EventBufferSize != base.Queue.EventBufferSize {
		t.Errorf("Queue.EventBufferSize = %d, want the untouched %d", got.Queue.EventBufferSize, base.Queue.EventBufferSize)
	}
	if got.ResponseCacheMB != base.ResponseCacheMB {
		t.Errorf("ResponseCacheMB = %d, want the untouched %d", got.ResponseCacheMB, base.ResponseCacheMB)
	}
	if got.Bot.ScoreThreshold != base.Bot.ScoreThreshold {
		t.Errorf("Bot.ScoreThreshold = %d, want the untouched %d", got.Bot.ScoreThreshold, base.Bot.ScoreThreshold)
	}
	if got.CVE.FeedInterval != base.CVE.FeedInterval {
		t.Errorf("CVE.FeedInterval = %q, want the untouched %q", got.CVE.FeedInterval, base.CVE.FeedInterval)
	}
	if got.HTTPTrace.Enabled != base.HTTPTrace.Enabled || got.HTTPTrace.Level != base.HTTPTrace.Level {
		t.Errorf("HTTPTrace = %+v, want the untouched %+v", got.HTTPTrace, base.HTTPTrace)
	}
}

/**
 * TestApplyStoredConfigOverridesAppliesDetectionKeys 断言检测域的键在启动期生效，
 * 并把 CVE 自动直断两个键同步进 Drop 结构体。
 */
func TestApplyStoredConfigOverridesAppliesDetectionKeys(t *testing.T) {
	db := newConfigOverrideDBForTest(t)
	const raw = `{
		"bot_enabled":{"value":false,"set":true},
		"bot_threshold":{"value":66,"set":true},
		"geoip_db_path":{"value":"/var/lib/GeoLite2-City.mmdb","set":true},
		"drop_enabled":{"value":false,"set":true},
		"drop_bot_threshold":{"value":77,"set":true},
		"cve_enabled":{"value":true,"set":true},
		"cve_feed_enabled":{"value":true,"set":true},
		"cve_feed_interval":{"value":"90m","set":true},
		"nvd_api_key":{"value":"key-123","set":true},
		"cve_auto_approve":{"value":true,"set":true},
		"cve_auto_drop_critical":{"value":false,"set":true},
		"cve_auto_drop_high":{"value":false,"set":true}
	}`
	if err := db.Create(&store.SystemSettings{Key: store.SettingKeyRuntimeConfigOverrides, Value: raw}).Error; err != nil {
		t.Fatalf("seed overrides: %v", err)
	}

	got, warns := ApplyStoredConfigOverrides(db, LoadConfigFromEnv())
	if len(warns) != 0 {
		t.Fatalf("warnings = %#v, want none", warns)
	}

	if got.Bot.Enabled {
		t.Error("Bot.Enabled = true, want the overridden false")
	}
	if got.Bot.ScoreThreshold != 66 {
		t.Errorf("Bot.ScoreThreshold = %d, want 66", got.Bot.ScoreThreshold)
	}
	if got.Bot.GeoIPDBPath != "/var/lib/GeoLite2-City.mmdb" {
		t.Errorf("Bot.GeoIPDBPath = %q, want the overridden path", got.Bot.GeoIPDBPath)
	}
	if got.Drop.Enabled {
		t.Error("Drop.Enabled = true, want the overridden false")
	}
	if got.Drop.BotScoreThreshold != 77 {
		t.Errorf("Drop.BotScoreThreshold = %d, want 77", got.Drop.BotScoreThreshold)
	}
	if !got.CVE.Enabled || !got.CVE.FeedEnabled || !got.CVE.AutoApprove {
		t.Errorf("CVE switches = %+v, want all three enabled", got.CVE)
	}
	if got.CVE.FeedInterval != "1h30m0s" {
		t.Errorf("CVE.FeedInterval = %q, want the normalised 1h30m0s", got.CVE.FeedInterval)
	}
	if got.CVE.NVDAPIKey != "key-123" {
		t.Errorf("CVE.NVDAPIKey = %q, want key-123", got.CVE.NVDAPIKey)
	}
	if got.Drop.CVEAutoDropCritical || got.Drop.CVEAutoDropHigh {
		t.Errorf("Drop CVE auto drop = %v/%v, want both disabled", got.Drop.CVEAutoDropCritical, got.Drop.CVEAutoDropHigh)
	}
}

/**
 * TestApplyStoredConfigOverridesIgnoresBrokenTable 断言坏表不会让启动失败：
 * 解析失败的整体回落、越界键被忽略、老键名被忽略，其余键照常生效。
 */
func TestApplyStoredConfigOverridesIgnoresBrokenTable(t *testing.T) {
	base := LoadConfigFromEnv()

	broken := newConfigOverrideDBForTest(t)
	if err := broken.Create(&store.SystemSettings{
		Key: store.SettingKeyRuntimeConfigOverrides, Value: `{"queue_batch_size":`,
	}).Error; err != nil {
		t.Fatalf("seed broken table: %v", err)
	}
	got, warns := ApplyStoredConfigOverrides(broken, base)
	if len(warns) == 0 {
		t.Error("warnings = none, want a parse warning")
	}
	if got.Queue.BatchSize != base.Queue.BatchSize {
		t.Errorf("Queue.BatchSize = %d, want the env value %d", got.Queue.BatchSize, base.Queue.BatchSize)
	}

	mixed := newConfigOverrideDBForTest(t)
	const raw = `{
		"geoip_db":{"value":"/legacy/path.mmdb","set":true},
		"data":{"value":"/legacy/data","set":true},
		"queue_batch_size":{"value":999999,"set":true},
		"bot_threshold":{"value":55,"set":true}
	}`
	if err := mixed.Create(&store.SystemSettings{Key: store.SettingKeyRuntimeConfigOverrides, Value: raw}).Error; err != nil {
		t.Fatalf("seed mixed table: %v", err)
	}
	got, warns = ApplyStoredConfigOverrides(mixed, base)
	// 三条告警：两个已退役的键名各一条，越界的 queue_batch_size 一条。
	if len(warns) != 3 {
		t.Errorf("warnings = %#v, want three (two retired keys plus the out-of-range one)", warns)
	}
	if got.Queue.BatchSize != base.Queue.BatchSize {
		t.Errorf("Queue.BatchSize = %d, want the clamped-away out-of-range value ignored", got.Queue.BatchSize)
	}
	if got.Bot.GeoIPDBPath != base.Bot.GeoIPDBPath {
		t.Errorf("Bot.GeoIPDBPath = %q, want the renamed key %q to be ignored", got.Bot.GeoIPDBPath, base.Bot.GeoIPDBPath)
	}
	if got.Bot.ScoreThreshold != 55 {
		t.Errorf("Bot.ScoreThreshold = %d, want the valid key 55 to survive", got.Bot.ScoreThreshold)
	}
}

/**
 * TestApplyStoredConfigOverridesWithoutTable 断言首次启动（表尚未迁移）时原样返回。
 */
func TestApplyStoredConfigOverridesWithoutTable(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	base := LoadConfigFromEnv()
	got, warns := ApplyStoredConfigOverrides(db, base)
	if len(warns) != 0 {
		t.Errorf("warnings = %#v, want none", warns)
	}
	if got.Queue != base.Queue || got.ResponseCacheMB != base.ResponseCacheMB {
		t.Error("config was modified although the settings table does not exist")
	}
}
