package core

import (
	"math"
	"time"

	"My-OpenWaf/internal/core/configoverride"
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

/**
 * ApplyStoredConfigOverrides 把「逐键三态覆盖表」应用到从环境变量加载的配置上。
 * 覆盖表的键值由管理端点写入数据库，优先级高于环境变量，但低于更具体的设置行（redis_config / drop_policy / bot_settings / log_config）。
 * @param db 主库句柄；表不存在或读取失败时原样返回 cfg。
 * @param cfg 从环境变量加载的配置。
 * @return 应用覆盖后的配置，以及覆盖表产生的告警。
 */
func ApplyStoredConfigOverrides(db *gorm.DB, cfg Config) (Config, []string) {
	overrides, warns := loadStoredConfigOverrides(db)
	if len(overrides) == 0 {
		return cfg, warns
	}
	entries := configoverride.ResolveAll(overrides, nil, &warns)

	applyBotOverrides(&cfg, entries)
	applyDropOverrides(&cfg, entries)
	applyCVEOverrides(&cfg, entries)
	applyQueueOverrides(&cfg, entries)
	applyCacheOverrides(&cfg, entries)
	applyProxyOverrides(&cfg, entries)
	applyTelemetryOverrides(&cfg, entries)
	applyStaticPathOverrides(&cfg, entries)

	return cfg, warns
}

// applyBotOverrides 应用 bot 检测与 GeoIP 相关键。
func applyBotOverrides(cfg *Config, entries map[string]configoverride.Entry) {
	if v, ok := boolEntry(entries, "bot_enabled"); ok {
		cfg.Bot.Enabled = v
	}
	if v, ok := intEntry(entries, "bot_threshold"); ok && v > 0 {
		cfg.Bot.ScoreThreshold = int(v)
	}
	if v, ok := stringEntry(entries, "geoip_db_path"); ok {
		cfg.Bot.GeoIPDBPath = v
	}
}

// applyDropOverrides 应用 TCP drop 策略相关键。
func applyDropOverrides(cfg *Config, entries map[string]configoverride.Entry) {
	if v, ok := boolEntry(entries, "drop_enabled"); ok {
		cfg.Drop.Enabled = v
	}
	if v, ok := intEntry(entries, "drop_bot_threshold"); ok && v > 0 {
		cfg.Drop.BotScoreThreshold = int(v)
	}
}

// applyCVEOverrides 应用 CVE 检测与情报源相关键。
//
// cve_auto_drop_critical / cve_auto_drop_high 同时写入 Drop 结构体：二者的
// 最终消费者是 store.ProtectionConfig 的同名字段（snapshot/build.go 里由
// protection 设置行决定，见 applyConfigOverrideBase），Drop 侧的这两个字段
// 是启动期的合并来源之一，这里一并同步可避免两处取值打架。
func applyCVEOverrides(cfg *Config, entries map[string]configoverride.Entry) {
	if v, ok := boolEntry(entries, "cve_enabled"); ok {
		cfg.CVE.Enabled = v
	}
	if v, ok := boolEntry(entries, "cve_feed_enabled"); ok {
		cfg.CVE.FeedEnabled = v
	}
	if v, ok := durationEntry(entries, "cve_feed_interval"); ok && v > 0 {
		cfg.CVE.FeedInterval = v.String()
	}
	if v, ok := stringEntry(entries, "nvd_api_key"); ok {
		cfg.CVE.NVDAPIKey = v
	}
	if v, ok := boolEntry(entries, "cve_auto_approve"); ok {
		cfg.CVE.AutoApprove = v
	}
	if v, ok := boolEntry(entries, "cve_auto_drop_critical"); ok {
		cfg.Drop.CVEAutoDropCritical = v
	}
	if v, ok := boolEntry(entries, "cve_auto_drop_high"); ok {
		cfg.Drop.CVEAutoDropHigh = v
	}
}

// applyQueueOverrides 应用队列容量与周期相关键，并复用加载期的钳制口径。
func applyQueueOverrides(cfg *Config, entries map[string]configoverride.Entry) {
	if v, ok := intEntry(entries, "queue_event_buffer_size"); ok && v > 0 {
		cfg.Queue.EventBufferSize = int(v)
	}
	if v, ok := intEntry(entries, "queue_drop_buffer_size"); ok && v > 0 {
		cfg.Queue.DropBufferSize = int(v)
	}
	if v, ok := intEntry(entries, "queue_batch_size"); ok && v > 0 {
		cfg.Queue.BatchSize = int(v)
	}
	if v, ok := durationEntry(entries, "queue_flush_interval"); ok && v > 0 {
		cfg.Queue.FlushInterval = v
	}
	if v, ok := intEntry(entries, "queue_write_batch_size"); ok && v > 0 {
		cfg.Queue.WriteQueueBatchSize = int(v)
	}
	if v, ok := intEntry(entries, "queue_write_capacity"); ok && v > 0 {
		cfg.Queue.WriteQueueCapacity = int(v)
	}
	if v, ok := durationEntry(entries, "queue_write_interval"); ok && v > 0 {
		cfg.Queue.WriteQueueInterval = v
	}
}

// applyCacheOverrides 应用响应缓存容量与默认 TTL。
func applyCacheOverrides(cfg *Config, entries map[string]configoverride.Entry) {
	if v, ok := intEntry(entries, "response_cache_mb"); ok && v > 0 {
		cfg.ResponseCacheMB = int(v)
	}
	if v, ok := intEntry(entries, "response_cache_ttl_sec"); ok && v > 0 {
		cfg.ResponseCacheTTLSec = int(v)
	}
}

// applyProxyOverrides 应用两侧的解压产出上限（压缩炸弹防护）。
func applyProxyOverrides(cfg *Config, entries map[string]configoverride.Entry) {
	if v, ok := intEntry(entries, "request_decompress_limit_bytes"); ok && v > 0 {
		cfg.RequestDecompressionMaxBytes = v
	}
	if v, ok := intEntry(entries, "response_decompress_limit_bytes"); ok && v > 0 {
		cfg.ResponseDecompressionMaxBytes = v
	}
}

// applyTelemetryOverrides 应用 Hertz Tracer 遥测相关键。
//
// 与队列参数同理：Tracer 只在数据面监听器构造期注册，进程起来之后没有插拔路径，
// 因此这两个键是「写进覆盖表 + 下次重启用上」。
func applyTelemetryOverrides(cfg *Config, entries map[string]configoverride.Entry) {
	if v, ok := boolEntry(entries, "trace_enabled"); ok {
		cfg.HTTPTrace.Enabled = v
	}
	if v, ok := stringEntry(entries, "trace_level"); ok && v != "" {
		cfg.HTTPTrace.Level = v
	}
}

// applyStaticPathOverrides 应用静态资源目录类键。
//
// captcha_dir 空串与「未设置」等价（消费点只在非空时覆盖默认目录），因此这里
// 不做空串保护；admin_static_dir 反之：空串表示使用内嵌资源，是合法取值，
// 显式清空必须如实生效。
func applyStaticPathOverrides(cfg *Config, entries map[string]configoverride.Entry) {
	if v, ok := stringEntry(entries, "captcha_dir"); ok {
		cfg.CaptchaDir = v
	}
	if v, ok := stringEntry(entries, "admin_static_dir"); ok {
		cfg.AdminStaticDir = v
	}
	if v, ok := intEntry(entries, "accesslog_sampling"); ok && v > 0 && v <= math.MaxUint32 {
		cfg.AccessLogSamplingRate = uint32(v)
	}
	if v, ok := stringEntry(entries, "log_color"); ok {
		cfg.LogColor = v
	}
}

// LoadConfigOverrideEntries 解析覆盖表并返回全部键的三态结果，供管理端点展示。
//
// @param repo 系统设置仓储；nil 时等价于「库中没有覆盖表」。
// @return 键名 -> 三态解析结果，以及解析过程中的告警。
func LoadConfigOverrideEntries(repo ConfigOverrideReader) (map[string]configoverride.Entry, []string) {
	raw := ""
	if repo != nil {
		if value, err := repo.Get(store.SettingKeyRuntimeConfigOverrides); err == nil {
			raw = value
		}
	}
	var warns []string
	overrides := configoverride.ParseStoredOverrides(raw, &warns)
	return configoverride.ResolveAll(overrides, nil, &warns), warns
}

// ConfigOverrideReader 是读取单个系统设置键的最小接口。
// 定义在消费侧而不是仓储侧：internal/store/repository 已被各业务包广泛依赖，
// 让它反向依赖 internal/core 会形成导入环，因此这里只依赖接口。
type ConfigOverrideReader interface {
	Get(key string) (string, error)
}

// gormSettingReader 是 ConfigOverrideReader 的最小 GORM 实现。
// 不复用 internal/store/repository 是为了不给 core 包引入整个仓储门面。
type gormSettingReader struct{ db *gorm.DB }

func (r *gormSettingReader) Get(key string) (string, error) {
	var setting store.SystemSettings
	if err := r.db.Where(clause.Eq{Column: clause.Column{Name: "key"}, Value: key}).First(&setting).Error; err != nil {
		return "", err
	}
	return setting.Value, nil
}

// loadStoredConfigOverrides 从库里读取覆盖表并解析成键值映射。
//
// 表不存在（首次启动，尚未 AutoMigrate）或读取失败都按「没有覆盖」处理：
// 此时还没有任何界面写过覆盖，回落环境变量就是正确语义。
func loadStoredConfigOverrides(db *gorm.DB) (configoverride.Overrides, []string) {
	if db == nil || !db.Migrator().HasTable(&store.SystemSettings{}) {
		return nil, nil
	}
	entries, warns := LoadConfigOverrideEntries(&gormSettingReader{db: db})
	overrides := make(configoverride.Overrides)
	for key, entry := range entries {
		if entry.Overridden {
			overrides[key] = entry.Value
		}
	}
	return overrides, warns
}

/**
 * overrideEntry 取出一个「确实被界面覆盖过」的键的解析结果。
 *
 * 必须先判 Overridden：ResolveAll 会为全部 45 个键给出结果（未覆盖的回落环境变量
 * 或内置默认值），只按「键是否存在」取值等于把每个键都当成覆盖过写一遍。那不只是
 * 啰嗦——注册表的规范化口径与 LoadConfigFromEnv 的原始口径并非逐字节相同
 * （例如 cve_feed_interval 会被规范化成 6h0m0s），无条件回写会把环境变量的取值
 * 改写成另一种写法。
 *
 * @param entries 三态解析结果。
 * @param key     注册表键名。
 * @return 该键的解析结果，以及它是否真的被覆盖。
 */
func overrideEntry(entries map[string]configoverride.Entry, key string) (configoverride.Entry, bool) {
	entry, ok := entries[key]
	if !ok || !entry.Overridden {
		return configoverride.Entry{}, false
	}
	return entry, true
}

func boolEntry(entries map[string]configoverride.Entry, key string) (bool, bool) {
	entry, ok := overrideEntry(entries, key)
	if !ok {
		return false, false
	}
	value, ok := entry.Value.(bool)
	return value, ok
}

func intEntry(entries map[string]configoverride.Entry, key string) (int64, bool) {
	entry, ok := overrideEntry(entries, key)
	if !ok {
		return 0, false
	}
	value, ok := entry.Value.(int64)
	return value, ok
}

func stringEntry(entries map[string]configoverride.Entry, key string) (string, bool) {
	entry, ok := overrideEntry(entries, key)
	if !ok {
		return "", false
	}
	value, ok := entry.Value.(string)
	return value, ok
}

/**
 * durationEntry 读取时长类键的覆盖值。
 *
 * 覆盖表把时长存成规范化文本（如 "3s"），这里解析回 time.Duration。文本在写入
 * 时已由 configoverride 校验过，解析失败只可能来自手工改库，此时按「未覆盖」
 * 处理并保留环境变量取值。
 *
 * @param entries 三态解析结果。
 * @param key     注册表键名。
 * @return 时长，以及该键是否存在且可用。
 */
func durationEntry(entries map[string]configoverride.Entry, key string) (time.Duration, bool) {
	text, ok := stringEntry(entries, key)
	if !ok {
		return 0, false
	}
	d, err := time.ParseDuration(text)
	if err != nil {
		return 0, false
	}
	return d, true
}
