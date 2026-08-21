package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// BotConfig holds bot-detection and GeoIP-scoring tuning knobs.
type BotConfig struct {
	Enabled           bool     `yaml:"enabled" json:"enabled"`
	GeoIPDBPath       string   `yaml:"geoip_db_path" json:"geoip_db_path"`
	HighRiskCountries []string `yaml:"high_risk_countries" json:"high_risk_countries"` // ISO 3166-1 alpha-2 codes
	DataCenterASNs    []uint   `yaml:"datacenter_asns" json:"datacenter_asns"`
	VPNProxyASNs      []uint   `yaml:"vpn_proxy_asns" json:"vpn_proxy_asns"`
	ScoreThreshold    int      `yaml:"score_threshold" json:"score_threshold"` // total score to trigger block (default 80)
}

// DefaultBotConfig returns a BotConfig with sensible production defaults.
func DefaultBotConfig() BotConfig {
	return BotConfig{
		Enabled:        true,
		GeoIPDBPath:    "",
		ScoreThreshold: 80,
		// High-risk countries: empty by default – admin configures per deployment.
		HighRiskCountries: nil,
		// Common cloud / datacenter ASNs (AWS, GCP, Azure, DigitalOcean, Vultr, Linode, OVH, Hetzner).
		DataCenterASNs: []uint{
			16509, 14618, // AWS
			15169, 396982, // Google Cloud
			8075,  // Microsoft Azure
			14061, // DigitalOcean
			20473, // Vultr / Choopa
			63949, // Linode / Akamai Connected Cloud
			16276, // OVH
			24940, // Hetzner
			13238, // Yandex Cloud
			45090, // Tencent Cloud
			37963, // Alibaba Cloud
		},
		// Common VPN / proxy ASNs.
		VPNProxyASNs: []uint{
			9009,   // M247 (used by NordVPN, Surfshark, etc.)
			20473,  // Choopa / Vultr (many VPN endpoints)
			60068,  // Datacamp / CDN77 (proxy services)
			212238, // Datacamp Limited
			206264, // Amarutu Technology (VPN hosting)
			62240,  // Clouvider (VPN hosting)
			396356, // Maxihost (proxy hosting)
			174,    // Cogent (some proxy infra)
		},
	}
}

// DropConfig controls the TCP drop (connection close) strategy.
type DropConfig struct {
	Enabled             bool `yaml:"enabled" json:"enabled"`
	BotScoreThreshold   int  `yaml:"bot_score_threshold" json:"bot_score_threshold"`       // default 80
	CVEAutoDropCritical bool `yaml:"cve_auto_drop_critical" json:"cve_auto_drop_critical"` // default true
	CVEAutoDropHigh     bool `yaml:"cve_auto_drop_high" json:"cve_auto_drop_high"`         // default true
}

// DefaultDropConfig returns a DropConfig with sensible production defaults.
func DefaultDropConfig() DropConfig {
	return DropConfig{
		Enabled:             true,
		BotScoreThreshold:   80,
		CVEAutoDropCritical: true,
		CVEAutoDropHigh:     true,
	}
}

// QueueConfig holds the tunable parameters that bound the request-path
// observability queues and the generic async write queue.
//
// 关键约束（see UnifiedWriter / WriteQueue 顶部注释）：
//   - 所有可观测写入仍由单个 goroutine 串行完成，这是消除 SQLite 写锁竞争
//     的刻意设计，本配置只调整容量与批大小，不改变线程模型。
//   - 单队列容量上限 1M、单批上限 10K、flush 间隔上限 60s 是经过上限保护
//     的硬阈值，避免误调把内存吃光或把事务体积拉到驱动上限。
//
// 所有字段必须被 observability 包消费；新增字段时务必同步在
// internal/observability/unified_writer.go 与 write_queue.go 接线。
type QueueConfig struct {
	// EventBufferSize 是安全事件/访问日志两类高频通道的容量。默认 16384；上限 1M。
	EventBufferSize int
	// DropBufferSize 是 DropEvent / BotScoreLog 两类低频通道的容量。默认 8192；上限 1M。
	DropBufferSize int
	// BatchSize 是 UnifiedWriter 触发 flush 的批次阈值（按四类合计）。默认 512；上限 10K。
	BatchSize int
	// FlushInterval 是 UnifiedWriter 的定时 flush 周期。默认 3s；上限 60s。
	FlushInterval time.Duration
	// WriteQueueBatchSize 是通用 WriteQueue 的批次阈值。默认 64；上限 10K。
	WriteQueueBatchSize int
	// WriteQueueCapacity 是通用 WriteQueue 的任务通道容量。默认 256；上限 1M。
	WriteQueueCapacity int
	// WriteQueueInterval 是 WriteQueue 的 ticker 周期。默认 50ms。
	WriteQueueInterval time.Duration
}

// 各项硬上限（与 internal/observability 中对应常量保持一致）。
// 供 LoadConfigFromEnv 钳制环境变量输入使用。
const (
	queueMaxChannelCapacity = 1 << 20 // 1M
	queueMaxBatchSize       = 10000
	queueMaxFlushInterval   = 60 * time.Second
)

// DefaultQueueConfig returns the production defaults that match the previous
// hard-coded constants in observability package. 通过配置项切换不会改变
// 任何运行时行为——默认值与原常量一一对应。
func DefaultQueueConfig() QueueConfig {
	return QueueConfig{
		EventBufferSize:     16384,
		DropBufferSize:      8192,
		BatchSize:           512,
		FlushInterval:       3 * time.Second,
		WriteQueueBatchSize: 64,
		WriteQueueCapacity:  256,
		WriteQueueInterval:  50 * time.Millisecond,
	}
}

/**
 * queueParseWarning 构造一条"环境变量值无法解析"的告警文本。
 *
 * @param name 环境变量名。
 * @param raw  原始值，原样回显以便运维定位拼写问题。
 * @param kept 解析失败后实际保留的值。
 * @return 告警文本。
 */
func queueParseWarning(name, raw string, kept any) string {
	return fmt.Sprintf("%s=%q is not a valid value, keeping %v", name, raw, kept)
}

/**
 * clampQueueInt 校验单个整型队列参数，越界时回退默认值或截断到上界。
 *
 * 下界必须拦截 0 与负数，而不是让值原样流到 make(chan)：容量 0 会让所有非阻塞
 * 入队直接走 default 分支，等于把该类记录整体丢弃；负数则直接 panic。批大小为 0
 * 会让 flush 阈值恒定满足，退化成逐条事务。
 *
 * @param name  参数对应的环境变量名，用于告警定位。
 * @param v     待校验值。
 * @param def   下界越界时回退的默认值。
 * @param max   允许的上界。
 * @param warns 告警累加目标。
 * @return 合规值，以及追加了本次告警的切片。
 */
func clampQueueInt(name string, v, def, max int, warns []string) (int, []string) {
	if v <= 0 {
		return def, append(warns, fmt.Sprintf("%s=%d is out of range, falling back to default %d", name, v, def))
	}
	if v > max {
		return max, append(warns, fmt.Sprintf("%s=%d exceeds the hard limit, clamped to %d", name, v, max))
	}
	return v, warns
}

/**
 * clampQueueDuration 校验单个时长类队列参数，语义与 clampQueueInt 一致。
 *
 * @param name  参数对应的环境变量名，用于告警定位。
 * @param v     待校验值。
 * @param def   下界越界时回退的默认值。
 * @param max   允许的上界；传 0 表示该参数不设上界。
 * @param warns 告警累加目标。
 * @return 合规值，以及追加了本次告警的切片。
 */
func clampQueueDuration(name string, v, def, max time.Duration, warns []string) (time.Duration, []string) {
	if v <= 0 {
		return def, append(warns, fmt.Sprintf("%s=%s is out of range, falling back to default %s", name, v, def))
	}
	if max > 0 && v > max {
		return max, append(warns, fmt.Sprintf("%s=%s exceeds the hard limit, clamped to %s", name, v, max))
	}
	return v, warns
}

/**
 * clampQueueConfig 把 cfg 钳制到安全范围内，与 internal/observability 中
 * clampUnifiedWriterOptions / clampWriteQueueOptions 的口径保持一致。
 *
 * 入口钳制的好处是：后续构造器内部不再重复条件判断，环境变量 / API 直接构造
 * 两条路径都拿到合规值。零值回退为默认值，负数同样视为零值。
 *
 * 钳制不静默：每次回退/截断都产出一条告警，由 NewRuntime 打成 WARN。零值结构体
 * （如 QueueConfig{}）因此会产出全部字段的告警，这是刻意的——它意味着调用方漏了
 * DefaultQueueConfig()。
 *
 * @param cfg 待钳制的配置（通常来自环境变量或 API 入参）。
 * @return 已应用安全上限的配置，以及每处越界的告警。
 */
func clampQueueConfig(cfg QueueConfig) (QueueConfig, []string) {
	def := DefaultQueueConfig()
	var warns []string

	cfg.EventBufferSize, warns = clampQueueInt(
		"MY_OPENWAF_QUEUE_EVENT_BUFFER_SIZE",
		cfg.EventBufferSize, def.EventBufferSize, queueMaxChannelCapacity, warns)
	cfg.DropBufferSize, warns = clampQueueInt(
		"MY_OPENWAF_QUEUE_DROP_BUFFER_SIZE",
		cfg.DropBufferSize, def.DropBufferSize, queueMaxChannelCapacity, warns)
	cfg.BatchSize, warns = clampQueueInt(
		"MY_OPENWAF_QUEUE_BATCH_SIZE",
		cfg.BatchSize, def.BatchSize, queueMaxBatchSize, warns)
	cfg.FlushInterval, warns = clampQueueDuration(
		"MY_OPENWAF_QUEUE_FLUSH_INTERVAL",
		cfg.FlushInterval, def.FlushInterval, queueMaxFlushInterval, warns)
	cfg.WriteQueueBatchSize, warns = clampQueueInt(
		"MY_OPENWAF_QUEUE_WRITE_BATCH_SIZE",
		cfg.WriteQueueBatchSize, def.WriteQueueBatchSize, queueMaxBatchSize, warns)
	cfg.WriteQueueCapacity, warns = clampQueueInt(
		"MY_OPENWAF_QUEUE_WRITE_CAPACITY",
		cfg.WriteQueueCapacity, def.WriteQueueCapacity, queueMaxChannelCapacity, warns)
	// WriteQueueInterval 不设上界：它只影响 flush 的最迟触发时间，调大不会放大
	// 单事务体积或内存占用，与容量/批大小的风险面不同。
	cfg.WriteQueueInterval, warns = clampQueueDuration(
		"MY_OPENWAF_QUEUE_WRITE_INTERVAL",
		cfg.WriteQueueInterval, def.WriteQueueInterval, 0, warns)

	return cfg, warns
}

// Config is process bootstrap: SQL backend + optional Redis (cache / future pubsub).
type Config struct {
	// DBDriver: sqlite | mysql | postgres (default sqlite).
	DBDriver string
	// DBDSN: sqlite file path, or full DSN for mysql/postgres.
	// If empty with sqlite, falls back to DataDir/waf.db.
	DBDSN string
	// LogDBDSN stores high-volume access/security/drop/bot logs separately.
	// If empty with sqlite, falls back to DataDir/waf_logs.db.
	LogDBDSN string
	// DataDir used when sqlite DSN has no directory part.
	DataDir string

	// Redis (optional). Empty Addr → no Redis client.
	RedisAddr     string
	RedisPassword string
	RedisDB       int

	// AdminBind is the address the admin control-plane server listens on.
	AdminBind string
	// AdminStaticDir overrides embedded frontend for local development.
	AdminStaticDir string

	// CVE detection configuration.
	CVE CVEConfig

	// Bot detection & GeoIP scoring configuration.
	Bot BotConfig

	// Drop (TCP connection close) strategy configuration.
	Drop DropConfig

	// ResponseCacheMB is the max response cache size in MiB (0 = use default 64).
	ResponseCacheMB int
	// ResponseCacheTTLSec is the default cache TTL in seconds (0 = use default 60).
	ResponseCacheTTLSec int

	// Queue 调优各类可观测/异步写入队列的容量与批大小。
	// 默认值与历史硬编码常量一致；环境变量主要用于高并发场景扩容。
	Queue QueueConfig
	// QueueWarnings 记录加载 Queue 时发生的解析失败与越界钳制。
	// 由 LoadConfigFromEnv 填充，NewRuntime 逐条打成 WARN。
	// 单独成字段而不是走 Validate()：Validate 在启动流程里被调用两次
	// （preflight + 应用存储 Redis 配置后），复用它会让每条告警重复出现。
	QueueWarnings []string
}

// CVEConfig controls CVE-specific detection and feed synchronisation.
type CVEConfig struct {
	Enabled      bool   `yaml:"enabled" json:"enabled"`
	FeedEnabled  bool   `yaml:"feed_enabled" json:"feed_enabled"`
	FeedInterval string `yaml:"feed_interval" json:"feed_interval"` // e.g. "6h"
	NVDAPIKey    string `yaml:"nvd_api_key" json:"nvd_api_key"`
	AutoApprove  bool   `yaml:"auto_approve" json:"auto_approve"` // auto-approve generated rules
}

func LoadConfigFromEnv() Config {
	dsn := strings.TrimSpace(os.Getenv("MY_OPENWAF_DSN"))
	if dsn == "" {
		dsn = strings.TrimSpace(os.Getenv("MY_OPENWAF_DB"))
	}
	dir := strings.TrimSpace(os.Getenv("MY_OPENWAF_DATA"))
	if dir == "" {
		dir = "./data"
	}
	if dsn == "" {
		dsn = filepath.Join(dir, "waf.db")
	}

	logDSN := strings.TrimSpace(os.Getenv("MY_OPENWAF_LOG_DSN"))
	if logDSN == "" {
		logDSN = strings.TrimSpace(os.Getenv("MY_OPENWAF_LOG_DB"))
	}
	if logDSN == "" {
		logDSN = filepath.Join(dir, "waf_logs.db")
	}

	driver := strings.ToLower(strings.TrimSpace(os.Getenv("MY_OPENWAF_DB_DRIVER")))
	if driver == "" {
		driver = "sqlite"
	}

	rd, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("MY_OPENWAF_REDIS_DB")))

	adminBind := strings.TrimSpace(os.Getenv("MY_OPENWAF_ADMIN_BIND"))
	if adminBind == "" {
		adminBind = ":9443"
	}

	botCfg := DefaultBotConfig()
	if geoPath := strings.TrimSpace(os.Getenv("MY_OPENWAF_GEOIP_DB")); geoPath != "" {
		botCfg.GeoIPDBPath = geoPath
	}
	if thr := strings.TrimSpace(os.Getenv("MY_OPENWAF_BOT_THRESHOLD")); thr != "" {
		if v, err := strconv.Atoi(thr); err == nil && v > 0 {
			botCfg.ScoreThreshold = v
		}
	}

	cveCfg := CVEConfig{
		Enabled:      strings.ToLower(strings.TrimSpace(os.Getenv("MY_OPENWAF_CVE_ENABLED"))) == "true",
		FeedEnabled:  strings.ToLower(strings.TrimSpace(os.Getenv("MY_OPENWAF_CVE_FEED_ENABLED"))) == "true",
		FeedInterval: strings.TrimSpace(os.Getenv("MY_OPENWAF_CVE_FEED_INTERVAL")),
		NVDAPIKey:    strings.TrimSpace(os.Getenv("MY_OPENWAF_NVD_API_KEY")),
		AutoApprove:  strings.ToLower(strings.TrimSpace(os.Getenv("MY_OPENWAF_CVE_AUTO_APPROVE"))) == "true",
	}
	if cveCfg.FeedInterval == "" {
		cveCfg.FeedInterval = "6h"
	}

	dropCfg := DefaultDropConfig()
	if strings.ToLower(strings.TrimSpace(os.Getenv("MY_OPENWAF_DROP_ENABLED"))) == "false" {
		dropCfg.Enabled = false
	}
	if thr := strings.TrimSpace(os.Getenv("MY_OPENWAF_DROP_BOT_THRESHOLD")); thr != "" {
		if v, err := strconv.Atoi(thr); err == nil && v > 0 {
			dropCfg.BotScoreThreshold = v
		}
	}

	cacheMB := 64
	if v := strings.TrimSpace(os.Getenv("MY_OPENWAF_RESPONSE_CACHE_MB")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cacheMB = n
		}
	}
	cacheTTL := 60
	if v := strings.TrimSpace(os.Getenv("MY_OPENWAF_RESPONSE_CACHE_TTL_SEC")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cacheTTL = n
		}
	}

	// 队列参数：未设置的环境变量保留 DefaultQueueConfig 的值，因此不显式设置任何
	// MY_OPENWAF_QUEUE_* 时运行时行为与硬编码常量时期完全一致。
	// 解析失败不能静默——静默会让一个拼错的值伪装成"已生效"，运维在 /metrics 上
	// 看到的仍是默认容量却无从解释，因此这里保留默认值并产出告警。
	queueCfg := DefaultQueueConfig()
	var queueWarns []string
	if v := strings.TrimSpace(os.Getenv("MY_OPENWAF_QUEUE_EVENT_BUFFER_SIZE")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			queueCfg.EventBufferSize = n
		} else {
			queueWarns = append(queueWarns, queueParseWarning("MY_OPENWAF_QUEUE_EVENT_BUFFER_SIZE", v, queueCfg.EventBufferSize))
		}
	}
	if v := strings.TrimSpace(os.Getenv("MY_OPENWAF_QUEUE_DROP_BUFFER_SIZE")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			queueCfg.DropBufferSize = n
		} else {
			queueWarns = append(queueWarns, queueParseWarning("MY_OPENWAF_QUEUE_DROP_BUFFER_SIZE", v, queueCfg.DropBufferSize))
		}
	}
	if v := strings.TrimSpace(os.Getenv("MY_OPENWAF_QUEUE_BATCH_SIZE")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			queueCfg.BatchSize = n
		} else {
			queueWarns = append(queueWarns, queueParseWarning("MY_OPENWAF_QUEUE_BATCH_SIZE", v, queueCfg.BatchSize))
		}
	}
	if v := strings.TrimSpace(os.Getenv("MY_OPENWAF_QUEUE_FLUSH_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			queueCfg.FlushInterval = d
		} else {
			queueWarns = append(queueWarns, queueParseWarning("MY_OPENWAF_QUEUE_FLUSH_INTERVAL", v, queueCfg.FlushInterval))
		}
	}
	if v := strings.TrimSpace(os.Getenv("MY_OPENWAF_QUEUE_WRITE_BATCH_SIZE")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			queueCfg.WriteQueueBatchSize = n
		} else {
			queueWarns = append(queueWarns, queueParseWarning("MY_OPENWAF_QUEUE_WRITE_BATCH_SIZE", v, queueCfg.WriteQueueBatchSize))
		}
	}
	if v := strings.TrimSpace(os.Getenv("MY_OPENWAF_QUEUE_WRITE_CAPACITY")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			queueCfg.WriteQueueCapacity = n
		} else {
			queueWarns = append(queueWarns, queueParseWarning("MY_OPENWAF_QUEUE_WRITE_CAPACITY", v, queueCfg.WriteQueueCapacity))
		}
	}
	if v := strings.TrimSpace(os.Getenv("MY_OPENWAF_QUEUE_WRITE_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			queueCfg.WriteQueueInterval = d
		} else {
			queueWarns = append(queueWarns, queueParseWarning("MY_OPENWAF_QUEUE_WRITE_INTERVAL", v, queueCfg.WriteQueueInterval))
		}
	}
	queueCfg, clampWarns := clampQueueConfig(queueCfg)
	queueWarns = append(queueWarns, clampWarns...)

	return Config{
		DBDriver:            driver,
		DBDSN:               dsn,
		LogDBDSN:            logDSN,
		DataDir:             dir,
		RedisAddr:           strings.TrimSpace(os.Getenv("MY_OPENWAF_REDIS_ADDR")),
		RedisPassword:       strings.TrimSpace(os.Getenv("MY_OPENWAF_REDIS_PASSWORD")),
		RedisDB:             rd,
		AdminBind:           adminBind,
		AdminStaticDir:      strings.TrimSpace(os.Getenv("MY_OPENWAF_ADMIN_STATIC_DIR")),
		Bot:                 botCfg,
		CVE:                 cveCfg,
		Drop:                dropCfg,
		ResponseCacheMB:     cacheMB,
		ResponseCacheTTLSec: cacheTTL,
		Queue:               queueCfg,
		QueueWarnings:       queueWarns,
	}
}
