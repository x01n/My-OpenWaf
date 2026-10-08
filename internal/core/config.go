package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// BotConfig 汇总 bot 检测与 GeoIP 打分的调优参数。
type BotConfig struct {
	Enabled           bool     `yaml:"enabled" json:"enabled"`
	GeoIPDBPath       string   `yaml:"geoip_db_path" json:"geoip_db_path"`
	HighRiskCountries []string `yaml:"high_risk_countries" json:"high_risk_countries"` // ISO 3166-1 alpha-2 国家码
	DataCenterASNs    []uint   `yaml:"datacenter_asns" json:"datacenter_asns"`
	VPNProxyASNs      []uint   `yaml:"vpn_proxy_asns" json:"vpn_proxy_asns"`
	ScoreThreshold    int      `yaml:"score_threshold" json:"score_threshold"` // 触发拦截的总分（默认 80）
}

// DefaultBotConfig 返回带生产可用默认值的 BotConfig。
func DefaultBotConfig() BotConfig {
	return BotConfig{
		Enabled:        true,
		GeoIPDBPath:    "",
		ScoreThreshold: 80,
		// 高风险国家默认留空——由管理员按部署环境配置。
		HighRiskCountries: nil,
		// 常见云 / 数据中心 ASN（AWS、GCP、Azure、DigitalOcean、Vultr、Linode、OVH、Hetzner）。
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
		// 常见 VPN / 代理 ASN。
		VPNProxyASNs: []uint{
			9009,   // M247（NordVPN、Surfshark 等在用）
			20473,  // Choopa / Vultr（大量 VPN 出口）
			60068,  // Datacamp / CDN77（代理服务）
			212238, // Datacamp Limited
			206264, // Amarutu Technology（VPN 托管）
			62240,  // Clouvider（VPN 托管）
			396356, // Maxihost（代理托管）
			174,    // Cogent（部分代理基础设施）
		},
	}
}

// DropConfig 控制 TCP drop（直接关闭连接）策略。
type DropConfig struct {
	Enabled             bool `yaml:"enabled" json:"enabled"`
	BotScoreThreshold   int  `yaml:"bot_score_threshold" json:"bot_score_threshold"`       // 默认 80
	CVEAutoDropCritical bool `yaml:"cve_auto_drop_critical" json:"cve_auto_drop_critical"` // 默认 true
	CVEAutoDropHigh     bool `yaml:"cve_auto_drop_high" json:"cve_auto_drop_high"`         // 默认 true
}

// DefaultDropConfig 返回带生产可用默认值的 DropConfig。
func DefaultDropConfig() DropConfig {
	return DropConfig{
		Enabled:             true,
		BotScoreThreshold:   80,
		CVEAutoDropCritical: true,
		CVEAutoDropHigh:     true,
	}
}

type QueueConfig struct {
	// EventBufferSize 是安全事件/访问日志两类高频通道的容量。默认 16384；上限 1M。
	EventBufferSize int
	// DropBufferSize 是 DropEvent / BotScoreLog 两类低频通道的容量。默认 8192；上限 1M。
	DropBufferSize int
	// BatchSize 是 UnifiedWriter 触发 flush 的批次阈值（按四类合计）。默认 256；上限 10K。
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

// DefaultQueueConfig 返回生产默认值。除 BatchSize 外均与 observability 包
// 参数化前的硬编码常量一致；BatchSize 经 SQLite 写径审计由 64 上调至 256。
// WriteQueue 各默认值不变。
func DefaultQueueConfig() QueueConfig {
	return QueueConfig{
		EventBufferSize:     16384,
		DropBufferSize:      8192,
		BatchSize:           256,
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
 * parseDecompressionLimitEnv 解析一个解压产出上限环境变量。
 *
 * 未设置或解析失败时返回 0，由 proxy 包按方向回退各自的默认值（请求 64 MiB /
 * 响应 8 MiB）；解析失败额外产出一条告警，避免拼错的取值伪装成"已生效"。
 *
 * @param name 环境变量名。
 * @param warns 告警累加目标。
 * @return 解析出的上限（字节）；0 表示未设置或不可用。
 */
func parseDecompressionLimitEnv(name string, warns *[]string) int64 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		*warns = append(*warns, queueParseWarning(name, v, "direction default"))
		return 0
	}
	return n
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

// Config 是进程引导配置：SQL 后端 + 可选 Redis（缓存 / 后续 pubsub）。
type Config struct {
	// DBDriver：sqlite | mysql | postgres（默认 sqlite）。
	DBDriver string
	// DBDSN：sqlite 文件路径，或 mysql/postgres 的完整 DSN。
	// sqlite 下为空时回退到 DataDir/waf.db。
	DBDSN string
	// LogDBDSN 单独存放高写入量的访问/安全/drop/bot 日志。
	// sqlite 下为空时回退到 DataDir/waf_logs.db。
	LogDBDSN string
	// DataDir 在 sqlite 的 DSN 不含目录部分时使用。
	DataDir string

	// Redis（可选）。Addr 为空则不创建 Redis 客户端。
	RedisAddr     string
	RedisPassword string
	RedisDB       int

	// AdminBind 是管理控制面服务器的监听地址。
	AdminBind string
	// AdminStaticDir 在本地开发时覆盖内嵌前端产物。
	AdminStaticDir string

	// CVE 检测配置。
	CVE CVEConfig

	// Bot 检测与 GeoIP 打分配置。
	Bot BotConfig

	// Drop（关闭 TCP 连接）策略配置。
	Drop DropConfig

	// ResponseCacheMB 是响应缓存的最大容量（MiB，0 = 使用默认值 64）。
	ResponseCacheMB int
	// ResponseCacheTTLSec 是默认缓存 TTL（秒，0 = 使用默认值 60）。
	ResponseCacheTTLSec int

	// RequestDecompressionMaxBytes 是请求侧单层解压的产出硬上限（字节），用于压缩
	// 炸弹防护。0 = 使用默认值 64 MiB（对应用户数据的 32 MiB 入站请求体上限）。
	RequestDecompressionMaxBytes int64
	// ResponseDecompressionMaxBytes 是响应侧单层解压的产出硬上限（字节）。
	// 0 = 使用默认值 8 MiB，与 maxStreamTransformBufferBytes 齐平。
	ResponseDecompressionMaxBytes int64

	// Queue 调优各类可观测/异步写入队列的容量与批大小。
	// 默认值与历史硬编码常量一致；环境变量主要用于高并发场景扩容。
	Queue QueueConfig
	// QueueWarnings 记录加载 Queue 时发生的解析失败与越界钳制。
	// 由 LoadConfigFromEnv 填充，NewRuntime 逐条打成 WARN。
	// 单独成字段而不是走 Validate()：Validate 在启动流程里被调用两次
	// （preflight + 应用存储 Redis 配置后），复用它会让每条告警重复出现。
	QueueWarnings []string
	HTTPTrace     HTTPTraceConfig
}

type HTTPTraceConfig struct {
	Enabled  bool
	Level    string
	Warnings []string
}

// CVEConfig 控制 CVE 专项检测与情报源同步。
type CVEConfig struct {
	Enabled      bool   `yaml:"enabled" json:"enabled"`
	FeedEnabled  bool   `yaml:"feed_enabled" json:"feed_enabled"`
	FeedInterval string `yaml:"feed_interval" json:"feed_interval"` // 例如 "6h"
	NVDAPIKey    string `yaml:"nvd_api_key" json:"nvd_api_key"`
	AutoApprove  bool   `yaml:"auto_approve" json:"auto_approve"` // 自动批准生成的规则
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

	// 解压产出上限：未设置时保持 0，由 proxy 包内的默认值兜底；解析失败沿用队列
	// 参数的处置口径——保留默认值并产出告警，不静默。
	var decompressionWarns []string
	requestDecompressionMaxBytes := parseDecompressionLimitEnv("MY_OPENWAF_REQUEST_DECOMPRESS_LIMIT_BYTES", &decompressionWarns)
	responseDecompressionMaxBytes := parseDecompressionLimitEnv("MY_OPENWAF_RESPONSE_DECOMPRESS_LIMIT_BYTES", &decompressionWarns)

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
	httpTraceCfg := DefaultHTTPTraceConfig()
	httpTraceCfg.Enabled = strings.ToLower(strings.TrimSpace(os.Getenv("MY_OPENWAF_TRACE_ENABLED"))) == "true"
	var httpTraceWarns []string
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("MY_OPENWAF_TRACE_LEVEL"))); v != "" {
		switch v {
		case "base", "detailed":
			httpTraceCfg.Level = v
		default:
			httpTraceWarns = append(httpTraceWarns, queueParseWarning("MY_OPENWAF_TRACE_LEVEL", v, httpTraceCfg.Level))
		}
	}
	httpTraceCfg.Warnings = httpTraceWarns

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
		DBDriver:                      driver,
		DBDSN:                         dsn,
		LogDBDSN:                      logDSN,
		DataDir:                       dir,
		RedisAddr:                     strings.TrimSpace(os.Getenv("MY_OPENWAF_REDIS_ADDR")),
		RedisPassword:                 strings.TrimSpace(os.Getenv("MY_OPENWAF_REDIS_PASSWORD")),
		RedisDB:                       rd,
		AdminBind:                     adminBind,
		AdminStaticDir:                strings.TrimSpace(os.Getenv("MY_OPENWAF_ADMIN_STATIC_DIR")),
		Bot:                           botCfg,
		CVE:                           cveCfg,
		Drop:                          dropCfg,
		ResponseCacheMB:               cacheMB,
		ResponseCacheTTLSec:           cacheTTL,
		RequestDecompressionMaxBytes:  requestDecompressionMaxBytes,
		ResponseDecompressionMaxBytes: responseDecompressionMaxBytes,
		Queue:                         queueCfg,
		QueueWarnings:                 append(queueWarns, decompressionWarns...),
		HTTPTrace:                     httpTraceCfg,
	}
}

/**
 * DefaultHTTPTraceConfig 返回遥测的默认配置：关闭、详细级别。
 *
 * 级别默认取 detailed 而不是 base：开关本身已经承担了"是否付采集成本"的决策，
 * 打开开关的人要的是分阶段数字，而不是再被一个默认值悄悄降级成只有总耗时。
 *
 * @return 默认配置，Warnings 为空。
 */
func DefaultHTTPTraceConfig() HTTPTraceConfig {
	return HTTPTraceConfig{Enabled: false, Level: "detailed"}
}
