package configoverride

import (
	"strconv"
	"strings"
	"time"
)

// Kind 描述一个配置键的取值类型，与 Admin 端点返回的 type 字段逐一对应。
// 只有四种取值：布尔、整数、时长与字符串；枚举类键用字符串承载，
// 合法取值由 Spec.EnumValues 声明。
type Kind string

const (
	KindBool     Kind = "bool"
	KindInt      Kind = "int"
	KindString   Kind = "string"
	KindDuration Kind = "duration"
)

// Scope 描述一个键在覆盖机制中的可写性。
type Scope string

const (
	// ScopeRuntime 表示该键可通过覆盖表读写。
	// 是否要等重启才生效另由 Spec.RestartRequired 表达。
	ScopeRuntime Scope = "runtime"
	// ScopeDelegated 表示该键已有专用 Admin 端点作为唯一写入口，
	// 覆盖机制只负责展示它的三态来源，避免出现第二份真相。
	ScopeDelegated Scope = "delegated"
	// ScopeBootstrap 表示该键是进程引导参数（数据库、监听地址、密钥），
	// 必须留在环境变量，覆盖机制只读展示。
	ScopeBootstrap Scope = "bootstrap"
	// ScopeTestOnly 表示该键仅供测试或基准使用，不进入管理界面，也不可覆盖。
	ScopeTestOnly Scope = "test_only"
)

// 域标识。Admin 端点返回的 group 字段直接取这些值，界面据此分组渲染，
// 顺序与冻结契约第 3 节一致。
const (
	GroupBootstrap     = "bootstrap"
	GroupNetwork       = "network"
	GroupDetection     = "detection"
	GroupObservability = "observability"
	GroupLimits        = "limits"
	GroupCache         = "cache"
	GroupQueue         = "queue"
	GroupHTTP3         = "http3"
	GroupInternal      = "internal"
)

// Group 是响应 groups[] 的一个元素。
type Group struct {
	// Key 是域标识。
	Key string
	// LabelKey 是该域的界面标题 i18n 键，恒为 "envOverrides.group." + Key。
	LabelKey string
}

// groupOrder 是响应 groups[] 的固定顺序。
var groupOrder = []string{
	GroupBootstrap,
	GroupNetwork,
	GroupDetection,
	GroupObservability,
	GroupLimits,
	GroupCache,
	GroupQueue,
	GroupHTTP3,
	GroupInternal,
}

// Groups 按固定顺序返回全部 9 个域。
//
// @return 域的副本，调用方改动不会污染包内状态。
func Groups() []Group {
	out := make([]Group, 0, len(groupOrder))
	for _, key := range groupOrder {
		out = append(out, Group{Key: key, LabelKey: "envOverrides.group." + key})
	}
	return out
}

// Spec 描述一个键的静态元数据。
type Spec struct {
	// Key 是覆盖表与 Admin 端点使用的稳定键名。
	Key string
	// Env 是环境变量名；空串表示该键没有环境变量载体，只可能来自内置默认值或覆盖表。
	Env string
	// Group 是键所属的域标识，取值见 Group* 常量。
	Group string
	// Kind 决定覆盖值的 JSON 类型与校验方式。
	Kind Kind
	// Scope 决定该键是否可写、写入口在哪里。
	Scope Scope
	// DefaultValue 是环境变量未设置（或取值不可用）时的生效值。
	// 类型与 Kind 一致：bool / int64 / string（时长类键用 Go duration 文本表达）。
	DefaultValue any
	// Min/Max 是整型与时长类键的合法区间；Min 为 0 表示不设下界，
	// Max 为 0 表示不设上界。时长类键的区间以纳秒为单位。
	Min int64
	Max int64
	// EnumValues 非空时，该键的取值必须是其中之一（不区分大小写）。
	EnumValues []string
	// Secret 为真时端点不得回显真实取值，只回报「已设置」。
	Secret bool
	// RestartRequired 为真时覆盖要等进程重启才生效（结构体在启动期已固化）。
	RestartRequired bool
	// DelegatedTo 是 ScopeDelegated 键的专用端点路径。
	DelegatedTo string
	// ParseEnv 把已设置的环境变量原文转换为生效值；第二个返回值为 false 时表示
	// 取值不可用，调用方回退 DefaultValue。为 nil 表示按字符串处理（保留原值）。
	ParseEnv func(raw string) (any, bool)
	// Description 是面向界面的中文说明。
	Description string
}

// LabelKey 返回该键的界面标题 i18n 键。
func (s Spec) LabelKey() string { return "envOverrides.key." + s.Key }

// DescriptionKey 返回该键的界面说明 i18n 键。
func (s Spec) DescriptionKey() string { return "envOverrides.key." + s.Key + ".desc" }

// ---- 环境变量取值解析器 ----
//
// 各解析器逐字复刻 LoadConfigFromEnv 与 logger 包里的既有口径，否则
// 「未覆盖时行为与现状逐字节一致」这条验收线不成立。

// parseBoolLiteralTrue 复刻「只有字面 true 才开」的口径（CVE 系列与 TRACE_ENABLED）。
func parseBoolLiteralTrue(raw string) (any, bool) {
	return strings.EqualFold(strings.TrimSpace(raw), "true"), true
}

// parseBoolLiteralFalse 复刻「只有字面 false 才关」的口径（DROP_ENABLED）。
func parseBoolLiteralFalse(raw string) (any, bool) {
	return !strings.EqualFold(strings.TrimSpace(raw), "false"), true
}

// parseBoolOne 复刻「只有 1 为真」的口径（LOG_ALSO_STDOUT）。
func parseBoolOne(raw string) (any, bool) {
	return strings.TrimSpace(raw) == "1", true
}

// parseTrimmedString 复刻字符串类环境变量的「去空白后使用」口径。
func parseTrimmedString(raw string) (any, bool) {
	return strings.TrimSpace(raw), true
}

// parseRawString 保留环境变量原文，用于行为上不做 trim 的键。
func parseRawString(raw string) (any, bool) {
	return raw, true
}

// parseStrictBool 解析覆盖表与端点提交的布尔值，只接受 JSON 布尔与 true/false 文本。
func parseStrictBool(raw string) (any, bool) {
	v, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return nil, false
	}
	return v, true
}

// parseIntPositive 复刻「正整数才生效」的口径（BOT_THRESHOLD / DROP_BOT_THRESHOLD /
// RESPONSE_CACHE_MB / RESPONSE_CACHE_TTL_SEC）。
func parseIntPositive(raw string) (any, bool) {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v <= 0 {
		return nil, false
	}
	return int64(v), true
}

// parseIntAny 复刻队列参数的「整数即生效，越界交给钳制」口径。
func parseIntAny(raw string) (any, bool) {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return nil, false
	}
	return int64(v), true
}

// parseIntAnyAllowFail 复刻 REDIS_DB 的「解析失败按 0 处理」口径。
func parseIntAnyAllowFail(raw string) (any, bool) {
	v, _ := strconv.Atoi(strings.TrimSpace(raw))
	return int64(v), true
}

// parsePositiveInt64 复刻解压上限的「正 int64 才生效」口径。
func parsePositiveInt64(raw string) (any, bool) {
	v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || v <= 0 {
		return nil, false
	}
	return v, true
}

// parseUintAtLeastOne 复刻 ACCESSLOG_SAMPLING 的「uint32 且不小于 1」口径。
func parseUintAtLeastOne(raw string) (any, bool) {
	v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 32)
	if err != nil || v < 1 {
		return nil, false
	}
	return int64(v), true
}

// parseDurationText 解析时长类键的取值：未设置或不可用时回退默认值。
func parseDurationText(raw string) (any, bool) {
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return nil, false
	}
	return d.String(), true
}

// parseTraceLevel 复刻 TRACE_LEVEL 的白名单口径，非白名单取值回退 detailed 并告警。
func parseTraceLevel(raw string) (any, bool) {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "base", "detailed":
		return v, true
	default:
		return nil, false
	}
}

// parseH3Allow0RTT 复刻 H3_ALLOW_0RTT 的三态口径：1 强制开、0 强制关、其它透传快照。
func parseH3Allow0RTT(raw string) (any, bool) {
	switch strings.TrimSpace(raw) {
	case "1":
		return "on", true
	case "0":
		return "off", true
	default:
		return "auto", true
	}
}

// parseLogLevel 复刻日志级别白名单，非法取值回退内置默认级别。
func parseLogLevel(raw string) (any, bool) {
	v := strings.ToUpper(strings.TrimSpace(raw))
	switch v {
	case "DEBUG", "INFO", "WARN", "WARNING", "ERROR":
		return v, true
	default:
		return nil, false
	}
}

// parseLogColor 复刻 LOG_COLOR 的「1 或 true 开、其余关」口径；
// 空值表示跟随终端自动判定，即规范值 auto。
func parseLogColor(raw string) (any, bool) {
	if strings.TrimSpace(raw) == "" {
		return "auto", true
	}
	v := strings.TrimSpace(raw)
	if v == "1" || strings.EqualFold(v, "true") {
		return "on", true
	}
	return "off", true
}

// 常见取值上界。
const (
	maxUint32      = int64(1<<32 - 1)
	maxDBSizeMB    = int64(1 << 20)
	maxSecondValue = int64(1 << 31)
)

// registry 是全部 45 个键的静态注册表，顺序与冻结契约第 3 节一致。
var registry = []Spec{
	// ---- 引导类：必须留在环境变量，只读展示 ----
	{
		Key: "db_driver", Env: "MY_OPENWAF_DB_DRIVER", Group: GroupBootstrap, Kind: KindString,
		Scope: ScopeBootstrap, DefaultValue: "sqlite",
		EnumValues:  []string{"sqlite", "mysql", "postgres", "postgresql"},
		ParseEnv:    func(raw string) (any, bool) { return strings.ToLower(strings.TrimSpace(raw)), true },
		Description: "数据库驱动；引导参数，数据库句柄在启动期打开。",
	},
	{
		Key: "dsn", Env: "MY_OPENWAF_DSN", Group: GroupBootstrap, Kind: KindString,
		Scope: ScopeBootstrap, DefaultValue: "", Secret: true, ParseEnv: parseTrimmedString,
		Description: "主数据库连接串；MY_OPENWAF_DB 是历史别名，优先级低于它。引导参数。",
	},
	{
		Key: "data_dir", Env: "MY_OPENWAF_DATA", Group: GroupBootstrap, Kind: KindString,
		Scope: ScopeBootstrap, DefaultValue: "./data", ParseEnv: parseTrimmedString,
		Description: "SQLite 默认路径所用的数据目录；引导参数。",
	},
	{
		Key: "admin_bind", Env: "MY_OPENWAF_ADMIN_BIND", Group: GroupBootstrap, Kind: KindString,
		Scope: ScopeBootstrap, DefaultValue: ":9443", ParseEnv: parseTrimmedString,
		Description: "管理控制面监听地址；引导参数，监听器在启动期创建。",
	},
	{
		Key: "log_dsn", Env: "MY_OPENWAF_LOG_DSN", Group: GroupBootstrap, Kind: KindString,
		Scope: ScopeBootstrap, DefaultValue: "", Secret: true, ParseEnv: parseTrimmedString,
		Description: "独立日志库连接串；MY_OPENWAF_LOG_DB 是历史别名，优先级低于它。引导参数。",
	},
	{
		Key: "pprof_bind", Env: "MY_OPENWAF_PPROF_BIND", Group: GroupBootstrap, Kind: KindString,
		Scope: ScopeBootstrap, DefaultValue: "", ParseEnv: parseTrimmedString,
		Description: "net/http/pprof 监听地址，空值表示关闭；引导参数。",
	},
	{
		Key: "jwt_secret", Env: "MY_OPENWAF_JWT_SECRET", Group: GroupBootstrap, Kind: KindString,
		Scope: ScopeBootstrap, DefaultValue: "", Secret: true, ParseEnv: parseTrimmedString,
		Description: "JWT 签名主密钥；环境变量优先于库中持久化值。引导参数。",
	},

	// ---- 网络与静态资源 ----
	{
		Key: "redis_addr", Env: "MY_OPENWAF_REDIS_ADDR", Group: GroupNetwork, Kind: KindString,
		Scope: ScopeDelegated, DefaultValue: "", ParseEnv: parseTrimmedString,
		DelegatedTo: "/api/v1/redis-config",
		Description: "Redis 地址；写入口是 redis_config 设置键，启用后整块覆盖环境变量。",
	},
	{
		Key: "redis_password", Env: "MY_OPENWAF_REDIS_PASSWORD", Group: GroupNetwork, Kind: KindString,
		Scope: ScopeDelegated, DefaultValue: "", Secret: true, ParseEnv: parseTrimmedString,
		DelegatedTo: "/api/v1/redis-config",
		Description: "Redis 密码；写入口是 redis_config 设置键，不回显真值。",
	},
	{
		Key: "redis_db", Env: "MY_OPENWAF_REDIS_DB", Group: GroupNetwork, Kind: KindInt,
		Scope: ScopeDelegated, DefaultValue: int64(0), Min: 0, Max: maxSecondValue,
		ParseEnv: parseIntAnyAllowFail, DelegatedTo: "/api/v1/redis-config",
		Description: "Redis 逻辑库编号；写入口是 redis_config 设置键。",
	},
	{
		Key: "admin_static_dir", Env: "MY_OPENWAF_ADMIN_STATIC_DIR", Group: GroupNetwork, Kind: KindString,
		Scope: ScopeRuntime, DefaultValue: "", ParseEnv: parseTrimmedString,
		RestartRequired: true,
		Description:     "用磁盘目录覆盖内嵌前端产物（本地开发用）；静态资源根在启动期装配。",
	},
	{
		Key: "captcha_dir", Env: "MY_OPENWAF_CAPTCHA_DIR", Group: GroupNetwork, Kind: KindString,
		Scope: ScopeRuntime, DefaultValue: "", ParseEnv: parseRawString,
		RestartRequired: true,
		Description: "验证码图片资源目录覆盖；验证码提供者在启动期创建。" +
			"空值表示使用内置默认目录，与未设置等价。",
	},

	// ---- 检测：CVE / Bot / Drop ----
	{
		Key: "cve_enabled", Env: "MY_OPENWAF_CVE_ENABLED", Group: GroupDetection, Kind: KindBool,
		Scope: ScopeRuntime, DefaultValue: false, ParseEnv: parseBoolLiteralTrue,
		Description: "全局 CVE 专项检测的默认开关；站点或策略显式设置 cve_enabled 时以站点为准。",
	},
	{
		Key: "cve_feed_enabled", Env: "MY_OPENWAF_CVE_FEED_ENABLED", Group: GroupDetection, Kind: KindBool,
		Scope: ScopeRuntime, DefaultValue: false, ParseEnv: parseBoolLiteralTrue, RestartRequired: true,
		Description: "CVE 情报源后台同步开关；同步管理器在启动期创建。",
	},
	{
		Key: "cve_feed_interval", Env: "MY_OPENWAF_CVE_FEED_INTERVAL", Group: GroupDetection, Kind: KindDuration,
		Scope: ScopeRuntime, DefaultValue: "6h", Min: 1, Max: 0, ParseEnv: parseDurationText,
		RestartRequired: true,
		Description:     "CVE 情报源同步周期（Go duration 文本，如 6h）；ticker 在启动期创建。",
	},
	{
		Key: "nvd_api_key", Env: "MY_OPENWAF_NVD_API_KEY", Group: GroupDetection, Kind: KindString,
		Scope: ScopeRuntime, DefaultValue: "", Secret: true, ParseEnv: parseTrimmedString,
		RestartRequired: true,
		Description:     "NVD API 密钥；不回显真值，同步管理器在启动期装配。",
	},
	{
		Key: "cve_auto_approve", Env: "MY_OPENWAF_CVE_AUTO_APPROVE", Group: GroupDetection, Kind: KindBool,
		Scope: ScopeRuntime, DefaultValue: false, ParseEnv: parseBoolLiteralTrue, RestartRequired: true,
		Description: "自动批准情报源生成的 CVE 规则；取值在同步管理器构造期固化。",
	},
	{
		Key: "geoip_db_path", Env: "MY_OPENWAF_GEOIP_DB", Group: GroupDetection, Kind: KindString,
		Scope: ScopeRuntime, DefaultValue: "", ParseEnv: parseTrimmedString, RestartRequired: true,
		Description: "MaxMind GeoLite2 数据库路径，空值表示不做地理维度打分；GeoIP 解析器在启动期创建。",
	},
	{
		Key: "bot_threshold", Env: "MY_OPENWAF_BOT_THRESHOLD", Group: GroupDetection, Kind: KindInt,
		Scope: ScopeRuntime, DefaultValue: int64(80), Min: 1, Max: 100, ParseEnv: parseIntPositive,
		RestartRequired: true,
		Description: "bot 评分触发拦截的总分阈值；阈值随 reload 取自 drop_policy 设置行，该行缺失时" +
			"回落到启动期固化的取值。",
	},
	{
		Key: "drop_enabled", Env: "MY_OPENWAF_DROP_ENABLED", Group: GroupDetection, Kind: KindBool,
		Scope: ScopeRuntime, DefaultValue: true, ParseEnv: parseBoolLiteralFalse, RestartRequired: true,
		Description: "TCP 连接关闭策略总开关；仅字面 false 关闭。drop_policy 设置键的对应字段优先，" +
			"该行缺失时回落到启动期固化的取值。",
	},
	{
		Key: "drop_bot_threshold", Env: "MY_OPENWAF_DROP_BOT_THRESHOLD", Group: GroupDetection, Kind: KindInt,
		Scope: ScopeRuntime, DefaultValue: int64(80), Min: 1, Max: 100, ParseEnv: parseIntPositive,
		RestartRequired: true,
		Description: "drop 决策使用的 bot 评分阈值。drop_policy 设置键的对应字段优先，" +
			"该行缺失时回落到启动期固化的取值。",
	},
	{
		Key: "cve_auto_drop_critical", Group: GroupDetection, Kind: KindBool,
		Scope: ScopeRuntime, DefaultValue: true,
		Description: "严重级 CVE 命中且规则未指定动作时升级为 drop；无环境变量载体。" +
			"protection 设置行与站点级覆盖依旧优先。",
	},
	{
		Key: "cve_auto_drop_high", Group: GroupDetection, Kind: KindBool,
		Scope: ScopeRuntime, DefaultValue: true,
		Description: "高危 CVE 命中且规则未指定动作时升级为 drop；无环境变量载体。" +
			"protection 设置行与站点级覆盖依旧优先。",
	},
	{
		Key: "bot_enabled", Group: GroupDetection, Kind: KindBool,
		Scope: ScopeRuntime, DefaultValue: true, RestartRequired: true,
		Description: "是否创建 GeoIP 解析器并给 bot 两阶段评分挂载地理位置打分；无环境变量载体，" +
			"解析器在启动期创建。",
	},

	// ---- 可观测性：日志与遥测 ----
	{
		Key: "trace_enabled", Env: "MY_OPENWAF_TRACE_ENABLED", Group: GroupObservability, Kind: KindBool,
		Scope: ScopeRuntime, DefaultValue: false, ParseEnv: parseBoolLiteralTrue,
		RestartRequired: true,
		Description:     "是否在数据面监听上注册 Hertz Tracer 采集分阶段耗时；仅字面 true 开启，Tracer 只在监听器构造期注册。",
	},
	{
		Key: "trace_level", Env: "MY_OPENWAF_TRACE_LEVEL", Group: GroupObservability, Kind: KindString,
		Scope: ScopeRuntime, DefaultValue: "detailed", EnumValues: []string{"base", "detailed"},
		ParseEnv: parseTraceLevel, RestartRequired: true,
		Description: "遥测采集级别；base 只有总耗时，detailed 追加各阶段事件。级别在 Tracer 构造期固化。",
	},
	{
		Key: "log_level", Env: "MY_OPENWAF_LOG_LEVEL", Group: GroupObservability, Kind: KindString,
		Scope: ScopeDelegated, DefaultValue: "INFO",
		EnumValues:  []string{"DEBUG", "INFO", "WARN", "WARNING", "ERROR"},
		ParseEnv:    parseLogLevel,
		DelegatedTo: "/api/v1/log-config",
		Description: "日志级别；写入口是 log_config 设置键，热生效。",
	},
	{
		Key: "log_file", Env: "MY_OPENWAF_LOG_FILE", Group: GroupObservability, Kind: KindString,
		Scope: ScopeDelegated, DefaultValue: "", ParseEnv: parseRawString,
		DelegatedTo: "/api/v1/log-config",
		Description: "日志文件路径，空值表示只写标准输出；写入口是 log_config 设置键，热生效。",
	},
	{
		Key: "log_also_stdout", Env: "MY_OPENWAF_LOG_ALSO_STDOUT", Group: GroupObservability, Kind: KindBool,
		Scope: ScopeDelegated, DefaultValue: false, ParseEnv: parseBoolOne,
		DelegatedTo: "/api/v1/log-config",
		Description: "日志同时镜像到标准输出；写入口是 log_config 设置键，热生效。",
	},
	{
		Key: "log_color", Env: "MY_OPENWAF_LOG_COLOR", Group: GroupObservability, Kind: KindString,
		Scope: ScopeRuntime, DefaultValue: "auto", EnumValues: []string{"auto", "on", "off"},
		ParseEnv: parseLogColor, RestartRequired: true,
		Description: "日志着色；auto 表示按标准输出是否为终端自动判定。着色模式在启动期" +
			"注入 logger，并在每次保存日志配置时透传。",
	},
	{
		Key: "accesslog_sampling", Env: "MY_OPENWAF_ACCESSLOG_SAMPLING", Group: GroupObservability, Kind: KindInt,
		Scope: ScopeRuntime, DefaultValue: int64(1), Min: 1, Max: maxUint32,
		ParseEnv: parseUintAtLeastOne, RestartRequired: true,
		Description: "访问日志采样率，1 表示全量记录；读取点在数据面监听器构造期固化。" +
			"带 WAF 动作或 4xx/5xx 的记录不受采样影响。",
	},

	// ---- 解压上限 ----
	{
		Key: "request_decompress_limit_bytes", Env: "MY_OPENWAF_REQUEST_DECOMPRESS_LIMIT_BYTES",
		Group: GroupLimits, Kind: KindInt, Scope: ScopeRuntime, DefaultValue: int64(0),
		Min: 1, Max: int64(1) << 40, ParseEnv: parsePositiveInt64, RestartRequired: true,
		Description: "请求体单层解压产出的硬上限（字节）；0 表示由 proxy 包按方向回退默认值。",
	},
	{
		Key: "response_decompress_limit_bytes", Env: "MY_OPENWAF_RESPONSE_DECOMPRESS_LIMIT_BYTES",
		Group: GroupLimits, Kind: KindInt, Scope: ScopeRuntime, DefaultValue: int64(0),
		Min: 1, Max: int64(1) << 40, ParseEnv: parsePositiveInt64, RestartRequired: true,
		Description: "上游响应体单层解压产出的硬上限（字节）；0 表示由 proxy 包按方向回退默认值。",
	},

	// ---- 响应缓存 ----
	{
		Key: "response_cache_mb", Env: "MY_OPENWAF_RESPONSE_CACHE_MB", Group: GroupCache, Kind: KindInt,
		Scope: ScopeRuntime, DefaultValue: int64(64), Min: 1, Max: maxDBSizeMB,
		ParseEnv: parseIntPositive, RestartRequired: true,
		Description: "响应缓存容量（MiB）；缓存实例在启动期创建。",
	},
	{
		Key: "response_cache_ttl_sec", Env: "MY_OPENWAF_RESPONSE_CACHE_TTL_SEC", Group: GroupCache, Kind: KindInt,
		Scope: ScopeRuntime, DefaultValue: int64(60), Min: 1, Max: maxSecondValue,
		ParseEnv: parseIntPositive, RestartRequired: true,
		Description: "响应缓存默认有效期（秒）；仅对未单独配置 TTL 的缓存规则生效。",
	},

	// ---- 队列与可观测性写入 ----
	{
		Key: "queue_event_buffer_size", Env: "MY_OPENWAF_QUEUE_EVENT_BUFFER_SIZE", Group: GroupQueue, Kind: KindInt,
		Scope: ScopeRuntime, DefaultValue: int64(16384), Min: 1, Max: 1 << 20,
		ParseEnv: parseIntAny, RestartRequired: true,
		Description: "安全事件与访问日志两类通道的容量；通道在启动期创建。",
	},
	{
		Key: "queue_drop_buffer_size", Env: "MY_OPENWAF_QUEUE_DROP_BUFFER_SIZE", Group: GroupQueue, Kind: KindInt,
		Scope: ScopeRuntime, DefaultValue: int64(8192), Min: 1, Max: 1 << 20,
		ParseEnv: parseIntAny, RestartRequired: true,
		Description: "drop 事件与 bot 评分日志两类通道的容量；通道在启动期创建。",
	},
	{
		Key: "queue_batch_size", Env: "MY_OPENWAF_QUEUE_BATCH_SIZE", Group: GroupQueue, Kind: KindInt,
		Scope: ScopeRuntime, DefaultValue: int64(4096), Min: 1, Max: 10000,
		ParseEnv: parseIntAny, RestartRequired: true,
		Description: "UnifiedWriter 触发 flush 的四类合计批次阈值；写入器在启动期创建。",
	},
	{
		Key: "queue_flush_interval", Env: "MY_OPENWAF_QUEUE_FLUSH_INTERVAL", Group: GroupQueue, Kind: KindDuration,
		Scope: ScopeRuntime, DefaultValue: "3s", Min: 1, Max: int64(60 * time.Second),
		ParseEnv: parseDurationText, RestartRequired: true,
		Description: "UnifiedWriter 的定时 flush 周期（Go duration 文本，如 3s）；上界 60s。",
	},
	{
		Key: "queue_write_batch_size", Env: "MY_OPENWAF_QUEUE_WRITE_BATCH_SIZE", Group: GroupQueue, Kind: KindInt,
		Scope: ScopeRuntime, DefaultValue: int64(64), Min: 1, Max: 10000,
		ParseEnv: parseIntAny, RestartRequired: true,
		Description: "通用 WriteQueue 的单事务批次阈值；写入队列在启动期创建。",
	},
	{
		Key: "queue_write_capacity", Env: "MY_OPENWAF_QUEUE_WRITE_CAPACITY", Group: GroupQueue, Kind: KindInt,
		Scope: ScopeRuntime, DefaultValue: int64(256), Min: 1, Max: 1 << 20,
		ParseEnv: parseIntAny, RestartRequired: true,
		Description: "通用 WriteQueue 的任务通道容量；通道在启动期创建。",
	},
	{
		Key: "queue_write_interval", Env: "MY_OPENWAF_QUEUE_WRITE_INTERVAL", Group: GroupQueue, Kind: KindDuration,
		Scope: ScopeRuntime, DefaultValue: "50ms", Min: 1, Max: 0,
		ParseEnv: parseDurationText, RestartRequired: true,
		Description: "通用 WriteQueue 的 ticker 周期；不设上界。",
	},

	// ---- HTTP/3 ----
	{
		Key: "h3_allow_0rtt", Env: "MY_OPENWAF_H3_ALLOW_0RTT", Group: GroupHTTP3, Kind: KindString,
		Scope: ScopeDelegated, DefaultValue: "auto", EnumValues: []string{"auto", "on", "off"},
		ParseEnv: parseH3Allow0RTT, DelegatedTo: "/api/v1/tls-config",
		Description: "HTTP/3 0-RTT 放行策略；auto 跟随快照的会话票据开关。" +
			"写入口是 tls_config 设置键的 allow_0rtt 三态，不做第二份真相。",
	},

	// ---- 测试与基准专用：只读返回，不进入可写清单 ----
	{
		Key: "h2ws_peeker_off", Env: "MY_OPENWAF_H2WS_PEEKER_OFF", Group: GroupInternal, Kind: KindString,
		Scope: ScopeTestOnly, DefaultValue: "", ParseEnv: parseRawString,
		Description: "h2 WebSocket 端到端测试的 Peeker 逃生门，运行时无效。",
	},
	{
		Key: "fingerprint_bench_db", Env: "MY_OPENWAF_FINGERPRINT_BENCH_DB", Group: GroupInternal, Kind: KindString,
		Scope: ScopeTestOnly, DefaultValue: "", ParseEnv: parseRawString,
		Description: "指纹缓存基准使用的数据库路径，运行时无效。",
	},
}

// byKey 是注册表的键索引。
var byKey = func() map[string]Spec {
	m := make(map[string]Spec, len(registry))
	for _, spec := range registry {
		m[spec.Key] = spec
	}
	return m
}()

// All 返回全部注册键的副本，顺序与注册表一致。
func All() []Spec {
	out := make([]Spec, len(registry))
	copy(out, registry)
	return out
}

// Lookup 按键名查找注册项。
func Lookup(key string) (Spec, bool) {
	spec, ok := byKey[key]
	return spec, ok
}

// IsWritable 报告该键是否允许通过覆盖表写入。
func (s Spec) IsWritable() bool { return s.Scope == ScopeRuntime }
