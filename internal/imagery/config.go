package imagery

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SettingKey 是图像转换全局配置在 system_settings 中的键名。
const SettingKey = "image_transform"

// Config 是图像转换的全局运行时配置。
//
// 首版只做全局配置（与 network_config / http2_config 同级），站点级覆盖留待
// 需要时再加。字段全部是确定性的数值或开关，不做半继承语义——避免出现
// 「继承的 null 被写成 false」这类三态问题。
type Config struct {
	// Enabled 是总开关。关闭时数据面完全忽略 image_process 参数，
	// 也不做自适应格式协商。
	Enabled bool `json:"enabled"`
	// AdaptiveWebP 开启后，当客户端 Accept 含 image/webp 且响应的目标格式
	// 不是 WebP 时，自动转码为 WebP，并在响应上声明 Vary: Accept。
	AdaptiveWebP bool `json:"adaptive_webp"`
	// MaxPixels 是单张图的宽×高上限。
	MaxPixels int64 `json:"max_pixels"`
	// MaxSide 是单边长度上限。
	MaxSide int `json:"max_side"`
	// MaxBytes 是输入字节上限。
	MaxBytes int64 `json:"max_bytes"`
	// TimeoutMS 是单张图转换的墙钟预算（毫秒）。
	TimeoutMS int `json:"timeout_ms"`
	// Concurrency 是同时进行的转换数量上限；0 表示按 CPU 核数。
	Concurrency int `json:"concurrency"`
	// DefaultQuality 是未显式给出 quality 参数时使用的编码质量。
	DefaultQuality int `json:"default_quality"`
}

// 配置边界。越界值在解析时被钳制并记录，而不是让配置静默失效。
const (
	// MinTimeoutMS、MaxTimeoutMS 界定单张图的墙钟预算。
	MinTimeoutMS = 50
	MaxTimeoutMS = 30000
	// MaxConcurrencyLimit 是并发额度上限，防止误配置成无限制。
	MaxConcurrencyLimit = 256
	// MinQuality、MaxQuality 界定默认质量。
	MinQuality = 1
	MaxQuality = 100
)

// DefaultConfig 返回默认的图像转换配置。
//
// 默认关闭：ESA 的图像转换也是「在控制台开启后才生效」的开关，且本能力会
// 引入新的解码攻击面（见包文档的安全评估），默认开启不合适。
//
// @return 默认配置。
func DefaultConfig() Config {
	return Config{
		Enabled:        false,
		AdaptiveWebP:   false,
		MaxPixels:      DefaultDecodeLimits.MaxPixels,
		MaxSide:        DefaultDecodeLimits.MaxSide,
		MaxBytes:       DefaultDecodeLimits.MaxBytes,
		TimeoutMS:      int(DefaultOpTimeout / time.Millisecond),
		Concurrency:    0,
		DefaultQuality: 0,
	}
}

// LoadConfig 从 system_settings 的原始 JSON 解析配置。
//
// 解析失败时返回错误而不是默认值：图像转换是显式开启的能力，把「配置写坏了」
// 静默降级为默认值会让问题不可见。空值与空对象返回默认配置。
//
// @param raw system_settings 中的原始 JSON 字符串。
// @return 规范化后的配置。
func LoadConfig(raw string) (Config, error) {
	cfg := DefaultConfig()
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return cfg, nil
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return Config{}, fmt.Errorf("imagery: parse %s config: %w", SettingKey, err)
	}
	return cfg.Normalize(), nil
}

// Normalize 把配置钳制到合法区间并补齐零值。
//
// @return 规范化后的配置。
func (c Config) Normalize() Config {
	if c.MaxPixels <= 0 {
		c.MaxPixels = DefaultDecodeLimits.MaxPixels
	}
	if c.MaxSide <= 0 {
		c.MaxSide = DefaultDecodeLimits.MaxSide
	}
	if c.MaxBytes <= 0 {
		c.MaxBytes = DefaultDecodeLimits.MaxBytes
	}
	if c.TimeoutMS <= 0 {
		c.TimeoutMS = int(DefaultOpTimeout / time.Millisecond)
	}
	if c.TimeoutMS < MinTimeoutMS {
		c.TimeoutMS = MinTimeoutMS
	}
	if c.TimeoutMS > MaxTimeoutMS {
		c.TimeoutMS = MaxTimeoutMS
	}
	if c.Concurrency < 0 {
		c.Concurrency = 0
	}
	if c.Concurrency > MaxConcurrencyLimit {
		c.Concurrency = MaxConcurrencyLimit
	}
	if c.DefaultQuality < 0 {
		c.DefaultQuality = 0
	}
	if c.DefaultQuality > MaxQuality {
		c.DefaultQuality = MaxQuality
	}
	return c
}

// DecodeLimits 把配置里的解码限额投影成 DecodeLimits。
//
// @return 解码限额。
func (c Config) DecodeLimits() DecodeLimits {
	n := c.Normalize()
	return DecodeLimits{MaxPixels: n.MaxPixels, MaxSide: n.MaxSide, MaxBytes: n.MaxBytes}
}

// Timeout 返回配置的墙钟预算。
//
// @return 超时时间。
func (c Config) Timeout() time.Duration {
	n := c.Normalize()
	return time.Duration(n.TimeoutMS) * time.Millisecond
}

// ApplyGateLimit 按配置调整并发闸门额度。
//
// Concurrency 为 0 时重置为 CPU 核数。
func (c Config) ApplyGateLimit() {
	SetGateLimit(c.Concurrency)
}

// AcceptsWebP 判断 Accept 头是否允许 WebP。
//
// 只在显式出现 image/webp 时返回 true。不接受 image/* 通配符——按
// 「未声明即不支持」处理，避免把 WebP 推给明确声明了具体类型的客户端。
//
// @param accept Accept 头原值。
// @return 允许 WebP 时为 true。
func AcceptsWebP(accept string) bool {
	if accept == "" {
		return false
	}
	for _, part := range strings.Split(accept, ",") {
		media := strings.TrimSpace(part)
		if i := strings.IndexByte(media, ';'); i >= 0 {
			media = strings.TrimSpace(media[:i])
		}
		if strings.EqualFold(media, "image/webp") {
			return true
		}
	}
	return false
}
