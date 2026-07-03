package system

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	coreredis "My-OpenWaf/internal/core/redis"
	"My-OpenWaf/internal/pkg/logger"
	snapshotpkg "My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/tlsmeta"
)

// NetworkConfig 网络协议配置。
type NetworkConfig struct {
	IPv6Enabled    bool   `json:"ipv6_enabled"`
	HTTP2Enabled   bool   `json:"http2_enabled"`
	HTTP3Enabled   bool   `json:"http3_enabled"`
	HTTP3Bind      string `json:"http3_bind"`
	DefaultALPN    string `json:"default_alpn"`
	DefaultNetwork string `json:"default_network"` // tcp, tcp4, tcp6
}

// LogConfig 日志配置。
type LogConfig struct {
	Level      string `json:"level"`       // DEBUG, INFO, WARN, ERROR
	FilePath   string `json:"file_path"`   // 日志文件路径
	AlsoStdout bool   `json:"also_stdout"` // 同时输出到控制台
}

// TLSDefaultConfig TLS 全局默认配置。
type TLSDefaultConfig struct {
	MinVersion               string `json:"min_version"`   // TLS10, TLS11, TLS12, TLS13
	MaxVersion               string `json:"max_version"`   // TLS10, TLS11, TLS12, TLS13
	CipherSuites             string `json:"cipher_suites"` // 逗号分隔
	DefaultALPN              string `json:"default_alpn"`  // h2,h3,http/1.1
	HasExplicitDefaultALPN   bool   `json:"has_explicit_default_alpn"`
	CurvePreferences         string `json:"curve_preferences"` // 逗号分隔
	PreferServerCipherSuites bool   `json:"prefer_server_cipher_suites"`
	SessionTicketsEnabled    bool   `json:"session_tickets_enabled"`
	SelfSignedOnIP           bool   `json:"self_signed_on_ip"` // IP 直接访问时使用自签证书
}

// RedisConfig Redis 连接配置。
type RedisConfig struct {
	Enabled  bool   `json:"enabled"`
	Addr     string `json:"addr"`
	Password string `json:"password,omitempty"`
	DB       int    `json:"db"`
}

// RedisConfigResponse Redis 配置响应，不回显密码。
type RedisConfigResponse struct {
	Enabled         bool   `json:"enabled"`
	Addr            string `json:"addr"`
	DB              int    `json:"db"`
	PasswordSet     bool   `json:"password_set"`
	Source          string `json:"source"`
	RestartRequired bool   `json:"restart_required"`
}

const (
	settingKeyNetwork    = "network_config"
	settingKeyHTTP2      = "http2_config"
	settingKeyLog        = "log_config"
	settingKeyTLSDefault = "tls_default_config"
)

// GetNetworkConfig 获取网络协议配置。
func GetNetworkConfig(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		cfg := loadNetworkConfig(repo)
		c.JSON(200, cfg)
	}
}

// UpdateNetworkConfig 更新网络协议配置。
func UpdateNetworkConfig(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			IPv6Enabled    *bool   `json:"ipv6_enabled"`
			HTTP2Enabled   *bool   `json:"http2_enabled"`
			HTTP3Enabled   *bool   `json:"http3_enabled"`
			HTTP3Bind      *string `json:"http3_bind"`
			DefaultALPN    *string `json:"default_alpn"`
			DefaultNetwork *string `json:"default_network"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		cfg := loadNetworkConfig(repo)
		if req.IPv6Enabled != nil {
			cfg.IPv6Enabled = *req.IPv6Enabled
		}
		if req.HTTP2Enabled != nil {
			cfg.HTTP2Enabled = *req.HTTP2Enabled
		}
		if req.HTTP3Enabled != nil {
			cfg.HTTP3Enabled = *req.HTTP3Enabled
		}
		if req.HTTP3Bind != nil {
			normalizedBind, ok := snapshotpkg.NormalizeHTTP3Bind(*req.HTTP3Bind)
			if !ok {
				c.JSON(400, map[string]string{"error": "invalid http3_bind"})
				return
			}
			cfg.HTTP3Bind = normalizedBind
		}
		if req.DefaultALPN != nil {
			cfg.DefaultALPN = snapshotpkg.NormalizeALPNList(*req.DefaultALPN)
		}
		if req.DefaultNetwork != nil {
			rawNetwork := strings.TrimSpace(*req.DefaultNetwork)
			if rawNetwork != "" {
				normalizedNetwork := snapshotpkg.NormalizeNetwork(rawNetwork)
				if normalizedNetwork == "" {
					c.JSON(400, map[string]string{"error": "invalid default_network"})
					return
				}
				cfg.DefaultNetwork = normalizedNetwork
			} else {
				cfg.DefaultNetwork = ""
			}
		}
		protocolSwitchChanged := req.HTTP2Enabled != nil || req.HTTP3Enabled != nil
		if (req.DefaultALPN != nil && strings.TrimSpace(cfg.DefaultALPN) == "") || (req.DefaultALPN == nil && protocolSwitchChanged) {
			cfg.DefaultALPN = snapshotpkg.DefaultALPNForProtocolSwitches(cfg.HTTP2Enabled, cfg.HTTP3Enabled)
		}
		cfg.DefaultALPN = snapshotpkg.NormalizeALPNList(cfg.DefaultALPN)
		if normalizedNetwork := snapshotpkg.NormalizeNetwork(cfg.DefaultNetwork); normalizedNetwork != "" {
			cfg.DefaultNetwork = normalizedNetwork
		} else {
			cfg.DefaultNetwork = "tcp"
		}
		data, _ := json.Marshal(cfg)
		if err := repo.Set(settingKeyNetwork, string(data)); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]interface{}{"error": "config applied but reload failed: " + err.Error(), "config": cfg})
			return
		}
		c.JSON(200, cfg)
	}
}

// GetHTTP2Config 获取 HTTP/2 运行参数配置。
func GetHTTP2Config(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		cfg := loadHTTP2Config(repo)
		c.JSON(200, cfg)
	}
}

// UpdateHTTP2Config 更新 HTTP/2 运行参数配置。
func UpdateHTTP2Config(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			ReadTimeoutSeconds           *int    `json:"read_timeout_seconds"`
			DisableKeepalive             *bool   `json:"disable_keepalive"`
			PermitProhibitedCipherSuites *bool   `json:"permit_prohibited_cipher_suites"`
			MaxConcurrentStreams         *uint32 `json:"max_concurrent_streams"`
			MaxReadFrameSize             *uint32 `json:"max_read_frame_size"`
			IdleTimeoutSeconds           *int    `json:"idle_timeout_seconds"`
			MaxUploadBufferPerConnection *int32  `json:"max_upload_buffer_per_connection"`
			MaxUploadBufferPerStream     *int32  `json:"max_upload_buffer_per_stream"`
			MaxHeaderBytes               *int    `json:"max_header_bytes"`
			MaxHeaderFields              *int    `json:"max_header_fields"`
			MaxHandlers                  *int    `json:"max_handlers"`
			MaxQueuedControlFrames       *int    `json:"max_queued_control_frames"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}

		cfg := loadHTTP2Config(repo)
		if req.ReadTimeoutSeconds != nil {
			cfg.ReadTimeoutSeconds = *req.ReadTimeoutSeconds
		}
		if req.DisableKeepalive != nil {
			cfg.DisableKeepalive = *req.DisableKeepalive
		}
		if req.PermitProhibitedCipherSuites != nil {
			cfg.PermitProhibitedCipherSuites = *req.PermitProhibitedCipherSuites
		}
		if req.MaxConcurrentStreams != nil {
			cfg.MaxConcurrentStreams = *req.MaxConcurrentStreams
		}
		if req.MaxReadFrameSize != nil {
			cfg.MaxReadFrameSize = *req.MaxReadFrameSize
		}
		if req.IdleTimeoutSeconds != nil {
			cfg.IdleTimeoutSeconds = *req.IdleTimeoutSeconds
		}
		if req.MaxUploadBufferPerConnection != nil {
			cfg.MaxUploadBufferPerConnection = *req.MaxUploadBufferPerConnection
		}
		if req.MaxUploadBufferPerStream != nil {
			cfg.MaxUploadBufferPerStream = *req.MaxUploadBufferPerStream
		}
		if req.MaxHeaderBytes != nil {
			cfg.MaxHeaderBytes = *req.MaxHeaderBytes
		}
		if req.MaxHeaderFields != nil {
			cfg.MaxHeaderFields = *req.MaxHeaderFields
		}
		if req.MaxHandlers != nil {
			cfg.MaxHandlers = *req.MaxHandlers
		}
		if req.MaxQueuedControlFrames != nil {
			cfg.MaxQueuedControlFrames = *req.MaxQueuedControlFrames
		}

		if err := validateHTTP2Config(cfg); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}

		data, _ := json.Marshal(cfg)
		if err := repo.Set(settingKeyHTTP2, string(data)); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]interface{}{"error": "config applied but reload failed: " + err.Error(), "config": cfg})
			return
		}
		c.JSON(200, cfg)
	}
}

// GetLogConfig 获取日志配置。
func GetLogConfig(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		cfg := loadLogConfig(repo)
		cfg.Level = logger.GetLevel()
		c.JSON(200, cfg)
	}
}

// UpdateLogConfig 更新日志配置并立即生效。
func UpdateLogConfig(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			Level      *string `json:"level"`
			FilePath   *string `json:"file_path"`
			AlsoStdout *bool   `json:"also_stdout"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		cfg := loadLogConfig(repo)
		if req.Level != nil {
			cfg.Level = *req.Level
		}
		if req.FilePath != nil {
			cfg.FilePath = *req.FilePath
		}
		if req.AlsoStdout != nil {
			cfg.AlsoStdout = *req.AlsoStdout
		}
		logger.Configure(logger.Config{Level: cfg.Level, FilePath: cfg.FilePath, AlsoStdout: cfg.AlsoStdout})
		cfg.Level = logger.GetLevel()
		data, _ := json.Marshal(cfg)
		if err := repo.Set(settingKeyLog, string(data)); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, cfg)
	}
}

// GetTLSDefaultConfig 获取 TLS 全局默认配置。
func GetTLSDefaultConfig(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		cfg := loadTLSDefaultConfig(repo)
		c.JSON(200, cfg)
	}
}

// UpdateTLSDefaultConfig 更新 TLS 全局默认配置。
func UpdateTLSDefaultConfig(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			MinVersion               *string `json:"min_version"`
			MaxVersion               *string `json:"max_version"`
			CipherSuites             *string `json:"cipher_suites"`
			DefaultALPN              *string `json:"default_alpn"`
			CurvePreferences         *string `json:"curve_preferences"`
			PreferServerCipherSuites *bool   `json:"prefer_server_cipher_suites"`
			SessionTicketsEnabled    *bool   `json:"session_tickets_enabled"`
			SelfSignedOnIP           *bool   `json:"self_signed_on_ip"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		cfg := loadTLSDefaultConfig(repo)
		if req.MinVersion != nil {
			minVersion := tlsmeta.NormalizeRuntimeVersionToken(*req.MinVersion)
			if minVersion == "" {
				c.JSON(400, map[string]string{"error": "unsupported min_version"})
				return
			}
			cfg.MinVersion = minVersion
		}
		if req.MaxVersion != nil {
			maxVersion := tlsmeta.NormalizeRuntimeVersionToken(*req.MaxVersion)
			if maxVersion == "" {
				c.JSON(400, map[string]string{"error": "unsupported max_version"})
				return
			}
			cfg.MaxVersion = maxVersion
		}
		if !tlsmeta.RuntimeVersionRangeValid(cfg.MinVersion, cfg.MaxVersion) {
			c.JSON(400, map[string]string{"error": "invalid tls version range"})
			return
		}
		if req.CipherSuites != nil {
			if invalid := tlsmeta.InvalidTLSConfigCipherSuiteToken(*req.CipherSuites); invalid != "" {
				c.JSON(400, map[string]string{"error": "unsupported cipher_suites: " + invalid})
				return
			}
			cfg.CipherSuites = *req.CipherSuites
		}
		if req.DefaultALPN != nil {
			if strings.TrimSpace(*req.DefaultALPN) == "" {
				cfg.DefaultALPN = snapshotpkg.DefaultALPNForProtocolSwitches(true, true)
				cfg.HasExplicitDefaultALPN = false
			} else {
				cfg.DefaultALPN = snapshotpkg.NormalizeALPNList(*req.DefaultALPN)
				cfg.HasExplicitDefaultALPN = true
			}
		}
		if req.CurvePreferences != nil {
			cfg.CurvePreferences = *req.CurvePreferences
		}
		if req.PreferServerCipherSuites != nil {
			cfg.PreferServerCipherSuites = *req.PreferServerCipherSuites
		}
		if req.SessionTicketsEnabled != nil {
			cfg.SessionTicketsEnabled = *req.SessionTicketsEnabled
		}
		if req.SelfSignedOnIP != nil {
			cfg.SelfSignedOnIP = *req.SelfSignedOnIP
		}
		data, _ := marshalTLSDefaultConfigForStorage(cfg)
		if err := repo.Set(settingKeyTLSDefault, string(data)); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]interface{}{"error": "config applied but reload failed: " + err.Error(), "config": cfg})
			return
		}
		c.JSON(200, cfg)
	}
}

// GetRedisConfig 获取 Redis 连接配置。
func GetRedisConfig(repo *repository.SystemSettingsRepo, restartRequired bool) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		cfg := LoadRedisConfig(repo)
		c.JSON(200, redisConfigResponse(cfg, restartRequired))
	}
}

// UpdateRedisConfig 更新 Redis 连接配置，并在支持时触发运行时热重载。
func UpdateRedisConfig(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			Enabled  *bool   `json:"enabled"`
			Addr     *string `json:"addr"`
			Password *string `json:"password"`
			DB       *int    `json:"db"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		cfg := LoadRedisConfig(repo)
		if req.Enabled != nil {
			cfg.Enabled = *req.Enabled
		}
		if req.Addr != nil {
			cfg.Addr = strings.TrimSpace(*req.Addr)
		}
		if req.Password != nil {
			cfg.Password = *req.Password
		}
		if req.DB != nil {
			cfg.DB = *req.DB
		}
		if err := validateRedisConfig(cfg); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := probeRedisConfig(cfg); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		data, _ := json.Marshal(cfg)
		if err := repo.Set(store.SettingKeyRedisConfig, string(data)); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if reload != nil {
			if err := reload(); err != nil {
				c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "config": redisConfigResponse(cfg, false)})
				return
			}
		}
		c.JSON(200, redisConfigResponse(cfg, reload == nil))
	}
}

// ListCipherSuites 列出所有可用的 TLS 密码套件。
func ListCipherSuites() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]interface{}{
			"secure":   getSecureCipherSuites(),
			"insecure": getInsecureCipherSuites(),
			"curves": []curveInfo{
				{ID: uint16(tls.X25519), Name: "X25519"},
				{ID: uint16(tls.CurveP256), Name: "CurveP256"},
				{ID: uint16(tls.CurveP384), Name: "CurveP384"},
				{ID: uint16(tls.CurveP521), Name: "CurveP521"},
			},
		})
	}
}

func LoadRedisConfig(repo *repository.SystemSettingsRepo) RedisConfig {
	cfg := RedisConfig{}
	val, err := repo.Get(store.SettingKeyRedisConfig)
	if err != nil || val == "" {
		return cfg
	}
	_ = json.Unmarshal([]byte(val), &cfg)
	cfg.Addr = strings.TrimSpace(cfg.Addr)
	if cfg.DB < 0 {
		cfg.DB = 0
	}
	return cfg
}

func redisConfigResponse(cfg RedisConfig, restartRequired bool) RedisConfigResponse {
	return RedisConfigResponse{
		Enabled:         cfg.Enabled,
		Addr:            cfg.Addr,
		DB:              cfg.DB,
		PasswordSet:     cfg.Password != "",
		Source:          "database",
		RestartRequired: restartRequired,
	}
}

func validateRedisConfig(cfg RedisConfig) error {
	if cfg.DB < 0 {
		return fmt.Errorf("redis db must be >= 0")
	}
	if !cfg.Enabled {
		return nil
	}
	if strings.TrimSpace(cfg.Addr) == "" {
		return fmt.Errorf("redis addr is required when enabled")
	}
	if _, _, err := net.SplitHostPort(cfg.Addr); err != nil {
		return fmt.Errorf("invalid redis addr %q: %w", cfg.Addr, err)
	}
	return nil
}

func probeRedisConfig(cfg RedisConfig) error {
	if !cfg.Enabled {
		return nil
	}
	client := coreredis.OptionalClient(coreredis.RedisOptions{
		Addr:     strings.TrimSpace(cfg.Addr),
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := coreredis.Ping(ctx, client); err != nil {
		if client != nil {
			_ = client.Close()
		}
		return fmt.Errorf("redis connection failed: %w", err)
	}
	if client != nil {
		_ = client.Close()
	}
	return nil
}

func loadHTTP2Config(repo *repository.SystemSettingsRepo) snapshotpkg.HTTP2Config {
	cfg := snapshotpkg.DefaultHTTP2Config()
	val, err := repo.Get(settingKeyHTTP2)
	if err != nil || val == "" {
		return cfg
	}
	return snapshotpkg.LoadHTTP2Config(val)
}

func validateHTTP2Config(cfg snapshotpkg.HTTP2Config) error {
	if cfg.ReadTimeoutSeconds <= 0 {
		return fmt.Errorf("http2 read_timeout_seconds must be > 0")
	}
	if cfg.MaxConcurrentStreams == 0 || cfg.MaxConcurrentStreams > snapshotpkg.MaxHTTP2ConcurrentStreams {
		return fmt.Errorf("http2 max_concurrent_streams must be between 1 and %d", snapshotpkg.MaxHTTP2ConcurrentStreams)
	}
	if cfg.MaxReadFrameSize < snapshotpkg.MinHTTP2ReadFrameSize || cfg.MaxReadFrameSize > snapshotpkg.MaxHTTP2ReadFrameSize {
		return fmt.Errorf("http2 max_read_frame_size must be between %d and %d", snapshotpkg.MinHTTP2ReadFrameSize, snapshotpkg.MaxHTTP2ReadFrameSize)
	}
	if cfg.IdleTimeoutSeconds <= 0 {
		return fmt.Errorf("http2 idle_timeout_seconds must be > 0")
	}
	if cfg.MaxUploadBufferPerConnection < snapshotpkg.MinHTTP2UploadBufferPerConnection || cfg.MaxUploadBufferPerConnection > snapshotpkg.MaxHTTP2UploadBufferPerConnection {
		return fmt.Errorf("http2 max_upload_buffer_per_connection must be between %d and %d", snapshotpkg.MinHTTP2UploadBufferPerConnection, snapshotpkg.MaxHTTP2UploadBufferPerConnection)
	}
	if cfg.MaxUploadBufferPerStream <= 0 || cfg.MaxUploadBufferPerStream > snapshotpkg.MaxHTTP2UploadBufferPerStream {
		return fmt.Errorf("http2 max_upload_buffer_per_stream must be between 1 and %d", snapshotpkg.MaxHTTP2UploadBufferPerStream)
	}
	if cfg.MaxHeaderBytes <= 0 || cfg.MaxHeaderBytes > snapshotpkg.MaxHTTP2HeaderBytes {
		return fmt.Errorf("http2 max_header_bytes must be between 1 and %d", snapshotpkg.MaxHTTP2HeaderBytes)
	}
	if cfg.MaxHeaderFields <= 0 || cfg.MaxHeaderFields > snapshotpkg.MaxHTTP2HeaderFields {
		return fmt.Errorf("http2 max_header_fields must be between 1 and %d", snapshotpkg.MaxHTTP2HeaderFields)
	}
	if cfg.MaxHandlers < 0 || cfg.MaxHandlers > snapshotpkg.MaxHTTP2Handlers {
		return fmt.Errorf("http2 max_handlers must be between 0 and %d", snapshotpkg.MaxHTTP2Handlers)
	}
	if cfg.MaxQueuedControlFrames <= 0 || cfg.MaxQueuedControlFrames > snapshotpkg.MaxHTTP2QueuedControlFrames {
		return fmt.Errorf("http2 max_queued_control_frames must be between 1 and %d", snapshotpkg.MaxHTTP2QueuedControlFrames)
	}
	return nil
}

func loadNetworkConfig(repo *repository.SystemSettingsRepo) NetworkConfig {
	cfg := NetworkConfig{
		HTTP2Enabled:   true,
		HTTP3Enabled:   true,
		HTTP3Bind:      ":443",
		DefaultALPN:    snapshotpkg.DefaultALPNForProtocolSwitches(true, true),
		DefaultNetwork: "tcp",
	}
	val, err := repo.Get(settingKeyNetwork)
	if err != nil || val == "" {
		return cfg
	}
	var explicit struct {
		DefaultALPN *string `json:"default_alpn"`
	}
	_ = json.Unmarshal([]byte(val), &explicit)
	_ = json.Unmarshal([]byte(val), &cfg)
	if explicit.DefaultALPN == nil || strings.TrimSpace(cfg.DefaultALPN) == "" {
		cfg.DefaultALPN = snapshotpkg.DefaultALPNForProtocolSwitches(cfg.HTTP2Enabled, cfg.HTTP3Enabled)
	}
	cfg.DefaultALPN = snapshotpkg.NormalizeALPNList(cfg.DefaultALPN)
	if normalizedNetwork := snapshotpkg.NormalizeNetwork(cfg.DefaultNetwork); normalizedNetwork != "" {
		cfg.DefaultNetwork = normalizedNetwork
	} else {
		cfg.DefaultNetwork = "tcp"
	}
	if cfg.HTTP3Enabled && strings.TrimSpace(cfg.HTTP3Bind) == "" {
		cfg.HTTP3Bind = ":443"
	}
	if normalizedBind, ok := snapshotpkg.NormalizeHTTP3Bind(cfg.HTTP3Bind); ok {
		cfg.HTTP3Bind = normalizedBind
	} else {
		cfg.HTTP3Bind = ":443"
	}
	return cfg
}

func loadTLSDefaultConfig(repo *repository.SystemSettingsRepo) TLSDefaultConfig {
	cfg := TLSDefaultConfig{
		MinVersion:               "TLS10",
		MaxVersion:               "TLS13",
		DefaultALPN:              snapshotpkg.DefaultALPNForProtocolSwitches(true, true),
		CurvePreferences:         "X25519,CurveP256,CurveP384",
		PreferServerCipherSuites: true,
		SessionTicketsEnabled:    true,
		SelfSignedOnIP:           true,
	}
	val, err := repo.Get(settingKeyTLSDefault)
	if err != nil || val == "" {
		return cfg
	}
	var explicit struct {
		DefaultALPN           *string `json:"default_alpn"`
		SessionTicketsEnabled *bool   `json:"session_tickets_enabled"`
	}
	_ = json.Unmarshal([]byte(val), &explicit)
	_ = json.Unmarshal([]byte(val), &cfg)
	if strings.TrimSpace(cfg.MinVersion) == "" {
		cfg.MinVersion = "TLS10"
	}
	if strings.TrimSpace(cfg.MaxVersion) == "" {
		cfg.MaxVersion = "TLS13"
	}
	if strings.TrimSpace(cfg.DefaultALPN) == "" {
		cfg.DefaultALPN = snapshotpkg.DefaultALPNForProtocolSwitches(true, true)
	}
	cfg.DefaultALPN = snapshotpkg.NormalizeALPNList(cfg.DefaultALPN)
	cfg.HasExplicitDefaultALPN = explicit.DefaultALPN != nil && strings.TrimSpace(*explicit.DefaultALPN) != ""
	if strings.TrimSpace(cfg.CurvePreferences) == "" {
		cfg.CurvePreferences = "X25519,CurveP256,CurveP384"
	}
	if explicit.SessionTicketsEnabled == nil {
		cfg.SessionTicketsEnabled = true
	}
	return cfg
}

func marshalTLSDefaultConfigForStorage(cfg TLSDefaultConfig) ([]byte, error) {
	var defaultALPN *string
	if cfg.HasExplicitDefaultALPN && strings.TrimSpace(cfg.DefaultALPN) != "" {
		defaultALPN = &cfg.DefaultALPN
	}
	return json.Marshal(struct {
		MinVersion               string  `json:"min_version"`
		MaxVersion               string  `json:"max_version"`
		CipherSuites             string  `json:"cipher_suites"`
		DefaultALPN              *string `json:"default_alpn,omitempty"`
		CurvePreferences         string  `json:"curve_preferences"`
		PreferServerCipherSuites bool    `json:"prefer_server_cipher_suites"`
		SessionTicketsEnabled    bool    `json:"session_tickets_enabled"`
		SelfSignedOnIP           bool    `json:"self_signed_on_ip"`
	}{
		MinVersion:               cfg.MinVersion,
		MaxVersion:               cfg.MaxVersion,
		CipherSuites:             cfg.CipherSuites,
		DefaultALPN:              defaultALPN,
		CurvePreferences:         cfg.CurvePreferences,
		PreferServerCipherSuites: cfg.PreferServerCipherSuites,
		SessionTicketsEnabled:    cfg.SessionTicketsEnabled,
		SelfSignedOnIP:           cfg.SelfSignedOnIP,
	})
}

func loadLogConfig(repo *repository.SystemSettingsRepo) LogConfig {
	cfg := LogConfig{Level: logger.GetLevel()}
	val, err := repo.Get(settingKeyLog)
	if err != nil || val == "" {
		return cfg
	}
	_ = json.Unmarshal([]byte(val), &cfg)
	if strings.TrimSpace(cfg.Level) == "" {
		cfg.Level = logger.GetLevel()
	}
	return cfg
}

type cipherSuiteInfo struct {
	ID           uint16   `json:"id"`
	HexID        string   `json:"hex_id"`
	Name         string   `json:"name"`
	TLSVersions  []string `json:"tls_versions"`
	Insecure     bool     `json:"insecure"`
	Configurable bool     `json:"configurable"`
}

func tlsVersionNames(versions []uint16) []string {
	out := make([]string, 0, len(versions))
	for _, version := range versions {
		if name := tlsmeta.CanonicalVersionName(version); name != "" {
			out = append(out, name)
		}
	}
	return out
}

func tlsConfigCipherSuiteSupported(versions []uint16) bool {
	for _, version := range versions {
		switch version {
		case tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12:
			return true
		}
	}
	return false
}

type curveInfo struct {
	ID   uint16 `json:"id"`
	Name string `json:"name"`
}

func getSecureCipherSuites() []cipherSuiteInfo {
	var result []cipherSuiteInfo
	for _, suite := range tls.CipherSuites() {
		result = append(result, cipherSuiteInfo{ID: suite.ID, HexID: fmt.Sprintf("0x%04x", suite.ID), Name: suite.Name, TLSVersions: tlsVersionNames(suite.SupportedVersions), Configurable: tlsConfigCipherSuiteSupported(suite.SupportedVersions)})
	}
	return result
}

func getInsecureCipherSuites() []cipherSuiteInfo {
	var result []cipherSuiteInfo
	for _, suite := range tls.InsecureCipherSuites() {
		result = append(result, cipherSuiteInfo{ID: suite.ID, HexID: fmt.Sprintf("0x%04x", suite.ID), Name: suite.Name, TLSVersions: tlsVersionNames(suite.SupportedVersions), Insecure: true, Configurable: tlsConfigCipherSuiteSupported(suite.SupportedVersions)})
	}
	return result
}
