package system

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/pkg/logger"
	"My-OpenWaf/internal/store/repository"
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
	MinVersion               string `json:"min_version"`       // TLS12, TLS13
	MaxVersion               string `json:"max_version"`       // TLS12, TLS13
	CipherSuites             string `json:"cipher_suites"`     // 逗号分隔
	DefaultALPN              string `json:"default_alpn"`      // h2,http/1.1
	CurvePreferences         string `json:"curve_preferences"` // 逗号分隔
	PreferServerCipherSuites bool   `json:"prefer_server_cipher_suites"`
	SelfSignedOnIP           bool   `json:"self_signed_on_ip"` // IP 直接访问时使用自签证书
}

const (
	settingKeyNetwork    = "network_config"
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
			cfg.HTTP3Bind = *req.HTTP3Bind
		}
		if req.DefaultALPN != nil {
			cfg.DefaultALPN = *req.DefaultALPN
		}
		if req.DefaultNetwork != nil {
			cfg.DefaultNetwork = *req.DefaultNetwork
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
			SelfSignedOnIP           *bool   `json:"self_signed_on_ip"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		cfg := loadTLSDefaultConfig(repo)
		if req.MinVersion != nil {
			cfg.MinVersion = *req.MinVersion
		}
		if req.MaxVersion != nil {
			cfg.MaxVersion = *req.MaxVersion
		}
		if req.CipherSuites != nil {
			cfg.CipherSuites = *req.CipherSuites
		}
		if req.DefaultALPN != nil {
			cfg.DefaultALPN = *req.DefaultALPN
		}
		if req.CurvePreferences != nil {
			cfg.CurvePreferences = *req.CurvePreferences
		}
		if req.PreferServerCipherSuites != nil {
			cfg.PreferServerCipherSuites = *req.PreferServerCipherSuites
		}
		if req.SelfSignedOnIP != nil {
			cfg.SelfSignedOnIP = *req.SelfSignedOnIP
		}
		data, _ := json.Marshal(cfg)
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

func loadNetworkConfig(repo *repository.SystemSettingsRepo) NetworkConfig {
	cfg := NetworkConfig{
		HTTP2Enabled:   true,
		HTTP3Enabled:   true,
		HTTP3Bind:      ":443",
		DefaultALPN:    "h2,h3,http/1.1",
		DefaultNetwork: "tcp",
	}
	val, err := repo.Get(settingKeyNetwork)
	if err != nil || val == "" {
		return cfg
	}
	_ = json.Unmarshal([]byte(val), &cfg)
	if strings.TrimSpace(cfg.DefaultALPN) == "" {
		cfg.DefaultALPN = "h2,h3,http/1.1"
	}
	if strings.TrimSpace(cfg.DefaultNetwork) == "" {
		cfg.DefaultNetwork = "tcp"
	}
	if cfg.HTTP3Enabled && strings.TrimSpace(cfg.HTTP3Bind) == "" {
		cfg.HTTP3Bind = ":443"
	}
	return cfg
}

func loadTLSDefaultConfig(repo *repository.SystemSettingsRepo) TLSDefaultConfig {
	cfg := TLSDefaultConfig{
		MinVersion:               "TLS10",
		MaxVersion:               "TLS13",
		DefaultALPN:              "h2,h3,http/1.1",
		CurvePreferences:         "X25519,CurveP256,CurveP384",
		PreferServerCipherSuites: true,
		SelfSignedOnIP:           true,
	}
	val, err := repo.Get(settingKeyTLSDefault)
	if err != nil || val == "" {
		return cfg
	}
	_ = json.Unmarshal([]byte(val), &cfg)
	if strings.TrimSpace(cfg.MinVersion) == "" {
		cfg.MinVersion = "TLS10"
	}
	if strings.TrimSpace(cfg.MaxVersion) == "" {
		cfg.MaxVersion = "TLS13"
	}
	if strings.TrimSpace(cfg.DefaultALPN) == "" {
		cfg.DefaultALPN = "h2,h3,http/1.1"
	}
	if strings.TrimSpace(cfg.CurvePreferences) == "" {
		cfg.CurvePreferences = "X25519,CurveP256,CurveP384"
	}
	return cfg
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
	ID          uint16   `json:"id"`
	HexID       string   `json:"hex_id"`
	Name        string   `json:"name"`
	TLSVersions []string `json:"tls_versions"`
	Insecure    bool     `json:"insecure"`
}

func tlsVersionNames(versions []uint16) []string {
	out := make([]string, 0, len(versions))
	for _, version := range versions {
		switch version {
		case tls.VersionTLS10:
			out = append(out, "TLS10")
		case tls.VersionTLS11:
			out = append(out, "TLS11")
		case tls.VersionTLS12:
			out = append(out, "TLS12")
		case tls.VersionTLS13:
			out = append(out, "TLS13")
		}
	}
	return out
}

type curveInfo struct {
	ID   uint16 `json:"id"`
	Name string `json:"name"`
}

func getSecureCipherSuites() []cipherSuiteInfo {
	var result []cipherSuiteInfo
	for _, suite := range tls.CipherSuites() {
		result = append(result, cipherSuiteInfo{ID: suite.ID, HexID: fmt.Sprintf("0x%04x", suite.ID), Name: suite.Name, TLSVersions: tlsVersionNames(suite.SupportedVersions)})
	}
	return result
}

func getInsecureCipherSuites() []cipherSuiteInfo {
	var result []cipherSuiteInfo
	for _, suite := range tls.InsecureCipherSuites() {
		result = append(result, cipherSuiteInfo{ID: suite.ID, HexID: fmt.Sprintf("0x%04x", suite.ID), Name: suite.Name, TLSVersions: tlsVersionNames(suite.SupportedVersions), Insecure: true})
	}
	return result
}
