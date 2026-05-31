package core

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

	return Config{
		DBDriver:       driver,
		DBDSN:          dsn,
		LogDBDSN:       logDSN,
		DataDir:        dir,
		RedisAddr:      strings.TrimSpace(os.Getenv("MY_OPENWAF_REDIS_ADDR")),
		RedisPassword:  strings.TrimSpace(os.Getenv("MY_OPENWAF_REDIS_PASSWORD")),
		RedisDB:        rd,
		AdminBind:      adminBind,
		AdminStaticDir: strings.TrimSpace(os.Getenv("MY_OPENWAF_ADMIN_STATIC_DIR")),
		Bot:            botCfg,
		CVE:            cveCfg,
		Drop:           dropCfg,
	}
}
