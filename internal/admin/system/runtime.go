package system

import (
	"context"
	"net/url"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core"
)

type RuntimeConfigResponse struct {
	DBDriver        string `json:"db_driver"`
	DBDSN           string `json:"db_dsn"`
	LogDBDSN        string `json:"log_db_dsn"`
	DataDir         string `json:"data_dir"`
	RedisAddr       string `json:"redis_addr"`
	RedisEnabled    bool   `json:"redis_enabled"`
	RedisDB         int    `json:"redis_db"`
	AdminBind       string `json:"admin_bind"`
	AdminStaticDir  string `json:"admin_static_dir"`
	GeoIPDBPath     string `json:"geoip_db_path"`
	CVEEnabled      bool   `json:"cve_enabled"`
	CVEFeedEnabled  bool   `json:"cve_feed_enabled"`
	CVEFeedInterval string `json:"cve_feed_interval"`
	DropEnabled     bool   `json:"drop_enabled"`
	Source          string `json:"source"`
	Editable        bool   `json:"editable"`
	RestartRequired bool   `json:"restart_required"`
}

func GetRuntimeConfig(cfg core.Config) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, RuntimeConfigResponse{
			DBDriver:        cfg.DBDriver,
			DBDSN:           maskDSN(cfg.DBDSN),
			LogDBDSN:        maskDSN(cfg.LogDBDSN),
			DataDir:         cfg.DataDir,
			RedisAddr:       cfg.RedisAddr,
			RedisEnabled:    strings.TrimSpace(cfg.RedisAddr) != "",
			RedisDB:         cfg.RedisDB,
			AdminBind:       cfg.AdminBind,
			AdminStaticDir:  cfg.AdminStaticDir,
			GeoIPDBPath:     cfg.Bot.GeoIPDBPath,
			CVEEnabled:      cfg.CVE.Enabled,
			CVEFeedEnabled:  cfg.CVE.FeedEnabled,
			CVEFeedInterval: cfg.CVE.FeedInterval,
			DropEnabled:     cfg.Drop.Enabled,
			Source:          "environment",
			Editable:        false,
			RestartRequired: true,
		})
	}
}

func maskDSN(dsn string) string {
	trimmed := strings.TrimSpace(dsn)
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err == nil && u.User != nil {
		if username := u.User.Username(); username != "" {
			u.User = url.UserPassword(username, "******")
		} else {
			u.User = url.UserPassword("******", "******")
		}
		return u.String()
	}
	if strings.Contains(trimmed, "password=") || strings.Contains(trimmed, "passwd=") || strings.Contains(trimmed, "pwd=") {
		parts := strings.Fields(trimmed)
		for i, part := range parts {
			lower := strings.ToLower(part)
			for _, key := range []string{"password=", "passwd=", "pwd="} {
				if strings.HasPrefix(lower, key) {
					parts[i] = part[:len(key)] + "******"
				}
			}
		}
		return strings.Join(parts, " ")
	}
	return trimmed
}
