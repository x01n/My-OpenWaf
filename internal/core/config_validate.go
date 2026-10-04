package core

import (
	"fmt"
	"net"
	"strings"
)

// Validate 在启动前检查配置是否成形。
// 返回一组非致命告警与一个致命错误（若有）。
func (c Config) Validate() (warnings []string, err error) {
	// DB 驱动必须是可识别的。
	// 与 database.Open 的分支保持一致：那里同时接受 postgresql 别名与空值（默认
	// sqlite）。若此处不认，配置成 postgresql 会在校验阶段就启动失败，别名形同虚设。
	switch c.DBDriver {
	case "", "sqlite", "mysql", "postgres", "postgresql":
		// 合法
	default:
		return nil, fmt.Errorf("unsupported db driver %q (want sqlite|mysql|postgres)", c.DBDriver)
	}

	// DSN 不得为空。
	if c.DBDSN == "" {
		return nil, fmt.Errorf("database DSN is empty")
	}

	// 管理端监听地址必须是合法的 host:port。
	if _, _, err := net.SplitHostPort(c.AdminBind); err != nil {
		return nil, fmt.Errorf("invalid admin bind address %q: %w", c.AdminBind, err)
	}

	// Redis：设置了地址时，必须是合法的 host:port。
	if c.RedisAddr != "" {
		if _, _, err := net.SplitHostPort(c.RedisAddr); err != nil {
			return nil, fmt.Errorf("invalid redis address %q: %w", c.RedisAddr, err)
		}
	}

	// 常见错误配置的告警。
	if c.DBDriver == "sqlite" && (strings.HasPrefix(c.DBDSN, "host=") || strings.Contains(c.DBDSN, "@tcp(")) {
		warnings = append(warnings, "DSN looks like mysql/postgres but driver is sqlite")
	}

	if c.AdminBind == ":80" || c.AdminBind == ":443" {
		warnings = append(warnings, "admin is binding to a well-known port; consider using a non-standard port")
	}

	return warnings, nil
}
