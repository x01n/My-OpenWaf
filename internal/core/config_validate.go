package core

import (
	"fmt"
	"net"
	"strings"
)

// Validate checks that the config is well-formed before startup.
// Returns a list of non-fatal warnings and a fatal error (if any).
func (c Config) Validate() (warnings []string, err error) {
	// DB driver must be recognized.
	switch c.DBDriver {
	case "sqlite", "mysql", "postgres":
		// ok
	default:
		return nil, fmt.Errorf("unsupported db driver %q (want sqlite|mysql|postgres)", c.DBDriver)
	}

	// DSN must not be empty.
	if c.DBDSN == "" {
		return nil, fmt.Errorf("database DSN is empty")
	}

	// Admin bind must be a valid host:port.
	if _, _, err := net.SplitHostPort(c.AdminBind); err != nil {
		return nil, fmt.Errorf("invalid admin bind address %q: %w", c.AdminBind, err)
	}

	// Redis: if addr set, must be valid host:port.
	if c.RedisAddr != "" {
		if _, _, err := net.SplitHostPort(c.RedisAddr); err != nil {
			return nil, fmt.Errorf("invalid redis address %q: %w", c.RedisAddr, err)
		}
	}

	// Warnings for common misconfigurations.
	if c.DBDriver == "sqlite" && (strings.HasPrefix(c.DBDSN, "host=") || strings.Contains(c.DBDSN, "@tcp(")) {
		warnings = append(warnings, "DSN looks like mysql/postgres but driver is sqlite")
	}

	if c.AdminBind == ":80" || c.AdminBind == ":443" {
		warnings = append(warnings, "admin is binding to a well-known port; consider using a non-standard port")
	}

	return warnings, nil
}
