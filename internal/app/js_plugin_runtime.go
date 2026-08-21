package app

import (
	"fmt"

	"My-OpenWaf/internal/waf/jsplugin"
)

/**
 * ensureJSPluginEngine creates the process-scoped QuickJS executor on first use.
 *
 * An empty script generation never closes the current executor because requests that
 * already captured the previous snapshot can still execute its scripts.
 */
func ensureJSPluginEngine(current *jsplugin.Engine, scripts []*jsplugin.Script) (*jsplugin.Engine, error) {
	if len(scripts) == 0 || current != nil {
		return current, nil
	}
	created, err := jsplugin.NewEngine(jsplugin.EngineOptions{})
	if err != nil {
		return nil, fmt.Errorf("create js plugin engine: %w", err)
	}
	return created, nil
}

// ensureJSPluginEngineForDryRun lazily creates the process-scoped executor for the
// admin dry-run endpoint even when the current snapshot has no enabled scripts.
// The caller must serialize creation with reload and shutdown.
func ensureJSPluginEngineForDryRun(current *jsplugin.Engine) (*jsplugin.Engine, error) {
	if current != nil {
		return current, nil
	}
	created, err := jsplugin.NewEngine(jsplugin.EngineOptions{})
	if err != nil {
		return nil, fmt.Errorf("create js plugin engine for dry-run: %w", err)
	}
	return created, nil
}
