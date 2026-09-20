//go:build !cgo || !quickjs

package snapshot

import (
	"errors"
	"strconv"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/jsplugin"
)

func TestLoadJSPluginsRejectsUnavailableFailClosedRuntime(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open snapshot JS plugin database: %v", err)
	}
	if err := db.AutoMigrate(&store.JSPlugin{}); err != nil {
		t.Fatalf("migrate snapshot JS plugin database: %v", err)
	}
	row := store.JSPlugin{
		Name:        "required-runtime",
		Source:      `export default { fetch() { return {}; } }`,
		Enabled:     true,
		Stage:       store.JSStageRequest,
		FailureMode: store.JSFailureModeClosed,
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("create fail-closed JS plugin: %v", err)
	}

	scripts, errs, err := loadJSPlugins(db)
	if !errors.Is(err, jsplugin.ErrCGODisabled) {
		t.Fatalf("loadJSPlugins() error = %v, want ErrCGODisabled", err)
	}
	if len(scripts) != 0 {
		t.Fatalf("compiled scripts = %d, want 0", len(scripts))
	}
	if errs[JSPluginErrorKey(row.ID)] == "" {
		t.Fatalf("compile diagnostics = %#v", errs)
	}
}

func TestLoadJSPluginsRejectsPersistedInvalidTimeoutBeforeCompile(t *testing.T) {
	for _, timeoutMS := range []int{-1, 1001} {
		t.Run(strconv.Itoa(timeoutMS), func(t *testing.T) {
			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
			if err != nil {
				t.Fatalf("open snapshot JS plugin database: %v", err)
			}
			if err := db.AutoMigrate(&store.JSPlugin{}); err != nil {
				t.Fatalf("migrate snapshot JS plugin database: %v", err)
			}
			row := store.JSPlugin{
				Name:        "invalid-timeout",
				Source:      `export default { fetch() { return {}; } }`,
				Enabled:     true,
				Stage:       store.JSStageRequest,
				FailureMode: store.JSFailureModeOpen,
				TimeoutMS:   timeoutMS,
			}
			if err := db.Create(&row).Error; err != nil {
				t.Fatalf("create JS plugin: %v", err)
			}

			scripts, errs, err := loadJSPlugins(db)
			if err != nil {
				t.Fatalf("loadJSPlugins() error = %v", err)
			}
			if len(scripts) != 0 {
				t.Fatalf("compiled scripts = %d, want 0", len(scripts))
			}
			if got := errs[JSPluginErrorKey(row.ID)]; got != "timeout_ms must be between 0 and 1000" {
				t.Fatalf("timeout diagnostic = %q", got)
			}
		})
	}
}
