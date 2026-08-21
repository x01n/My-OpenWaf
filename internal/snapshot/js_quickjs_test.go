//go:build cgo && quickjs

package snapshot

import (
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/jsplugin"
)

func newJSPluginSnapshotTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open snapshot JS plugin database: %v", err)
	}
	if err := db.AutoMigrate(&store.JSPlugin{}); err != nil {
		t.Fatalf("migrate snapshot JS plugin database: %v", err)
	}
	return db
}

func TestLoadJSPluginsSkipsFailOpenCompileError(t *testing.T) {
	db := newJSPluginSnapshotTestDB(t)
	row := store.JSPlugin{
		Name:        "broken-open",
		Source:      `export default { fetch() {`,
		Enabled:     true,
		Stage:       store.JSStageRequest,
		FailureMode: store.JSFailureModeOpen,
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("create fail-open JS plugin: %v", err)
	}

	scripts, errs, err := loadJSPlugins(db)
	if err != nil {
		t.Fatalf("loadJSPlugins() error = %v", err)
	}
	if len(scripts) != 0 {
		t.Fatalf("compiled scripts = %d, want 0", len(scripts))
	}
	if errs[JSPluginErrorKey(row.ID)] == "" {
		t.Fatalf("compile diagnostics = %#v", errs)
	}
}

func TestLoadJSPluginsValidatesTimeoutMS(t *testing.T) {
	cases := []struct {
		name       string
		timeoutMS  int
		wantScript int
		wantError  bool
	}{
		{name: "zero inherits engine timeout", timeoutMS: 0, wantScript: 1},
		{name: "negative rejected", timeoutMS: -1, wantError: true},
		{name: "valid override", timeoutMS: 35, wantScript: 1},
		{name: "maximum override", timeoutMS: 1000, wantScript: 1},
		{name: "above maximum rejected", timeoutMS: 1001, wantError: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newJSPluginSnapshotTestDB(t)
			row := store.JSPlugin{
				Name:        tc.name,
				Source:      `export default { fetch() { return {}; } }`,
				Enabled:     true,
				Stage:       store.JSStageRequest,
				FailureMode: store.JSFailureModeOpen,
				TimeoutMS:   tc.timeoutMS,
			}
			if err := db.Create(&row).Error; err != nil {
				t.Fatalf("create JS plugin: %v", err)
			}

			scripts, errs, err := loadJSPlugins(db)
			if err != nil {
				t.Fatalf("loadJSPlugins() error = %v", err)
			}
			if len(scripts) != tc.wantScript {
				t.Fatalf("compiled scripts = %d, want %d", len(scripts), tc.wantScript)
			}
			if tc.wantError {
				if got := errs[JSPluginErrorKey(row.ID)]; got != "timeout_ms must be between 0 and 1000" {
					t.Fatalf("timeout diagnostic = %q", got)
				}
			} else if len(errs) != 0 {
				t.Fatalf("unexpected diagnostics = %#v", errs)
			}
		})
	}
}

func TestLoadJSPluginsInstallsFailClosedGuardForInvalidTimeout(t *testing.T) {
	db := newJSPluginSnapshotTestDB(t)
	row := store.JSPlugin{
		Name:        "invalid-timeout-closed",
		Source:      `export default { fetch() { return {}; } }`,
		Enabled:     true,
		Stage:       store.JSStageRequest,
		FailureMode: store.JSFailureModeClosed,
		TimeoutMS:   1001,
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("create JS plugin: %v", err)
	}

	scripts, errs, err := loadJSPlugins(db)
	if err != nil {
		t.Fatalf("loadJSPlugins() error = %v", err)
	}
	if len(scripts) != 1 {
		t.Fatalf("compiled scripts = %d, want 1 fail-closed guard", len(scripts))
	}
	if got := errs[JSPluginErrorKey(row.ID)]; got != "timeout_ms must be between 0 and 1000" {
		t.Fatalf("timeout diagnostic = %q", got)
	}
	guard := scripts[0]
	if guard.ID() != row.ID || guard.FailureMode() != store.JSFailureModeClosed {
		t.Fatalf("fail-closed guard metadata = %#v", guard.Metadata())
	}

	engine, err := jsplugin.NewEngine(jsplugin.EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if _, err := engine.Execute(t.Context(), guard, jsplugin.RequestSnapshot{}); err == nil {
		t.Fatal("fail-closed invalid-timeout guard execution error = nil; request stage would silently allow")
	}
}

func TestLoadJSPluginsInstallsFailClosedBuildGuardWithoutDroppingOtherScripts(t *testing.T) {
	db := newJSPluginSnapshotTestDB(t)
	rows := []store.JSPlugin{
		{
			Name:        "broken-closed",
			Source:      `export default { fetch() {`,
			Enabled:     true,
			Priority:    10,
			Stage:       store.JSStageRequest,
			FailureMode: store.JSFailureModeClosed,
		},
		{
			Name:        "still-loaded",
			Source:      `export default { fetch() { return {}; } }`,
			Enabled:     true,
			Priority:    20,
			Stage:       store.JSStageRequest,
			FailureMode: store.JSFailureModeOpen,
		},
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("create JS plugin %q: %v", rows[i].Name, err)
		}
	}

	scripts, errs, err := loadJSPlugins(db)
	if err != nil {
		t.Fatalf("loadJSPlugins() error = %v", err)
	}
	if len(scripts) != 2 {
		t.Fatalf("compiled scripts = %d, want fail-closed guard plus valid script", len(scripts))
	}
	if errs[JSPluginErrorKey(rows[0].ID)] == "" {
		t.Fatalf("compile diagnostics = %#v", errs)
	}
	guard := scripts[0]
	if guard.ID() != rows[0].ID || guard.FailureMode() != store.JSFailureModeClosed {
		t.Fatalf("fail-closed guard metadata = %#v", guard.Metadata())
	}
	if scripts[1].ID() != rows[1].ID {
		t.Fatalf("valid script metadata = %#v", scripts[1].Metadata())
	}

	engine, err := jsplugin.NewEngine(jsplugin.EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if _, err := engine.Execute(t.Context(), guard, jsplugin.RequestSnapshot{}); err == nil {
		t.Fatal("fail-closed build guard execution error = nil; request stage would silently allow")
	}
	if _, err := engine.Execute(t.Context(), scripts[1], jsplugin.RequestSnapshot{}); err != nil {
		t.Fatalf("valid script execution error = %v", err)
	}
}

func TestLoadJSPluginsPreservesStableOrderAndMetadata(t *testing.T) {
	db := newJSPluginSnapshotTestDB(t)
	rows := []store.JSPlugin{
		{
			Name:        "later",
			Source:      `export default { fetch() { return {}; } }`,
			Enabled:     true,
			Priority:    20,
			Stage:       store.JSStageRequest,
			FailureMode: store.JSFailureModeOpen,
		},
		{
			Name:        "earlier",
			Source:      `export default { fetch() { return {}; } }`,
			Enabled:     true,
			Priority:    10,
			Stage:       store.JSStageRequest,
			FailureMode: store.JSFailureModeClosed,
		},
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("create JS plugin %q: %v", rows[i].Name, err)
		}
	}

	scripts, errs, err := loadJSPlugins(db)
	if err != nil {
		t.Fatalf("loadJSPlugins() error = %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("compile diagnostics = %#v", errs)
	}
	if len(scripts) != 2 {
		t.Fatalf("compiled scripts = %d, want 2", len(scripts))
	}
	if scripts[0].ID() != rows[1].ID || scripts[0].Priority() != 10 || scripts[0].FailureMode() != store.JSFailureModeClosed {
		t.Fatalf("first script metadata = %#v", scripts[0].Metadata())
	}
	if scripts[1].ID() != rows[0].ID || scripts[1].Priority() != 20 || scripts[1].FailureMode() != store.JSFailureModeOpen {
		t.Fatalf("second script metadata = %#v", scripts[1].Metadata())
	}
}

func TestLoadJSPluginsSkipsEnabledResponseStage(t *testing.T) {
	db := newJSPluginSnapshotTestDB(t)
	row := store.JSPlugin{
		Name:        "legacy-response",
		Source:      `export default { fetch() { return {}; } }`,
		Enabled:     true,
		Stage:       store.JSStageResponse,
		FailureMode: store.JSFailureModeClosed,
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("create legacy response JS plugin: %v", err)
	}

	scripts, errs, err := loadJSPlugins(db)
	if err != nil {
		t.Fatalf("loadJSPlugins() error = %v", err)
	}
	if len(scripts) != 0 {
		t.Fatalf("compiled scripts = %d, want 0", len(scripts))
	}
	if got := errs[JSPluginErrorKey(row.ID)]; got != "response stage is unavailable because response execution is not implemented" {
		t.Fatalf("response-stage diagnostic = %q", got)
	}
}
