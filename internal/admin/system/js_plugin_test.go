package system

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

func newJSPluginRepoForTest(t *testing.T) *repository.JSPluginRepo {
	t.Helper()
	return repository.NewJSPluginRepo(newJSPluginDBForTest(t))
}

func newJSPluginDBForTest(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.JSPlugin{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestCreateJSPluginPersistsAndReloads(t *testing.T) {
	repo := newJSPluginRepoForTest(t)
	reloaded := 0
	body, _ := json.Marshal(map[string]any{
		"name": "edge-request", "source": "return 1", "stage": "request",
		"failure_mode": "fail_closed", "priority": 7, "timeout_ms": 35,
	})
	ctx := invokeThreatIntelHandler(t, CreateJSPlugin(repo, func() error { reloaded++; return nil }), "POST", "/api/v1/js-plugins", nil, body)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("want 201, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloaded != 1 {
		t.Fatalf("reload count = %d, want 1", reloaded)
	}
	items, err := repo.List()
	if err != nil || len(items) != 1 {
		t.Fatalf("persisted items = %d, err=%v", len(items), err)
	}
	if items[0].Stage != store.JSStageRequest || items[0].FailureMode != store.JSFailureModeClosed || items[0].TimeoutMS != 35 {
		t.Fatalf("persisted fields = %+v", items[0])
	}
}

func TestCreateJSPluginRejectsInvalidContract(t *testing.T) {
	repo := newJSPluginRepoForTest(t)
	cases := []string{
		`{"source":"x","stage":"request","failure_mode":"fail_open"}`,
		`{"name":"x","source":"x","stage":"pre","failure_mode":"fail_open"}`,
		`{"name":"x","source":"x","stage":"request","failure_mode":"closed"}`,
		`{"name":"x","source":"x","stage":"response","failure_mode":"fail_open","timeout_ms":1001}`,
	}
	for _, raw := range cases {
		ctx := invokeThreatIntelHandler(t, CreateJSPlugin(repo, func() error { return nil }), "POST", "/x", nil, []byte(raw))
		if ctx.Response.StatusCode() != 400 {
			t.Errorf("invalid body %s: status=%d", raw, ctx.Response.StatusCode())
		}
	}
	items, _ := repo.List()
	if len(items) != 0 {
		t.Fatalf("invalid scripts persisted: %d", len(items))
	}
}

func TestUpdateJSPluginPreservesFieldsAndParsesSiteScope(t *testing.T) {
	repo := newJSPluginRepoForTest(t)
	siteID := uint(9)
	item := store.JSPlugin{Name: "edge", Source: "x", Stage: store.JSStageResponse, Enabled: true, Priority: 10, SiteID: &siteID, FailureMode: store.JSFailureModeOpen}
	if err := repo.Create(&item); err != nil {
		t.Fatal(err)
	}
	handler := UpdateJSPlugin(repo, func() error { return nil })
	invokeThreatIntelHandler(t, handler, "POST", "/x", idParam(item.ID), []byte(`{"priority":2}`))
	got, _ := repo.Get(item.ID)
	if got.Priority != 2 || got.SiteID == nil || *got.SiteID != 9 {
		t.Fatalf("partial update lost fields: %+v", got)
	}
	invokeThreatIntelHandler(t, handler, "POST", "/x", idParam(item.ID), []byte(`{"site_id":null}`))
	got, _ = repo.Get(item.ID)
	if got.SiteID != nil {
		t.Fatalf("site_id null should clear scope: %+v", got.SiteID)
	}
}

func TestJSPluginRuntimeEndpointsAreExplicitlyUnavailable(t *testing.T) {
	validate := invokeThreatIntelHandler(t, ValidateJSPlugin(), "POST", "/x", nil, []byte(`{}`))
	if validate.Response.StatusCode() != 503 || !bytes.Contains(validate.Response.Body(), []byte("javascript runtime unavailable")) {
		t.Fatalf("validate response = %d %s", validate.Response.StatusCode(), validate.Response.Body())
	}
	dryRun := invokeThreatIntelHandler(t, DryRunJSPlugin(), "POST", "/x", nil, []byte(`{}`))
	if dryRun.Response.StatusCode() != 503 || !bytes.Contains(dryRun.Response.Body(), []byte("javascript runtime unavailable")) {
		t.Fatalf("dry-run response = %d %s", dryRun.Response.StatusCode(), dryRun.Response.Body())
	}
	stats := invokeThreatIntelHandler(t, GetJSPluginStats(), "GET", "/x", nil, nil)
	if stats.Response.StatusCode() != 503 || !bytes.Contains(stats.Response.Body(), []byte(`"items":[]`)) {
		t.Fatalf("stats response = %d %s", stats.Response.StatusCode(), stats.Response.Body())
	}
}
