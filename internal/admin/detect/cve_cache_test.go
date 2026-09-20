package detect

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/cve"

	"gorm.io/gorm"
)

type cveRoundTripFunc func(*http.Request) (*http.Response, error)

func (f cveRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type cveHandlerSQLCounter struct {
	queries atomic.Int64
	writes  atomic.Int64
}

func registerCVEHandlerSQLCounter(t *testing.T, db *gorm.DB) *cveHandlerSQLCounter {
	t.Helper()
	counter := &cveHandlerSQLCounter{}
	if err := db.Callback().Query().Before("gorm:query").Register("test:cve-handler-query", func(*gorm.DB) {
		counter.queries.Add(1)
	}); err != nil {
		t.Fatalf("register query callback: %v", err)
	}
	for name, register := range map[string]func(string, func(*gorm.DB)) error{
		"create": db.Callback().Create().Before("gorm:create").Register,
		"update": db.Callback().Update().Before("gorm:update").Register,
		"delete": db.Callback().Delete().Before("gorm:delete").Register,
	} {
		if err := register("test:cve-handler-"+name, func(*gorm.DB) {
			counter.writes.Add(1)
		}); err != nil {
			t.Fatalf("register %s callback: %v", name, err)
		}
	}
	return counter
}

func TestCVERuleListEmbedsEquivalentStatsAndWarmStatsUsesZeroSQL(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	if err := repo.EnsureBuiltinCatalog(); err != nil {
		t.Fatalf("ensure built-in catalog: %v", err)
	}
	counter := registerCVEHandlerSQLCounter(t, repo.DB())

	listCtx := invokeCVERuleListHandler(t, ListCVERules(repo), "/api/v1/cve-rules?scope=global&page_size=200")
	if listCtx.Response.StatusCode() != 200 {
		t.Fatalf("list status=%d body=%s", listCtx.Response.StatusCode(), listCtx.Response.Body())
	}
	if got := counter.writes.Load(); got != 0 {
		t.Fatalf("list write callbacks=%d want=0", got)
	}
	if got := counter.queries.Load(); got != 2 {
		t.Fatalf("cold list query callbacks=%d want=2", got)
	}
	var listResp struct {
		Stats cveRuleStats `json:"stats"`
	}
	if err := json.Unmarshal(listCtx.Response.Body(), &listResp); err != nil {
		t.Fatalf("decode list response: %v", err)
	}

	counter.queries.Store(0)
	counter.writes.Store(0)
	statsCtx := invokeCVERuleListHandler(t, GetCVERuleStats(repo), "/api/v1/cve-rules/stats?scope=global")
	if statsCtx.Response.StatusCode() != 200 {
		t.Fatalf("stats status=%d body=%s", statsCtx.Response.StatusCode(), statsCtx.Response.Body())
	}
	if got := counter.queries.Load(); got != 0 {
		t.Fatalf("warm stats query callbacks=%d want=0", got)
	}
	if got := counter.writes.Load(); got != 0 {
		t.Fatalf("warm stats write callbacks=%d want=0", got)
	}
	var statsResp cveRuleStats
	if err := json.Unmarshal(statsCtx.Response.Body(), &statsResp); err != nil {
		t.Fatalf("decode stats response: %v", err)
	}
	if !reflect.DeepEqual(listResp.Stats, statsResp) {
		t.Fatalf("embedded stats=%#v direct stats=%#v", listResp.Stats, statsResp)
	}
}

func TestCVERuleListStatsRemainUnfiltered(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	custom := cve.CVERuleModel{
		CVEID:       "CVE-2026-70002",
		Category:    "cache-only-category",
		Pattern:     "cache-list-filter",
		Target:      "all",
		Severity:    "critical",
		Action:      "intercept",
		Enabled:     true,
		Description: "cache list filter",
		Source:      "custom",
		Approved:    true,
	}
	if err := repo.Create(&custom); err != nil {
		t.Fatalf("create custom rule: %v", err)
	}

	ctx := invokeCVERuleListHandler(t, ListCVERules(repo), "/api/v1/cve-rules?scope=global&page_size=200&category=cache-only-category")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("list status=%d body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var resp struct {
		Total int64        `json:"total"`
		Stats cveRuleStats `json:"stats"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 {
		t.Fatalf("filtered total=%d want=1", resp.Total)
	}
	if resp.Stats.Total <= resp.Total {
		t.Fatalf("unfiltered stats total=%d want greater than filtered total=%d", resp.Stats.Total, resp.Total)
	}
	if resp.Stats.ByCategory[custom.Category] != 1 {
		t.Fatalf("stats category count=%d want=1", resp.Stats.ByCategory[custom.Category])
	}
}

func TestCVERuleScopePatchInvalidatesWarmCanonicalSnapshot(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	rule := cve.CVERuleModel{
		CVEID:       "CVE-2026-70003",
		Category:    "general",
		Pattern:     "cache-scope-invalidation",
		Target:      "all",
		Severity:    "high",
		Action:      "intercept",
		Enabled:     true,
		Description: "scope invalidation",
		Source:      "custom",
		Approved:    true,
	}
	if err := repo.Create(&rule); err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if _, err := repo.CanonicalSnapshot(); err != nil {
		t.Fatalf("warm snapshot: %v", err)
	}

	body := []byte(`{"scope":"global","enabled":false}`)
	patchCtx := invokeCVEHandler(t, UpdateSingleCVERule(repo, nil), "POST", "/api/v1/cve-rules/"+strconv.FormatUint(uint64(rule.ID), 10)+"/patch", strconv.FormatUint(uint64(rule.ID), 10), body)
	if patchCtx.Response.StatusCode() != 200 {
		t.Fatalf("patch status=%d body=%s", patchCtx.Response.StatusCode(), patchCtx.Response.Body())
	}

	views, err := listEffectiveCVERules(repo, cveScopeContext{ScopeType: "global"}, repository.CVERuleFilter{Query: rule.CVEID})
	if err != nil {
		t.Fatalf("list patched rule: %v", err)
	}
	if len(views) != 1 || views[0].Effective.Enabled {
		t.Fatalf("patched views=%#v want one disabled rule", views)
	}
}

func TestSyncCVERulesInvalidatesSnapshotAfterPartialFailure(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	rule := cve.CVERuleModel{
		CVEID:       "CVE-2026-70004",
		Category:    "general",
		Pattern:     "cache-sync-invalidation",
		Target:      "all",
		Severity:    "high",
		Action:      "intercept",
		Enabled:     true,
		Description: "before sync",
		Source:      "custom",
		Approved:    true,
	}
	if err := repo.Create(&rule); err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if _, err := repo.CanonicalSnapshot(); err != nil {
		t.Fatalf("warm snapshot: %v", err)
	}
	if err := repo.DB().Model(&cve.CVERuleModel{}).Where("id = ?", rule.ID).Update("description", "written during failed sync").Error; err != nil {
		t.Fatalf("simulate external sync write: %v", err)
	}

	previousTransport := http.DefaultTransport
	http.DefaultTransport = cveRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader(`{"error":"forced"}`)),
			Header:     make(http.Header),
		}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = previousTransport })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := cve.NewCVEFeedManager(repo.DB(), cve.NewCVEDetector(), time.Hour, "", false, log)
	ctx := invokeCVEHandler(t, SyncCVERules(manager, repo), "POST", "/api/v1/cve-rules/sync", "", nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("sync status=%d want=500 body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	snapshot, err := repo.CanonicalSnapshot()
	if err != nil {
		t.Fatalf("snapshot after failed sync: %v", err)
	}
	for i := range snapshot.Rules {
		if snapshot.Rules[i].ID == rule.ID {
			if snapshot.Rules[i].Description != "written during failed sync" {
				t.Fatalf("stale description=%q", snapshot.Rules[i].Description)
			}
			return
		}
	}
	t.Fatalf("rule %d missing after failed sync", rule.ID)
}

func TestCVERuleBatchAndResetInvalidateWarmCanonicalSnapshot(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	rule := cve.CVERuleModel{
		CVEID:       "CVE-2026-70005",
		Category:    "general",
		Pattern:     "cache-batch-reset-invalidation",
		Target:      "all",
		Severity:    "high",
		Action:      "intercept",
		Enabled:     true,
		Description: "batch reset invalidation",
		Source:      "custom",
		Approved:    true,
	}
	if err := repo.Create(&rule); err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if _, err := repo.CanonicalSnapshot(); err != nil {
		t.Fatalf("warm snapshot: %v", err)
	}

	body := []byte(`{"scope":"global","ids":[` + strconv.FormatUint(uint64(rule.ID), 10) + `],"enabled":false}`)
	batchCtx := invokeCVEHandler(t, BatchUpdateCVERules(repo, nil), "POST", "/api/v1/cve-rules/batch", "", body)
	if batchCtx.Response.StatusCode() != 200 {
		t.Fatalf("batch status=%d body=%s", batchCtx.Response.StatusCode(), batchCtx.Response.Body())
	}
	views, err := listEffectiveCVERules(repo, cveScopeContext{ScopeType: "global"}, repository.CVERuleFilter{Query: rule.CVEID})
	if err != nil {
		t.Fatalf("list after batch: %v", err)
	}
	if len(views) != 1 || views[0].Effective.Enabled {
		t.Fatalf("batch views=%#v want one disabled rule", views)
	}

	id := strconv.FormatUint(uint64(rule.ID), 10)
	resetCtx := invokeCVEHandler(t, ResetCVERuleOverride(repo, nil), "POST", "/api/v1/cve-rules/"+id+"/reset?scope=global", id, nil)
	if resetCtx.Response.StatusCode() != 200 {
		t.Fatalf("reset status=%d body=%s", resetCtx.Response.StatusCode(), resetCtx.Response.Body())
	}
	views, err = listEffectiveCVERules(repo, cveScopeContext{ScopeType: "global"}, repository.CVERuleFilter{Query: rule.CVEID})
	if err != nil {
		t.Fatalf("list after reset: %v", err)
	}
	if len(views) != 1 || !views[0].Effective.Enabled {
		t.Fatalf("reset views=%#v want one enabled rule", views)
	}
}
