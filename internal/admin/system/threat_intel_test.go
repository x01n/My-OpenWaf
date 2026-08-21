package system

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

/**
 * newThreatIntelDBForTest 建立含订阅源、IP 条目与同步日志表的内存库。
 *
 * @param t 测试上下文。
 * @return 已迁移的 gorm 句柄。
 */
func newThreatIntelDBForTest(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.ThreatIntelFeed{}, &store.IPListEntry{}, &store.ThreatIntelSyncLog{}); err != nil {
		t.Fatalf("migrate threat intel tables: %v", err)
	}
	return db
}

/**
 * invokeThreatIntelHandler 直接驱动 Hertz handler 并返回响应上下文。
 */
func invokeThreatIntelHandler(t *testing.T, handler app.HandlerFunc, method, uri string, params param.Params, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI(uri)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(payload)
	}

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = params
	handler(context.Background(), ctx)
	return ctx
}

// stubThreatIntelSyncer 记录 SyncNow 调用并按需返回错误。
type stubThreatIntelSyncer struct {
	calledWith []uint
	err        error
}

func (s *stubThreatIntelSyncer) SyncNow(feedID uint) error {
	s.calledWith = append(s.calledWith, feedID)
	return s.err
}

func TestNormalizeFeedFields(t *testing.T) {
	tests := []struct {
		name       string
		kind       string
		action     string
		wantKind   string
		wantAction string
		wantOK     bool
	}{
		{name: "blacklist empty action defaults intercept", kind: string(store.IPListBlack), action: "", wantKind: "blacklist", wantAction: "intercept", wantOK: true},
		{name: "whitelist always allows", kind: string(store.IPListWhite), action: "drop", wantKind: "whitelist", wantAction: "intercept", wantOK: true},
		{name: "legacy block normalizes to drop", kind: string(store.IPListBlack), action: "block", wantKind: "blacklist", wantAction: "drop", wantOK: true},
		{name: "reject unknown kind", kind: "greylist", action: "intercept", wantOK: false},
		{name: "reject empty kind", kind: "", action: "intercept", wantOK: false},
		{name: "reject unknown action", kind: string(store.IPListBlack), action: "challenge", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, action, ok := normalizeFeedFields(tt.kind, tt.action)
			if ok != tt.wantOK {
				t.Fatalf("normalizeFeedFields(%q, %q) ok = %v, want %v", tt.kind, tt.action, ok, tt.wantOK)
			}
			if kind != tt.wantKind || action != tt.wantAction {
				t.Fatalf("normalizeFeedFields(%q, %q) = (%q, %q), want (%q, %q)", tt.kind, tt.action, kind, action, tt.wantKind, tt.wantAction)
			}
		})
	}
}

func TestListThreatIntelFeedsReturnsItemsAndTotal(t *testing.T) {
	repo := repository.NewThreatIntelRepo(newThreatIntelDBForTest(t))
	for _, name := range []string{"feed-a", "feed-b"} {
		if err := repo.Create(&store.ThreatIntelFeed{Name: name, URL: "https://intel.example.test/" + name, Kind: "blacklist", Action: "intercept", SyncInterval: 3600}); err != nil {
			t.Fatalf("seed feed %s: %v", name, err)
		}
	}

	ctx := invokeThreatIntelHandler(t, ListThreatIntelFeeds(repo), "GET", "/api/v1/threat-intel-feeds", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("list status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp struct {
		Items []store.ThreatIntelFeed `json:"items"`
		Total int                     `json:"total"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode feed list: %v", err)
	}
	if resp.Total != 2 || len(resp.Items) != 2 {
		t.Fatalf("feed list = total %d len %d, want 2", resp.Total, len(resp.Items))
	}
	// 仓库按 id DESC 返回，最后写入的排在最前。
	if resp.Items[0].Name != "feed-b" {
		t.Fatalf("first feed = %q, want feed-b", resp.Items[0].Name)
	}
}

func TestCreateThreatIntelFeedAppliesDefaultsAndIgnoresRuntimeFields(t *testing.T) {
	db := newThreatIntelDBForTest(t)
	repo := repository.NewThreatIntelRepo(db)

	payload := []byte(`{"name":"blocklist","url":"https://intel.example.test/list.txt","kind":"blacklist","action":"block","last_error":"stale error","entry_count":999}`)
	ctx := invokeThreatIntelHandler(t, CreateThreatIntelFeed(repo, func() error { return nil }), "POST", "/api/v1/threat-intel-feeds", nil, payload)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("create status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var created store.ThreatIntelFeed
	if err := json.Unmarshal(ctx.Response.Body(), &created); err != nil {
		t.Fatalf("decode created feed: %v", err)
	}
	if created.Action != "drop" {
		t.Fatalf("action = %q, want drop (legacy block normalized)", created.Action)
	}
	if created.SyncInterval != 3600 {
		t.Fatalf("sync_interval = %d, want default 3600", created.SyncInterval)
	}

	stored, err := repo.Get(created.ID)
	if err != nil {
		t.Fatalf("load created feed: %v", err)
	}
	if stored.LastError != "" || stored.EntryCount != 0 || stored.LastSyncAt != nil {
		t.Fatalf("client supplied runtime fields must be ignored: %#v", stored)
	}
}

func TestCreateThreatIntelFeedRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{name: "missing name", payload: `{"url":"https://intel.example.test/list.txt","kind":"blacklist"}`},
		{name: "missing url", payload: `{"name":"x","kind":"blacklist"}`},
		{name: "invalid kind", payload: `{"name":"x","url":"https://intel.example.test/list.txt","kind":"greylist"}`},
		{name: "invalid action", payload: `{"name":"x","url":"https://intel.example.test/list.txt","kind":"blacklist","action":"challenge"}`},
		{name: "malformed json", payload: `{"name":`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := repository.NewThreatIntelRepo(newThreatIntelDBForTest(t))
			ctx := invokeThreatIntelHandler(t, CreateThreatIntelFeed(repo, func() error { return nil }), "POST", "/api/v1/threat-intel-feeds", nil, []byte(tt.payload))
			if ctx.Response.StatusCode() != 400 {
				t.Fatalf("status = %d, want 400: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
			items, err := repo.List()
			if err != nil {
				t.Fatalf("list feeds: %v", err)
			}
			if len(items) != 0 {
				t.Fatalf("rejected payload must not persist a feed, got %d", len(items))
			}
		})
	}
}

func TestUpdateThreatIntelFeedPreservesOmittedFields(t *testing.T) {
	repo := repository.NewThreatIntelRepo(newThreatIntelDBForTest(t))
	syncedAt := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	seed := &store.ThreatIntelFeed{
		Name:         "keep-name",
		URL:          "https://intel.example.test/keep.txt",
		Kind:         "blacklist",
		Action:       "drop",
		Enabled:      true,
		SyncInterval: 900,
		LastSyncAt:   &syncedAt,
		EntryCount:   42,
	}
	if err := repo.Create(seed); err != nil {
		t.Fatalf("seed feed: %v", err)
	}

	idStr := strconv.FormatUint(uint64(seed.ID), 10)
	ctx := invokeThreatIntelHandler(t, UpdateThreatIntelFeed(repo, func() error { return nil }),
		"POST", "/api/v1/threat-intel-feeds/"+idStr+"/update", param.Params{{Key: "id", Value: idStr}}, []byte(`{"enabled":false}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("update status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	got, err := repo.Get(seed.ID)
	if err != nil {
		t.Fatalf("load updated feed: %v", err)
	}
	if got.Enabled {
		t.Fatalf("explicit enabled=false was not saved: %#v", got)
	}
	if got.Name != "keep-name" || got.URL != "https://intel.example.test/keep.txt" || got.Kind != "blacklist" || got.Action != "drop" || got.SyncInterval != 900 {
		t.Fatalf("omitted fields must be preserved: %#v", got)
	}
	if got.EntryCount != 42 || got.LastSyncAt == nil {
		t.Fatalf("runtime fields must survive an update: %#v", got)
	}
}

func TestUpdateThreatIntelFeedRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		wantStatus int
	}{
		{name: "empty name", payload: `{"name":""}`, wantStatus: 400},
		{name: "empty url", payload: `{"url":""}`, wantStatus: 400},
		{name: "invalid kind", payload: `{"kind":"greylist"}`, wantStatus: 400},
		{name: "invalid action", payload: `{"action":"challenge"}`, wantStatus: 400},
		{name: "non positive sync_interval", payload: `{"sync_interval":0}`, wantStatus: 400},
		{name: "negative sync_interval", payload: `{"sync_interval":-5}`, wantStatus: 400},
		{name: "malformed json", payload: `{"name":`, wantStatus: 400},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := repository.NewThreatIntelRepo(newThreatIntelDBForTest(t))
			seed := &store.ThreatIntelFeed{Name: "orig", URL: "https://intel.example.test/a.txt", Kind: "blacklist", Action: "intercept", Enabled: true, SyncInterval: 600}
			if err := repo.Create(seed); err != nil {
				t.Fatalf("seed feed: %v", err)
			}
			idStr := strconv.FormatUint(uint64(seed.ID), 10)

			ctx := invokeThreatIntelHandler(t, UpdateThreatIntelFeed(repo, func() error { return nil }),
				"POST", "/api/v1/threat-intel-feeds/"+idStr+"/update", param.Params{{Key: "id", Value: idStr}}, []byte(tt.payload))
			if ctx.Response.StatusCode() != tt.wantStatus {
				t.Fatalf("status = %d, want %d: %s", ctx.Response.StatusCode(), tt.wantStatus, bytes.TrimSpace(ctx.Response.Body()))
			}

			got, err := repo.Get(seed.ID)
			if err != nil {
				t.Fatalf("load feed: %v", err)
			}
			if got.Name != "orig" || got.URL != "https://intel.example.test/a.txt" || got.Kind != "blacklist" || got.Action != "intercept" || got.SyncInterval != 600 {
				t.Fatalf("rejected update must not mutate the feed: %#v", got)
			}
		})
	}
}

func TestUpdateThreatIntelFeedInvalidIDAndMissingFeed(t *testing.T) {
	repo := repository.NewThreatIntelRepo(newThreatIntelDBForTest(t))

	badID := invokeThreatIntelHandler(t, UpdateThreatIntelFeed(repo, func() error { return nil }),
		"POST", "/api/v1/threat-intel-feeds/abc/update", param.Params{{Key: "id", Value: "abc"}}, []byte(`{"name":"x"}`))
	if badID.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d, want 400", badID.Response.StatusCode())
	}

	missing := invokeThreatIntelHandler(t, UpdateThreatIntelFeed(repo, func() error { return nil }),
		"POST", "/api/v1/threat-intel-feeds/999/update", param.Params{{Key: "id", Value: "999"}}, []byte(`{"name":"x"}`))
	if missing.Response.StatusCode() != 404 {
		t.Fatalf("missing feed status = %d, want 404", missing.Response.StatusCode())
	}
}

func TestDeleteThreatIntelFeedRemovesDerivedEntriesAndReloads(t *testing.T) {
	db := newThreatIntelDBForTest(t)
	repo := repository.NewThreatIntelRepo(db)
	seed := &store.ThreatIntelFeed{Name: "delete-me", URL: "https://intel.example.test/d.txt", Kind: "blacklist", Action: "intercept", SyncInterval: 3600}
	if err := repo.Create(seed); err != nil {
		t.Fatalf("seed feed: %v", err)
	}
	if err := repo.ReplaceFeedEntries(seed.ID, []store.IPListEntry{
		{Kind: store.IPListBlack, Value: "198.51.100.7", Enabled: true, Action: "intercept", FeedID: &seed.ID},
	}); err != nil {
		t.Fatalf("seed derived entries: %v", err)
	}
	if got := repo.CountFeedEntries(seed.ID); got != 1 {
		t.Fatalf("derived entry count before delete = %d, want 1", got)
	}

	reloadCount := 0
	idStr := strconv.FormatUint(uint64(seed.ID), 10)
	ctx := invokeThreatIntelHandler(t, DeleteThreatIntelFeed(repo, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/threat-intel-feeds/"+idStr+"/delete", param.Params{{Key: "id", Value: idStr}}, nil)
	if ctx.Response.StatusCode() != 204 {
		t.Fatalf("delete status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload count = %d, want 1", reloadCount)
	}
	if got := repo.CountFeedEntries(seed.ID); got != 0 {
		t.Fatalf("derived entry count after delete = %d, want 0", got)
	}
}

func TestDeleteThreatIntelFeedInvalidIDAndReloadFailure(t *testing.T) {
	repo := repository.NewThreatIntelRepo(newThreatIntelDBForTest(t))

	badID := invokeThreatIntelHandler(t, DeleteThreatIntelFeed(repo, func() error { return nil }),
		"POST", "/api/v1/threat-intel-feeds/xyz/delete", param.Params{{Key: "id", Value: "xyz"}}, nil)
	if badID.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d, want 400", badID.Response.StatusCode())
	}

	seed := &store.ThreatIntelFeed{Name: "reload-fail", URL: "https://intel.example.test/r.txt", Kind: "whitelist", Action: "intercept", SyncInterval: 3600}
	if err := repo.Create(seed); err != nil {
		t.Fatalf("seed feed: %v", err)
	}
	idStr := strconv.FormatUint(uint64(seed.ID), 10)
	ctx := invokeThreatIntelHandler(t, DeleteThreatIntelFeed(repo, func() error { return errors.New("reload boom") }),
		"POST", "/api/v1/threat-intel-feeds/"+idStr+"/delete", param.Params{{Key: "id", Value: idStr}}, nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("reload failure status = %d, want 500", ctx.Response.StatusCode())
	}
	if !bytes.Contains(ctx.Response.Body(), []byte("reload failed")) {
		t.Fatalf("reload failure body should mention reload failed: %s", bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestSyncThreatIntelFeedReturnsFeedAfterSync(t *testing.T) {
	repo := repository.NewThreatIntelRepo(newThreatIntelDBForTest(t))
	seed := &store.ThreatIntelFeed{Name: "sync-me", URL: "https://intel.example.test/s.txt", Kind: "blacklist", Action: "intercept", SyncInterval: 3600}
	if err := repo.Create(seed); err != nil {
		t.Fatalf("seed feed: %v", err)
	}
	syncer := &stubThreatIntelSyncer{}
	idStr := strconv.FormatUint(uint64(seed.ID), 10)

	ctx := invokeThreatIntelHandler(t, SyncThreatIntelFeed(repo, syncer),
		"POST", "/api/v1/threat-intel-feeds/"+idStr+"/sync", param.Params{{Key: "id", Value: idStr}}, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("sync status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if len(syncer.calledWith) != 1 || syncer.calledWith[0] != seed.ID {
		t.Fatalf("SyncNow calls = %v, want [%d]", syncer.calledWith, seed.ID)
	}

	var got store.ThreatIntelFeed
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode synced feed: %v", err)
	}
	if got.ID != seed.ID || got.Name != "sync-me" {
		t.Fatalf("sync response = %#v, want the synced feed", got)
	}
}

func TestSyncThreatIntelFeedErrorPaths(t *testing.T) {
	repo := repository.NewThreatIntelRepo(newThreatIntelDBForTest(t))
	seed := &store.ThreatIntelFeed{Name: "sync-err", URL: "https://intel.example.test/e.txt", Kind: "blacklist", Action: "intercept", SyncInterval: 3600}
	if err := repo.Create(seed); err != nil {
		t.Fatalf("seed feed: %v", err)
	}
	idStr := strconv.FormatUint(uint64(seed.ID), 10)

	badID := invokeThreatIntelHandler(t, SyncThreatIntelFeed(repo, &stubThreatIntelSyncer{}),
		"POST", "/api/v1/threat-intel-feeds/nan/sync", param.Params{{Key: "id", Value: "nan"}}, nil)
	if badID.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d, want 400", badID.Response.StatusCode())
	}

	// syncer 为 nil 表示威胁情报管理器未启动，应返回 503 而非 panic。
	unavailable := invokeThreatIntelHandler(t, SyncThreatIntelFeed(repo, nil),
		"POST", "/api/v1/threat-intel-feeds/"+idStr+"/sync", param.Params{{Key: "id", Value: idStr}}, nil)
	if unavailable.Response.StatusCode() != 503 {
		t.Fatalf("nil syncer status = %d, want 503", unavailable.Response.StatusCode())
	}

	failing := invokeThreatIntelHandler(t, SyncThreatIntelFeed(repo, &stubThreatIntelSyncer{err: errors.New("fetch failed")}),
		"POST", "/api/v1/threat-intel-feeds/"+idStr+"/sync", param.Params{{Key: "id", Value: idStr}}, nil)
	if failing.Response.StatusCode() != 500 {
		t.Fatalf("sync error status = %d, want 500", failing.Response.StatusCode())
	}
	if !bytes.Contains(failing.Response.Body(), []byte("fetch failed")) {
		t.Fatalf("sync error body = %s, want the syncer error", bytes.TrimSpace(failing.Response.Body()))
	}

	// 同步成功但目标 feed 已不存在时降级为状态响应。
	missing := invokeThreatIntelHandler(t, SyncThreatIntelFeed(repo, &stubThreatIntelSyncer{}),
		"POST", "/api/v1/threat-intel-feeds/424242/sync", param.Params{{Key: "id", Value: "424242"}}, nil)
	if missing.Response.StatusCode() != 200 {
		t.Fatalf("missing feed sync status = %d, want 200", missing.Response.StatusCode())
	}
	if !bytes.Contains(missing.Response.Body(), []byte("synced")) {
		t.Fatalf("missing feed sync body = %s, want status synced", bytes.TrimSpace(missing.Response.Body()))
	}
}

func TestListThreatIntelSyncLogsFiltersAndPaginates(t *testing.T) {
	db := newThreatIntelDBForTest(t)
	logRepo := repository.NewThreatIntelSyncLogRepo(db)
	seedLogs := []store.ThreatIntelSyncLog{
		{FeedID: 1, FeedName: "feed-1", Success: true, Trigger: "auto", EntriesAdded: 10},
		{FeedID: 1, FeedName: "feed-1", Success: false, Trigger: "manual", Error: "http 500"},
		{FeedID: 2, FeedName: "feed-2", Success: true, Trigger: "auto", EntriesAdded: 3},
	}
	for i := range seedLogs {
		if err := logRepo.Create(&seedLogs[i]); err != nil {
			t.Fatalf("seed sync log %d: %v", i, err)
		}
	}

	type listResp struct {
		Items    []store.ThreatIntelSyncLog `json:"items"`
		Total    int64                      `json:"total"`
		Page     int                        `json:"page"`
		PageSize int                        `json:"page_size"`
	}
	decode := func(t *testing.T, ctx *app.RequestContext) listResp {
		t.Helper()
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		var resp listResp
		if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
			t.Fatalf("decode sync log list: %v", err)
		}
		return resp
	}

	all := decode(t, invokeThreatIntelHandler(t, ListThreatIntelSyncLogs(logRepo), "GET", "/api/v1/threat-intel-sync-logs", nil, nil))
	if all.Total != 3 || len(all.Items) != 3 {
		t.Fatalf("unfiltered list = total %d len %d, want 3", all.Total, len(all.Items))
	}
	// page/page_size 缺省或非法时回落到 1 / 20。
	if all.Page != 1 || all.PageSize != 20 {
		t.Fatalf("default paging = page %d size %d, want 1/20", all.Page, all.PageSize)
	}

	byFeed := decode(t, invokeThreatIntelHandler(t, ListThreatIntelSyncLogs(logRepo), "GET", "/api/v1/threat-intel-sync-logs?feed_id=1", nil, nil))
	if byFeed.Total != 2 {
		t.Fatalf("feed_id=1 total = %d, want 2", byFeed.Total)
	}

	success := decode(t, invokeThreatIntelHandler(t, ListThreatIntelSyncLogs(logRepo), "GET", "/api/v1/threat-intel-sync-logs?status=success", nil, nil))
	if success.Total != 2 {
		t.Fatalf("status=success total = %d, want 2", success.Total)
	}

	failed := decode(t, invokeThreatIntelHandler(t, ListThreatIntelSyncLogs(logRepo), "GET", "/api/v1/threat-intel-sync-logs?status=failed", nil, nil))
	if failed.Total != 1 || len(failed.Items) != 1 {
		t.Fatalf("status=failed = total %d len %d, want 1", failed.Total, len(failed.Items))
	}
	if failed.Items[0].Error != "http 500" {
		t.Fatalf("failed log error = %q, want http 500", failed.Items[0].Error)
	}

	// page_size 超出上限或非法值回落到 20，page < 1 回落到 1。
	clamped := decode(t, invokeThreatIntelHandler(t, ListThreatIntelSyncLogs(logRepo), "GET", "/api/v1/threat-intel-sync-logs?page=0&page_size=5000", nil, nil))
	if clamped.Page != 1 || clamped.PageSize != 20 {
		t.Fatalf("clamped paging = page %d size %d, want 1/20", clamped.Page, clamped.PageSize)
	}

	paged := decode(t, invokeThreatIntelHandler(t, ListThreatIntelSyncLogs(logRepo), "GET", "/api/v1/threat-intel-sync-logs?page=2&page_size=2", nil, nil))
	if paged.Total != 3 || len(paged.Items) != 1 {
		t.Fatalf("page 2 size 2 = total %d len %d, want total 3 len 1", paged.Total, len(paged.Items))
	}

	// 非法 feed_id 被忽略而非报错。
	ignored := decode(t, invokeThreatIntelHandler(t, ListThreatIntelSyncLogs(logRepo), "GET", "/api/v1/threat-intel-sync-logs?feed_id=abc", nil, nil))
	if ignored.Total != 3 {
		t.Fatalf("invalid feed_id total = %d, want 3 (filter ignored)", ignored.Total)
	}
}
