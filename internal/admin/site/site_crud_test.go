package site

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

/**
 * invokeSiteRouteHandler 以自定义方法、URI 和路由参数调用 handler。
 * 与既有的 invokeSiteHandler 不同，这里的路由参数是原始字符串，
 * 因此可以覆盖 ParseUint 失败（非法 ID）等分支。
 *
 * @param payload 非 nil 时作为 JSON 请求体发送
 */
func invokeSiteRouteHandler(t *testing.T, handler app.HandlerFunc, method, uri string, params param.Params, payload []byte) *app.RequestContext {
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

// idParams 构造只含 id 的路由参数集合。
func idParams(id string) param.Params {
	return param.Params{{Key: "id", Value: id}}
}

// newSiteReposWithoutListenerTable 只迁移 sites 表，用于触发监听器仓库的 SQL 错误分支。
func newSiteReposWithoutListenerTable(t *testing.T) (*repository.SiteRepo, *repository.SiteListenerRepo) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}); err != nil {
		t.Fatalf("migrate sites: %v", err)
	}
	return repository.NewSiteRepo(db), repository.NewSiteListenerRepo(db)
}

// newSiteReposWithoutSiteTable 只迁移 site_listeners 表，用于触发站点仓库的 SQL 错误分支。
func newSiteReposWithoutSiteTable(t *testing.T) (*repository.SiteRepo, *repository.SiteListenerRepo) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SiteListener{}); err != nil {
		t.Fatalf("migrate site listeners: %v", err)
	}
	return repository.NewSiteRepo(db), repository.NewSiteListenerRepo(db)
}

/**
 * seedSiteWithEnabled 创建站点并确保 enabled 字段真实落库。
 * store.Site.Enabled 带 gorm `default:true`：插入零值 false 时列默认值生效，
 * 且 GORM 会把默认值 true 回写进结构体，因此禁用站点必须在 Create 之后
 * 重新置 false 再 Save 一次。
 */
func seedSiteWithEnabled(t *testing.T, repo *repository.SiteRepo, item *store.Site, enabled bool) {
	t.Helper()
	item.Enabled = enabled
	if err := repo.Create(item); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	if enabled {
		return
	}
	item.Enabled = false
	if err := repo.Update(item); err != nil {
		t.Fatalf("disable seeded site: %v", err)
	}
}

func decodeSiteListResponse(t *testing.T, body []byte) (items []siteListItem, total int64) {
	t.Helper()
	var resp struct {
		Items []siteListItem `json:"items"`
		Total int64          `json:"total"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode site list: %v (body=%s)", err, body)
	}
	return resp.Items, resp.Total
}

func TestListSitesSummarizesLegacyBind(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	plain := store.Site{Host: "legacy-http.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true}
	secured := store.Site{Host: "legacy-https.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8443", Network: "tcp", Enabled: true, TLSEnabled: true, CertID: uintPtr(1)}
	for _, item := range []*store.Site{&plain, &secured} {
		if err := siteRepo.Create(item); err != nil {
			t.Fatalf("seed site %s: %v", item.Host, err)
		}
	}

	ctx := invokeSiteRouteHandler(t, ListSites(siteRepo, listenerRepo), "GET", "/api/v1/sites", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	items, total := decodeSiteListResponse(t, ctx.Response.Body())
	if total != 2 || len(items) != 2 {
		t.Fatalf("expected two sites, total=%d items=%d", total, len(items))
	}
	if items[0].ListenerSummary != ":8080" || items[0].TLSSummary != "HTTP" || items[0].ManagedListenerCount != 0 {
		t.Fatalf("plain site summary mismatch: %#v", items[0])
	}
	if items[1].ListenerSummary != ":8443" || items[1].TLSSummary != "HTTPS" || items[1].ManagedListenerCount != 0 {
		t.Fatalf("secured site summary mismatch: %#v", items[1])
	}
}

func TestListSitesSummarizesManagedListeners(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	mixed := store.Site{Host: "managed-mixed.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true}
	plain := store.Site{Host: "managed-plain.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":9090", Network: "tcp", Enabled: true}
	for _, item := range []*store.Site{&mixed, &plain} {
		if err := siteRepo.Create(item); err != nil {
			t.Fatalf("seed site %s: %v", item.Host, err)
		}
	}

	listeners := []*store.SiteListener{
		{SiteID: mixed.ID, Bind: ":8443", Network: "tcp", TLSEnabled: true, CertID: uintPtr(1), Enabled: true},
		{SiteID: mixed.ID, Bind: ":8444", Network: "tcp", Enabled: true},
		{SiteID: mixed.ID, Bind: ":8445", Network: "tcp", TLSEnabled: true, CertID: uintPtr(1)},
		{SiteID: plain.ID, Bind: ":9091", Network: "tcp", Enabled: true},
	}
	for _, listener := range listeners {
		if err := listenerRepo.Create(listener); err != nil {
			t.Fatalf("seed listener %s: %v", listener.Bind, err)
		}
	}
	// SiteListener.Enabled 带 gorm default:true，插入时的零值会被列默认值覆盖，
	// 因此必须在创建后显式落库为 false，才能验证 AllEnabled 的过滤行为。
	disabled := listeners[2]
	disabled.Enabled = false
	if err := listenerRepo.Update(disabled); err != nil {
		t.Fatalf("disable listener: %v", err)
	}

	ctx := invokeSiteRouteHandler(t, ListSites(siteRepo, listenerRepo), "GET", "/api/v1/sites", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	items, total := decodeSiteListResponse(t, ctx.Response.Body())
	if total != 2 || len(items) != 2 {
		t.Fatalf("expected two sites, total=%d items=%d", total, len(items))
	}
	if items[0].ManagedListenerCount != 2 {
		t.Fatalf("disabled listener must be excluded, got count=%d", items[0].ManagedListenerCount)
	}
	if items[0].ListenerSummary != ":8443 / :8444" {
		t.Fatalf("mixed listener summary = %q", items[0].ListenerSummary)
	}
	if items[0].TLSSummary != "多监听（含 HTTPS）" {
		t.Fatalf("mixed tls summary = %q", items[0].TLSSummary)
	}
	if items[1].ManagedListenerCount != 1 || items[1].ListenerSummary != ":9091" {
		t.Fatalf("plain managed summary mismatch: %#v", items[1])
	}
	if items[1].TLSSummary != "多监听（HTTP）" {
		t.Fatalf("plain managed tls summary = %q", items[1].TLSSummary)
	}
}

func TestListSitesAppliesPagination(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	for i := 0; i < 3; i++ {
		item := store.Site{Host: "page-" + strconv.Itoa(i) + ".example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true}
		if err := siteRepo.Create(&item); err != nil {
			t.Fatalf("seed site %d: %v", i, err)
		}
	}

	ctx := invokeSiteRouteHandler(t, ListSites(siteRepo, listenerRepo), "GET", "/api/v1/sites?page=2&page_size=2", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	items, total := decodeSiteListResponse(t, ctx.Response.Body())
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}
	if len(items) != 1 || items[0].Host != "page-2.example" {
		t.Fatalf("unexpected second page: %#v", items)
	}
}

func TestListSitesReturns500WhenSiteQueryFails(t *testing.T) {
	siteRepo, listenerRepo := newSiteReposWithoutSiteTable(t)
	ctx := invokeSiteRouteHandler(t, ListSites(siteRepo, listenerRepo), "GET", "/api/v1/sites", nil, nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestListSitesReturns500WhenListenerQueryFails(t *testing.T) {
	siteRepo, listenerRepo := newSiteReposWithoutListenerTable(t)
	item := store.Site{Host: "listener-error.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true}
	if err := siteRepo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeSiteRouteHandler(t, ListSites(siteRepo, listenerRepo), "GET", "/api/v1/sites", nil, nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestGetSiteReturnsStoredSite(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{Host: "get-site.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeSiteRouteHandler(t, GetSite(repo), "GET", "/api/v1/sites/1", idParams(strconv.FormatUint(uint64(item.ID), 10)), nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var loaded store.Site
	if err := json.Unmarshal(ctx.Response.Body(), &loaded); err != nil {
		t.Fatalf("decode site: %v", err)
	}
	if loaded.ID != item.ID || loaded.Host != "get-site.example" {
		t.Fatalf("unexpected site payload: %#v", loaded)
	}
}

func TestGetSiteRejectsInvalidID(t *testing.T) {
	repo := newSiteRepoForTest(t)
	ctx := invokeSiteRouteHandler(t, GetSite(repo), "GET", "/api/v1/sites/abc", idParams("abc"), nil)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), "invalid id")
}

func TestGetSiteReturns404ForMissingSite(t *testing.T) {
	repo := newSiteRepoForTest(t)
	ctx := invokeSiteRouteHandler(t, GetSite(repo), "GET", "/api/v1/sites/404", idParams("404"), nil)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), "not found")
}

func TestDeleteSiteRemovesSiteAndListeners(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := store.Site{Host: "delete-site.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true}
	if err := siteRepo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	for _, bind := range []string{":8443", ":8444"} {
		listener := store.SiteListener{SiteID: item.ID, Bind: bind, Network: "tcp", Enabled: true}
		if err := listenerRepo.Create(&listener); err != nil {
			t.Fatalf("seed listener %s: %v", bind, err)
		}
	}

	reloadCalled := false
	ctx := invokeSiteRouteHandler(t, DeleteSite(siteRepo, listenerRepo, func() error {
		reloadCalled = true
		return nil
	}), "POST", "/api/v1/sites/1/delete", idParams(strconv.FormatUint(uint64(item.ID), 10)), nil)
	if ctx.Response.StatusCode() != 204 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if !reloadCalled {
		t.Fatal("reload was not called")
	}
	if _, err := siteRepo.Get(item.ID); err == nil {
		t.Fatal("site should be deleted")
	}
	remaining, err := listenerRepo.ListBySite(item.ID)
	if err != nil {
		t.Fatalf("list listeners: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("listeners should be deleted with the site, got %#v", remaining)
	}
}

func TestDeleteSiteRejectsInvalidID(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	reloadCalled := false
	ctx := invokeSiteRouteHandler(t, DeleteSite(siteRepo, listenerRepo, func() error {
		reloadCalled = true
		return nil
	}), "POST", "/api/v1/sites/abc/delete", idParams("abc"), nil)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCalled {
		t.Fatal("reload should not be called")
	}
	requireErrorMessage(t, ctx.Response.Body(), "invalid id")
}

func TestDeleteSiteReturns500WhenRepoFails(t *testing.T) {
	siteRepo, listenerRepo := newSiteReposWithoutListenerTable(t)
	item := store.Site{Host: "delete-error.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true}
	if err := siteRepo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeSiteRouteHandler(t, DeleteSite(siteRepo, listenerRepo, func() error { return nil }), "POST", "/api/v1/sites/1/delete", idParams(strconv.FormatUint(uint64(item.ID), 10)), nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestDeleteSiteReportsReloadFailure(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := store.Site{Host: "delete-reload.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true}
	if err := siteRepo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeSiteRouteHandler(t, DeleteSite(siteRepo, listenerRepo, func() error {
		return errTestReload
	}), "POST", "/api/v1/sites/1/delete", idParams(strconv.FormatUint(uint64(item.ID), 10)), nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), "config applied but reload failed: "+errTestReload.Error())
	// 删除已经提交，reload 失败不回滚。
	if _, err := siteRepo.Get(item.ID); err == nil {
		t.Fatal("site should still be deleted after reload failure")
	}
}

func TestStartSiteEnablesSite(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{Host: "start-site.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp"}
	seedSiteWithEnabled(t, repo, &item, false)

	reloadCalled := false
	ctx := invokeSiteRouteHandler(t, StartSite(repo, func() error {
		reloadCalled = true
		return nil
	}), "POST", "/api/v1/sites/1/start", idParams(strconv.FormatUint(uint64(item.ID), 10)), nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if !reloadCalled {
		t.Fatal("reload was not called")
	}
	var resp map[string]string
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["status"] != "running" || resp["message"] != "site started" {
		t.Fatalf("unexpected start payload: %#v", resp)
	}
	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if !loaded.Enabled {
		t.Fatal("start should enable the site")
	}
}

func TestStopSiteDisablesSite(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{Host: "stop-site.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeSiteRouteHandler(t, StopSite(repo, func() error { return nil }), "POST", "/api/v1/sites/1/stop", idParams(strconv.FormatUint(uint64(item.ID), 10)), nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp map[string]string
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["status"] != "stopped" || resp["message"] != "site stopped" {
		t.Fatalf("unexpected stop payload: %#v", resp)
	}
	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.Enabled {
		t.Fatal("stop should disable the site")
	}
}

func TestStartStopSiteRejectInvalidIDAndMissingSite(t *testing.T) {
	tests := []struct {
		name    string
		build   func(repo *repository.SiteRepo) app.HandlerFunc
		rawID   string
		status  int
		message string
	}{
		{name: "start invalid id", build: func(repo *repository.SiteRepo) app.HandlerFunc { return StartSite(repo, func() error { return nil }) }, rawID: "abc", status: 400, message: "invalid id"},
		{name: "start missing site", build: func(repo *repository.SiteRepo) app.HandlerFunc { return StartSite(repo, func() error { return nil }) }, rawID: "404", status: 404, message: "site not found"},
		{name: "stop invalid id", build: func(repo *repository.SiteRepo) app.HandlerFunc { return StopSite(repo, func() error { return nil }) }, rawID: "abc", status: 400, message: "invalid id"},
		{name: "stop missing site", build: func(repo *repository.SiteRepo) app.HandlerFunc { return StopSite(repo, func() error { return nil }) }, rawID: "404", status: 404, message: "site not found"},
		{name: "status invalid id", build: func(repo *repository.SiteRepo) app.HandlerFunc { return GetSiteStatus(repo) }, rawID: "abc", status: 400, message: "invalid id"},
		{name: "status missing site", build: func(repo *repository.SiteRepo) app.HandlerFunc { return GetSiteStatus(repo) }, rawID: "404", status: 404, message: "site not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newSiteRepoForTest(t)
			ctx := invokeSiteRouteHandler(t, tt.build(repo), "POST", "/api/v1/sites/"+tt.rawID+"/lifecycle", idParams(tt.rawID), nil)
			if ctx.Response.StatusCode() != tt.status {
				t.Fatalf("status = %d, want %d, body=%s", ctx.Response.StatusCode(), tt.status, bytes.TrimSpace(ctx.Response.Body()))
			}
			requireErrorMessage(t, ctx.Response.Body(), tt.message)
		})
	}
}

func TestStartSiteReportsReloadFailure(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{Host: "start-reload.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp"}
	seedSiteWithEnabled(t, repo, &item, false)

	ctx := invokeSiteRouteHandler(t, StartSite(repo, func() error { return errTestReload }), "POST", "/api/v1/sites/1/start", idParams(strconv.FormatUint(uint64(item.ID), 10)), nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Error string     `json:"error"`
		Item  store.Site `json:"item"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error != "config applied but reload failed: "+errTestReload.Error() {
		t.Fatalf("error = %q", resp.Error)
	}
	if resp.Item.ID != item.ID || !resp.Item.Enabled {
		t.Fatalf("reload failure should echo the persisted site, got %#v", resp.Item)
	}
}

func TestStopSiteReportsReloadFailure(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{Host: "stop-reload.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeSiteRouteHandler(t, StopSite(repo, func() error { return errTestReload }), "POST", "/api/v1/sites/1/stop", idParams(strconv.FormatUint(uint64(item.ID), 10)), nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.Enabled {
		t.Fatal("stop persists before reload, site should be disabled")
	}
}

/**
 * TestGetSiteStatusFallsBackToEnabledFlag 覆盖 siteStatusMap 中不存在条目时的回退分支。
 * 这里显式指定较大的站点 ID，避免与 Start/Stop 用例写入的进程级全局映射冲突。
 */
func TestGetSiteStatusFallsBackToEnabledFlag(t *testing.T) {
	tests := []struct {
		name    string
		id      uint
		enabled bool
		want    string
	}{
		{name: "enabled site reports running", id: 7001, enabled: true, want: "running"},
		{name: "disabled site reports stopped", id: 7002, enabled: false, want: "stopped"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newSiteRepoForTest(t)
			item := store.Site{ID: tt.id, Host: "status-fallback.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp"}
			seedSiteWithEnabled(t, repo, &item, tt.enabled)

			ctx := invokeSiteRouteHandler(t, GetSiteStatus(repo), "GET", "/api/v1/sites/1/status", idParams(strconv.FormatUint(uint64(tt.id), 10)), nil)
			if ctx.Response.StatusCode() != 200 {
				t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
			var resp struct {
				ID     uint   `json:"id"`
				Host   string `json:"host"`
				Status string `json:"status"`
			}
			if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp.ID != tt.id || resp.Host != "status-fallback.example" || resp.Status != tt.want {
				t.Fatalf("unexpected status payload: %#v", resp)
			}
		})
	}
}

func TestGetSiteStatusReflectsStartAndStop(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{ID: 7100, Host: "status-transition.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp"}
	seedSiteWithEnabled(t, repo, &item, false)
	rawID := strconv.FormatUint(uint64(item.ID), 10)

	if ctx := invokeSiteRouteHandler(t, StartSite(repo, func() error { return nil }), "POST", "/api/v1/sites/1/start", idParams(rawID), nil); ctx.Response.StatusCode() != 200 {
		t.Fatalf("start failed: %d %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if got := readSiteStatus(t, repo, rawID); got != "running" {
		t.Fatalf("status after start = %q, want running", got)
	}

	if ctx := invokeSiteRouteHandler(t, StopSite(repo, func() error { return nil }), "POST", "/api/v1/sites/1/stop", idParams(rawID), nil); ctx.Response.StatusCode() != 200 {
		t.Fatalf("stop failed: %d %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if got := readSiteStatus(t, repo, rawID); got != "stopped" {
		t.Fatalf("status after stop = %q, want stopped", got)
	}
}

func readSiteStatus(t *testing.T, repo *repository.SiteRepo, rawID string) string {
	t.Helper()
	ctx := invokeSiteRouteHandler(t, GetSiteStatus(repo), "GET", "/api/v1/sites/1/status", idParams(rawID), nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status request failed: %d %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	return resp.Status
}
