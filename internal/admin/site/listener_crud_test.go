package site

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// listenerParams 构造同时包含站点 ID 与监听器 ID 的路由参数集合。
func listenerParams(siteID, listenerID string) param.Params {
	return param.Params{
		{Key: "id", Value: siteID},
		{Key: "lid", Value: listenerID},
	}
}

// newSiteListenerCertReposForTest 额外迁移证书表，用于覆盖 TLS 证书校验分支。
func newSiteListenerCertReposForTest(t *testing.T) (*repository.SiteRepo, *repository.SiteListenerRepo, *repository.CertificateRepo) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}, &store.SiteListener{}, &store.Certificate{}); err != nil {
		t.Fatalf("migrate listener and certificate tables: %v", err)
	}
	return repository.NewSiteRepo(db), repository.NewSiteListenerRepo(db), repository.NewCertificateRepo(db)
}

// seedListenerSite 创建一个用于监听器用例的基础站点。
func seedListenerSite(t *testing.T, repo *repository.SiteRepo, host, bind string) *store.Site {
	t.Helper()
	item := &store.Site{Host: host, UpstreamURLs: "http://127.0.0.1:8080", Bind: bind, Network: "tcp", Enabled: true}
	if err := repo.Create(item); err != nil {
		t.Fatalf("seed site %s: %v", host, err)
	}
	return item
}

func decodeListenerListResponse(t *testing.T, body []byte) (items []store.SiteListener, total int) {
	t.Helper()
	var resp struct {
		Items []store.SiteListener `json:"items"`
		Total int                  `json:"total"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode listener list: %v (body=%s)", err, body)
	}
	return resp.Items, resp.Total
}

/**
 * TestListSiteListenersSynthesizesLegacyEntry 覆盖站点没有显式监听器行时
 * 由 Site.Bind/TLSEnabled/CertID 合成虚拟条目的分支。
 */
func TestListSiteListenersSynthesizesLegacyEntry(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := &store.Site{Host: "legacy-listener.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8443", Network: "tcp6", Enabled: true, TLSEnabled: true, CertID: uintPtr(3)}
	if err := siteRepo.Create(item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeSiteRouteHandler(t, ListSiteListeners(siteRepo, listenerRepo), "GET", "/api/v1/sites/1/listeners", idParams(strconv.FormatUint(uint64(item.ID), 10)), nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	items, total := decodeListenerListResponse(t, ctx.Response.Body())
	if total != 1 || len(items) != 1 {
		t.Fatalf("expected one synthesised listener, total=%d items=%d", total, len(items))
	}
	synth := items[0]
	if synth.ID != 0 || synth.Note != "legacy" {
		t.Fatalf("synthesised entry should be virtual with legacy note, got %#v", synth)
	}
	if synth.SiteID != item.ID || synth.Bind != ":8443" || synth.Network != "tcp6" || !synth.TLSEnabled || !synth.Enabled {
		t.Fatalf("synthesised entry does not mirror legacy site fields: %#v", synth)
	}
	if synth.CertID == nil || *synth.CertID != 3 {
		t.Fatalf("synthesised entry cert_id = %#v, want 3", synth.CertID)
	}
}

func TestListSiteListenersReturnsPersistedRows(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := seedListenerSite(t, siteRepo, "managed-listener.example", ":8080")
	for _, bind := range []string{":8444", ":8443"} {
		listener := store.SiteListener{SiteID: item.ID, Bind: bind, Network: "tcp", Enabled: true}
		if err := listenerRepo.Create(&listener); err != nil {
			t.Fatalf("seed listener %s: %v", bind, err)
		}
	}

	ctx := invokeSiteRouteHandler(t, ListSiteListeners(siteRepo, listenerRepo), "GET", "/api/v1/sites/1/listeners", idParams(strconv.FormatUint(uint64(item.ID), 10)), nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	items, total := decodeListenerListResponse(t, ctx.Response.Body())
	if total != 2 || len(items) != 2 {
		t.Fatalf("expected two listeners, total=%d items=%d", total, len(items))
	}
	// ListBySite 按 bind 升序返回。
	if items[0].Bind != ":8443" || items[1].Bind != ":8444" {
		t.Fatalf("unexpected listener order: %q,%q", items[0].Bind, items[1].Bind)
	}
}

func TestListSiteListenersRejectsInvalidIDAndMissingSite(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)

	ctx := invokeSiteRouteHandler(t, ListSiteListeners(siteRepo, listenerRepo), "GET", "/api/v1/sites/abc/listeners", idParams("abc"), nil)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d", ctx.Response.StatusCode())
	}
	requireErrorMessage(t, ctx.Response.Body(), "invalid site id")

	ctx = invokeSiteRouteHandler(t, ListSiteListeners(siteRepo, listenerRepo), "GET", "/api/v1/sites/404/listeners", idParams("404"), nil)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("missing site status = %d", ctx.Response.StatusCode())
	}
	requireErrorMessage(t, ctx.Response.Body(), "site not found")
}

func TestListSiteListenersReturns500WhenQueryFails(t *testing.T) {
	siteRepo, listenerRepo := newSiteReposWithoutListenerTable(t)
	item := seedListenerSite(t, siteRepo, "listener-query-error.example", ":8080")

	ctx := invokeSiteRouteHandler(t, ListSiteListeners(siteRepo, listenerRepo), "GET", "/api/v1/sites/1/listeners", idParams(strconv.FormatUint(uint64(item.ID), 10)), nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestCreateSiteListenerRejectsInvalidIDAndMissingSite(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	handler := CreateSiteListener(siteRepo, listenerRepo, nil, func() error { return nil })

	ctx := invokeSiteRouteHandler(t, handler, "POST", "/api/v1/sites/abc/listeners", idParams("abc"), []byte(`{"bind":":8443"}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d", ctx.Response.StatusCode())
	}
	requireErrorMessage(t, ctx.Response.Body(), "invalid site id")

	ctx = invokeSiteRouteHandler(t, handler, "POST", "/api/v1/sites/404/listeners", idParams("404"), []byte(`{"bind":":8443"}`))
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("missing site status = %d", ctx.Response.StatusCode())
	}
	requireErrorMessage(t, ctx.Response.Body(), "site not found")
}

func TestCreateSiteListenerRejectsMalformedBody(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := seedListenerSite(t, siteRepo, "listener-bad-body.example", ":8080")

	ctx := invokeCreateSiteListenerHandler(t, CreateSiteListener(siteRepo, listenerRepo, nil, func() error { return nil }), item.ID, []byte(`{"bind":`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestCreateSiteListenerRequiresBind(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := seedListenerSite(t, siteRepo, "listener-no-bind.example", ":8080")

	ctx := invokeCreateSiteListenerHandler(t, CreateSiteListener(siteRepo, listenerRepo, nil, func() error { return nil }), item.ID, []byte(`{"network":"tcp","enabled":true}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), "bind is required")
}

// TestCreateSiteListenerDefaultsNetworkToTCP 覆盖请求未携带 network 时的默认值分支。
func TestCreateSiteListenerDefaultsNetworkToTCP(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := seedListenerSite(t, siteRepo, "listener-default-network.example", ":8080")

	ctx := invokeCreateSiteListenerHandler(t, CreateSiteListener(siteRepo, listenerRepo, nil, func() error { return nil }), item.ID, []byte(`{"bind":":8443","enabled":true}`))
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var created store.SiteListener
	if err := json.Unmarshal(ctx.Response.Body(), &created); err != nil {
		t.Fatalf("decode created listener: %v", err)
	}
	if created.Network != "tcp" {
		t.Fatalf("created listener network = %q, want tcp", created.Network)
	}
}

/**
 * TestCreateSiteListenerSkipsLegacyPromotion 覆盖不触发 legacy 迁移的两个条件：
 * 新监听器 bind 与站点 legacy bind 相同，或站点本身没有 legacy bind。
 */
func TestCreateSiteListenerSkipsLegacyPromotion(t *testing.T) {
	tests := []struct {
		name     string
		siteBind string
		payload  string
	}{
		{name: "same bind as legacy", siteBind: ":8080", payload: `{"bind":":8080","enabled":true}`},
		{name: "site without legacy bind", siteBind: "", payload: `{"bind":":8443","enabled":true}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
			item := seedListenerSite(t, siteRepo, "listener-no-promotion.example", tt.siteBind)

			ctx := invokeCreateSiteListenerHandler(t, CreateSiteListener(siteRepo, listenerRepo, nil, func() error { return nil }), item.ID, []byte(tt.payload))
			if ctx.Response.StatusCode() != 201 {
				t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
			rows, err := listenerRepo.ListBySite(item.ID)
			if err != nil {
				t.Fatalf("list listeners: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("legacy promotion should be skipped, got %d rows: %#v", len(rows), rows)
			}
		})
	}
}

// TestCreateSiteListenerPromotesLegacyBind 验证首个显式监听器会把 legacy bind 落库为真实行。
func TestCreateSiteListenerPromotesLegacyBind(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := &store.Site{Host: "listener-promotion.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp4", Enabled: true, TLSEnabled: true, CertID: uintPtr(5)}
	if err := siteRepo.Create(item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeCreateSiteListenerHandler(t, CreateSiteListener(siteRepo, listenerRepo, nil, func() error { return nil }), item.ID, []byte(`{"bind":":8443","network":"tcp","enabled":true}`))
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	rows, err := listenerRepo.ListBySite(item.ID)
	if err != nil {
		t.Fatalf("list listeners: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected legacy row plus new row, got %#v", rows)
	}
	var promoted *store.SiteListener
	for i := range rows {
		if rows[i].Bind == ":8080" {
			promoted = &rows[i]
		}
	}
	if promoted == nil {
		t.Fatalf("legacy bind was not promoted: %#v", rows)
	}
	if promoted.Note != "migrated from legacy bind" || promoted.Network != "tcp4" || !promoted.TLSEnabled || !promoted.Enabled {
		t.Fatalf("promoted listener does not mirror legacy fields: %#v", promoted)
	}
	if promoted.CertID == nil || *promoted.CertID != 5 {
		t.Fatalf("promoted listener cert_id = %#v, want 5", promoted.CertID)
	}
}

func TestCreateSiteListenerValidatesTLSCertificate(t *testing.T) {
	siteRepo, listenerRepo, certRepo := newSiteListenerCertReposForTest(t)
	cert := store.Certificate{Name: "listener-cert", CertPEM: "cert", KeyPEM: "key"}
	if err := certRepo.Create(&cert); err != nil {
		t.Fatalf("seed certificate: %v", err)
	}
	item := seedListenerSite(t, siteRepo, "listener-tls.example", ":8080")

	tests := []struct {
		name       string
		payload    string
		wantStatus int
		wantError  string
	}{
		{name: "tls without cert id", payload: `{"bind":":8443","tls_enabled":true}`, wantStatus: 400, wantError: "TLS-enabled site requires cert_id"},
		{name: "tls with unknown cert id", payload: `{"bind":":8444","tls_enabled":true,"cert_id":9999}`, wantStatus: 400, wantError: "certificate not found"},
		{name: "tls with existing cert id", payload: `{"bind":":8445","tls_enabled":true,"cert_id":` + strconv.FormatUint(uint64(cert.ID), 10) + `}`, wantStatus: 201},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := invokeCreateSiteListenerHandler(t, CreateSiteListener(siteRepo, listenerRepo, certRepo, func() error { return nil }), item.ID, []byte(tt.payload))
			if ctx.Response.StatusCode() != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body=%s", ctx.Response.StatusCode(), tt.wantStatus, bytes.TrimSpace(ctx.Response.Body()))
			}
			if tt.wantError != "" {
				requireErrorMessage(t, ctx.Response.Body(), tt.wantError)
			}
		})
	}
}

func TestCreateSiteListenerReturns500WhenPersistFails(t *testing.T) {
	siteRepo, listenerRepo := newSiteReposWithoutListenerTable(t)
	item := seedListenerSite(t, siteRepo, "listener-persist-error.example", ":8080")

	ctx := invokeCreateSiteListenerHandler(t, CreateSiteListener(siteRepo, listenerRepo, nil, func() error { return nil }), item.ID, []byte(`{"bind":":8443","enabled":true}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestCreateSiteListenerReportsReloadFailure(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := seedListenerSite(t, siteRepo, "listener-reload.example", ":8080")

	ctx := invokeCreateSiteListenerHandler(t, CreateSiteListener(siteRepo, listenerRepo, nil, func() error { return errTestReload }), item.ID, []byte(`{"bind":":8443","enabled":true}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Error string             `json:"error"`
		Item  store.SiteListener `json:"item"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error != "config applied but reload failed: "+errTestReload.Error() {
		t.Fatalf("error = %q", resp.Error)
	}
	if resp.Item.Bind != ":8443" {
		t.Fatalf("reload failure should echo the created listener, got %#v", resp.Item)
	}
}

func TestUpdateSiteListenerRejectsInvalidRouteParams(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := seedListenerSite(t, siteRepo, "listener-update-params.example", ":8080")
	listener := store.SiteListener{SiteID: item.ID, Bind: ":8443", Network: "tcp", Enabled: true}
	if err := listenerRepo.Create(&listener); err != nil {
		t.Fatalf("seed listener: %v", err)
	}
	other := seedListenerSite(t, siteRepo, "listener-update-other.example", ":9090")
	handler := UpdateSiteListener(siteRepo, listenerRepo, nil, func() error { return nil })

	tests := []struct {
		name    string
		params  param.Params
		status  int
		message string
	}{
		{name: "invalid site id", params: listenerParams("abc", "1"), status: 400, message: "invalid site id"},
		{name: "invalid listener id", params: listenerParams(strconv.FormatUint(uint64(item.ID), 10), "abc"), status: 400, message: "invalid listener id"},
		{name: "missing site", params: listenerParams("404", "1"), status: 404, message: "site not found"},
		{name: "missing listener", params: listenerParams(strconv.FormatUint(uint64(item.ID), 10), "404"), status: 404, message: "listener not found"},
		{name: "listener owned by another site", params: listenerParams(strconv.FormatUint(uint64(other.ID), 10), strconv.FormatUint(uint64(listener.ID), 10)), status: 404, message: "listener not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := invokeSiteRouteHandler(t, handler, "POST", "/api/v1/sites/1/listeners/1/update", tt.params, []byte(`{"bind":":8443","network":"tcp","enabled":true}`))
			if ctx.Response.StatusCode() != tt.status {
				t.Fatalf("status = %d, want %d, body=%s", ctx.Response.StatusCode(), tt.status, bytes.TrimSpace(ctx.Response.Body()))
			}
			requireErrorMessage(t, ctx.Response.Body(), tt.message)
		})
	}
}

func TestUpdateSiteListenerPersistsChanges(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := seedListenerSite(t, siteRepo, "listener-update-ok.example", ":8080")
	listener := store.SiteListener{SiteID: item.ID, Bind: ":8443", Network: "tcp4", Enabled: true, Note: "before"}
	if err := listenerRepo.Create(&listener); err != nil {
		t.Fatalf("seed listener: %v", err)
	}

	reloadCalled := false
	ctx := invokeUpdateSiteListenerHandler(t, UpdateSiteListener(siteRepo, listenerRepo, nil, func() error {
		reloadCalled = true
		return nil
	}), item.ID, listener.ID, []byte(`{"bind":":9443","note":"after"}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if !reloadCalled {
		t.Fatal("reload was not called")
	}

	loaded, err := listenerRepo.Get(listener.ID)
	if err != nil {
		t.Fatalf("load listener: %v", err)
	}
	if loaded.Bind != ":9443" || loaded.Note != "after" {
		t.Fatalf("listener changes not persisted: %#v", loaded)
	}
	// 请求未携带 network，但既有值 tcp4 会被保留（handler 仅在空值时回落到 tcp）。
	if loaded.Network != "tcp4" {
		t.Fatalf("listener network = %q, want tcp4", loaded.Network)
	}
	if loaded.SiteID != item.ID {
		t.Fatalf("listener site id = %d, want %d", loaded.SiteID, item.ID)
	}
}

// TestUpdateSiteListenerDefaultsEmptyNetworkToTCP 覆盖显式传空 network 时回落到 tcp 的分支。
func TestUpdateSiteListenerDefaultsEmptyNetworkToTCP(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := seedListenerSite(t, siteRepo, "listener-update-empty-network.example", ":8080")
	listener := store.SiteListener{SiteID: item.ID, Bind: ":8443", Network: "tcp6", Enabled: true}
	if err := listenerRepo.Create(&listener); err != nil {
		t.Fatalf("seed listener: %v", err)
	}

	ctx := invokeUpdateSiteListenerHandler(t, UpdateSiteListener(siteRepo, listenerRepo, nil, func() error { return nil }), item.ID, listener.ID, []byte(`{"bind":":8443","network":""}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	loaded, err := listenerRepo.Get(listener.ID)
	if err != nil {
		t.Fatalf("load listener: %v", err)
	}
	if loaded.Network != "tcp" {
		t.Fatalf("listener network = %q, want tcp", loaded.Network)
	}
}

func TestUpdateSiteListenerRejectsMalformedBody(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := seedListenerSite(t, siteRepo, "listener-update-bad-body.example", ":8080")
	listener := store.SiteListener{SiteID: item.ID, Bind: ":8443", Network: "tcp", Enabled: true}
	if err := listenerRepo.Create(&listener); err != nil {
		t.Fatalf("seed listener: %v", err)
	}

	ctx := invokeUpdateSiteListenerHandler(t, UpdateSiteListener(siteRepo, listenerRepo, nil, func() error { return nil }), item.ID, listener.ID, []byte(`{"bind":`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestUpdateSiteListenerValidatesTLSCertificate(t *testing.T) {
	siteRepo, listenerRepo, certRepo := newSiteListenerCertReposForTest(t)
	item := seedListenerSite(t, siteRepo, "listener-update-tls.example", ":8080")
	listener := store.SiteListener{SiteID: item.ID, Bind: ":8443", Network: "tcp", Enabled: true}
	if err := listenerRepo.Create(&listener); err != nil {
		t.Fatalf("seed listener: %v", err)
	}

	ctx := invokeUpdateSiteListenerHandler(t, UpdateSiteListener(siteRepo, listenerRepo, certRepo, func() error { return nil }), item.ID, listener.ID, []byte(`{"bind":":8443","tls_enabled":true,"cert_id":9999}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), "certificate not found")

	loaded, err := listenerRepo.Get(listener.ID)
	if err != nil {
		t.Fatalf("load listener: %v", err)
	}
	if loaded.TLSEnabled {
		t.Fatal("rejected update should not enable TLS")
	}
}

func TestUpdateSiteListenerReportsReloadFailure(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := seedListenerSite(t, siteRepo, "listener-update-reload.example", ":8080")
	listener := store.SiteListener{SiteID: item.ID, Bind: ":8443", Network: "tcp", Enabled: true}
	if err := listenerRepo.Create(&listener); err != nil {
		t.Fatalf("seed listener: %v", err)
	}

	ctx := invokeUpdateSiteListenerHandler(t, UpdateSiteListener(siteRepo, listenerRepo, nil, func() error { return errTestReload }), item.ID, listener.ID, []byte(`{"bind":":9443"}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	loaded, err := listenerRepo.Get(listener.ID)
	if err != nil {
		t.Fatalf("load listener: %v", err)
	}
	if loaded.Bind != ":9443" {
		t.Fatalf("update persists before reload, bind = %q", loaded.Bind)
	}
}

func TestDeleteSiteListenerRemovesRow(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := seedListenerSite(t, siteRepo, "listener-delete.example", ":8080")
	listener := store.SiteListener{SiteID: item.ID, Bind: ":8443", Network: "tcp", Enabled: true}
	if err := listenerRepo.Create(&listener); err != nil {
		t.Fatalf("seed listener: %v", err)
	}

	reloadCalled := false
	ctx := invokeSiteRouteHandler(t, DeleteSiteListener(siteRepo, listenerRepo, func() error {
		reloadCalled = true
		return nil
	}), "POST", "/api/v1/sites/1/listeners/1/delete", listenerParams(strconv.FormatUint(uint64(item.ID), 10), strconv.FormatUint(uint64(listener.ID), 10)), nil)
	if ctx.Response.StatusCode() != 204 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if !reloadCalled {
		t.Fatal("reload was not called")
	}
	rows, err := listenerRepo.ListBySite(item.ID)
	if err != nil {
		t.Fatalf("list listeners: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("listener should be deleted, got %#v", rows)
	}
}

func TestDeleteSiteListenerRejectsInvalidRouteParams(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := seedListenerSite(t, siteRepo, "listener-delete-params.example", ":8080")
	listener := store.SiteListener{SiteID: item.ID, Bind: ":8443", Network: "tcp", Enabled: true}
	if err := listenerRepo.Create(&listener); err != nil {
		t.Fatalf("seed listener: %v", err)
	}
	other := seedListenerSite(t, siteRepo, "listener-delete-other.example", ":9090")
	handler := DeleteSiteListener(siteRepo, listenerRepo, func() error { return nil })

	tests := []struct {
		name    string
		params  param.Params
		status  int
		message string
	}{
		{name: "invalid site id", params: listenerParams("abc", "1"), status: 400, message: "invalid site id"},
		{name: "invalid listener id", params: listenerParams(strconv.FormatUint(uint64(item.ID), 10), "abc"), status: 400, message: "invalid listener id"},
		{name: "missing listener", params: listenerParams(strconv.FormatUint(uint64(item.ID), 10), "404"), status: 404, message: "listener not found"},
		{name: "listener owned by another site", params: listenerParams(strconv.FormatUint(uint64(other.ID), 10), strconv.FormatUint(uint64(listener.ID), 10)), status: 404, message: "listener not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := invokeSiteRouteHandler(t, handler, "POST", "/api/v1/sites/1/listeners/1/delete", tt.params, nil)
			if ctx.Response.StatusCode() != tt.status {
				t.Fatalf("status = %d, want %d, body=%s", ctx.Response.StatusCode(), tt.status, bytes.TrimSpace(ctx.Response.Body()))
			}
			requireErrorMessage(t, ctx.Response.Body(), tt.message)
		})
	}

	// 被拒绝的请求不得删除任何行。
	rows, err := listenerRepo.ListBySite(item.ID)
	if err != nil {
		t.Fatalf("list listeners: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rejected delete should keep the listener, got %#v", rows)
	}
}

func TestDeleteSiteListenerReportsReloadFailure(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := seedListenerSite(t, siteRepo, "listener-delete-reload.example", ":8080")
	listener := store.SiteListener{SiteID: item.ID, Bind: ":8443", Network: "tcp", Enabled: true}
	if err := listenerRepo.Create(&listener); err != nil {
		t.Fatalf("seed listener: %v", err)
	}

	ctx := invokeSiteRouteHandler(t, DeleteSiteListener(siteRepo, listenerRepo, func() error {
		return errTestReload
	}), "POST", "/api/v1/sites/1/listeners/1/delete", listenerParams(strconv.FormatUint(uint64(item.ID), 10), strconv.FormatUint(uint64(listener.ID), 10)), nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), "config applied but reload failed: "+errTestReload.Error())
}
