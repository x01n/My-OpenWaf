package site

import (
	"bytes"
	"strconv"
	"testing"

	"My-OpenWaf/internal/store"
)

/**
 * 本文件集中覆盖各 handler 中「前置读取成功、写库失败」的 500 分支。
 * 这类分支无法通过缺表构造（缺表会让前置的 Get 先失败并返回 404），
 * 因此统一使用 GORM 回调注入写失败。
 */

func TestUpdateSiteReturns500WhenPersistFails(t *testing.T) {
	repo, db := newSiteRepoWithDB(t)
	item := store.Site{Host: "update-persist-error.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	failSubsequentUpdates(t, db)

	reloadCalled := false
	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error {
		reloadCalled = true
		return nil
	}), item.ID, []byte(`{"upstream_host":"backend.example"}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCalled {
		t.Fatal("reload should not be called when persist fails")
	}
	requireErrorMessage(t, ctx.Response.Body(), errTestWrite.Error())
}

func TestStartSiteReturns500WhenPersistFails(t *testing.T) {
	repo, db := newSiteRepoWithDB(t)
	item := store.Site{Host: "start-persist-error.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	failSubsequentUpdates(t, db)

	ctx := invokeSiteRouteHandler(t, StartSite(repo, func() error { return nil }), "POST", "/api/v1/sites/1/start", idParams(strconv.FormatUint(uint64(item.ID), 10)), nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), errTestWrite.Error())
}

func TestStopSiteReturns500WhenPersistFails(t *testing.T) {
	repo, db := newSiteRepoWithDB(t)
	item := store.Site{Host: "stop-persist-error.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	failSubsequentUpdates(t, db)

	ctx := invokeSiteRouteHandler(t, StopSite(repo, func() error { return nil }), "POST", "/api/v1/sites/1/stop", idParams(strconv.FormatUint(uint64(item.ID), 10)), nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), errTestWrite.Error())
}

func TestUpdateSiteErrorPagesReturns500WhenPersistFails(t *testing.T) {
	repo, db := newSiteRepoWithDB(t)
	item := seedSiteWithErrorPages(t, repo, `{}`)
	failSubsequentUpdates(t, db)

	body := []byte(`{"error_pages":{"503":{"status_code":503,"title":"Down","html":"<p>down</p>","content_type":"text/html"}}}`)
	ctx := invokeSiteErrorPagesHandler(t, UpdateSiteErrorPages(repo, func() error { return nil }), item.ID, body)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), errTestWrite.Error())
}

func TestUpdateSiteListenerReturns500WhenPersistFails(t *testing.T) {
	siteRepo, listenerRepo, db := newSiteAndListenerReposWithDB(t)
	item := seedListenerSite(t, siteRepo, "listener-persist-error.example", ":8080")
	listener := store.SiteListener{SiteID: item.ID, Bind: ":8443", Network: "tcp", Enabled: true}
	if err := listenerRepo.Create(&listener); err != nil {
		t.Fatalf("seed listener: %v", err)
	}
	failSubsequentUpdates(t, db)

	ctx := invokeUpdateSiteListenerHandler(t, UpdateSiteListener(siteRepo, listenerRepo, nil, func() error { return nil }), item.ID, listener.ID, []byte(`{"bind":":9443"}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), errTestWrite.Error())
}

func TestDeleteSiteListenerReturns500WhenDeleteFails(t *testing.T) {
	siteRepo, listenerRepo, db := newSiteAndListenerReposWithDB(t)
	item := seedListenerSite(t, siteRepo, "listener-delete-error.example", ":8080")
	listener := store.SiteListener{SiteID: item.ID, Bind: ":8443", Network: "tcp", Enabled: true}
	if err := listenerRepo.Create(&listener); err != nil {
		t.Fatalf("seed listener: %v", err)
	}
	failSubsequentDeletes(t, db)

	ctx := invokeSiteRouteHandler(t, DeleteSiteListener(siteRepo, listenerRepo, func() error { return nil }), "POST", "/api/v1/sites/1/listeners/1/delete", listenerParams(strconv.FormatUint(uint64(item.ID), 10), strconv.FormatUint(uint64(listener.ID), 10)), nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), errTestWrite.Error())
}
