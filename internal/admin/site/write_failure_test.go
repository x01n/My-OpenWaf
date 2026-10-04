package site

import (
	"bytes"
	"strconv"
	"testing"

	"My-OpenWaf/internal/store"
)

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
