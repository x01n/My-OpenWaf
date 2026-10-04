package listener

import (
	"bytes"
	"strconv"
	"testing"

	"My-OpenWaf/internal/store"
)

func TestUpdateSiteListenerReturns500WhenPersistFails(t *testing.T) {
	siteRepo, listenerRepo, db := newSiteAndListenerReposWithDBForTest(t)
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
	siteRepo, listenerRepo, db := newSiteAndListenerReposWithDBForTest(t)
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
