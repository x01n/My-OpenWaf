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

func newSiteAndListenerReposForTest(t *testing.T) (*repository.SiteRepo, *repository.SiteListenerRepo) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}, &store.SiteListener{}); err != nil {
		t.Fatalf("migrate site listener tables: %v", err)
	}
	return repository.NewSiteRepo(db), repository.NewSiteListenerRepo(db)
}

func invokeCreateSiteListenerHandler(t *testing.T, handler app.HandlerFunc, siteID uint, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/sites/" + strconv.FormatUint(uint64(siteID), 10) + "/listeners")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: strconv.FormatUint(uint64(siteID), 10)}}
	handler(context.Background(), ctx)
	return ctx
}

func invokeUpdateSiteListenerHandler(t *testing.T, handler app.HandlerFunc, siteID uint, listenerID uint, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/sites/" + strconv.FormatUint(uint64(siteID), 10) + "/listeners/" + strconv.FormatUint(uint64(listenerID), 10) + "/update")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{
		{Key: "id", Value: strconv.FormatUint(uint64(siteID), 10)},
		{Key: "lid", Value: strconv.FormatUint(uint64(listenerID), 10)},
	}
	handler(context.Background(), ctx)
	return ctx
}

func TestCreateSiteListenerNormalizesSupportedNetwork(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := store.Site{
		Host:         "listener-network.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8080",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := siteRepo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeCreateSiteListenerHandler(t, CreateSiteListener(siteRepo, listenerRepo, nil, func() error { return nil }), item.ID, []byte(`{"bind":":8443","network":" TCP6 ","enabled":true}`))
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	items, err := listenerRepo.ListBySite(item.ID)
	if err != nil {
		t.Fatalf("list listeners: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected created listener plus promoted legacy listener, got %d", len(items))
	}
	found := false
	for _, listener := range items {
		if listener.Bind == ":8443" {
			found = true
			if listener.Network != "tcp6" {
				t.Fatalf("created listener network = %q, want tcp6", listener.Network)
			}
		}
	}
	if !found {
		t.Fatalf("created listener not found: %+v", items)
	}
}

func TestCreateSiteListenerRejectsInvalidNetwork(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := store.Site{
		Host:         "listener-invalid-network.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8080",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := siteRepo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	reloadCalled := false
	ctx := invokeCreateSiteListenerHandler(t, CreateSiteListener(siteRepo, listenerRepo, nil, func() error {
		reloadCalled = true
		return nil
	}), item.ID, []byte(`{"bind":":8443","network":"udp","enabled":true}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCalled {
		t.Fatal("reload should not be called")
	}
	var resp map[string]string
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "invalid network" {
		t.Fatalf("error = %q, want invalid network", resp["error"])
	}
	items, err := listenerRepo.ListBySite(item.ID)
	if err != nil {
		t.Fatalf("list listeners: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("listener was created after invalid network: %+v", items)
	}
}

func TestUpdateSiteListenerRejectsInvalidNetwork(t *testing.T) {
	siteRepo, listenerRepo := newSiteAndListenerReposForTest(t)
	item := store.Site{
		Host:         "listener-update-invalid-network.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8080",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := siteRepo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	listener := store.SiteListener{
		SiteID:  item.ID,
		Bind:    ":8443",
		Network: "tcp4",
		Enabled: true,
	}
	if err := listenerRepo.Create(&listener); err != nil {
		t.Fatalf("seed listener: %v", err)
	}

	reloadCalled := false
	ctx := invokeUpdateSiteListenerHandler(t, UpdateSiteListener(siteRepo, listenerRepo, nil, func() error {
		reloadCalled = true
		return nil
	}), item.ID, listener.ID, []byte(`{"bind":":8443","network":"udp","enabled":true}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCalled {
		t.Fatal("reload should not be called")
	}
	var resp map[string]string
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "invalid network" {
		t.Fatalf("error = %q, want invalid network", resp["error"])
	}
	loaded, err := listenerRepo.Get(listener.ID)
	if err != nil {
		t.Fatalf("load listener: %v", err)
	}
	if loaded.Network != "tcp4" {
		t.Fatalf("network changed after rejected update: %q", loaded.Network)
	}
}
