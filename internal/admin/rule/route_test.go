package rule

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

func newApplicationRouteReposForTest(t *testing.T) (*repository.SiteRepo, *repository.ApplicationRouteRuleRepo) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}, &store.ApplicationRouteRule{}); err != nil {
		t.Fatalf("migrate application route tables: %v", err)
	}
	if err := db.Create(&store.Site{Host: "example.test", Bind: ":80", Network: "tcp", Enabled: true}).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}
	return repository.NewSiteRepo(db), repository.NewApplicationRouteRuleRepo(db)
}

func invokeApplicationRouteHandler(t *testing.T, handler app.HandlerFunc, method, uri string, params param.Params, payload map[string]any) *app.RequestContext {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI(uri)
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(body)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = params
	handler(context.Background(), ctx)
	return ctx
}

func TestCreateApplicationRouteRuleDefaultsEnabledWhenOmitted(t *testing.T) {
	siteRepo, ruleRepo := newApplicationRouteReposForTest(t)
	reloaded := 0
	handler := CreateApplicationRouteRule(siteRepo, ruleRepo, func() error {
		reloaded++
		return nil
	})

	ctx := invokeApplicationRouteHandler(t, handler, "POST", "/api/v1/sites/1/application-route-rules", param.Params{{Key: "id", Value: "1"}}, map[string]any{
		"name":       "method get",
		"priority":   10,
		"target":     store.AppRouteTargetRequestMethod,
		"op":         store.AppRouteOpEq,
		"pattern":    "GET",
		"header_key": "",
	})
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloaded != 1 {
		t.Fatalf("expected one reload, got %d", reloaded)
	}
	var resp store.ApplicationRouteRule
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Enabled {
		t.Fatalf("expected omitted enabled to default true in response: %#v", resp)
	}
	stored, err := ruleRepo.Get(resp.ID)
	if err != nil {
		t.Fatalf("load stored rule: %v", err)
	}
	if !stored.Enabled {
		t.Fatalf("expected omitted enabled to default true in storage: %#v", stored)
	}
}

func TestCreateApplicationRouteRuleHonorsExplicitDisabled(t *testing.T) {
	siteRepo, ruleRepo := newApplicationRouteReposForTest(t)
	handler := CreateApplicationRouteRule(siteRepo, ruleRepo, func() error { return nil })

	ctx := invokeApplicationRouteHandler(t, handler, "POST", "/api/v1/sites/1/application-route-rules", param.Params{{Key: "id", Value: "1"}}, map[string]any{
		"name":       "disabled method",
		"enabled":    false,
		"priority":   10,
		"target":     store.AppRouteTargetRequestMethod,
		"op":         store.AppRouteOpEq,
		"pattern":    "DELETE",
		"header_key": "",
	})
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp store.ApplicationRouteRule
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Enabled {
		t.Fatalf("expected explicit enabled false in response: %#v", resp)
	}
	stored, err := ruleRepo.Get(resp.ID)
	if err != nil {
		t.Fatalf("load stored rule: %v", err)
	}
	if stored.Enabled {
		t.Fatalf("expected explicit enabled false in storage: %#v", stored)
	}
}

func TestUpdateApplicationRouteRuleKeepsEnabledWhenOmitted(t *testing.T) {
	siteRepo, ruleRepo := newApplicationRouteReposForTest(t)
	seed := &store.ApplicationRouteRule{
		SiteID:   1,
		Name:     "disabled rule",
		Enabled:  false,
		Priority: 1,
		Target:   store.AppRouteTargetRequestMethod,
		Op:       store.AppRouteOpEq,
		Pattern:  "POST",
	}
	if err := ruleRepo.Create(seed); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	seed.Enabled = false
	if err := ruleRepo.Update(seed); err != nil {
		t.Fatalf("disable seeded rule: %v", err)
	}
	handler := UpdateApplicationRouteRule(siteRepo, ruleRepo, func() error { return nil })

	ctx := invokeApplicationRouteHandler(t, handler, "POST", "/api/v1/sites/1/application-route-rules/1/update", param.Params{
		{Key: "id", Value: "1"},
		{Key: "rid", Value: "1"},
	}, map[string]any{
		"name":       "still disabled",
		"priority":   2,
		"target":     store.AppRouteTargetRequestMethod,
		"op":         store.AppRouteOpEq,
		"pattern":    "PUT",
		"header_key": "",
	})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp store.ApplicationRouteRule
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Enabled {
		t.Fatalf("expected omitted enabled to keep existing false in response: %#v", resp)
	}
	stored, err := ruleRepo.Get(seed.ID)
	if err != nil {
		t.Fatalf("load stored rule: %v", err)
	}
	if stored.Enabled {
		t.Fatalf("expected omitted enabled to keep existing false in storage: %#v", stored)
	}
}

func TestUpdateApplicationRouteRuleHonorsExplicitDisabled(t *testing.T) {
	siteRepo, ruleRepo := newApplicationRouteReposForTest(t)
	seed := &store.ApplicationRouteRule{
		SiteID:   1,
		Name:     "enabled rule",
		Enabled:  true,
		Priority: 1,
		Target:   store.AppRouteTargetRequestMethod,
		Op:       store.AppRouteOpEq,
		Pattern:  "GET",
	}
	if err := ruleRepo.Create(seed); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	handler := UpdateApplicationRouteRule(siteRepo, ruleRepo, func() error { return nil })

	ctx := invokeApplicationRouteHandler(t, handler, "POST", "/api/v1/sites/1/application-route-rules/1/update", param.Params{
		{Key: "id", Value: "1"},
		{Key: "rid", Value: "1"},
	}, map[string]any{
		"name":       "disabled by request",
		"enabled":    false,
		"priority":   3,
		"target":     store.AppRouteTargetRequestMethod,
		"op":         store.AppRouteOpEq,
		"pattern":    "PATCH",
		"header_key": "",
	})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp store.ApplicationRouteRule
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Enabled {
		t.Fatalf("expected explicit enabled false in response: %#v", resp)
	}
	stored, err := ruleRepo.Get(seed.ID)
	if err != nil {
		t.Fatalf("load stored rule: %v", err)
	}
	if stored.Enabled {
		t.Fatalf("expected explicit enabled false in storage: %#v", stored)
	}
}
