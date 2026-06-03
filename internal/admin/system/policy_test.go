package system

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

func newPolicyRepoForTest(t *testing.T) *repository.PolicyRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Policy{}); err != nil {
		t.Fatalf("migrate policies: %v", err)
	}
	return repository.NewPolicyRepo(db)
}

func invokePolicyHandler(t *testing.T, handler app.HandlerFunc, method, uri string, params param.Params, payload []byte) *app.RequestContext {
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

func TestPolicyDescriptionPersistsAcrossCreateUpdateGetList(t *testing.T) {
	repo := newPolicyRepoForTest(t)
	reloadCount := 0

	createCtx := invokePolicyHandler(t, CreatePolicy(repo, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/policies", nil, []byte(`{"name":"default policy","description":"core site"}`))
	if createCtx.Response.StatusCode() != 201 {
		t.Fatalf("unexpected create status %d: %s", createCtx.Response.StatusCode(), bytes.TrimSpace(createCtx.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload count after create = %d, want 1", reloadCount)
	}

	var created store.Policy
	if err := json.Unmarshal(createCtx.Response.Body(), &created); err != nil {
		t.Fatalf("decode created policy: %v", err)
	}
	if created.Description != "core site" {
		t.Fatalf("created policy description = %q, want %q", created.Description, "core site")
	}

	idParam := param.Params{{Key: "id", Value: strconv.FormatUint(uint64(created.ID), 10)}}
	updateCtx := invokePolicyHandler(t, UpdatePolicy(repo, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/policies/"+strconv.FormatUint(uint64(created.ID), 10)+"/update", idParam, []byte(`{"name":"default policy","description":"updated detail"}`))
	if updateCtx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected update status %d: %s", updateCtx.Response.StatusCode(), bytes.TrimSpace(updateCtx.Response.Body()))
	}
	if reloadCount != 2 {
		t.Fatalf("reload count after update = %d, want 2", reloadCount)
	}

	var updated store.Policy
	if err := json.Unmarshal(updateCtx.Response.Body(), &updated); err != nil {
		t.Fatalf("decode updated policy: %v", err)
	}
	if updated.Description != "updated detail" {
		t.Fatalf("updated policy description = %q, want %q", updated.Description, "updated detail")
	}

	getCtx := invokePolicyHandler(t, GetPolicy(repo), "GET", "/api/v1/policies/"+strconv.FormatUint(uint64(created.ID), 10), idParam, nil)
	if getCtx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected get status %d: %s", getCtx.Response.StatusCode(), bytes.TrimSpace(getCtx.Response.Body()))
	}
	var got store.Policy
	if err := json.Unmarshal(getCtx.Response.Body(), &got); err != nil {
		t.Fatalf("decode policy detail: %v", err)
	}
	if got.Description != "updated detail" {
		t.Fatalf("detail policy description = %q, want %q", got.Description, "updated detail")
	}

	listCtx := invokePolicyHandler(t, ListPolicies(repo), "GET", "/api/v1/policies?page=1&page_size=20", nil, nil)
	if listCtx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected list status %d: %s", listCtx.Response.StatusCode(), bytes.TrimSpace(listCtx.Response.Body()))
	}
	var listResp struct {
		Items []store.Policy `json:"items"`
		Total int64          `json:"total"`
	}
	if err := json.Unmarshal(listCtx.Response.Body(), &listResp); err != nil {
		t.Fatalf("decode policy list: %v", err)
	}
	if listResp.Total != 1 || len(listResp.Items) != 1 {
		t.Fatalf("policy list size = total %d len %d, want 1", listResp.Total, len(listResp.Items))
	}
	if listResp.Items[0].Description != "updated detail" {
		t.Fatalf("list policy description = %q, want %q", listResp.Items[0].Description, "updated detail")
	}
}
