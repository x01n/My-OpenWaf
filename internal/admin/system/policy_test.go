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

func TestDefaultPolicyHandlersAndDeleteIntegrity(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Policy{}, &store.Site{}, &store.Rule{}); err != nil {
		t.Fatalf("migrate policy references: %v", err)
	}
	policyRepo := repository.NewPolicyRepo(db)
	siteRepo := repository.NewSiteRepo(db)
	one := uint(1)
	defaultPolicy := store.Policy{Name: "default", DefaultSlot: &one}
	otherPolicy := store.Policy{Name: "other"}
	if err := db.Create(&defaultPolicy).Error; err != nil {
		t.Fatalf("seed default policy: %v", err)
	}
	if err := db.Create(&otherPolicy).Error; err != nil {
		t.Fatalf("seed other policy: %v", err)
	}
	getCtx := invokePolicyHandler(t, GetDefaultPolicy(policyRepo), "GET", "/api/v1/policies/default", nil, nil)
	if getCtx.Response.StatusCode() != 200 {
		t.Fatalf("get default status %d: %s", getCtx.Response.StatusCode(), getCtx.Response.Body())
	}
	var got store.Policy
	if err := json.Unmarshal(getCtx.Response.Body(), &got); err != nil {
		t.Fatalf("decode default policy: %v", err)
	}
	if got.ID != defaultPolicy.ID || !got.IsDefault {
		t.Fatalf("default policy response = %+v", got)
	}

	defaultID := strconv.FormatUint(uint64(defaultPolicy.ID), 10)
	deleteDefault := invokePolicyHandler(t, DeletePolicy(policyRepo, siteRepo, func() error { return nil }), "POST", "/api/v1/policies/"+defaultID+"/delete", param.Params{{Key: "id", Value: defaultID}}, nil)
	if deleteDefault.Response.StatusCode() != 409 {
		t.Fatalf("delete default status %d: %s", deleteDefault.Response.StatusCode(), deleteDefault.Response.Body())
	}

	rule := store.Rule{Name: "reference", PolicyID: otherPolicy.ID, Phase: store.PhaseCustom, Pattern: "block_path:/blocked", Action: store.ActionIntercept, Enabled: true}
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("seed rule reference: %v", err)
	}
	otherID := strconv.FormatUint(uint64(otherPolicy.ID), 10)
	deleteReferenced := invokePolicyHandler(t, DeletePolicy(policyRepo, siteRepo, func() error { return nil }), "POST", "/api/v1/policies/"+otherID+"/delete", param.Params{{Key: "id", Value: otherID}}, nil)
	if deleteReferenced.Response.StatusCode() != 400 {
		t.Fatalf("delete referenced status %d: %s", deleteReferenced.Response.StatusCode(), deleteReferenced.Response.Body())
	}
	var refs struct {
		RuleRefs int64 `json:"rule_refs"`
	}
	if err := json.Unmarshal(deleteReferenced.Response.Body(), &refs); err != nil {
		t.Fatalf("decode references: %v", err)
	}
	if refs.RuleRefs != 1 {
		t.Fatalf("rule_refs = %d, want 1", refs.RuleRefs)
	}

	if err := db.Delete(&rule).Error; err != nil {
		t.Fatalf("delete rule reference: %v", err)
	}
	reloads := 0
	setCtx := invokePolicyHandler(t, SetDefaultPolicy(policyRepo, func() error {
		reloads++
		return nil
	}), "POST", "/api/v1/policies/"+otherID+"/set-default", param.Params{{Key: "id", Value: otherID}}, nil)
	if setCtx.Response.StatusCode() != 200 || reloads != 1 {
		t.Fatalf("set default status %d reloads %d: %s", setCtx.Response.StatusCode(), reloads, setCtx.Response.Body())
	}
	newDefault, err := policyRepo.GetDefault()
	if err != nil {
		t.Fatalf("load switched default: %v", err)
	}
	if newDefault.ID != otherPolicy.ID || !newDefault.IsDefault {
		t.Fatalf("switched default = %+v", newDefault)
	}
}

func TestSetDefaultReleasesSoftDeletedDefaultSlot(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Policy{}); err != nil {
		t.Fatalf("migrate policies: %v", err)
	}
	one := uint(1)
	deletedDefault := store.Policy{Name: "deleted default", DefaultSlot: &one}
	nextDefault := store.Policy{Name: "next default"}
	if err := db.Create(&deletedDefault).Error; err != nil {
		t.Fatalf("seed deleted default: %v", err)
	}
	if err := db.Create(&nextDefault).Error; err != nil {
		t.Fatalf("seed next default: %v", err)
	}
	if err := db.Delete(&deletedDefault).Error; err != nil {
		t.Fatalf("soft delete default: %v", err)
	}

	repo := repository.NewPolicyRepo(db)
	item, err := repo.SetDefault(nextDefault.ID)
	if err != nil {
		t.Fatalf("set default: %v", err)
	}
	if item.ID != nextDefault.ID || !item.IsDefault {
		t.Fatalf("set default result = %+v", item)
	}
	var deleted store.Policy
	if err := db.Unscoped().First(&deleted, deletedDefault.ID).Error; err != nil {
		t.Fatalf("load deleted policy: %v", err)
	}
	if deleted.DefaultSlot != nil {
		t.Fatalf("deleted default slot = %v, want nil", deleted.DefaultSlot)
	}
}
