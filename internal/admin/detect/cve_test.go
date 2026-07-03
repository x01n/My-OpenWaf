package detect

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/cve"
)

func newCVERuleRepoForTest(t *testing.T) *repository.CVERuleRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&cve.CVERuleModel{}); err != nil {
		t.Fatalf("migrate cve rules: %v", err)
	}
	return repository.NewCVERuleRepo(db)
}

func invokeCVERuleListHandler(t *testing.T, handler app.HandlerFunc, uri string) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI(uri)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}

func TestListCVERulesFiltersByQueryBeforePagination(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	seed := []cve.CVERuleModel{
		{
			CVEID:       "CVE-2024-0001",
			Category:    "general",
			Pattern:     "first",
			Target:      "url",
			Severity:    "low",
			Action:      "intercept",
			Enabled:     true,
			Description: "ordinary rule",
			Source:      "custom",
			Approved:    true,
		},
		{
			CVEID:       "CVE-2026-49975",
			Category:    "general",
			Pattern:     "second",
			Target:      "url",
			Severity:    "critical",
			Action:      "intercept",
			Enabled:     true,
			Description: "Microsoft SharePoint ToolShell exploit detection",
			Source:      "custom",
			Approved:    true,
		},
	}
	for i := range seed {
		if err := repo.Create(&seed[i]); err != nil {
			t.Fatalf("seed cve rule %d: %v", i, err)
		}
	}

	ctx := invokeCVERuleListHandler(
		t,
		ListCVERules(repo),
		"/api/v1/cve-rules?page=1&page_size=1&q=SHAREPOINT",
	)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp struct {
		Items []cve.CVERuleModel `json:"items"`
		Total int64              `json:"total"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 {
		t.Fatalf("total = %d, want 1", resp.Total)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("items len = %d, want 1", len(resp.Items))
	}
	if resp.Items[0].CVEID != "CVE-2026-49975" {
		t.Fatalf("matched cve_id = %q, want %q", resp.Items[0].CVEID, "CVE-2026-49975")
	}
}
