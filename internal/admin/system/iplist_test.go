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

func newIPListRepoForTest(t *testing.T) *repository.IPListRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.IPListEntry{}); err != nil {
		t.Fatalf("migrate IP list entries: %v", err)
	}
	return repository.NewIPListRepo(db)
}

func invokeIPEntryHandler(t *testing.T, handler app.HandlerFunc, id uint, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/ip-lists/" + strconv.FormatUint(uint64(id), 10) + "/update")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: strconv.FormatUint(uint64(id), 10)}}
	handler(context.Background(), ctx)
	return ctx
}

func seedIPListEntry(t *testing.T, repo *repository.IPListRepo) *store.IPListEntry {
	t.Helper()
	item := &store.IPListEntry{
		Kind:    store.IPListBlack,
		Value:   "192.0.2.10",
		Note:    "keep note",
		Enabled: true,
		Action:  "drop",
	}
	if err := repo.Create(item); err != nil {
		t.Fatalf("create IP list entry: %v", err)
	}
	return item
}

func TestNormalizeIPListAction(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "empty defaults intercept", in: "", want: "intercept", ok: true},
		{name: "intercept", in: "intercept", want: "intercept", ok: true},
		{name: "drop remains canonical", in: "drop", want: "drop", ok: true},
		{name: "legacy block maps drop", in: "block", want: "drop", ok: true},
		{name: "reject challenge", in: "challenge", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalizeIPListAction(tt.in)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("normalizeIPListAction(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestUpdateIPEntryPreservesOmittedFields(t *testing.T) {
	repo := newIPListRepoForTest(t)
	item := seedIPListEntry(t, repo)
	reloaded := false

	ctx := invokeIPEntryHandler(t, UpdateIPEntry(repo, func() error {
		reloaded = true
		return nil
	}), item.ID, []byte(`{"enabled":false}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if !reloaded {
		t.Fatalf("reload was not called")
	}

	got, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load IP list entry: %v", err)
	}
	if got.Enabled {
		t.Fatalf("explicit enabled=false was not saved: %#v", got)
	}
	if got.Kind != store.IPListBlack || got.Value != "192.0.2.10" || got.Note != "keep note" || got.Action != "drop" {
		t.Fatalf("omitted fields should be preserved: %#v", got)
	}

	var resp store.IPListEntry
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response IP list entry: %v", err)
	}
	if resp.Kind != got.Kind || resp.Value != got.Value || resp.Note != got.Note || resp.Action != got.Action || resp.Enabled != got.Enabled {
		t.Fatalf("response should include the saved entry, got %#v want %#v", resp, got)
	}
}

func TestUpdateIPEntryNormalizesExplicitAction(t *testing.T) {
	repo := newIPListRepoForTest(t)
	item := seedIPListEntry(t, repo)

	ctx := invokeIPEntryHandler(t, UpdateIPEntry(repo, func() error { return nil }), item.ID, []byte(`{"action":"block"}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	got, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load IP list entry: %v", err)
	}
	if got.Action != "drop" {
		t.Fatalf("explicit block action should normalize to drop, got %#v", got)
	}
	if got.Kind != store.IPListBlack || got.Value != "192.0.2.10" || got.Note != "keep note" || !got.Enabled {
		t.Fatalf("omitted fields should be preserved when updating action: %#v", got)
	}
}

func TestUpdateIPEntryRejectsInvalidExplicitAction(t *testing.T) {
	repo := newIPListRepoForTest(t)
	item := seedIPListEntry(t, repo)

	ctx := invokeIPEntryHandler(t, UpdateIPEntry(repo, func() error { return nil }), item.ID, []byte(`{"action":"challenge"}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected invalid action to be rejected, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	got, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load IP list entry: %v", err)
	}
	if got.Action != "drop" || got.Kind != store.IPListBlack || got.Value != "192.0.2.10" || got.Note != "keep note" || !got.Enabled {
		t.Fatalf("invalid action should not change the entry: %#v", got)
	}
}

func TestUpdateIPEntryRejectsEmptyExplicitValue(t *testing.T) {
	repo := newIPListRepoForTest(t)
	item := seedIPListEntry(t, repo)

	ctx := invokeIPEntryHandler(t, UpdateIPEntry(repo, func() error { return nil }), item.ID, []byte(`{"value":""}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected empty value to be rejected, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	got, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load IP list entry: %v", err)
	}
	if got.Action != "drop" || got.Kind != store.IPListBlack || got.Value != "192.0.2.10" || got.Note != "keep note" || !got.Enabled {
		t.Fatalf("empty value should not change the entry: %#v", got)
	}
}
