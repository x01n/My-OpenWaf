package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/cloudwego/hertz/pkg/route/param"

	"My-OpenWaf/internal/store"
)

func TestListIPEntriesFiltersByKindAndSite(t *testing.T) {
	repo := newIPListRepoForTest(t)
	siteID := uint(7)
	seed := []store.IPListEntry{
		{Kind: store.IPListBlack, Value: "198.51.100.1", Enabled: true, Action: "intercept"},
		{Kind: store.IPListWhite, Value: "198.51.100.2", Enabled: true, Action: "intercept"},
		{Kind: store.IPListBlack, Value: "198.51.100.3", Enabled: true, Action: "drop", SiteID: &siteID},
	}
	for i := range seed {
		if err := repo.Create(&seed[i]); err != nil {
			t.Fatalf("seed entry %d: %v", i, err)
		}
	}

	type listResp struct {
		Items []store.IPListEntry `json:"items"`
		Total int64               `json:"total"`
		Page  int                 `json:"page"`
	}
	decode := func(t *testing.T, uri string) listResp {
		t.Helper()
		ctx := invokeThreatIntelHandler(t, ListIPEntries(repo), "GET", uri, nil, nil)
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("list status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		var resp listResp
		if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
			t.Fatalf("decode ip list: %v", err)
		}
		return resp
	}

	// 不带 site_id 时仅返回全局条目（site_id IS NULL）。
	global := decode(t, "/api/v1/ip-lists")
	if global.Total != 2 {
		t.Fatalf("global total = %d, want 2", global.Total)
	}

	blackOnly := decode(t, "/api/v1/ip-lists?kind=blacklist")
	if blackOnly.Total != 1 || blackOnly.Items[0].Value != "198.51.100.1" {
		t.Fatalf("blacklist filter = %#v, want the single global blacklist entry", blackOnly.Items)
	}

	bySite := decode(t, "/api/v1/ip-lists?site_id=7")
	if bySite.Total != 1 || bySite.Items[0].Value != "198.51.100.3" {
		t.Fatalf("site filter = %#v, want the site-scoped entry", bySite.Items)
	}

	// 非法 site_id 被忽略，回落到全局范围。
	badSite := decode(t, "/api/v1/ip-lists?site_id=abc")
	if badSite.Total != 2 {
		t.Fatalf("invalid site_id total = %d, want 2 (filter ignored)", badSite.Total)
	}

	paged := decode(t, "/api/v1/ip-lists?page=2&page_size=1")
	if paged.Total != 2 || len(paged.Items) != 1 || paged.Page != 2 {
		t.Fatalf("paged list = total %d len %d page %d, want 2/1/2", paged.Total, len(paged.Items), paged.Page)
	}
}

func TestGetIPEntryReturnsEntryAndValidatesID(t *testing.T) {
	repo := newIPListRepoForTest(t)
	item := seedIPListEntry(t, repo)
	idStr := strconv.FormatUint(uint64(item.ID), 10)

	ok := invokeThreatIntelHandler(t, GetIPEntry(repo), "GET", "/api/v1/ip-lists/"+idStr, param.Params{{Key: "id", Value: idStr}}, nil)
	if ok.Response.StatusCode() != 200 {
		t.Fatalf("get status %d: %s", ok.Response.StatusCode(), bytes.TrimSpace(ok.Response.Body()))
	}
	var got store.IPListEntry
	if err := json.Unmarshal(ok.Response.Body(), &got); err != nil {
		t.Fatalf("decode ip entry: %v", err)
	}
	if got.ID != item.ID || got.Value != "192.0.2.10" || got.Action != "drop" {
		t.Fatalf("ip entry = %#v, want the seeded entry", got)
	}

	badID := invokeThreatIntelHandler(t, GetIPEntry(repo), "GET", "/api/v1/ip-lists/nan", param.Params{{Key: "id", Value: "nan"}}, nil)
	if badID.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d, want 400", badID.Response.StatusCode())
	}

	missing := invokeThreatIntelHandler(t, GetIPEntry(repo), "GET", "/api/v1/ip-lists/4242", param.Params{{Key: "id", Value: "4242"}}, nil)
	if missing.Response.StatusCode() != 404 {
		t.Fatalf("missing entry status = %d, want 404", missing.Response.StatusCode())
	}
}

func TestCreateIPEntryNormalizesActionAndReloads(t *testing.T) {
	repo := newIPListRepoForTest(t)
	reloadCount := 0

	ctx := invokeThreatIntelHandler(t, CreateIPEntry(repo, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/ip-lists", nil, []byte(`{"kind":"blacklist","value":"203.0.113.0/24","note":"scanner","action":"block"}`))
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("create status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload count = %d, want 1", reloadCount)
	}

	var created store.IPListEntry
	if err := json.Unmarshal(ctx.Response.Body(), &created); err != nil {
		t.Fatalf("decode created entry: %v", err)
	}
	if created.Action != "drop" {
		t.Fatalf("action = %q, want drop (legacy block normalized)", created.Action)
	}

	stored, err := repo.Get(created.ID)
	if err != nil {
		t.Fatalf("load created entry: %v", err)
	}
	if stored.Value != "203.0.113.0/24" || stored.Note != "scanner" || stored.Kind != store.IPListBlack {
		t.Fatalf("stored entry = %#v", stored)
	}
}

func TestCreateIPEntryRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{name: "invalid kind", payload: `{"kind":"greylist","value":"203.0.113.1"}`},
		{name: "missing kind", payload: `{"value":"203.0.113.1"}`},
		{name: "missing value", payload: `{"kind":"blacklist","value":""}`},
		{name: "invalid action", payload: `{"kind":"blacklist","value":"203.0.113.1","action":"challenge"}`},
		{name: "malformed json", payload: `{"kind":`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newIPListRepoForTest(t)
			reloadCount := 0
			ctx := invokeThreatIntelHandler(t, CreateIPEntry(repo, func() error {
				reloadCount++
				return nil
			}), "POST", "/api/v1/ip-lists", nil, []byte(tt.payload))
			if ctx.Response.StatusCode() != 400 {
				t.Fatalf("status = %d, want 400: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
			if reloadCount != 0 {
				t.Fatalf("rejected create must not reload, got %d calls", reloadCount)
			}
			_, total, err := repo.List(0, 100, "", nil)
			if err != nil {
				t.Fatalf("list entries: %v", err)
			}
			if total != 0 {
				t.Fatalf("rejected create must not persist an entry, got %d", total)
			}
		})
	}
}

func TestCreateIPEntryReportsReloadFailure(t *testing.T) {
	repo := newIPListRepoForTest(t)

	ctx := invokeThreatIntelHandler(t, CreateIPEntry(repo, func() error { return errors.New("reload boom") }),
		"POST", "/api/v1/ip-lists", nil, []byte(`{"kind":"whitelist","value":"203.0.113.9"}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("reload failure status = %d, want 500", ctx.Response.StatusCode())
	}
	if !bytes.Contains(ctx.Response.Body(), []byte("reload failed")) {
		t.Fatalf("reload failure body = %s, want it to mention the failure", bytes.TrimSpace(ctx.Response.Body()))
	}
	_, total, err := repo.List(0, 100, "", nil)
	if err != nil {
		t.Fatalf("list entries: %v", err)
	}
	if total != 1 {
		t.Fatalf("entry total = %d, want 1 even when reload fails", total)
	}
}

func TestUpdateIPEntryInvalidIDAndMissingEntry(t *testing.T) {
	repo := newIPListRepoForTest(t)

	badID := invokeThreatIntelHandler(t, UpdateIPEntry(repo, func() error { return nil }),
		"POST", "/api/v1/ip-lists/nan/update", param.Params{{Key: "id", Value: "nan"}}, []byte(`{"enabled":false}`))
	if badID.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d, want 400", badID.Response.StatusCode())
	}

	missing := invokeThreatIntelHandler(t, UpdateIPEntry(repo, func() error { return nil }),
		"POST", "/api/v1/ip-lists/5150/update", param.Params{{Key: "id", Value: "5150"}}, []byte(`{"enabled":false}`))
	if missing.Response.StatusCode() != 404 {
		t.Fatalf("missing entry status = %d, want 404", missing.Response.StatusCode())
	}

	item := seedIPListEntry(t, repo)
	idStr := strconv.FormatUint(uint64(item.ID), 10)
	badBody := invokeThreatIntelHandler(t, UpdateIPEntry(repo, func() error { return nil }),
		"POST", "/api/v1/ip-lists/"+idStr+"/update", param.Params{{Key: "id", Value: idStr}}, []byte(`{"enabled":`))
	if badBody.Response.StatusCode() != 400 {
		t.Fatalf("malformed body status = %d, want 400", badBody.Response.StatusCode())
	}

	badKind := invokeThreatIntelHandler(t, UpdateIPEntry(repo, func() error { return nil }),
		"POST", "/api/v1/ip-lists/"+idStr+"/update", param.Params{{Key: "id", Value: idStr}}, []byte(`{"kind":"greylist"}`))
	if badKind.Response.StatusCode() != 400 {
		t.Fatalf("invalid kind status = %d, want 400", badKind.Response.StatusCode())
	}
}

func TestUpdateIPEntryAppliesSiteScopeAndNote(t *testing.T) {
	repo := newIPListRepoForTest(t)
	item := seedIPListEntry(t, repo)
	idStr := strconv.FormatUint(uint64(item.ID), 10)

	ctx := invokeThreatIntelHandler(t, UpdateIPEntry(repo, func() error { return nil }),
		"POST", "/api/v1/ip-lists/"+idStr+"/update", param.Params{{Key: "id", Value: idStr}}, []byte(`{"site_id":12,"note":"scoped"}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("update status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	got, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load entry: %v", err)
	}
	if got.SiteID == nil || *got.SiteID != 12 {
		t.Fatalf("site_id = %v, want 12", got.SiteID)
	}
	if got.Note != "scoped" {
		t.Fatalf("note = %q, want scoped", got.Note)
	}

	// 省略 site_id 的后续更新不得改变已有作用域。
	keep := invokeThreatIntelHandler(t, UpdateIPEntry(repo, func() error { return nil }),
		"POST", "/api/v1/ip-lists/"+idStr+"/update", param.Params{{Key: "id", Value: idStr}}, []byte(`{"note":"still scoped"}`))
	if keep.Response.StatusCode() != 200 {
		t.Fatalf("omitted site_id status %d: %s", keep.Response.StatusCode(), bytes.TrimSpace(keep.Response.Body()))
	}
	kept, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load entry: %v", err)
	}
	if kept.SiteID == nil || *kept.SiteID != 12 {
		t.Fatalf("site_id = %v, want 12 preserved when omitted", kept.SiteID)
	}
}

func TestDeleteIPEntryRemovesEntryAndReloads(t *testing.T) {
	repo := newIPListRepoForTest(t)
	item := seedIPListEntry(t, repo)
	idStr := strconv.FormatUint(uint64(item.ID), 10)

	reloadCount := 0
	ctx := invokeThreatIntelHandler(t, DeleteIPEntry(repo, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/ip-lists/"+idStr+"/delete", param.Params{{Key: "id", Value: idStr}}, nil)
	if ctx.Response.StatusCode() != 204 {
		t.Fatalf("delete status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload count = %d, want 1", reloadCount)
	}
	if _, err := repo.Get(item.ID); err == nil {
		t.Fatalf("entry should be gone after delete")
	}
}

func TestDeleteIPEntryInvalidIDAndReloadFailure(t *testing.T) {
	repo := newIPListRepoForTest(t)

	badID := invokeThreatIntelHandler(t, DeleteIPEntry(repo, func() error { return nil }),
		"POST", "/api/v1/ip-lists/nan/delete", param.Params{{Key: "id", Value: "nan"}}, nil)
	if badID.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d, want 400", badID.Response.StatusCode())
	}

	item := seedIPListEntry(t, repo)
	idStr := strconv.FormatUint(uint64(item.ID), 10)
	ctx := invokeThreatIntelHandler(t, DeleteIPEntry(repo, func() error { return errors.New("reload boom") }),
		"POST", "/api/v1/ip-lists/"+idStr+"/delete", param.Params{{Key: "id", Value: idStr}}, nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("reload failure status = %d, want 500", ctx.Response.StatusCode())
	}
	if !bytes.Contains(ctx.Response.Body(), []byte("reload failed")) {
		t.Fatalf("reload failure body = %s, want it to mention the failure", bytes.TrimSpace(ctx.Response.Body()))
	}
}
