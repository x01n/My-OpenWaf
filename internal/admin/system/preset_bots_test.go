package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"My-OpenWaf/internal/store"
)

func TestListPresetBotWhitelistReturnsAllEntries(t *testing.T) {
	ctx := invokeThreatIntelHandler(t, ListPresetBotWhitelist(), "GET", "/api/v1/preset-bot-whitelist", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("list status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp struct {
		Items []struct {
			Value string `json:"value"`
			Note  string `json:"note"`
		} `json:"items"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode preset list: %v", err)
	}
	if resp.Total != len(presetBotEntries) || len(resp.Items) != len(presetBotEntries) {
		t.Fatalf("preset list = total %d len %d, want %d", resp.Total, len(resp.Items), len(presetBotEntries))
	}
	for i, item := range resp.Items {
		if item.Value != presetBotEntries[i].Value || item.Note != presetBotEntries[i].Note {
			t.Fatalf("preset item %d = %#v, want %#v", i, item, presetBotEntries[i])
		}
		if item.Value == "" || item.Note == "" {
			t.Fatalf("preset item %d has an empty field: %#v", i, item)
		}
	}
	// 预览接口不得写库，因此不注入 "[预置]" 前缀。
	if strings.Contains(string(ctx.Response.Body()), "[预置]") {
		t.Fatalf("preview response should carry raw notes without the seed prefix")
	}
}

func TestSeedBotWhitelistAddsThenSkipsOnSecondRun(t *testing.T) {
	repo := newIPListRepoForTest(t)
	reloadCount := 0
	reload := func() error {
		reloadCount++
		return nil
	}

	first := invokeThreatIntelHandler(t, SeedBotWhitelist(repo, reload), "POST", "/api/v1/preset-bot-whitelist/seed", nil, nil)
	if first.Response.StatusCode() != 200 {
		t.Fatalf("first seed status %d: %s", first.Response.StatusCode(), bytes.TrimSpace(first.Response.Body()))
	}
	var firstResp SeedBotWhitelistResp
	if err := json.Unmarshal(first.Response.Body(), &firstResp); err != nil {
		t.Fatalf("decode first seed response: %v", err)
	}
	if firstResp.Added != len(presetBotEntries) || firstResp.Skipped != 0 {
		t.Fatalf("first seed = added %d skipped %d, want added %d skipped 0", firstResp.Added, firstResp.Skipped, len(presetBotEntries))
	}
	if len(firstResp.Entries) != len(presetBotEntries) {
		t.Fatalf("first seed entries = %d, want %d", len(firstResp.Entries), len(presetBotEntries))
	}
	if reloadCount != 1 {
		t.Fatalf("reload count after first seed = %d, want 1", reloadCount)
	}

	items, total, err := repo.List(0, 500, string(store.IPListWhite), nil)
	if err != nil {
		t.Fatalf("list seeded entries: %v", err)
	}
	if int(total) != len(presetBotEntries) {
		t.Fatalf("seeded whitelist total = %d, want %d", total, len(presetBotEntries))
	}
	for _, item := range items {
		if item.Kind != store.IPListWhite || !item.Enabled || item.Action != "intercept" {
			t.Fatalf("seeded entry = %#v, want enabled whitelist/intercept", item)
		}
		if !strings.HasPrefix(item.Note, "[预置] ") {
			t.Fatalf("seeded entry note = %q, want the [预置] prefix", item.Note)
		}
		if item.SiteID != nil {
			t.Fatalf("seeded entry must be global, got site_id %v", *item.SiteID)
		}
	}

	// 二次执行必须幂等：全部跳过且不重复插入。
	second := invokeThreatIntelHandler(t, SeedBotWhitelist(repo, reload), "POST", "/api/v1/preset-bot-whitelist/seed", nil, nil)
	if second.Response.StatusCode() != 200 {
		t.Fatalf("second seed status %d: %s", second.Response.StatusCode(), bytes.TrimSpace(second.Response.Body()))
	}
	var secondResp SeedBotWhitelistResp
	if err := json.Unmarshal(second.Response.Body(), &secondResp); err != nil {
		t.Fatalf("decode second seed response: %v", err)
	}
	if secondResp.Added != 0 || secondResp.Skipped != len(presetBotEntries) {
		t.Fatalf("second seed = added %d skipped %d, want added 0 skipped %d", secondResp.Added, secondResp.Skipped, len(presetBotEntries))
	}
	if reloadCount != 2 {
		t.Fatalf("reload count after second seed = %d, want 2", reloadCount)
	}

	_, totalAfter, err := repo.List(0, 500, string(store.IPListWhite), nil)
	if err != nil {
		t.Fatalf("list entries after second seed: %v", err)
	}
	if totalAfter != total {
		t.Fatalf("whitelist total changed on re-seed: %d -> %d", total, totalAfter)
	}
}

func TestSeedBotWhitelistSkipsOnlyMatchingWhitelistValues(t *testing.T) {
	repo := newIPListRepoForTest(t)
	// 同值但 kind 为黑名单，不应被判为已存在。
	if err := repo.Create(&store.IPListEntry{Kind: store.IPListBlack, Value: presetBotEntries[0].Value, Enabled: true, Action: "intercept"}); err != nil {
		t.Fatalf("seed conflicting blacklist entry: %v", err)
	}

	ctx := invokeThreatIntelHandler(t, SeedBotWhitelist(repo, func() error { return nil }), "POST", "/api/v1/preset-bot-whitelist/seed", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("seed status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp SeedBotWhitelistResp
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode seed response: %v", err)
	}
	if resp.Added != len(presetBotEntries) || resp.Skipped != 0 {
		t.Fatalf("blacklist entry must not suppress whitelist seeding: added %d skipped %d", resp.Added, resp.Skipped)
	}
}

func TestSeedBotWhitelistReportsReloadFailureWithPartialResult(t *testing.T) {
	repo := newIPListRepoForTest(t)

	ctx := invokeThreatIntelHandler(t, SeedBotWhitelist(repo, func() error { return errors.New("reload boom") }), "POST", "/api/v1/preset-bot-whitelist/seed", nil, nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("reload failure status = %d, want 500", ctx.Response.StatusCode())
	}

	var resp struct {
		Error  string               `json:"error"`
		Result SeedBotWhitelistResp `json:"result"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode reload failure response: %v", err)
	}
	if !strings.Contains(resp.Error, "reload failed") || !strings.Contains(resp.Error, "reload boom") {
		t.Fatalf("error = %q, want it to surface the reload failure", resp.Error)
	}
	if resp.Result.Added != len(presetBotEntries) {
		t.Fatalf("partial result added = %d, want %d", resp.Result.Added, len(presetBotEntries))
	}

	// 条目已写入，只有 reload 失败，管理员可重试。
	_, total, err := repo.List(0, 500, string(store.IPListWhite), nil)
	if err != nil {
		t.Fatalf("list entries: %v", err)
	}
	if int(total) != len(presetBotEntries) {
		t.Fatalf("entries persisted = %d, want %d even when reload fails", total, len(presetBotEntries))
	}
}
