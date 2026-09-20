package system

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/cloudwego/hertz/pkg/route/param"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

/*
本文件中的测试用于复现生产代码缺陷，当前预期为失败。修复生产代码后即应转绿。

缺陷 C —— 威胁情报订阅源的新建/更新不触发 reload：
  internal/admin/system/threat_intel.go:43 (CreateThreatIntelFeed) 与 :82 (UpdateThreatIntelFeed)
  都接收 reload 参数，internal/admin/router.go:231-232 也确实注入了 reload，
  但两个 handler 的函数体从未调用它；同文件的 DeleteThreatIntelFeed(:167) 调用了。
  后果：新建订阅源或切换 enabled/kind/action 后，snapshot 与 IP 名单运行态不会即时刷新，
  要等到下一次定时同步或其他配置变更顺带 reload 才生效。
  这违反 CLAUDE.md “Configuration mutations must trigger the injected reload path”。
  建议修复：在两个 handler 写库成功后、返回响应前调用 reload()，
  并沿用同包既有的失败处理风格（500 + "config applied but reload failed: "）。

缺陷 D —— site_id 显式传 null 无法把条目改回全局作用域：
  internal/admin/system/iplist.go:106 与 internal/admin/system/threat_intel.go:101
  用 `SiteID **uint` 表达“未提供 / 显式 null / 具体值”三态，
  但 JSON 反序列化遇到 null 时会把最外层指针直接置为 nil，
  于是“显式 null”与“字段缺省”不可区分，handler 的 `if body.SiteID != nil` 判定为 false。
  后果：站点级 IP 条目与订阅源一旦绑定 site_id，就无法通过 update 接口改回全局。
  建议修复：改用 json.RawMessage 或自定义类型区分两种情况，
  例如 `SiteID json.RawMessage` 后按 `bytes.Equal(raw, []byte("null"))` 判空。
*/

func TestDefectCreateThreatIntelFeedDoesNotReload(t *testing.T) {
	repo := repository.NewThreatIntelRepo(newThreatIntelDBForTest(t))
	reloadCount := 0

	ctx := invokeThreatIntelHandler(t, CreateThreatIntelFeed(repo, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/threat-intel-feeds", nil,
		[]byte(`{"name":"reload-check","url":"https://intel.example.test/list.txt","kind":"blacklist","enabled":true}`))
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("create status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload count = %d, want 1; creating a feed must refresh the snapshot", reloadCount)
	}
}

func TestDefectUpdateThreatIntelFeedDoesNotReload(t *testing.T) {
	repo := repository.NewThreatIntelRepo(newThreatIntelDBForTest(t))
	seed := &store.ThreatIntelFeed{Name: "toggle", URL: "https://intel.example.test/t.txt", Kind: "blacklist", Action: "intercept", Enabled: true, SyncInterval: 3600}
	if err := repo.Create(seed); err != nil {
		t.Fatalf("seed feed: %v", err)
	}
	idStr := strconv.FormatUint(uint64(seed.ID), 10)
	reloadCount := 0

	ctx := invokeThreatIntelHandler(t, UpdateThreatIntelFeed(repo, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/threat-intel-feeds/"+idStr+"/update", param.Params{{Key: "id", Value: idStr}}, []byte(`{"enabled":false}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("update status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload count = %d, want 1; disabling a feed must refresh the snapshot", reloadCount)
	}
}

func TestDefectUpdateIPEntryCannotClearSiteScope(t *testing.T) {
	repo := newIPListRepoForTest(t)
	siteID := uint(12)
	item := &store.IPListEntry{Kind: store.IPListBlack, Value: "192.0.2.77", Enabled: true, Action: "intercept", SiteID: &siteID}
	if err := repo.Create(item); err != nil {
		t.Fatalf("seed scoped entry: %v", err)
	}
	idStr := strconv.FormatUint(uint64(item.ID), 10)

	ctx := invokeThreatIntelHandler(t, UpdateIPEntry(repo, func() error { return nil }),
		"POST", "/api/v1/ip-lists/"+idStr+"/update", param.Params{{Key: "id", Value: idStr}}, []byte(`{"site_id":null}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("update status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	got, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load entry: %v", err)
	}
	if got.SiteID != nil {
		t.Fatalf("site_id = %d, want nil after an explicit null; "+
			"the **uint tri-state cannot distinguish an explicit null from an omitted field", *got.SiteID)
	}
}

func TestDefectUpdateThreatIntelFeedCannotClearSiteScope(t *testing.T) {
	repo := repository.NewThreatIntelRepo(newThreatIntelDBForTest(t))
	siteID := uint(5)
	seed := &store.ThreatIntelFeed{Name: "scoped", URL: "https://intel.example.test/s.txt", Kind: "blacklist", Action: "intercept", Enabled: true, SyncInterval: 3600, SiteID: &siteID}
	if err := repo.Create(seed); err != nil {
		t.Fatalf("seed scoped feed: %v", err)
	}
	idStr := strconv.FormatUint(uint64(seed.ID), 10)

	ctx := invokeThreatIntelHandler(t, UpdateThreatIntelFeed(repo, func() error { return nil }),
		"POST", "/api/v1/threat-intel-feeds/"+idStr+"/update", param.Params{{Key: "id", Value: idStr}}, []byte(`{"site_id":null}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("update status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	got, err := repo.Get(seed.ID)
	if err != nil {
		t.Fatalf("load feed: %v", err)
	}
	if got.SiteID != nil {
		t.Fatalf("site_id = %d, want nil after an explicit null; "+
			"the **uint tri-state cannot distinguish an explicit null from an omitted field", *got.SiteID)
	}
}
