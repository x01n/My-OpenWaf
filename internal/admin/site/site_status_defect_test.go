package site

import (
	"bytes"
	"testing"

	"My-OpenWaf/internal/store"
)

/**
 * 【缺陷复现测试 — 当前会失败】
 *
 * 缺陷位置：internal/admin/site/site.go
 *   - StartSite (404-433) / StopSite (435-464) 写入进程级全局 siteStatusMap
 *   - GetSiteStatus (466-497) 优先读取 siteStatusMap，仅在缺失时才回退到 site.Enabled
 *
 * 问题：siteStatusMap 是 StartSite/StopSite 独占维护的缓存，
 * UpdateSite 与 DeleteSite 都不会让它失效。因此站点通过常规「站点编辑」
 * 接口（POST /sites/:id/update，携带 enabled 字段）被停用后，
 * GET /sites/:id/status 仍会返回上一次 start 写入的 "running"，
 * 与数据库中的 enabled=false 不一致。前端 sitesApi.getStatus
 * （frontend/lib/api.ts:211）消费该接口，会显示错误的运行状态。
 *
 * 复现步骤：POST /sites/:id/start -> POST /sites/:id/update {"enabled":false}
 * -> GET /sites/:id/status，期望 "stopped"，实际返回 "running"。
 *
 * 建议修复（三选一，由主代理决策）：
 *   1. 直接删除 siteStatusMap，GetSiteStatus 一律由 site.Enabled 推导
 *      （该 map 与 Enabled 完全冗余，且是进程级状态，多实例部署下本就不可靠）；
 *   2. 在 UpdateSite 成功后同步写入 siteStatusMap，并在 DeleteSite 成功后
 *      删除对应条目（同时可修掉 map 随删除站点无限增长的问题）；
 *   3. 保留缓存但降低其优先级，仅当与 site.Enabled 一致时才采用。
 */
func TestGetSiteStatusFollowsEnabledFlagAfterUpdateSite(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{ID: 8500, Host: "status-stale.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	if ctx := invokeSiteRouteHandler(t, StartSite(repo, func() error { return nil }), "POST", "/api/v1/sites/8500/start", idParams("8500"), nil); ctx.Response.StatusCode() != 200 {
		t.Fatalf("start failed: %d %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID, []byte(`{"enabled":false}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("update failed: %d %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.Enabled {
		t.Fatalf("precondition broken: update did not persist enabled=false")
	}

	if got := readSiteStatus(t, repo, "8500"); got != "stopped" {
		t.Fatalf("status = %q, want %q（siteStatusMap 未随 UpdateSite 失效，状态接口返回了陈旧值）", got, "stopped")
	}
}
