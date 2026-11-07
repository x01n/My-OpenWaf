package site

import (
	"testing"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// seedDynamicOverrideSite 造一个「站点覆盖了动态保护 JS 模式与路径」的站点。
func seedDynamicOverrideSite(t *testing.T, repo *repository.SiteRepo) *store.Site {
	t.Helper()
	enabled := true
	item := &store.Site{
		Host:             "dynamic-inherit.example",
		UpstreamURLs:     "http://127.0.0.1:8080",
		Bind:             ":8080",
		Network:          "tcp",
		Enabled:          true,
		DynamicJSEnabled: &enabled,
		DynamicJSMode:    "paths",
		DynamicJSPaths:   `["/a.js","/b.js"]`,
	}
	if err := repo.Create(item); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	return item
}

/**
 * TestUpdateSiteClearsDynamicJSModeWhenJSOverridesInherited 锁定动态保护从属字段的清理。
 *
 * `dynamic_js_mode` 与 `dynamic_js_paths` 是 store.Site 上的值类型字段，
 * 与 `dynamic_js_enabled`（*bool）组成「父开关 + 从属字段」结构。
 * 当请求把父开关置回「继承全局」（`dynamic_js_enabled: null`）时，
 * 从属字段必须一并清空——否则快照构建期 `if site.DynamicJSMode != ""`
 * 仍会把遗留的 "paths" 当成站点覆盖，覆盖掉全局的 JS 模式。
 *
 * 这与 `clearInheritedProtectionOverrides` 对 Bot/OWASP/CVE/RateLimit
 * 四组的既有处理口径一致（见 internal/store/site.go 的同族字段）。
 */
func TestUpdateSiteClearsDynamicJSModeWhenJSOverridesInherited(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := seedDynamicOverrideSite(t, repo)

	// 模拟「切回继承全局」的部分更新：父开关显式 null，从属字段未提供。
	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID,
		[]byte(`{"dynamic_js_enabled":null}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("update status = %d, body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.DynamicJSEnabled != nil {
		t.Fatalf("dynamic_js_enabled = %v, want nil (inherit)", *loaded.DynamicJSEnabled)
	}
	if loaded.DynamicJSMode != "" {
		t.Fatalf("dynamic_js_mode = %q, want empty after inheriting global JS mode", loaded.DynamicJSMode)
	}
	if loaded.DynamicJSPaths != "" {
		t.Fatalf("dynamic_js_paths = %q, want empty after inheriting global JS paths", loaded.DynamicJSPaths)
	}
}

/**
 * TestUpdateSiteDynamicNullModeIsNotSilentlyIgnored 锁定 `dynamic_js_mode: null` 的语义。
 *
 * 值类型 string 遇 JSON null 时 encoding/json 不做任何赋值（非 no-op 的只有
 * Pointer/Interface/Map/Slice），因此 null 与「字段缺省」在绑定层不可区分。
 * 站点级覆盖契约要求 null 表示「取消覆盖」，此处必须与同族指针字段一致。
 */
func TestUpdateSiteDynamicNullModeIsNotSilentlyIgnored(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := seedDynamicOverrideSite(t, repo)

	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID,
		[]byte(`{"dynamic_js_enabled":null,"dynamic_js_mode":null,"dynamic_js_paths":null}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("update status = %d, body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.DynamicJSMode != "" {
		t.Fatalf("dynamic_js_mode = %q, want empty for an explicit null (tri-state reset)", loaded.DynamicJSMode)
	}
	if loaded.DynamicJSPaths != "" {
		t.Fatalf("dynamic_js_paths = %q, want empty for an explicit null", loaded.DynamicJSPaths)
	}
}

/**
 * TestUpdateSiteKeepsDynamicOverridesWhenJSEnabled 确认清理只作用于「继承」分支，
 * 站点级覆盖仍然原样保留。
 */
func TestUpdateSiteKeepsDynamicOverridesWhenJSEnabled(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := seedDynamicOverrideSite(t, repo)

	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID,
		[]byte(`{"dynamic_protection_enabled":true}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("update status = %d, body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.DynamicJSMode != "paths" {
		t.Fatalf("dynamic_js_mode = %q, want %q — 覆盖值不得被误清", loaded.DynamicJSMode, "paths")
	}
	if loaded.DynamicJSPaths != `["/a.js","/b.js"]` {
		t.Fatalf("dynamic_js_paths = %q, want 原值保留", loaded.DynamicJSPaths)
	}
}
