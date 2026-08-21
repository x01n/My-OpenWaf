package system

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/core"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

/**
 * TestImportBackupRejectsMissingVersionField 覆盖 version 字段完全缺失的入参。
 *
 * 与 TestImportBackupRejectsVersionZero 的区别在输入形态：那里显式传 "version": 0，
 * 这里 JSON 里根本没有该键，走的是 Go 零值路径。手工裁剪或旧工具导出的备份正是
 * 这种形态，因此两条路径都要挡住，且不得触发 reload。
 */
func TestImportBackupRejectsMissingVersionField(t *testing.T) {
	db := newBackupDBForTest(t)
	reloadCount := 0
	reload := func() error { reloadCount++; return nil }

	// data 里只有 certificates，完全不含 version 键。
	body, err := json.Marshal(map[string]any{
		"data":         map[string]any{"certificates": []any{}},
		"replace_mode": false,
	})
	if err != nil {
		t.Fatalf("encode request body: %v", err)
	}
	ctx := invokeBackupHandler(t, ImportBackup(db, reload), body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("missing version status = %d, want 400; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	respStr := string(bytes.TrimSpace(ctx.Response.Body()))
	if !strings.Contains(respStr, "missing or invalid backup version") {
		t.Fatalf("error message = %q, want 'missing or invalid backup version'", respStr)
	}
	if reloadCount != 0 {
		t.Fatalf("reload called %d times, want 0 when version is missing", reloadCount)
	}
}

/**
 * TestImportBackupRejectsVersionJustAboveMax 覆盖上限的相邻值 BackupVersion+1。
 *
 * TestImportBackupRejectsVersionTooHigh 用的是 +99，挡不住「比较写成 >= 或差一」
 * 这类边界错误。同时断言 reload 未被调用：校验失败时不应扰动运行时快照。
 */
func TestImportBackupRejectsVersionJustAboveMax(t *testing.T) {
	db := newBackupDBForTest(t)
	reloadCount := 0
	reload := func() error { reloadCount++; return nil }

	body, err := json.Marshal(map[string]any{
		"data":         map[string]any{"version": store.BackupVersion + 1},
		"replace_mode": false,
	})
	if err != nil {
		t.Fatalf("encode request body: %v", err)
	}
	ctx := invokeBackupHandler(t, ImportBackup(db, reload), body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("version=%d status = %d, want 400; body=%s", store.BackupVersion+1, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 0 {
		t.Fatalf("reload called %d times, want 0 when version exceeds max", reloadCount)
	}
}

/**
 * TestImportBackupAtMaxVersionRestoresRecords 覆盖恰好等于上限的合法最小备份。
 *
 * version == BackupVersion 必须被接受（上限是闭区间），记录落库，reload 恰好一次，
 * 且响应体计数与入参一致。TestImportBackupCallsReloadOnSuccess 用的是不含任何记录的
 * 空 backup，走不到 upsert 分支，这里带一条证书和一个站点把落库路径也跑通。
 */
func TestImportBackupAtMaxVersionRestoresRecords(t *testing.T) {
	db := newBackupDBForTest(t)
	reloadCount := 0
	reload := func() error { reloadCount++; return nil }

	body, err := json.Marshal(map[string]any{
		"data": map[string]any{
			"version": store.BackupVersion,
			"certificates": []map[string]any{{
				"id":       1,
				"name":     "import.example.test",
				"cert_pem": "imported certificate pem",
				"key_pem":  "imported private key pem",
				"source":   store.CertSourceManual,
			}},
			"sites": []map[string]any{{
				"id":            1,
				"host":          "import.example.test",
				"upstream_urls": "http://127.0.0.1:8080",
				"bind":          ":80",
				"network":       "tcp",
				"enabled":       true,
			}},
		},
		"replace_mode": false,
	})
	if err != nil {
		t.Fatalf("encode request body: %v", err)
	}
	ctx := invokeBackupHandler(t, ImportBackup(db, reload), body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("import status = %d, want 200; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload called %d times, want 1", reloadCount)
	}

	var response struct {
		Status       string `json:"status"`
		Sites        int    `json:"sites"`
		Certificates int    `json:"certificates"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Status != "restored" {
		t.Fatalf("status = %q, want \"restored\"", response.Status)
	}
	if response.Certificates != 1 || response.Sites != 1 {
		t.Fatalf("counts = certificates:%d sites:%d, want 1 and 1", response.Certificates, response.Sites)
	}

	var certCount, siteCount int64
	if err := db.Model(&store.Certificate{}).Count(&certCount).Error; err != nil {
		t.Fatalf("count certificates: %v", err)
	}
	if err := db.Model(&store.Site{}).Count(&siteCount).Error; err != nil {
		t.Fatalf("count sites: %v", err)
	}
	if certCount != 1 || siteCount != 1 {
		t.Fatalf("persisted counts = certificates:%d sites:%d, want 1 and 1", certCount, siteCount)
	}
}

/**
 * TestImportBackupReloadPublishesConfigDiagnostics 验证备份导入后的真实快照重建链路。
 *
 * IP 列表项与无效 OWASP 白名单均由备份导入。reload 回调执行生产链路中的
 * revision bump 与 Runtime.ReloadSnapshot，以确认新快照同时发布两类诊断，且诊断
 * 不泄漏原始配置或备注。
 */
func TestImportBackupReloadPublishesConfigDiagnostics(t *testing.T) {
	db := newBackupDBForTest(t)
	if err := db.AutoMigrate(&store.ConfigRevision{}); err != nil {
		t.Fatalf("migrate reload diagnostics tables: %v", err)
	}

	layer, err := cache.NewLayer()
	if err != nil {
		t.Fatalf("create snapshot cache: %v", err)
	}
	holder := &snapshot.Holder{}
	runtime := &core.Runtime{DB: db, Snapshot: holder, Cache: layer}
	if err := runtime.SetSnapshotDynamicKeyBase(bytes.Repeat([]byte{0x5a}, 32)); err != nil {
		t.Fatalf("set snapshot dynamic key base: %v", err)
	}
	reloadCount := 0
	reload := func() error {
		reloadCount++
		if err := store.BumpRevision(db); err != nil {
			return err
		}
		return runtime.ReloadSnapshot()
	}

	invalidIP := "import-sensitive-invalid-ip"
	secretNote := "import-secret-note"
	badWhitelist := `["/private",`
	body, err := json.Marshal(map[string]any{
		"data": map[string]any{
			"version": store.BackupVersion,
			"ip_list_entries": []map[string]any{{
				"id":      901,
				"kind":    store.IPListBlack,
				"value":   invalidIP,
				"note":    secretNote,
				"enabled": true,
				"action":  "intercept",
			}},
			"policy_owasp_rule_configs": []map[string]any{{
				"id":             902,
				"policy_id":      1,
				"builtin_id":     "owasp:test:backup-reload",
				"whitelist_json": badWhitelist,
			}},
		},
		"replace_mode": false,
	})
	if err != nil {
		t.Fatalf("encode request body: %v", err)
	}
	ctx := invokeBackupHandler(t, ImportBackup(db, reload), body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("import status = %d, want 200; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload called %d times, want 1", reloadCount)
	}

	sn := holder.Load()
	if sn == nil {
		t.Fatal("runtime snapshot was not published")
	}
	if sn.Revision != 1 {
		t.Fatalf("snapshot revision = %d, want 1", sn.Revision)
	}
	var foundIP, foundOWASP bool
	for _, diagnostic := range sn.ConfigDiagnostics {
		switch {
		case diagnostic.Kind == "ip_list_entry" &&
			diagnostic.Reason == "invalid_ip_or_cidr" &&
			diagnostic.IPListEntryID == 901 &&
			diagnostic.Scope == "global" &&
			diagnostic.SiteID == 0:
			foundIP = true
		case diagnostic.Kind == "owasp_whitelist" &&
			diagnostic.Reason == "invalid_json" &&
			diagnostic.PolicyID == 1 &&
			diagnostic.RuleID == "owasp:test:backup-reload":
			foundOWASP = true
		}
	}
	if !foundIP || !foundOWASP {
		t.Fatalf("snapshot diagnostics = %#v, want imported IP and OWASP diagnostics", sn.ConfigDiagnostics)
	}
	encoded, err := json.Marshal(sn.ConfigDiagnostics)
	if err != nil {
		t.Fatalf("marshal snapshot diagnostics: %v", err)
	}
	for _, raw := range []string{invalidIP, secretNote, badWhitelist} {
		if bytes.Contains(encoded, []byte(raw)) {
			t.Fatalf("snapshot diagnostics contain raw sensitive value %q", raw)
		}
	}
}

/**
 * TestImportBackupSkipsReloadWhenStoreFails 断言 store 层失败时不触发 reload。
 *
 * 构造手段是让 default_policy_id 指向一个未随备份导入的策略：ImportBackup 会在事务内
 * 校验该引用并整体回滚。此时应返回 500 且 reload 一次都不调用，否则会把一个已回滚的
 * 事务当成配置变更推给运行时。
 */
func TestImportBackupSkipsReloadWhenStoreFails(t *testing.T) {
	db := newBackupDBForTest(t)
	reloadCount := 0
	reload := func() error { reloadCount++; return nil }

	body, err := json.Marshal(map[string]any{
		"data": map[string]any{
			"version":           store.BackupVersion,
			"default_policy_id": 4242,
		},
		"replace_mode": false,
	})
	if err != nil {
		t.Fatalf("encode request body: %v", err)
	}
	ctx := invokeBackupHandler(t, ImportBackup(db, reload), body)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("status = %d, want 500; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 0 {
		t.Fatalf("reload called %d times, want 0 when import fails", reloadCount)
	}
	// 失败详情只进服务端日志，响应体不得回带底层错误文本。
	respStr := string(bytes.TrimSpace(ctx.Response.Body()))
	if !strings.Contains(respStr, "import failed, check server logs for details") {
		t.Fatalf("error message = %q, want generic import failure message", respStr)
	}
}

func TestImportBackupRejectsEnabledResponseJSPluginWithoutReload(t *testing.T) {
	db := newBackupDBForTest(t)
	reloadCount := 0
	reload := func() error { reloadCount++; return nil }

	body, err := json.Marshal(map[string]any{
		"data": map[string]any{
			"version": store.BackupVersion,
			"js_plugins": []map[string]any{{
				"name":         "enabled-response",
				"source":       "function handle(ctx) { return null; }",
				"enabled":      true,
				"stage":        store.JSStageResponse,
				"failure_mode": store.JSFailureModeOpen,
			}},
		},
		"replace_mode": true,
	})
	if err != nil {
		t.Fatalf("encode request body: %v", err)
	}

	ctx := invokeBackupHandler(t, ImportBackup(db, reload), body)
	if ctx.Response.StatusCode() != 400 || !bytes.Contains(ctx.Response.Body(), []byte("response stage is unavailable because response execution is not implemented")) {
		t.Fatalf("response = %d %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if reloadCount != 0 {
		t.Fatalf("reload called %d times after rejected JavaScript plugin backup", reloadCount)
	}
}
