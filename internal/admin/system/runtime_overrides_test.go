package system

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// newRuntimeOverridesRepoForTest 建立仅含系统设置表的内存库。
func newRuntimeOverridesRepoForTest(t *testing.T) *repository.SystemSettingsRepo {
	t.Helper()
	return newRuntimeOverridesRepoWithSitesForTest(t, false)
}

/**
 * newRuntimeOverridesRepoWithSitesForTest 建立内存库，可选地一并迁移站点表。
 *
 * @param withSites 为真时同时迁移 store.Site，供「被站点级覆盖顶掉」的诊断用例使用。
 * @return 绑定该库的系统设置仓储。
 */
func newRuntimeOverridesRepoWithSitesForTest(t *testing.T, withSites bool) *repository.SystemSettingsRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	models := []any{&store.SystemSettings{}}
	if withSites {
		models = append(models, &store.Site{})
	}
	if err := db.AutoMigrate(models...); err != nil {
		t.Fatalf("migrate tables: %v", err)
	}
	return repository.NewSystemSettingsRepo(db)
}

// decodeOverridesResponse 解析端点返回的覆盖清单。
func decodeOverridesResponse(t *testing.T, body []byte) RuntimeConfigOverridesResponse {
	t.Helper()
	var resp RuntimeConfigOverridesResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode response %s: %v", string(body), err)
	}
	return resp
}

// noopReload 是写端点用的空重载：只验证写入与回读，不牵动真实快照。
func noopReload() error { return nil }

/**
 * TestRuntimeConfigOverrideItemFieldNames 断言 items[] 的字段名与契约一致。
 *
 * 前端直接消费 key / env / group / type / default_value / env_value /
 * effective_value / source / overridden / value / sensitive / editable /
 * min / max / label_key / description_key 这 16 个字段名，改名等于让界面读空。
 * 这里直接解 JSON 对象而不是解结构体：解结构体只能证明本包自己的 tag，
 * 无法证明「响应里真的没有 v1 旧字段名」。
 */
func TestRuntimeConfigOverrideItemFieldNames(t *testing.T) {
	repo := newRuntimeOverridesRepoForTest(t)
	ctx := invokeSystemConfigHandler(t, ListRuntimeConfigOverrides(repo, repo.DB()), "GET", "/api/v1/runtime-config/env-overrides", nil)

	var raw struct {
		Groups []map[string]json.RawMessage `json:"groups"`
		Items  []map[string]json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &raw); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(raw.Items) != 45 {
		t.Fatalf("items = %d, want 45", len(raw.Items))
	}
	if len(raw.Groups) != 9 {
		t.Fatalf("groups = %d, want 9", len(raw.Groups))
	}

	wantFields := []string{
		"key", "env", "group", "type", "default_value", "env_value", "effective_value",
		"source", "overridden", "value", "sensitive", "editable", "min", "max",
		"label_key", "description_key",
	}
	retiredFields := []string{"env_name", "domain", "secret"}
	for _, item := range raw.Items {
		key := string(item["key"])
		for _, field := range wantFields {
			if _, ok := item[field]; !ok {
				t.Errorf("item %s is missing field %q", key, field)
			}
		}
		for _, field := range retiredFields {
			if _, ok := item[field]; ok {
				t.Errorf("item %s still carries the retired v1 field %q", key, field)
			}
		}
		// min / max 必须显式出现且是 null 或数字，不能被 omitempty 省掉。
		for _, field := range []string{"min", "max"} {
			value := strings.TrimSpace(string(item[field]))
			if value == "" {
				t.Errorf("item %s field %q is empty", key, field)
			}
			if value != "null" && !json.Valid([]byte(value)) {
				t.Errorf("item %s field %q = %s, want null or a number", key, field, value)
			}
		}
	}
}

/**
 * TestRuntimeConfigOverrideGroupsAndLabels 断言 groups[] 的域与 i18n 键，
 * 以及每个 item 的 label_key / description_key 派生规则。
 */
func TestRuntimeConfigOverrideGroupsAndLabels(t *testing.T) {
	repo := newRuntimeOverridesRepoForTest(t)
	ctx := invokeSystemConfigHandler(t, ListRuntimeConfigOverrides(repo, repo.DB()), "GET", "/api/v1/runtime-config/env-overrides", nil)
	resp := decodeOverridesResponse(t, ctx.Response.Body())

	wantGroups := []string{
		"bootstrap", "network", "detection", "observability", "limits",
		"cache", "queue", "http3", "internal",
	}
	if len(resp.Groups) != len(wantGroups) {
		t.Fatalf("groups = %d, want %d", len(resp.Groups), len(wantGroups))
	}
	for i, group := range resp.Groups {
		if group.Key != wantGroups[i] {
			t.Errorf("groups[%d].key = %q, want %q", i, group.Key, wantGroups[i])
		}
		if group.LabelKey != "envOverrides.group."+wantGroups[i] {
			t.Errorf("groups[%d].label_key = %q", i, group.LabelKey)
		}
	}

	for _, item := range resp.Items {
		if item.LabelKey != "envOverrides.key."+item.Key {
			t.Errorf("item %s label_key = %q", item.Key, item.LabelKey)
		}
		if item.DescriptionKey != "envOverrides.key."+item.Key+".desc" {
			t.Errorf("item %s description_key = %q", item.Key, item.DescriptionKey)
		}
	}
}

/**
 * TestRuntimeConfigOverrideDurationType 断言三个时长键在响应里的 type 是 duration。
 */
func TestRuntimeConfigOverrideDurationType(t *testing.T) {
	repo := newRuntimeOverridesRepoForTest(t)
	ctx := invokeSystemConfigHandler(t, ListRuntimeConfigOverrides(repo, repo.DB()), "GET", "/api/v1/runtime-config/env-overrides", nil)
	resp := decodeOverridesResponse(t, ctx.Response.Body())

	byKey := make(map[string]RuntimeConfigOverrideItem, len(resp.Items))
	for _, item := range resp.Items {
		byKey[item.Key] = item
	}
	for key, wantDefault := range map[string]string{
		"cve_feed_interval":    "6h",
		"queue_flush_interval": "3s",
		"queue_write_interval": "50ms",
	} {
		item, ok := byKey[key]
		if !ok {
			t.Fatalf("key %q is missing from the response", key)
		}
		if item.Type != "duration" {
			t.Errorf("key %q type = %q, want duration", key, item.Type)
		}
		if item.DefaultValue != wantDefault {
			t.Errorf("key %q default_value = %#v, want %q", key, item.DefaultValue, wantDefault)
		}
	}
}

/**
 * TestRuntimeConfigOverrideRestartRequiredReported 断言端点如实回报需重启的键数。
 *
 * 26 个键的取值在启动装配期写进结构体并贯穿进程生命周期（覆盖表只在
 * core.NewRuntime 里解析一次，reload 不重新应用它），因此界面必须提示重启；
 * 只有一个键（cve_enabled）走快照重建，是真热生效。
 *
 * 这条断言与 configoverride 包的 TestRestartRequiredMatchesContract 是同一条
 * 事实的两个视角：那边看注册表，这边看端点真的把它送出去了。
 */
func TestRuntimeConfigOverrideRestartRequiredReported(t *testing.T) {
	repo := newRuntimeOverridesRepoForTest(t)
	ctx := invokeSystemConfigHandler(t, ListRuntimeConfigOverrides(repo, repo.DB()), "GET", "/api/v1/runtime-config/env-overrides", nil)
	resp := decodeOverridesResponse(t, ctx.Response.Body())

	restart := map[string]bool{}
	for _, item := range resp.Items {
		if item.RestartRequired {
			restart[item.Key] = true
		}
	}
	if len(restart) != 26 {
		t.Fatalf("restart_required key count = %d, want 26: %v", len(restart), restart)
	}
	if restart["cve_enabled"] {
		t.Error("cve_enabled is applied on every snapshot rebuild and must not require a restart")
	}
	for _, key := range []string{"queue_batch_size", "response_cache_mb", "drop_enabled", "bot_enabled", "log_color", "admin_static_dir"} {
		if !restart[key] {
			t.Errorf("key %q must be reported as restart_required", key)
		}
	}
	// 需重启不等于只读：这些键仍然可写，只是要重启才生效。
	for _, item := range resp.Items {
		if item.RestartRequired && !item.Editable {
			t.Errorf("key %q is restart_required but not editable; restart is not read-only", item.Key)
		}
	}
}

/**
 * TestRuntimeConfigOverrideReadOnlyScope 断言只读键的 editable / sensitive 构成。
 */
func TestRuntimeConfigOverrideReadOnlyScope(t *testing.T) {
	repo := newRuntimeOverridesRepoForTest(t)
	ctx := invokeSystemConfigHandler(t, ListRuntimeConfigOverrides(repo, repo.DB()), "GET", "/api/v1/runtime-config/env-overrides", nil)
	resp := decodeOverridesResponse(t, ctx.Response.Body())

	scopeCounts := map[string]int{}
	editable := 0
	for _, item := range resp.Items {
		scopeCounts[item.Scope]++
		if item.Editable {
			editable++
		}
		switch item.Group {
		case "bootstrap", "internal":
			if item.Editable {
				t.Errorf("key %q in group %q must not be editable", item.Key, item.Group)
			}
		}
	}
	if _, ok := scopeCounts["env_only"]; ok {
		t.Fatalf("scope env_only is still in use: %v", scopeCounts)
	}
	wantScopes := map[string]int{"runtime": 29, "delegated": 7, "bootstrap": 7, "test_only": 2}
	for scope, n := range wantScopes {
		if scopeCounts[scope] != n {
			t.Errorf("scope %q count = %d, want %d", scope, scopeCounts[scope], n)
		}
	}
	if editable != 29 {
		t.Fatalf("editable key count = %d, want 29", editable)
	}

	// 密钥类不回显真值。
	for _, item := range resp.Items {
		if !item.Sensitive {
			continue
		}
		if item.EnvValue != nil {
			t.Errorf("key %q is sensitive and must not echo env_value, got %#v", item.Key, item.EnvValue)
		}
		if item.EffectiveValue != "" {
			t.Errorf("key %q is sensitive and must not echo effective_value, got %#v", item.Key, item.EffectiveValue)
		}
	}
}

/**
 * TestRuntimeConfigOverridesWriteThenClear 断言写端点：
 * `overrides` 字段能写入、`clear` 能回到 unset，响应是写后回读的同形状快照。
 */
func TestRuntimeConfigOverridesWriteThenClear(t *testing.T) {
	repo := newRuntimeOverridesRepoForTest(t)
	handler := UpdateRuntimeConfigOverrides(repo, repo.DB(), noopReload)

	// 环境变量确保不会干扰：写进去的键必须来自覆盖表。
	t.Setenv("MY_OPENWAF_BOT_THRESHOLD", "42")

	body := []byte(`{"overrides":{"bot_threshold":55,"cve_enabled":true,"queue_flush_interval":"5s","geoip_db_path":"/tmp/x.mmdb","bot_enabled":false}}`)
	ctx := invokeSystemConfigHandler(t, handler, "POST", "/api/v1/runtime-config/env-overrides", body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status = %d body = %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	resp := decodeOverridesResponse(t, ctx.Response.Body())
	if len(resp.Items) != 45 {
		t.Fatalf("write response items = %d, want 45", len(resp.Items))
	}
	if len(resp.Groups) != 9 {
		t.Fatalf("write response groups = %d, want 9", len(resp.Groups))
	}

	byKey := make(map[string]RuntimeConfigOverrideItem, len(resp.Items))
	for _, item := range resp.Items {
		byKey[item.Key] = item
	}
	checks := []struct {
		key       string
		value     any
		effective any
	}{
		{"bot_threshold", float64(55), float64(55)},
		{"cve_enabled", true, true},
		{"queue_flush_interval", "5s", "5s"},
		{"geoip_db_path", "/tmp/x.mmdb", "/tmp/x.mmdb"},
		{"bot_enabled", false, false},
	}
	for _, want := range checks {
		item := byKey[want.key]
		if !item.Overridden {
			t.Errorf("key %q must be marked overridden after the write", want.key)
		}
		if item.Source != "db" {
			t.Errorf("key %q source = %q, want db", want.key, item.Source)
		}
		if item.Value != want.value {
			t.Errorf("key %q value = %#v, want %#v", want.key, item.Value, want.value)
		}
		if item.EffectiveValue != want.effective {
			t.Errorf("key %q effective_value = %#v, want %#v", want.key, item.EffectiveValue, want.effective)
		}
	}
	// 覆盖表里的条目数必须与写入的键数一致，不能顺带写进别的键。
	var stored map[string]json.RawMessage
	if err := json.Unmarshal([]byte(resp.Stored), &stored); err != nil {
		t.Fatalf("stored table is not valid JSON: %v", err)
	}
	if len(stored) != len(checks) {
		t.Fatalf("stored table has %d keys, want %d: %s", len(stored), len(checks), resp.Stored)
	}

	// clear 先应用：同一个请求里既清又写时，clear 的键回到 unset。
	ctx = invokeSystemConfigHandler(t, handler, "POST", "/api/v1/runtime-config/env-overrides",
		[]byte(`{"clear":["bot_threshold","queue_flush_interval"],"overrides":{"cve_enabled":true}}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("clear status = %d body = %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	resp = decodeOverridesResponse(t, ctx.Response.Body())
	byKey = make(map[string]RuntimeConfigOverrideItem, len(resp.Items))
	for _, item := range resp.Items {
		byKey[item.Key] = item
	}
	cleared := byKey["bot_threshold"]
	if cleared.Overridden {
		t.Errorf("bot_threshold must be unset after clear, got %+v", cleared)
	}
	if cleared.Source != "env" {
		t.Errorf("bot_threshold source = %q, want env after clear", cleared.Source)
	}
	if cleared.Value != nil {
		t.Errorf("bot_threshold value = %#v, want null after clear", cleared.Value)
	}
	if cleared.EffectiveValue != float64(42) {
		t.Errorf("bot_threshold effective_value = %#v, want the env value 42", cleared.EffectiveValue)
	}
	if byKey["queue_flush_interval"].Overridden {
		t.Error("queue_flush_interval must be unset after clear")
	}
	if byKey["queue_flush_interval"].Source != "default" {
		t.Errorf("queue_flush_interval source = %q, want default after clear", byKey["queue_flush_interval"].Source)
	}
	if !byKey["cve_enabled"].Overridden {
		t.Error("cve_enabled must keep its override written in the same request")
	}
	// 上一轮写入的其他键不受影响。
	if !byKey["geoip_db_path"].Overridden || !byKey["bot_enabled"].Overridden {
		t.Error("untouched overrides must survive a later write")
	}
}

/**
 * TestRuntimeConfigOverridesWriteRejectsBadInput 断言 400 的三类来源：
 * 未知键、不可写键、取值非法；且失败时库里的覆盖表一字未动。
 *
 * 不可写键覆盖三档：引导类（bootstrap）、专用端点（delegated）、测试专用
 * （test_only）。
 */
func TestRuntimeConfigOverridesWriteRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{name: "unknown key", body: `{"overrides":{"totally_unknown":1}}`},
		{name: "bootstrap key", body: `{"overrides":{"admin_bind":":8080"}}`},
		{name: "delegated key", body: `{"overrides":{"h3_allow_0rtt":"on"}}`},
		{name: "test only key", body: `{"overrides":{"h2ws_peeker_off":"1"}}`},
		{name: "unknown key in clear", body: `{"clear":["totally_unknown"]}`},
		{name: "bootstrap key in clear", body: `{"clear":["admin_bind"]}`},
		{name: "value out of range", body: `{"overrides":{"queue_batch_size":999999}}`},
		{name: "unparsable duration", body: `{"overrides":{"queue_flush_interval":"soon"}}`},
		{name: "wrong type", body: `{"overrides":{"bot_threshold":"high"}}`},
		{name: "invalid body", body: `{"overrides":`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			repo := newRuntimeOverridesRepoForTest(t)
			if err := repo.Set(store.SettingKeyRuntimeConfigOverrides, `{"cve_enabled":{"value":true,"set":true}}`); err != nil {
				t.Fatalf("seed overrides: %v", err)
			}
			handler := UpdateRuntimeConfigOverrides(repo, repo.DB(), noopReload)
			ctx := invokeSystemConfigHandler(t, handler, "POST", "/api/v1/runtime-config/env-overrides", []byte(tt.body))
			if ctx.Response.StatusCode() != 400 {
				t.Fatalf("status = %d, want 400 (body = %s)", ctx.Response.StatusCode(), ctx.Response.Body())
			}
			var payload map[string]any
			if err := json.Unmarshal(ctx.Response.Body(), &payload); err != nil {
				t.Fatalf("error response is not JSON: %v", err)
			}
			if message, _ := payload["error"].(string); strings.TrimSpace(message) == "" {
				t.Fatalf("error response carries no message: %s", ctx.Response.Body())
			}
			// 被拒绝的请求不得改动库里的覆盖表。
			stored, err := repo.Get(store.SettingKeyRuntimeConfigOverrides)
			if err != nil {
				t.Fatalf("read stored overrides: %v", err)
			}
			if stored != `{"cve_enabled":{"value":true,"set":true}}` {
				t.Fatalf("stored overrides = %s, want the seeded value unchanged", stored)
			}
		})
	}
}

/**
 * TestRuntimeConfigOverridesWriteWithoutReload 断言 reload 为 nil 时写端点仍可用。
 *
 * 单测与嵌入式调用方会传 nil；此时保存必须成功，只跳过重载。
 */
func TestRuntimeConfigOverridesWriteWithoutReload(t *testing.T) {
	repo := newRuntimeOverridesRepoForTest(t)
	ctx := invokeSystemConfigHandler(t, UpdateRuntimeConfigOverrides(repo, repo.DB(), nil), "POST",
		"/api/v1/runtime-config/env-overrides", []byte(`{"overrides":{"drop_bot_threshold":91}}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status = %d body = %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	resp := decodeOverridesResponse(t, ctx.Response.Body())
	for _, item := range resp.Items {
		if item.Key != "drop_bot_threshold" {
			continue
		}
		if !item.Overridden || item.Value != float64(91) {
			t.Fatalf("drop_bot_threshold = %+v, want an override of 91", item)
		}
		return
	}
	t.Fatal("drop_bot_threshold is missing from the response")
}

/**
 * TestRuntimeConfigOverridesReloadFailureIsReported 断言重载失败时如实返回 500
 * 并带上已写入的覆盖表原文，而不是把失败伪装成成功。
 */
func TestRuntimeConfigOverridesReloadFailureIsReported(t *testing.T) {
	repo := newRuntimeOverridesRepoForTest(t)
	failing := func() error { return errRuntimeOverridesReload }
	ctx := invokeSystemConfigHandler(t, UpdateRuntimeConfigOverrides(repo, repo.DB(), failing), "POST",
		"/api/v1/runtime-config/env-overrides", []byte(`{"overrides":{"cve_enabled":true}}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("status = %d, want 500", ctx.Response.StatusCode())
	}
	var payload map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &payload); err != nil {
		t.Fatalf("error response is not JSON: %v", err)
	}
	stored, _ := payload["stored"].(string)
	if !strings.Contains(stored, "cve_enabled") {
		t.Fatalf("error response stored = %q, want the written table echoed back", stored)
	}
}

// errRuntimeOverridesReload 是写端点重载失败场景的固定错误。
var errRuntimeOverridesReload = errRuntimeOverrides("reload failed on purpose")

type errRuntimeOverrides string

func (e errRuntimeOverrides) Error() string { return string(e) }

/**
 * TestRuntimeConfigOverridesStoredIsEchoed 断言 GET 把库里的覆盖表原文回显，
 * 便于界面与运维诊断。
 */
func TestRuntimeConfigOverridesStoredIsEchoed(t *testing.T) {
	repo := newRuntimeOverridesRepoForTest(t)
	const raw = `{"bot_threshold":{"value":55,"set":true}}`
	if err := repo.Set(store.SettingKeyRuntimeConfigOverrides, raw); err != nil {
		t.Fatalf("seed overrides: %v", err)
	}
	ctx := invokeSystemConfigHandler(t, ListRuntimeConfigOverrides(repo, repo.DB()), "GET", "/api/v1/runtime-config/env-overrides", nil)
	resp := decodeOverridesResponse(t, ctx.Response.Body())
	if resp.Stored != raw {
		t.Fatalf("stored = %q, want %q", resp.Stored, raw)
	}
	if len(resp.Warnings) != 0 {
		t.Fatalf("warnings = %#v, want none for a clean table", resp.Warnings)
	}

	// 坏表按「没有覆盖」处理并产出告警，端点照常 200。
	if err := repo.Set(store.SettingKeyRuntimeConfigOverrides, `{"bot_threshold":`); err != nil {
		t.Fatalf("seed broken overrides: %v", err)
	}
	ctx = invokeSystemConfigHandler(t, ListRuntimeConfigOverrides(repo, repo.DB()), "GET", "/api/v1/runtime-config/env-overrides", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status = %d, want 200 for a broken table", ctx.Response.StatusCode())
	}
	resp = decodeOverridesResponse(t, ctx.Response.Body())
	if len(resp.Warnings) == 0 {
		t.Fatal("warnings = none, want a parse warning for a broken table")
	}
	for _, item := range resp.Items {
		if item.Overridden {
			t.Fatalf("key %q is overridden, want no override from a broken table", item.Key)
		}
	}
}

/**
 * TestRuntimeConfigOverridesNilRepo 断言仓储缺失时读端点照常返回清单（空覆盖），
 * 写端点返回 500 而不是 panic。
 */
func TestRuntimeConfigOverridesNilRepo(t *testing.T) {
	ctx := invokeSystemConfigHandler(t, ListRuntimeConfigOverrides(nil, nil), "GET", "/api/v1/runtime-config/env-overrides", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("read status = %d, want 200", ctx.Response.StatusCode())
	}
	resp := decodeOverridesResponse(t, ctx.Response.Body())
	if len(resp.Items) != 45 {
		t.Fatalf("items = %d, want 45", len(resp.Items))
	}

	ctx = invokeSystemConfigHandler(t, UpdateRuntimeConfigOverrides(nil, nil, noopReload), "POST",
		"/api/v1/runtime-config/env-overrides", []byte(`{"overrides":{"cve_enabled":true}}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("write status = %d, want 500", ctx.Response.StatusCode())
	}
}

/**
 * TestRuntimeConfigOverridesSettingKeyIsProtected 断言覆盖表设置键在通用设置端点上
 * 被列为受保护键，只能经本端点写入。
 */
func TestRuntimeConfigOverridesSettingKeyIsProtected(t *testing.T) {
	endpoint, ok := protectedSettingKeys[store.SettingKeyRuntimeConfigOverrides]
	if !ok {
		t.Fatalf("setting key %q is not protected", store.SettingKeyRuntimeConfigOverrides)
	}
	if endpoint != "/api/v1/runtime-config/env-overrides" {
		t.Fatalf("protected endpoint = %q, want /api/v1/runtime-config/env-overrides", endpoint)
	}
}

/**
 * TestRuntimeConfigOverrideShadowedByDiagnosis 断言只读诊断字段 shadowed_by 的判定。
 *
 * 诊断的语义边界必须按测试钉死，避免被误读成「覆盖表已失效」：
 *   - 只在覆盖表真的写过该键时才非空；
 *   - 只对经过 ProtectionConfig 的三个键生效，其余键恒为空；
 *   - 站点级优先于 protection 行；
 *   - 站点级是「至少一个启用站点不采用全局值」，不是「所有站点都不用」。
 */
func TestRuntimeConfigOverrideShadowedByDiagnosis(t *testing.T) {
	disabled := false
	enabledSite := store.Site{Host: "a.example.test", Bind: ":80", Network: "tcp", UpstreamURLs: "http://127.0.0.1:8080", Enabled: true, CVEEnabled: &disabled}
	// Enabled 显式置 false 后仍会被 gorm 的 default:true 覆盖回 true（已实测：
	// 建表后 Create 一个 Enabled:false 的行，读回来是 true），因此这里必须用
	// 原生 UPDATE 把它改成 0，才能真正造出「停用站点」这个场景。
	disabledSite := store.Site{Host: "b.example.test", Bind: ":80", Network: "tcp", UpstreamURLs: "http://127.0.0.1:8080", Enabled: false, CVEEnabled: &disabled}

	cases := []struct {
		name          string
		overrides     string
		protectionRow string
		sites         []store.Site
		want          map[string]string
	}{
		{
			name:      "no protection row and no sites leaves every key unshadowed",
			overrides: `{"cve_enabled":{"value":true,"set":true},"cve_auto_drop_high":{"value":false,"set":true}}`,
			want:      map[string]string{"cve_enabled": "", "cve_auto_drop_high": ""},
		},
		{
			name:          "protection row shadows the three protection-config keys",
			overrides:     `{"cve_enabled":{"value":true,"set":true},"cve_auto_drop_critical":{"value":false,"set":true}}`,
			protectionRow: `{"cve_enabled":false}`,
			want: map[string]string{
				"cve_enabled":            "protection_row",
				"cve_auto_drop_critical": "protection_row",
				"cve_auto_drop_high":     "",
			},
		},
		{
			name:          "an enabled site with a site level switch wins over the protection row",
			overrides:     `{"cve_enabled":{"value":true,"set":true}}`,
			protectionRow: `{"cve_enabled":false}`,
			sites:         []store.Site{enabledSite},
			want:          map[string]string{"cve_enabled": "site_override"},
		},
		{
			name:      "a disabled site does not count",
			overrides: `{"cve_enabled":{"value":true,"set":true}}`,
			sites:     []store.Site{disabledSite},
			want:      map[string]string{"cve_enabled": ""},
		},
		{
			name:          "keys outside the protection chain are never shadowed",
			overrides:     `{"queue_batch_size":{"value":512,"set":true},"drop_enabled":{"value":false,"set":true}}`,
			protectionRow: `{"cve_enabled":false}`,
			sites:         []store.Site{enabledSite},
			want:          map[string]string{"queue_batch_size": "", "drop_enabled": ""},
		},
		{
			name:          "an unset key is never shadowed even when a protection row exists",
			overrides:     `{"cve_enabled":{"value":true,"set":true}}`,
			protectionRow: `{"cve_enabled":false}`,
			want:          map[string]string{"cve_auto_drop_critical": "", "cve_auto_drop_high": ""},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			repo := newRuntimeOverridesRepoWithSitesForTest(t, len(tt.sites) > 0)
			if err := repo.Set(store.SettingKeyRuntimeConfigOverrides, tt.overrides); err != nil {
				t.Fatalf("seed overrides: %v", err)
			}
			if tt.protectionRow != "" {
				if err := repo.Set("protection", tt.protectionRow); err != nil {
					t.Fatalf("seed protection row: %v", err)
				}
			}
			for i := range tt.sites {
				// Create 会把 default:true 写回结构体本身，因此「用户想要的
				// 启用状态」必须在 Create 之前取走，否则下面这个判断永远为假。
				wantEnabled := tt.sites[i].Enabled
				if err := repo.DB().Create(&tt.sites[i]).Error; err != nil {
					t.Fatalf("seed site: %v", err)
				}
				// gorm 的 `default:true` 让零值 false 在插入时被列默认值覆盖，
				// 停用站点必须随后用原生 UPDATE 写回。
				if !wantEnabled {
					if err := repo.DB().Exec("UPDATE sites SET enabled = 0 WHERE id = ?", tt.sites[i].ID).Error; err != nil {
						t.Fatalf("disable site: %v", err)
					}
				}
			}

			ctx := invokeSystemConfigHandler(t, ListRuntimeConfigOverrides(repo, repo.DB()), "GET", "/api/v1/runtime-config/env-overrides", nil)
			if ctx.Response.StatusCode() != 200 {
				t.Fatalf("status = %d body = %s", ctx.Response.StatusCode(), ctx.Response.Body())
			}
			resp := decodeOverridesResponse(t, ctx.Response.Body())
			byKey := make(map[string]RuntimeConfigOverrideItem, len(resp.Items))
			for _, item := range resp.Items {
				byKey[item.Key] = item
			}
			for key, want := range tt.want {
				if got := byKey[key].ShadowedBy; got != want {
					t.Errorf("key %q shadowed_by = %q, want %q", key, got, want)
				}
			}
		})
	}
}

/**
 * TestRuntimeConfigOverrideShadowedBySurvivesWriteReadBack 断言写后回读的响应里
 * 也带诊断字段（GET 与 POST 同形状是契约要求）。
 */
func TestRuntimeConfigOverrideShadowedBySurvivesWriteReadBack(t *testing.T) {
	repo := newRuntimeOverridesRepoWithSitesForTest(t, false)
	if err := repo.Set("protection", `{"cve_enabled":false}`); err != nil {
		t.Fatalf("seed protection row: %v", err)
	}
	ctx := invokeSystemConfigHandler(t, UpdateRuntimeConfigOverrides(repo, repo.DB(), noopReload), "POST",
		"/api/v1/runtime-config/env-overrides", []byte(`{"overrides":{"cve_enabled":true}}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status = %d body = %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	resp := decodeOverridesResponse(t, ctx.Response.Body())
	for _, item := range resp.Items {
		if item.Key != "cve_enabled" {
			continue
		}
		if item.ShadowedBy != "protection_row" {
			t.Fatalf("cve_enabled shadowed_by = %q, want protection_row after the write", item.ShadowedBy)
		}
		return
	}
	t.Fatal("cve_enabled is missing from the response")
}
