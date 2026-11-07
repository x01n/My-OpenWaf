package snapshot

import (
	"bytes"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/approute"
)

// newSnapshotOverrideDBForTest 建立仅含站点、策略、规则与系统设置表的快照库。
func newSnapshotOverrideDBForTest(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&store.Site{},
		&store.SiteListener{},
		&store.Certificate{},
		&store.Policy{},
		&store.Rule{},
		&store.SystemSettings{},
		&approute.ApplicationRouteRule{},
	); err != nil {
		t.Fatalf("migrate tables: %v", err)
	}
	defaultSlot := uint(1)
	if err := db.Create(&store.Policy{Name: "default", DefaultSlot: &defaultSlot}).Error; err != nil {
		t.Fatalf("seed default policy: %v", err)
	}
	return db
}

/**
 * TestProtectionConfigFromMapAppliesOverrideOnlyWithoutProtectionRow 断言覆盖表对全局
 * 保护配置的作用范围：只在 `protection` 设置行缺失时充当默认值的替代品。
 *
 * 完整的优先序（自低到高）：内置默认值 < 覆盖表 < `protection` 设置行 < 站点级字段。
 *
 * 最后一段不能读作「站点管理员显式开了 CVE」：mergeProtection 只判
 * `site.CVEEnabled != nil`，而该字段有两个来源——站点上的显式设置，以及
 * `Site.ApplyProtectionModeOverrides` 在站点选定保护档时无条件填入的 `&true`
 * （internal/store/site.go:161/173，observe 与 protect 两档都写 true，且没有
 * `if s.CVEEnabled == nil` 守卫）。因此对设过保护档的站点，这个非 nil 值是
 * 档位自动填的，不是逐站点的 CVE 决策。
 *
 * 这条测试同时钉住「快照重建会重新读覆盖表」这一事实——`protectionConfigFromMap`
 * 是 `Build()` 的一部分，而 `Build()` 每次配置重载都会跑，所以走这条链的键
 * （cve_enabled / cve_auto_drop_critical / cve_auto_drop_high）是真热生效。
 */
func TestProtectionConfigFromMapAppliesOverrideOnlyWithoutProtectionRow(t *testing.T) {
	const overrides = `{"cve_enabled":{"value":false,"set":true},"cve_auto_drop_critical":{"value":false,"set":true}}`

	// 无 protection 行：覆盖表胜出。
	got, err := protectionConfigFromMap(map[string]string{store.SettingKeyRuntimeConfigOverrides: overrides})
	if err != nil {
		t.Fatalf("protectionConfigFromMap: %v", err)
	}
	if got.CVEEnabled {
		t.Error("CVEEnabled = true, want the overridden false")
	}
	if got.CVEAutoDropCritical {
		t.Error("CVEAutoDropCritical = true, want the overridden false")
	}
	if got.CVEAutoDropHigh != store.DefaultProtectionConfig().CVEAutoDropHigh {
		t.Errorf("CVEAutoDropHigh = %v, want the untouched default", got.CVEAutoDropHigh)
	}

	// 有 protection 行：该行整体覆盖，覆盖表被顶掉（不产生第二份真相）。
	protectionJSON := `{"cve_enabled":true,"cve_auto_drop_critical":true,"cve_auto_drop_high":true}`
	got, err = protectionConfigFromMap(map[string]string{
		store.SettingKeyRuntimeConfigOverrides: overrides,
		"protection":                           protectionJSON,
	})
	if err != nil {
		t.Fatalf("protectionConfigFromMap with a protection row: %v", err)
	}
	if !got.CVEEnabled || !got.CVEAutoDropCritical {
		t.Errorf("protection row must win over the override table, got %+v", got)
	}
}

/**
 * TestProtectionRowSuppressesOverrideEntirely 钉住上一条的边界：`protection` 设置行存在时
 * 覆盖表对这三个键**完全失效**，包括「覆盖表要求关、设置行要求开」的方向。
 *
 * 这是「不产生第二份真相」这条设计的直接后果：那份设置行是管理端
 * `PutProtectionSettings` 用 `json.Marshal(整个 ProtectionConfig)` 写出来的，
 * 每个开关都有值，因此只要用户进过一次全局防护页并保存，覆盖表对这三个键
 * 就永久不再生效（直到该行被删除）。
 *
 * 本测试存在的意义是把这条优先级钉死：任何人若改成「覆盖表优先」或做成深合并，
 * 这里会红，从而被迫显式面对上面的后果。
 */
func TestProtectionRowSuppressesOverrideEntirely(t *testing.T) {
	// 覆盖表把三个键全关；设置行把它们全开。
	const overrides = `{"cve_enabled":{"value":false,"set":true},` +
		`"cve_auto_drop_critical":{"value":false,"set":true},` +
		`"cve_auto_drop_high":{"value":false,"set":true}}`
	protectionJSON := `{"cve_enabled":true,"cve_auto_drop_critical":true,"cve_auto_drop_high":true}`

	got, err := protectionConfigFromMap(map[string]string{
		store.SettingKeyRuntimeConfigOverrides: overrides,
		"protection":                           protectionJSON,
	})
	if err != nil {
		t.Fatalf("protectionConfigFromMap: %v", err)
	}
	if !got.CVEEnabled {
		t.Error("CVEEnabled = false, want the protection row's true to win over the override")
	}
	if !got.CVEAutoDropCritical || !got.CVEAutoDropHigh {
		t.Errorf("auto-drop = %v/%v, want the protection row's true to win over the override",
			got.CVEAutoDropCritical, got.CVEAutoDropHigh)
	}

	// 设置行只写了三个键之外的内容也照样整体顶掉：json.Unmarshal 落到
	// applyConfigOverrideBase 的结果上，缺失字段保持该结果——但只要有任一
	// CVE 字段出现，它就带着自己的取值。
	partial := `{"cve_enabled":true}`
	got, err = protectionConfigFromMap(map[string]string{
		store.SettingKeyRuntimeConfigOverrides: overrides,
		"protection":                           partial,
	})
	if err != nil {
		t.Fatalf("protectionConfigFromMap with a partial row: %v", err)
	}
	if !got.CVEEnabled {
		t.Error("a partial protection row must still win for the field it carries")
	}
	// 该行没提的 auto-drop 字段保持覆盖表的值（false）——这就是「顶层整体顶掉、
	// 缺失字段沿用底稿」的真实语义，不是逐字段覆盖。
	if got.CVEAutoDropCritical || got.CVEAutoDropHigh {
		t.Errorf("auto-drop = %v/%v, want the override's false to survive for fields the row omits",
			got.CVEAutoDropCritical, got.CVEAutoDropHigh)
	}
}

/**
 * TestBuildSnapshotsCoverageOfOverrideKeys 断言「哪些键随快照重建生效、哪些不生效」。
 *
 * 这张表是 `restart_required` 标注的取证依据：Build() 每次配置重载都会重新执行，
 * 因此它能读到的键是真热生效；读不到的键（消费点在启动装配期）只能靠重启。
 */
func TestBuildSnapshotsCoverageOfOverrideKeys(t *testing.T) {
	db := newSnapshotOverrideDBForTest(t)
	if err := db.Create(&store.SystemSettings{
		Key: store.SettingKeyRuntimeConfigOverrides,
		// 故意写入 drop/bot 三类键：它们没有任何快照消费者，必须对快照零影响。
		Value: `{"cve_enabled":{"value":true,"set":true},` +
			`"drop_enabled":{"value":false,"set":true},` +
			`"drop_bot_threshold":{"value":11,"set":true},` +
			`"bot_threshold":{"value":22,"set":true},` +
			`"bot_enabled":{"value":false,"set":true}}`,
	}).Error; err != nil {
		t.Fatalf("seed overrides: %v", err)
	}

	sn, err := Build(db, 1, bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if !sn.Protection.CVEEnabled {
		t.Error("snapshot Protection.CVEEnabled = false, want the overridden true")
	}
	// 下面这些键在快照里没有对应字段：能编译通过本身就说明它们没有快照消费者。
	if sn.Protection.CVEAutoDropCritical != store.DefaultProtectionConfig().CVEAutoDropCritical {
		t.Errorf("CVEAutoDropCritical = %v, want the untouched default", sn.Protection.CVEAutoDropCritical)
	}
}
