package store

import (
	"reflect"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// newBackupTestDB 创建带完整配置表的内存测试库。
func newBackupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// 用 BackupModels 而非手写清单：漏一个模型会让 ExportBackup 报 "no such table"，
	// 且错在导出阶段而非迁移阶段，不易一眼看出。
	if err := db.AutoMigrate(BackupModels()...); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// seedBackupData 填充一组有外键关联的配置数据。
func seedBackupData(t *testing.T, db *gorm.DB) {
	t.Helper()
	cert := Certificate{Name: "test-cert"}
	if err := db.Create(&cert).Error; err != nil {
		t.Fatalf("create cert: %v", err)
	}
	policy := Policy{Name: "test-policy"}
	if err := db.Create(&policy).Error; err != nil {
		t.Fatalf("create policy: %v", err)
	}
	site := Site{Host: "example.com", Bind: ":8080", CertID: &cert.ID, PolicyID: &policy.ID}
	if err := db.Create(&site).Error; err != nil {
		t.Fatalf("create site: %v", err)
	}
	ip := IPListEntry{Kind: IPListBlack, Value: "1.2.3.4", Action: "intercept", SiteID: &site.ID}
	if err := db.Create(&ip).Error; err != nil {
		t.Fatalf("create ip: %v", err)
	}
	if err := db.Create(&SystemSettings{Key: "test_key", Value: "test_val"}).Error; err != nil {
		t.Fatalf("create setting: %v", err)
	}
}

func TestExportBackup(t *testing.T) {
	db := newBackupTestDB(t)
	seedBackupData(t, db)

	data, err := ExportBackup(db)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if data.Version != BackupVersion {
		t.Errorf("version = %d, want %d", data.Version, BackupVersion)
	}
	if len(data.Certificates) != 1 {
		t.Errorf("certificates = %d, want 1", len(data.Certificates))
	}
	if len(data.Sites) != 1 {
		t.Errorf("sites = %d, want 1", len(data.Sites))
	}
	if len(data.IPListEntries) != 1 {
		t.Errorf("ip entries = %d, want 1", len(data.IPListEntries))
	}
	if len(data.SystemSettings) != 1 {
		t.Errorf("settings = %d, want 1", len(data.SystemSettings))
	}
}

func TestImportBackupRoundTrip(t *testing.T) {
	src := newBackupTestDB(t)
	seedBackupData(t, src)
	data, err := ExportBackup(src)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// 导入到一个全新的空库。
	dst := newBackupTestDB(t)
	if err := ImportBackup(dst, data, false); err != nil {
		t.Fatalf("import: %v", err)
	}

	restored, err := ExportBackup(dst)
	if err != nil {
		t.Fatalf("re-export: %v", err)
	}
	if len(restored.Sites) != 1 {
		t.Fatalf("restored sites = %d, want 1", len(restored.Sites))
	}
	// 验证外键 ID 被保留。
	if restored.Sites[0].CertID == nil || data.Sites[0].CertID == nil ||
		*restored.Sites[0].CertID != *data.Sites[0].CertID {
		t.Errorf("restored site CertID mismatch")
	}
	if restored.Sites[0].ID != data.Sites[0].ID {
		t.Errorf("restored site ID = %d, want %d (original ID must be preserved)", restored.Sites[0].ID, data.Sites[0].ID)
	}
	if len(restored.IPListEntries) != 1 {
		t.Errorf("restored ip entries = %d, want 1", len(restored.IPListEntries))
	}
	if len(restored.SystemSettings) != 1 {
		t.Errorf("restored settings = %d, want 1", len(restored.SystemSettings))
	}
}

func TestImportBackupReplaceMode(t *testing.T) {
	dst := newBackupTestDB(t)
	// 目标库先放一些旧数据。
	oldCert := Certificate{Name: "old-cert"}
	if err := dst.Create(&oldCert).Error; err != nil {
		t.Fatalf("seed old cert: %v", err)
	}
	oldSite := Site{Host: "old.com", Bind: ":9999"}
	if err := dst.Create(&oldSite).Error; err != nil {
		t.Fatalf("seed old site: %v", err)
	}

	// 从另一个库导出新配置。
	src := newBackupTestDB(t)
	seedBackupData(t, src)
	data, err := ExportBackup(src)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// replaceMode 应清空旧数据后导入新数据。
	if err := ImportBackup(dst, data, true); err != nil {
		t.Fatalf("import replace: %v", err)
	}

	restored, err := ExportBackup(dst)
	if err != nil {
		t.Fatalf("re-export: %v", err)
	}
	// 旧的 old.com 应被清除，只剩 example.com。
	if len(restored.Sites) != 1 {
		t.Fatalf("sites after replace = %d, want 1", len(restored.Sites))
	}
	if restored.Sites[0].Host != "example.com" {
		t.Errorf("site host = %q, want example.com (old data must be replaced)", restored.Sites[0].Host)
	}
	if len(restored.Certificates) != 1 {
		t.Errorf("certificates after replace = %d, want 1", len(restored.Certificates))
	}
}

func TestImportBackupEmptyIsNoop(t *testing.T) {
	db := newBackupTestDB(t)
	seedBackupData(t, db)

	// 合并模式导入空备份不应删除现有数据。
	empty := &BackupData{Version: BackupVersion}
	if err := ImportBackup(db, empty, false); err != nil {
		t.Fatalf("import empty: %v", err)
	}
	data, err := ExportBackup(db)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(data.Sites) != 1 {
		t.Errorf("sites = %d, want 1 (empty merge import must not delete)", len(data.Sites))
	}
}

// TestBackupIncludesLuaPlugins 验证 Lua 策略脚本被纳入备份。
//
// 漏掉的后果是静默丢失：用户导出配置、重建实例、导入恢复，站点和规则都在，
// 唯独自定义策略消失，且全程没有任何提示。脚本内容只存在于数据库里，
// 丢了就无法从别处找回。
func TestBackupIncludesLuaPlugins(t *testing.T) {
	src := newBackupTestDB(t)

	siteScoped := uint(7)
	plugins := []LuaPlugin{
		{
			Name:        "global-pre",
			Stage:       LuaStagePre,
			Source:      `function handle(ctx) return nil end`,
			Enabled:     true,
			Priority:    50,
			TimeoutMS:   200,
			Description: "全站脚本",
		},
		{
			Name:     "site-post",
			Stage:    LuaStagePost,
			Source:   `function handle(ctx) if ctx.action == "intercept" then return "allow" end return nil end`,
			Enabled:  false,
			Priority: 100,
			SiteID:   &siteScoped,
		},
	}
	for i := range plugins {
		if err := src.Create(&plugins[i]).Error; err != nil {
			t.Fatalf("create lua plugin %q: %v", plugins[i].Name, err)
		}
	}
	// Enabled 带 gorm:"default:true"，Create 会把 false 当零值忽略而落库为 true。
	// 这里用 UpdateColumn 绕过该行为，确保源库里确实是 false——否则本测试
	// 根本测不到「停用状态能否被备份保留」。
	if err := src.Model(&LuaPlugin{}).Where("name = ?", "site-post").
		UpdateColumn("enabled", false).Error; err != nil {
		t.Fatalf("强制停用: %v", err)
	}

	data, err := ExportBackup(src)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(data.LuaPlugins) != 2 {
		t.Fatalf("导出的 Lua 脚本数 = %d, want 2", len(data.LuaPlugins))
	}
	// 先确认导出侧无误，这样后面若失败可断定问题出在导入侧。
	for _, p := range data.LuaPlugins {
		if p.Name == "site-post" && p.Enabled {
			t.Fatalf("导出侧就丢了停用状态——问题不在导入")
		}
	}

	dst := newBackupTestDB(t)
	if err := ImportBackup(dst, data, false); err != nil {
		t.Fatalf("import: %v", err)
	}

	var restored []LuaPlugin
	if err := dst.Order("name").Find(&restored).Error; err != nil {
		t.Fatalf("查询恢复结果: %v", err)
	}
	if len(restored) != 2 {
		t.Fatalf("恢复的 Lua 脚本数 = %d, want 2", len(restored))
	}

	byName := map[string]LuaPlugin{}
	for _, p := range restored {
		byName[p.Name] = p
	}

	global, ok := byName["global-pre"]
	if !ok {
		t.Fatal("全站脚本未被恢复")
	}
	// 源码是脚本的全部价值，逐字节比对而非只看数量。
	if global.Source != plugins[0].Source {
		t.Errorf("源码不一致\n得到: %q\nwant: %q", global.Source, plugins[0].Source)
	}
	if global.Stage != LuaStagePre || global.Priority != 50 || global.TimeoutMS != 200 {
		t.Errorf("字段丢失: stage=%q priority=%d timeout=%d", global.Stage, global.Priority, global.TimeoutMS)
	}
	if global.SiteID != nil {
		t.Errorf("全站脚本的 SiteID 应保持 nil，得到 %v", *global.SiteID)
	}
	if global.ID != plugins[0].ID {
		t.Errorf("主键未保留: %d, want %d", global.ID, plugins[0].ID)
	}

	scoped, ok := byName["site-post"]
	if !ok {
		t.Fatal("站点级脚本未被恢复")
	}
	// SiteID 是 *uint 三态字段，恢复成 nil 会让站点级脚本变成全站生效——
	// 本该只作用于一个站点的策略突然作用于全部站点。
	if scoped.SiteID == nil {
		t.Error("站点级脚本的 SiteID 丢失，恢复后会变成全站生效")
	} else if *scoped.SiteID != siteScoped {
		t.Errorf("SiteID = %d, want %d", *scoped.SiteID, siteScoped)
	}
	// Enabled=false 必须保持：恢复后自动启用一个被停用的策略同样是事故。
	if scoped.Enabled {
		t.Error("已停用的脚本恢复后变成启用状态")
	}
}

// TestImportBackupReplaceModeClearsLuaPlugins 验证整体替换模式会清掉旧脚本。
//
// 若 clearConfigTables 漏了 lua_plugins，「整体替换」就会退化成合并：
// 目标实例上原有的脚本残留下来，与导入的配置叠加生效。
func TestImportBackupReplaceModeClearsLuaPlugins(t *testing.T) {
	dst := newBackupTestDB(t)
	stale := LuaPlugin{
		Name:    "stale-should-be-removed",
		Stage:   LuaStagePre,
		Source:  `function handle(ctx) return "intercept" end`,
		Enabled: true,
	}
	if err := dst.Create(&stale).Error; err != nil {
		t.Fatalf("create stale plugin: %v", err)
	}

	src := newBackupTestDB(t)
	fresh := LuaPlugin{
		Name:    "fresh",
		Stage:   LuaStagePre,
		Source:  `function handle(ctx) return nil end`,
		Enabled: true,
	}
	if err := src.Create(&fresh).Error; err != nil {
		t.Fatalf("create fresh plugin: %v", err)
	}
	data, err := ExportBackup(src)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	if err := ImportBackup(dst, data, true); err != nil {
		t.Fatalf("import replace: %v", err)
	}

	var got []LuaPlugin
	if err := dst.Find(&got).Error; err != nil {
		t.Fatalf("查询: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("替换模式后脚本数 = %d, want 1", len(got))
	}
	if got[0].Name != "fresh" {
		t.Errorf("残留了旧脚本 %q——替换模式退化成了合并", got[0].Name)
	}
}

// TestBackupIncludesJSPlugins 验证 JavaScript 边缘脚本及其关键字段被纳入备份。
func TestBackupIncludesJSPlugins(t *testing.T) {
	src := newBackupTestDB(t)

	siteID := uint(7)
	want := JSPlugin{
		Name:        "edge-response",
		Source:      `function handle(ctx) { return { action: "observe" }; }`,
		Enabled:     true,
		Priority:    23,
		SiteID:      &siteID,
		Stage:       JSStageResponse,
		FailureMode: JSFailureModeClosed,
		TimeoutMS:   275,
		Description: "响应阶段脚本",
	}
	if err := src.Create(&want).Error; err != nil {
		t.Fatalf("create js plugin: %v", err)
	}

	data, err := ExportBackup(src)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(data.JSPlugins) != 1 {
		t.Fatalf("导出的 JS 脚本数 = %d, want 1", len(data.JSPlugins))
	}
	if data.JSPlugins[0].ID != want.ID {
		t.Fatalf("导出的 JS 脚本 ID = %d, want %d", data.JSPlugins[0].ID, want.ID)
	}

	dst := newBackupTestDB(t)
	if err := ImportBackup(dst, data, false); err != nil {
		t.Fatalf("import: %v", err)
	}

	var got JSPlugin
	if err := dst.First(&got, want.ID).Error; err != nil {
		t.Fatalf("查询恢复的 JS 脚本: %v", err)
	}
	if got.Source != want.Source {
		t.Errorf("Source = %q, want %q", got.Source, want.Source)
	}
	if got.SiteID == nil {
		t.Fatal("SiteID 丢失")
	} else if *got.SiteID != siteID {
		t.Errorf("SiteID = %d, want %d", *got.SiteID, siteID)
	}
	if got.Stage != want.Stage {
		t.Errorf("Stage = %q, want %q", got.Stage, want.Stage)
	}
	if got.FailureMode != want.FailureMode {
		t.Errorf("FailureMode = %q, want %q", got.FailureMode, want.FailureMode)
	}
	if got.TimeoutMS != want.TimeoutMS {
		t.Errorf("TimeoutMS = %d, want %d", got.TimeoutMS, want.TimeoutMS)
	}
	if got.Description != want.Description {
		t.Errorf("Description = %q, want %q", got.Description, want.Description)
	}
}

// TestImportBackupReplaceModeClearsJSPlugins 验证整体替换模式会清掉旧 JS 脚本。
func TestImportBackupReplaceModeClearsJSPlugins(t *testing.T) {
	dst := newBackupTestDB(t)
	stale := JSPlugin{
		Name:        "stale-js-plugin",
		Source:      `function handle(ctx) { return { action: "intercept" }; }`,
		Stage:       JSStageRequest,
		FailureMode: JSFailureModeOpen,
	}
	if err := dst.Create(&stale).Error; err != nil {
		t.Fatalf("create stale js plugin: %v", err)
	}

	src := newBackupTestDB(t)
	fresh := JSPlugin{
		Name:        "fresh-js-plugin",
		Source:      `function handle(ctx) { return null; }`,
		Stage:       JSStageResponse,
		FailureMode: JSFailureModeClosed,
	}
	if err := src.Create(&fresh).Error; err != nil {
		t.Fatalf("create fresh js plugin: %v", err)
	}
	data, err := ExportBackup(src)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	if err := ImportBackup(dst, data, true); err != nil {
		t.Fatalf("import replace: %v", err)
	}

	var got []JSPlugin
	if err := dst.Order("id").Find(&got).Error; err != nil {
		t.Fatalf("查询恢复的 JS 脚本: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("替换模式后 JS 脚本数 = %d, want 1", len(got))
	}
	if got[0].Name != fresh.Name {
		t.Errorf("残留了旧 JS 脚本 %q——替换模式退化成了合并", got[0].Name)
	}
}

// TestBackupPreservesDisabledSiteAndZeroPriority 验证「用户主动关掉/清零」的配置
// 能被备份还原，而不是被 DB 默认值悄悄逆转。
//
// 这是安全相关的：Site.Enabled 带 gorm:"default:true"，若恢复时被重置为 true，
// 一个被管理员主动停用的站点（已下线或正在修漏洞）会重新对外提供服务，
// 而管理员不会收到任何提示。Rule.Priority 带 default:100，从 0 被改成 100 则会
// 改变规则执行顺序——规则按 priority ASC, ID ASC 排序，本该最先生效的拦截规则
// 会被挤到后面。
func TestBackupPreservesDisabledSiteAndZeroPriority(t *testing.T) {
	src := newBackupTestDB(t)

	site := Site{Host: "disabled.example.com", Bind: ":8081"}
	if err := src.Create(&site).Error; err != nil {
		t.Fatalf("create site: %v", err)
	}
	policy := Policy{Name: "p"}
	if err := src.Create(&policy).Error; err != nil {
		t.Fatalf("create policy: %v", err)
	}
	rule := Rule{
		Name:     "top-priority-block",
		PolicyID: policy.ID,
		Phase:    PhaseACL,
		Pattern:  "block_path:/admin",
		Action:   RuleAction("intercept"),
	}
	if err := src.Create(&rule).Error; err != nil {
		t.Fatalf("create rule: %v", err)
	}
	// 用 UpdateColumn 绕开 Create 对 default 字段的零值顶替，
	// 确保源库里确实是「停用 / 优先级 0」。
	if err := src.Model(&Site{}).Where("id = ?", site.ID).
		UpdateColumn("enabled", false).Error; err != nil {
		t.Fatalf("停用站点: %v", err)
	}
	if err := src.Model(&Rule{}).Where("id = ?", rule.ID).
		UpdateColumns(map[string]interface{}{"enabled": false, "priority": 0}).Error; err != nil {
		t.Fatalf("清零规则: %v", err)
	}

	data, err := ExportBackup(src)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(data.Sites) != 1 || data.Sites[0].Enabled {
		t.Fatalf("导出侧就丢了停用状态，问题不在导入")
	}
	if len(data.Rules) != 1 || data.Rules[0].Priority != 0 {
		t.Fatalf("导出侧就丢了 priority=0，问题不在导入")
	}

	dst := newBackupTestDB(t)
	if err := ImportBackup(dst, data, false); err != nil {
		t.Fatalf("import: %v", err)
	}

	var gotSite Site
	if err := dst.First(&gotSite, site.ID).Error; err != nil {
		t.Fatalf("查询恢复的站点: %v", err)
	}
	if gotSite.Enabled {
		t.Error("停用的站点恢复后被自动启用——会重新对外提供服务")
	}

	var gotRule Rule
	if err := dst.First(&gotRule, rule.ID).Error; err != nil {
		t.Fatalf("查询恢复的规则: %v", err)
	}
	if gotRule.Priority != 0 {
		t.Errorf("priority 被改写为 %d，规则执行顺序会变", gotRule.Priority)
	}
	if gotRule.Enabled {
		t.Error("停用的规则恢复后被自动启用")
	}
}

// TestBackupPreservesNonZeroValues 确认修复没有走向另一个极端：
// 非零值必须原样保留，不能被误当成「需要还原的零值」而清掉。
func TestBackupPreservesNonZeroValues(t *testing.T) {
	src := newBackupTestDB(t)
	policy := Policy{Name: "p"}
	if err := src.Create(&policy).Error; err != nil {
		t.Fatalf("create policy: %v", err)
	}
	rule := Rule{
		Name:       "keep",
		PolicyID:   policy.ID,
		Phase:      PhaseCustom,
		Pattern:    "block_path:/x",
		Action:     RuleAction("intercept"),
		Priority:   42,
		Enabled:    true,
		StatusCode: 418,
	}
	if err := src.Create(&rule).Error; err != nil {
		t.Fatalf("create rule: %v", err)
	}

	data, err := ExportBackup(src)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	dst := newBackupTestDB(t)
	if err := ImportBackup(dst, data, false); err != nil {
		t.Fatalf("import: %v", err)
	}

	var got Rule
	if err := dst.First(&got, rule.ID).Error; err != nil {
		t.Fatalf("查询: %v", err)
	}
	if got.Priority != 42 {
		t.Errorf("priority = %d, want 42（非零值被误清）", got.Priority)
	}
	if !got.Enabled {
		t.Error("enabled 被误清为 false")
	}
	if got.StatusCode != 418 {
		t.Errorf("status_code = %d, want 418", got.StatusCode)
	}
	if got.Name != "keep" {
		t.Errorf("name = %q, want keep", got.Name)
	}
}

// TestBackupModelsCoverBackupData 守住 BackupModels 与 BackupData 的一致性。
//
// 两者脱节的后果不对称：BackupData 多出一个字段而 BackupModels 漏了它，
// 测试库就建不出那张表，ExportBackup 报 "no such table"；反过来若某个模型
// 已从 BackupData 移除却留在 BackupModels 里，则会凭空迁移一张没人用的表。
// 用反射逐字段核对，比靠人记住「加字段时要同步改三处」可靠。
func TestBackupModelsCoverBackupData(t *testing.T) {
	models := BackupModels()
	// 模型指针 -> 其指向的结构体类型
	modelTypes := make(map[reflect.Type]bool, len(models))
	for _, m := range models {
		mt := reflect.TypeOf(m)
		if mt.Kind() != reflect.Ptr {
			t.Fatalf("BackupModels 应返回指针，得到 %s", mt.Kind())
		}
		modelTypes[mt.Elem()] = true
	}

	dataType := reflect.TypeOf(BackupData{})
	var sliceFields int
	for i := 0; i < dataType.NumField(); i++ {
		f := dataType.Field(i)
		if f.Type.Kind() != reflect.Slice {
			continue // Version / ExportedAt 不是数据表
		}
		sliceFields++
		elem := f.Type.Elem()
		if !modelTypes[elem] {
			t.Errorf("BackupData.%s 的元素类型 %s 不在 BackupModels 中——"+
				"测试库建不出该表，ExportBackup 会报 no such table", f.Name, elem.Name())
		}
	}

	if sliceFields != len(models) {
		t.Errorf("BackupData 有 %d 个数据表字段，BackupModels 返回 %d 个——"+
			"存在多余或缺失的模型", sliceFields, len(models))
	}
}

func TestImportBackupRepairsPolicyReferencesAndPreservesExplicitDefault(t *testing.T) {
	db := newBackupTestDB(t)
	defaultID := uint(20)
	orphanID := uint(999)
	data := &BackupData{
		Version:         BackupVersion,
		DefaultPolicyID: &defaultID,
		Policies: []Policy{
			{ID: 10, Name: "first policy"},
			{ID: defaultID, Name: "explicit default"},
		},
		Rules: []Rule{
			{ID: 1, Name: "zero", PolicyID: 0, Phase: PhaseCustom, Pattern: "block_path:/zero", Action: ActionIntercept, Enabled: true},
			{ID: 2, Name: "orphan", PolicyID: orphanID, Phase: PhaseCustom, Pattern: "block_path:/orphan", Action: ActionIntercept, Enabled: true},
		},
		Sites: []Site{
			{ID: 1, Host: "zero.example", Bind: ":80", PolicyID: uintPtrForBackupTest(0)},
			{ID: 2, Host: "orphan.example", Bind: ":81", PolicyID: &orphanID},
		},
	}

	if err := ImportBackup(db, data, false); err != nil {
		t.Fatalf("import: %v", err)
	}
	if err := ImportBackup(db, data, false); err != nil {
		t.Fatalf("repeat import: %v", err)
	}

	var defaultPolicy Policy
	if err := db.Where("default_slot = ?", 1).First(&defaultPolicy).Error; err != nil {
		t.Fatalf("load default policy: %v", err)
	}
	if defaultPolicy.ID != defaultID {
		t.Fatalf("default policy id = %d, want %d", defaultPolicy.ID, defaultID)
	}

	var rules []Rule
	if err := db.Order("id ASC").Find(&rules).Error; err != nil {
		t.Fatalf("load rules: %v", err)
	}
	for i := range rules {
		if rules[i].PolicyID != defaultID {
			t.Fatalf("rule %d policy_id = %d, want %d", rules[i].ID, rules[i].PolicyID, defaultID)
		}
	}

	var sites []Site
	if err := db.Order("id ASC").Find(&sites).Error; err != nil {
		t.Fatalf("load sites: %v", err)
	}
	for i := range sites {
		if sites[i].PolicyID != nil {
			t.Fatalf("site %d policy_id = %v, want nil", sites[i].ID, sites[i].PolicyID)
		}
	}
}

func uintPtrForBackupTest(value uint) *uint { return &value }
