package repository

import (
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"My-OpenWaf/internal/store"
)

// newZeroDefaultsTestDB 建一个含全部受测模型的内存库。
func newZeroDefaultsTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&store.Site{}, &store.SiteListener{}, &store.Policy{}, &store.Rule{},
		&store.IPListEntry{}, &store.ThreatIntelFeed{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// TestCreateHonorsExplicitDisabled 覆盖所有「新建时显式停用」的入口。
//
// 这些模型的 Enabled 都带 gorm:"default:true"，而 GORM 在 INSERT 时会把布尔
// 零值当成「未设置」并交给数据库默认值。项目里已有 5 处 repository 手工写了
// 插入后回写的补偿代码，但另外 5 处漏了——手工重复本身就是不可靠的。
//
// 每一项漏掉的后果都是「用户表达了停用意图，系统却启用了它」：
//   - Site：站点立刻接受流量并代理到上游
//   - SiteListener：监听器立刻占用端口
//   - Rule：规则立刻参与拦截判定
//   - IPListEntry：黑/白名单条目立刻生效
//   - ThreatIntelFeed：订阅源立刻开始同步并注入 IP 名单
func TestCreateHonorsExplicitDisabled(t *testing.T) {
	cases := []struct {
		name   string
		create func(t *testing.T, db *gorm.DB) (id uint, enabled func(*gorm.DB, uint) bool)
	}{
		{
			name: "Site",
			create: func(t *testing.T, db *gorm.DB) (uint, func(*gorm.DB, uint) bool) {
				item := &store.Site{
					Host: "disabled.example.com", Bind: ":18443",
					UpstreamURLs: `["http://127.0.0.1:8800"]`, Enabled: false,
				}
				if err := NewSiteRepo(db).Create(item); err != nil {
					t.Fatalf("create: %v", err)
				}
				return item.ID, func(db *gorm.DB, id uint) bool {
					var got store.Site
					_ = db.First(&got, id).Error
					return got.Enabled
				}
			},
		},
		{
			name: "SiteListener",
			create: func(t *testing.T, db *gorm.DB) (uint, func(*gorm.DB, uint) bool) {
				item := &store.SiteListener{SiteID: 1, Bind: ":18080", Enabled: false}
				if err := NewSiteListenerRepo(db).Create(item); err != nil {
					t.Fatalf("create: %v", err)
				}
				return item.ID, func(db *gorm.DB, id uint) bool {
					var got store.SiteListener
					_ = db.First(&got, id).Error
					return got.Enabled
				}
			},
		},
		{
			name: "Rule",
			create: func(t *testing.T, db *gorm.DB) (uint, func(*gorm.DB, uint) bool) {
				policy := &store.Policy{Name: "p"}
				if err := db.Create(policy).Error; err != nil {
					t.Fatalf("create policy: %v", err)
				}
				item := &store.Rule{
					Name: "disabled-rule", PolicyID: policy.ID, Phase: store.PhaseACL,
					Pattern: "block_path:/x", Action: store.RuleAction("intercept"),
					Enabled: false,
				}
				if err := NewRuleRepo(db).Create(item); err != nil {
					t.Fatalf("create: %v", err)
				}
				return item.ID, func(db *gorm.DB, id uint) bool {
					var got store.Rule
					_ = db.First(&got, id).Error
					return got.Enabled
				}
			},
		},
		{
			name: "IPListEntry",
			create: func(t *testing.T, db *gorm.DB) (uint, func(*gorm.DB, uint) bool) {
				item := &store.IPListEntry{
					Kind: store.IPListBlack, Value: "203.0.113.7",
					Action: "intercept", Enabled: false,
				}
				if err := NewIPListRepo(db).Create(item); err != nil {
					t.Fatalf("create: %v", err)
				}
				return item.ID, func(db *gorm.DB, id uint) bool {
					var got store.IPListEntry
					_ = db.First(&got, id).Error
					return got.Enabled
				}
			},
		},
		{
			name: "ThreatIntelFeed",
			create: func(t *testing.T, db *gorm.DB) (uint, func(*gorm.DB, uint) bool) {
				item := &store.ThreatIntelFeed{
					Name: "disabled-feed", URL: "https://feeds.example.com/list.txt",
					Kind: "blacklist", Enabled: false,
				}
				if err := NewThreatIntelRepo(db).Create(item); err != nil {
					t.Fatalf("create: %v", err)
				}
				return item.ID, func(db *gorm.DB, id uint) bool {
					var got store.ThreatIntelFeed
					_ = db.First(&got, id).Error
					return got.Enabled
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newZeroDefaultsTestDB(t)
			id, readEnabled := tc.create(t, db)
			if readEnabled(db, id) {
				t.Errorf("%s: 新建时显式停用，落库后却是启用状态", tc.name)
			}
		})
	}
}

// TestCreateRuleHonorsZeroPriority 单列出来，因为它不是布尔字段。
//
// Rule.Priority 带 gorm:"default:100"，规则按 priority ASC, ID ASC 排序执行。
// 用户把优先级设成 0 是想让这条规则最先生效；被改成 100 之后它会排到所有
// 默认优先级规则的后面——一条本该抢先拦截的规则变成了兜底规则。
// 注意：既有的手工补偿只处理 Enabled，即便照搬到 RuleRepo 也修不了这一项。
func TestCreateRuleHonorsZeroPriority(t *testing.T) {
	db := newZeroDefaultsTestDB(t)
	policy := &store.Policy{Name: "p"}
	if err := db.Create(policy).Error; err != nil {
		t.Fatalf("create policy: %v", err)
	}

	item := &store.Rule{
		Name: "top-priority", PolicyID: policy.ID, Phase: store.PhaseACL,
		Pattern: "block_path:/admin", Action: store.RuleAction("intercept"),
		Enabled: true, Priority: 0,
	}
	if err := NewRuleRepo(db).Create(item); err != nil {
		t.Fatalf("create: %v", err)
	}

	var got store.Rule
	if err := db.First(&got, item.ID).Error; err != nil {
		t.Fatalf("查询: %v", err)
	}
	if got.Priority != 0 {
		t.Errorf("priority = %d, want 0——规则被挤到默认优先级之后，执行顺序被改变", got.Priority)
	}
}

// TestCreateWritesValuesFaithfully 守住反向边界：非零值不能被误清。
//
// 修零值不能矫枉过正——显式启用的站点不该被写成停用、priority=42 不该被清成 0。
func TestCreateWritesValuesFaithfully(t *testing.T) {
	db := newZeroDefaultsTestDB(t)

	site := &store.Site{
		Host: "live.example.com", Bind: ":18444",
		UpstreamURLs: `["http://127.0.0.1:8800"]`, Enabled: true,
	}
	if err := NewSiteRepo(db).Create(site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	var gotSite store.Site
	if err := db.First(&gotSite, site.ID).Error; err != nil {
		t.Fatalf("查询站点: %v", err)
	}
	if !gotSite.Enabled {
		t.Error("显式启用的站点被写成了停用")
	}

	policy := &store.Policy{Name: "p"}
	if err := db.Create(policy).Error; err != nil {
		t.Fatalf("create policy: %v", err)
	}
	rule := &store.Rule{
		Name: "keep", PolicyID: policy.ID, Phase: store.PhaseACL,
		Pattern: "block_path:/y", Action: store.RuleAction("intercept"),
		Enabled: true, Priority: 42, StatusCode: 418,
	}
	if err := NewRuleRepo(db).Create(rule); err != nil {
		t.Fatalf("create rule: %v", err)
	}
	var gotRule store.Rule
	if err := db.First(&gotRule, rule.ID).Error; err != nil {
		t.Fatalf("查询规则: %v", err)
	}
	if gotRule.Priority != 42 || !gotRule.Enabled || gotRule.StatusCode != 418 {
		t.Errorf("非零值被改动: priority=%d enabled=%v status=%d",
			gotRule.Priority, gotRule.Enabled, gotRule.StatusCode)
	}
}

// TestApplyDefaultsThenCreateMatchesHandlerFlow 验证 handler 的完整流程。
//
// 职责是分开的：handler 用 ApplyModelDefaults 把「用户没提供」的字段补成默认值，
// repository 只负责如实落库。这里复现 handler 的调用顺序，确认两者合起来的结果
// 既保住默认值、又不吞掉用户显式设的零值——单靠任何一层都做不到，因为 Go 的
// 值类型区分不了「没设」和「设成了零值」。
func TestApplyDefaultsThenCreateMatchesHandlerFlow(t *testing.T) {
	db := newZeroDefaultsTestDB(t)
	policy := &store.Policy{Name: "p"}
	if err := db.Create(policy).Error; err != nil {
		t.Fatalf("create policy: %v", err)
	}

	// 场景一：用户没提供 priority/enabled，应拿到模型声明的默认值。
	unset := &store.Rule{
		Name: "unset", PolicyID: policy.ID, Phase: store.PhaseACL,
		Pattern: "block_path:/a", Action: store.RuleAction("intercept"),
	}
	if err := store.ApplyModelDefaults(unset); err != nil {
		t.Fatalf("apply defaults: %v", err)
	}
	if err := NewRuleRepo(db).Create(unset); err != nil {
		t.Fatalf("create: %v", err)
	}
	var gotUnset store.Rule
	if err := db.First(&gotUnset, unset.ID).Error; err != nil {
		t.Fatalf("查询: %v", err)
	}
	if gotUnset.Priority != 100 || !gotUnset.Enabled {
		t.Errorf("未提供的字段应取默认值，得到 priority=%d enabled=%v",
			gotUnset.Priority, gotUnset.Enabled)
	}

	// 场景二：用户显式传了 priority=0 / enabled=false。
	// 模拟 json.Unmarshal 覆盖——先填默认值，再由请求体改写。
	explicit := &store.Rule{
		Name: "explicit", PolicyID: policy.ID, Phase: store.PhaseACL,
		Pattern: "block_path:/b", Action: store.RuleAction("intercept"),
	}
	if err := store.ApplyModelDefaults(explicit); err != nil {
		t.Fatalf("apply defaults: %v", err)
	}
	explicit.Priority = 0    // 请求体里的 "priority": 0
	explicit.Enabled = false // 请求体里的 "enabled": false
	if err := NewRuleRepo(db).Create(explicit); err != nil {
		t.Fatalf("create: %v", err)
	}
	var gotExplicit store.Rule
	if err := db.First(&gotExplicit, explicit.ID).Error; err != nil {
		t.Fatalf("查询: %v", err)
	}
	if gotExplicit.Priority != 0 {
		t.Errorf("显式 priority=0 被改成 %d", gotExplicit.Priority)
	}
	if gotExplicit.Enabled {
		t.Error("显式 enabled=false 被改成了启用")
	}
}

// TestUpdateCanDisable 验证停用一个已启用的对象能生效。
//
// 与新建路径不同，Update 用的是 db.Save（全字段 UPDATE），零值本来就能写进去。
// 但这是比新建更常用的路径——站点出问题时管理员要能立刻关停它——值得单独钉住，
// 免得日后有人把 Save 换成 Updates(struct) 时悄悄退化（后者同样会跳过零值）。
func TestUpdateCanDisable(t *testing.T) {
	db := newZeroDefaultsTestDB(t)
	repo := NewSiteRepo(db)

	site := &store.Site{
		Host: "live.example.com", Bind: ":18446",
		UpstreamURLs: `["http://127.0.0.1:8800"]`, Enabled: true,
	}
	if err := repo.Create(site); err != nil {
		t.Fatalf("create site: %v", err)
	}

	site.Enabled = false
	if err := repo.Update(site); err != nil {
		t.Fatalf("update site: %v", err)
	}

	var got store.Site
	if err := db.First(&got, site.ID).Error; err != nil {
		t.Fatalf("查询站点: %v", err)
	}
	if got.Enabled {
		t.Error("停用操作未生效——管理员无法关停站点")
	}
}
