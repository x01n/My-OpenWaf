package store

import (
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// atomicityProbe 是只为「插入 + 回写零值必须原子」这一条测试存在的模型。
//
// Num 带 default:1，而建表语句上挂着 `CHECK (num = 1)`：插入时数据库默认值 1 满足
// 约束，回写零值 0 必然违反约束。于是「Create 成功但 UpdateColumns 失败」这个原本
// 难以捕捉的窗口可以被稳定复现，不必依赖时序或注入回调。
//
// 测试自己负责建表（不用 AutoMigrate），这样 CHECK 约束由测试掌控。
type atomicityProbe struct {
	ID  uint `gorm:"primaryKey" json:"id"`
	Num int  `gorm:"default:1" json:"num"`
}

func (atomicityProbe) TableName() string { return "atomicity_probe" }

// newAtomicityProbeDB 建一个与生产配置一致（SkipDefaultTransaction: true）的内存库。
//
// 这条设置是关键：生产库（internal/core/database/gorm.go）关掉了 GORM 的默认事务，
// 单条 Create 不带任何事务保护，两条语句之间必须由调用方自己包事务。
func newAtomicityProbeDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		SkipDefaultTransaction: true,
		Logger:                 gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Exec(
		`CREATE TABLE atomicity_probe (id integer PRIMARY KEY AUTOINCREMENT, num integer NOT NULL CHECK (num = 1))`,
	).Error; err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	return db
}

// TestCreateWithZeroDefaultsRollsBackWhenWritebackFails 守护「插入与回写同事务」。
//
// 缺陷形态：Create 成功、UpdateColumns 失败时函数返回错误，但行已经落库且零值没有
// 回写。调用方按错误判定「创建失败」，界面上却没有这条记录——而库里的行已经存在
// 并可能立刻生效（Enabled=false 却被写成 true 的站点会直接开始代理流量）。
//
// probe 表上的 CHECK 约束让「Create 成功但 UpdateColumns 失败」这个窗口可稳定复现：
// 插入时数据库默认值 1 通过约束，回写零值 0 必然违反约束。
func TestCreateWithZeroDefaultsRollsBackWhenWritebackFails(t *testing.T) {
	db := newAtomicityProbeDB(t)

	item := &atomicityProbe{Num: 0}
	err := CreateWithZeroDefaults(db, item)
	if err == nil {
		t.Fatal("回写零值违反 CHECK 约束，必须返回错误；拿到 nil 说明错误被吞掉了")
	}

	var rows int64
	if err := db.Model(&atomicityProbe{}).Count(&rows).Error; err != nil {
		t.Fatalf("count probe rows: %v", err)
	}
	if rows != 0 {
		t.Fatalf("插入已回滚但库里仍有 %d 行；调用方拿到错误、库里却留下记录，这正是无事务的缺陷形态", rows)
	}
}

// TestCreateWithZeroDefaultsKeepsStructConsistentOnRollback 记录失败路径上的对象状态。
//
// 回滚后调用方手里的对象必须等于「用户最初传入的零值」——它不该被 GORM 顶替成数据库
// 默认值（1），否则调用方按错误判定失败、手里却拿着一个看似已生效的对象。
//
// 注意这里的 0 不是本函数的内存回写产生的：gorm 的 UpdateColumns 在把赋值列表写入
// 结构体后才执行 UPDATE，语句失败也照样生效。因此「内存回写排在提交之后」这一顺序
// 要求无法由结构体状态区分，只能靠代码审查保证，测试覆盖不到。
func TestCreateWithZeroDefaultsKeepsStructConsistentOnRollback(t *testing.T) {
	db := newAtomicityProbeDB(t)

	item := &atomicityProbe{Num: 0}
	if err := CreateWithZeroDefaults(db, item); err == nil {
		t.Fatal("回写零值违反 CHECK 约束，必须返回错误")
	}
	if item.Num != 0 {
		t.Errorf("item.Num = %d, want 0（用户传入的原始零值）；对象被 GORM 顶替成了默认值，"+
			"而调用方拿到的是错误", item.Num)
	}
}

// TestCreateWithZeroDefaultsCommitsBothStatementsOnSuccess 守住成功路径未被事务破坏。
//
// 加事务只允许改变失败路径的语义；插入成功时零值回写仍须落库、行仍须存在。
func TestCreateWithZeroDefaultsCommitsBothStatementsOnSuccess(t *testing.T) {
	db := newAtomicityProbeDB(t)

	// 不触发回写：Num 保持零值时会被 GORM 用默认值 1 顶替，CHECK 约束不阻挡插入，
	// 但没有 zeroed 字段（回写时的 0 会违反约束），所以这里改用「显式非零值」路径。
	ok := &atomicityProbe{Num: 1}
	if err := CreateWithZeroDefaults(db, ok); err != nil {
		t.Fatalf("create with explicit value: %v", err)
	}
	if ok.ID == 0 {
		t.Fatal("主键未回填")
	}
	var got atomicityProbe
	if err := db.First(&got, ok.ID).Error; err != nil {
		t.Fatalf("load probe row: %v", err)
	}
	if got.Num != 1 {
		t.Errorf("num = %d, want 1", got.Num)
	}
}
