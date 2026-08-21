package repository

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"My-OpenWaf/internal/store"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newFalsePositiveRepoForTest(t *testing.T) *FalsePositiveRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.FalsePositiveReport{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewFalsePositiveRepo(db)
}

func TestFalsePositiveCreateListGetUpdate(t *testing.T) {
	repo := newFalsePositiveRepoForTest(t)

	rec := &store.FalsePositiveReport{
		SecurityEventID: 42,
		RequestID:       "req-abc",
		RuleIDStr:       "owasp:sqli:1001",
		Category:        "owasp",
		ClientIP:        "1.2.3.4",
		Host:            "example.com",
		Path:            "/api/login",
		SubmittedBy:     "admin",
		Note:            "误报 - 是合法登录尝试",
		Status:          "pending",
	}
	if err := repo.Create(rec); err != nil {
		t.Fatalf("create: %v", err)
	}
	if rec.ID == 0 {
		t.Fatal("id not set after create")
	}

	// List 无过滤应返回该记录。
	items, total, err := repo.List(0, 10, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("list count = %d/%d, want 1/1", total, len(items))
	}
	if items[0].Note != rec.Note {
		t.Errorf("note = %q, want %q", items[0].Note, rec.Note)
	}

	// Get by id。
	got, err := repo.Get(rec.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.RuleIDStr != rec.RuleIDStr {
		t.Errorf("rule = %q, want %q", got.RuleIDStr, rec.RuleIDStr)
	}

	// UpdateStatus。
	if err := repo.UpdateStatus(rec.ID, "confirmed"); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = repo.Get(rec.ID)
	if got.Status != "confirmed" {
		t.Errorf("status = %q, want confirmed", got.Status)
	}

	// List 按 status 过滤。
	_, cnt, _ := repo.List(0, 10, "pending")
	if cnt != 0 {
		t.Errorf("pending count = %d, want 0 after status change", cnt)
	}
	_, cnt, _ = repo.List(0, 10, "confirmed")
	if cnt != 1 {
		t.Errorf("confirmed count = %d, want 1", cnt)
	}

	// Delete。
	if err := repo.Delete(rec.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, cnt, _ = repo.List(0, 10, "")
	if cnt != 0 {
		t.Errorf("count after delete = %d, want 0", cnt)
	}
}

/**
 * newFalsePositiveReportForTest 构造一条带指定去重键的反馈记录。
 */
func newFalsePositiveReportForTest(sourceEventKey string) *store.FalsePositiveReport {
	rec := &store.FalsePositiveReport{
		SecurityEventID: 7,
		RequestID:       "req-dedupe",
		RuleIDStr:       "owasp:xss:2002",
		Category:        "owasp",
		ClientIP:        "203.0.113.9",
		Host:            "example.com",
		Path:            "/search",
		Status:          "pending",
	}
	if sourceEventKey != "" {
		key := sourceEventKey
		rec.SourceEventKey = &key
	}
	return rec
}

func TestFalsePositiveCreateOrGetBySourceEventRequiresKey(t *testing.T) {
	repo := newFalsePositiveRepoForTest(t)

	// nil 记录、nil 键、空字符串键三种输入都应被实现拒绝且不落库。
	if _, created, err := repo.CreateOrGetBySourceEvent(nil); err == nil || created {
		t.Errorf("nil record: err = %v, created = %v, want error and created=false", err, created)
	}
	if _, created, err := repo.CreateOrGetBySourceEvent(newFalsePositiveReportForTest("")); err == nil || created {
		t.Errorf("nil key: err = %v, created = %v, want error and created=false", err, created)
	}
	emptyKey := ""
	recEmpty := newFalsePositiveReportForTest("placeholder")
	recEmpty.SourceEventKey = &emptyKey
	if _, created, err := repo.CreateOrGetBySourceEvent(recEmpty); err == nil || created {
		t.Errorf("empty key: err = %v, created = %v, want error and created=false", err, created)
	}

	if _, total, err := repo.List(0, 10, ""); err != nil {
		t.Fatalf("list: %v", err)
	} else if total != 0 {
		t.Errorf("stored records = %d, want 0", total)
	}
}

func TestFalsePositiveCreateOrGetBySourceEventDeduplicates(t *testing.T) {
	repo := newFalsePositiveRepoForTest(t)
	const key = "security-event:31"

	first, created, err := repo.CreateOrGetBySourceEvent(newFalsePositiveReportForTest(key))
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	if !created {
		t.Fatal("first create created = false, want true")
	}

	second := newFalsePositiveReportForTest(key)
	second.Note = "第二次提交的备注应被忽略"
	got, created, err := repo.CreateOrGetBySourceEvent(second)
	if err != nil {
		t.Fatalf("second create: %v", err)
	}
	if created {
		t.Error("second create created = true, want false")
	}
	if got.ID != first.ID {
		t.Errorf("second create id = %d, want %d", got.ID, first.ID)
	}
	if got.Note != first.Note {
		t.Errorf("second create note = %q, want existing %q", got.Note, first.Note)
	}
	if _, total, err := repo.List(0, 10, ""); err != nil {
		t.Fatalf("list: %v", err)
	} else if total != 1 {
		t.Errorf("stored records = %d, want 1", total)
	}
}

func TestFalsePositiveDeleteReleasesSourceEventKey(t *testing.T) {
	repo := newFalsePositiveRepoForTest(t)
	const key = "security-event:44"

	first, created, err := repo.CreateOrGetBySourceEvent(newFalsePositiveReportForTest(key))
	if err != nil || !created {
		t.Fatalf("seed create: err = %v, created = %v", err, created)
	}
	if err := repo.Delete(first.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// 软删除已释放唯一键，同一源事件可再次提交反馈。
	second, created, err := repo.CreateOrGetBySourceEvent(newFalsePositiveReportForTest(key))
	if err != nil {
		t.Fatalf("recreate after delete: %v", err)
	}
	if !created {
		t.Fatal("recreate after delete created = false, want true")
	}
	if second.ID == first.ID {
		t.Errorf("recreated id = %d, want a new row distinct from %d", second.ID, first.ID)
	}
	if _, total, err := repo.List(0, 10, ""); err != nil {
		t.Fatalf("list: %v", err)
	} else if total != 1 {
		t.Errorf("live records = %d, want 1", total)
	}
}

func TestFalsePositiveUpdateStatusAndDeleteMissingID(t *testing.T) {
	repo := newFalsePositiveRepoForTest(t)

	err := repo.UpdateStatus(4242, "confirmed")
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("UpdateStatus on missing id = %v, want gorm.ErrRecordNotFound", err)
	}
	err = repo.Delete(4242)
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("Delete on missing id = %v, want gorm.ErrRecordNotFound", err)
	}

	// 已存在记录的重复删除同样应报告"不存在"。
	rec, created, err := repo.CreateOrGetBySourceEvent(newFalsePositiveReportForTest("security-event:55"))
	if err != nil || !created {
		t.Fatalf("seed create: err = %v, created = %v", err, created)
	}
	if err := repo.Delete(rec.ID); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := repo.Delete(rec.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("second delete = %v, want gorm.ErrRecordNotFound", err)
	}

	// 状态未变化时也不能被误判为记录不存在。
	live, created, err := repo.CreateOrGetBySourceEvent(newFalsePositiveReportForTest("security-event:56"))
	if err != nil || !created {
		t.Fatalf("seed live record: err = %v, created = %v", err, created)
	}
	if err := repo.UpdateStatus(live.ID, live.Status); err != nil {
		t.Errorf("UpdateStatus with unchanged status = %v, want nil", err)
	}
}

func TestFalsePositiveCreateOrGetBySourceEventConcurrent(t *testing.T) {
	// 并发用例必须让所有 goroutine 看到同一份数据：纯 ":memory:" 每条连接各自持有
	// 私有库，database/sql 连接池一旦开出第二条连接断言就失去意义，故改用临时文件库，
	// 并沿用 internal/core/database 的 WAL + busy_timeout 组合吸收写锁竞争。
	dsn := filepath.Join(t.TempDir(), "false_positive.db") + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.FalsePositiveReport{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(8)
	repo := NewFalsePositiveRepo(db)

	const workers = 8
	const key = "security-event:concurrent"
	type outcome struct {
		id      uint
		created bool
		err     error
	}
	results := make([]outcome, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := range workers {
		go func(idx int) {
			defer wg.Done()
			<-start
			saved, created, err := repo.CreateOrGetBySourceEvent(newFalsePositiveReportForTest(key))
			res := outcome{created: created, err: err}
			if saved != nil {
				res.id = saved.ID
			}
			results[idx] = res
		}(i)
	}
	close(start)
	wg.Wait()

	createdCount := 0
	var sharedID uint
	for i, res := range results {
		if res.err != nil {
			t.Fatalf("worker %d: %v", i, res.err)
		}
		if res.created {
			createdCount++
		}
		if sharedID == 0 {
			sharedID = res.id
		} else if res.id != sharedID {
			t.Errorf("worker %d returned id %d, want all workers to share id %d", i, res.id, sharedID)
		}
	}
	if createdCount != 1 {
		t.Errorf("created=true count = %d, want exactly 1", createdCount)
	}
	if _, total, err := repo.List(0, 20, ""); err != nil {
		t.Fatalf("list: %v", err)
	} else if total != 1 {
		t.Errorf("stored records = %d, want 1", total)
	}
}
