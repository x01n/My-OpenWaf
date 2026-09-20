package cve

import (
	"sync/atomic"
	"testing"

	"My-OpenWaf/internal/store"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type catalogSQLCounter struct {
	queries atomic.Int64
	creates atomic.Int64
	updates atomic.Int64
	deletes atomic.Int64
}

func newCatalogTestDB(t *testing.T) (*gorm.DB, *catalogSQLCounter) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&CVERuleModel{}, &store.CVERuleScopeOverride{}); err != nil {
		t.Fatalf("migrate CVE catalog: %v", err)
	}
	counter := &catalogSQLCounter{}
	if err := db.Callback().Query().Before("gorm:query").Register("test:cve-catalog-query", func(*gorm.DB) {
		counter.queries.Add(1)
	}); err != nil {
		t.Fatalf("register query callback: %v", err)
	}
	if err := db.Callback().Create().Before("gorm:create").Register("test:cve-catalog-create", func(*gorm.DB) {
		counter.creates.Add(1)
	}); err != nil {
		t.Fatalf("register create callback: %v", err)
	}
	if err := db.Callback().Update().Before("gorm:update").Register("test:cve-catalog-update", func(*gorm.DB) {
		counter.updates.Add(1)
	}); err != nil {
		t.Fatalf("register update callback: %v", err)
	}
	if err := db.Callback().Delete().Before("gorm:delete").Register("test:cve-catalog-delete", func(*gorm.DB) {
		counter.deletes.Add(1)
	}); err != nil {
		t.Fatalf("register delete callback: %v", err)
	}
	return db, counter
}

func (c *catalogSQLCounter) reset() {
	c.queries.Store(0)
	c.creates.Store(0)
	c.updates.Store(0)
	c.deletes.Store(0)
}

func TestReconcileBuiltinCatalogBatchesMissingAndSkipsUnchangedWrites(t *testing.T) {
	db, counter := newCatalogTestDB(t)
	definitions := builtinCatalogModels()
	if len(definitions) == 0 {
		t.Fatal("expected built-in CVE definitions")
	}

	counter.reset()
	if err := ReconcileBuiltinCatalog(db); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if got := counter.queries.Load(); got != 1 {
		t.Fatalf("first reconcile query callbacks=%d want=1", got)
	}
	if got := counter.creates.Load(); got != 1 {
		t.Fatalf("first reconcile create callbacks=%d want one batch", got)
	}
	if got := counter.updates.Load(); got != 0 {
		t.Fatalf("first reconcile update callbacks=%d want=0", got)
	}
	var rows []CVERuleModel
	if err := db.Where("source = ?", builtinCatalogSource).Order("pattern ASC").Find(&rows).Error; err != nil {
		t.Fatalf("list reconciled catalog: %v", err)
	}
	if len(rows) != len(definitions) {
		t.Fatalf("catalog rows=%d want=%d", len(rows), len(definitions))
	}
	updatedAt := make(map[uint]int64, len(rows))
	for i := range rows {
		updatedAt[rows[i].ID] = rows[i].UpdatedAt.UnixNano()
	}

	counter.reset()
	if err := ReconcileBuiltinCatalog(db); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if got := counter.queries.Load(); got != 1 {
		t.Fatalf("second reconcile query callbacks=%d want=1", got)
	}
	if got := counter.creates.Load(); got != 0 {
		t.Fatalf("second reconcile create callbacks=%d want=0", got)
	}
	if got := counter.updates.Load(); got != 0 {
		t.Fatalf("second reconcile update callbacks=%d want=0", got)
	}
	if got := counter.deletes.Load(); got != 0 {
		t.Fatalf("second reconcile delete callbacks=%d want=0", got)
	}
	var unchanged []CVERuleModel
	if err := db.Where("source = ?", builtinCatalogSource).Find(&unchanged).Error; err != nil {
		t.Fatalf("list unchanged catalog: %v", err)
	}
	for i := range unchanged {
		if got := unchanged[i].UpdatedAt.UnixNano(); got != updatedAt[unchanged[i].ID] {
			t.Fatalf("unchanged rule %d updated_at=%d want=%d", unchanged[i].ID, got, updatedAt[unchanged[i].ID])
		}
	}
}

func TestReconcileBuiltinCatalogPreservesDuplicateRowsAndOverrides(t *testing.T) {
	db, counter := newCatalogTestDB(t)
	if err := ReconcileBuiltinCatalog(db); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	desired := builtinCatalogModels()[0]
	var original CVERuleModel
	if err := db.Where("source = ? AND pattern = ?", builtinCatalogSource, desired.Pattern).First(&original).Error; err != nil {
		t.Fatalf("load original catalog row: %v", err)
	}
	original.Description = "stale original metadata"
	original.Category = "stale"
	original.Enabled = !desired.Enabled
	original.Action = "observe"
	if err := db.Save(&original).Error; err != nil {
		t.Fatalf("stale original row: %v", err)
	}
	duplicate := original
	duplicate.ID = 0
	duplicate.Description = "stale duplicate metadata"
	duplicate.Action = "challenge"
	if err := db.Create(&duplicate).Error; err != nil {
		t.Fatalf("create duplicate row: %v", err)
	}
	overrideEnabled := true
	override := store.CVERuleScopeOverride{
		RuleID:    duplicate.ID,
		ScopeType: store.CVEScopeGlobal,
		ScopeID:   0,
		Enabled:   &overrideEnabled,
	}
	if err := db.Create(&override).Error; err != nil {
		t.Fatalf("create duplicate override: %v", err)
	}

	counter.reset()
	if err := ReconcileBuiltinCatalog(db); err != nil {
		t.Fatalf("reconcile duplicates: %v", err)
	}
	if got := counter.deletes.Load(); got != 0 {
		t.Fatalf("delete callbacks=%d want=0", got)
	}
	var duplicates []CVERuleModel
	if err := db.Where("source = ? AND pattern = ?", builtinCatalogSource, desired.Pattern).Order("id ASC").Find(&duplicates).Error; err != nil {
		t.Fatalf("list duplicate rows: %v", err)
	}
	if len(duplicates) != 2 {
		t.Fatalf("duplicate rows=%d want=2", len(duplicates))
	}
	for i := range duplicates {
		if !catalogMetadataEqual(duplicates[i], desired) {
			t.Fatalf("duplicate[%d] metadata not reconciled: %#v", i, duplicates[i])
		}
	}
	if duplicates[0].Action != "observe" || duplicates[1].Action != "challenge" {
		t.Fatalf("actions changed: %q, %q", duplicates[0].Action, duplicates[1].Action)
	}
	var savedOverride store.CVERuleScopeOverride
	if err := db.First(&savedOverride, override.ID).Error; err != nil {
		t.Fatalf("duplicate override removed: %v", err)
	}
	if savedOverride.RuleID != duplicate.ID {
		t.Fatalf("override rule_id=%d want=%d", savedOverride.RuleID, duplicate.ID)
	}
}
