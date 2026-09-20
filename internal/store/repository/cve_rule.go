package repository

import (
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/cve"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"gorm.io/gorm"
)

const (
	cveCanonicalSnapshotTTL       = 10 * time.Second
	cveCanonicalSnapshotRuleLimit = 10000
)

// CVERuleCanonicalSnapshot is the bounded canonical source used to build all
// scoped CVE views. Callers receive a deep copy and may mutate it safely.
type CVERuleCanonicalSnapshot struct {
	Rules           []cve.CVERuleModel
	OverridesByRule map[uint][]store.CVERuleScopeOverride
}

type cveCanonicalSnapshotEntry struct {
	value     CVERuleCanonicalSnapshot
	expiresAt time.Time
}

type CVERuleRepo struct {
	db *gorm.DB

	reconcileMu    sync.Mutex
	reconcileReady bool

	snapshotMu         sync.RWMutex
	snapshot           *cveCanonicalSnapshotEntry
	snapshotGeneration uint64
	snapshotFlight     singleflight.Group
}

func NewCVERuleRepo(db *gorm.DB) *CVERuleRepo {
	return &CVERuleRepo{db: db}
}

// EnsureBuiltinCatalog provides a once-per-repository fallback for tests and
// alternate entrypoints that do not run the application startup reconciler.
func (r *CVERuleRepo) EnsureBuiltinCatalog() error {
	r.reconcileMu.Lock()
	defer r.reconcileMu.Unlock()
	if r.reconcileReady {
		return nil
	}
	if err := cve.ReconcileBuiltinCatalog(r.db); err != nil {
		return err
	}
	r.reconcileReady = true
	r.InvalidateCanonicalSnapshot()
	return nil
}

// MarkBuiltinCatalogReady records that application startup already completed
// catalog reconciliation, avoiding a redundant first-request fallback query.
func (r *CVERuleRepo) MarkBuiltinCatalogReady() {
	r.reconcileMu.Lock()
	r.reconcileReady = true
	r.reconcileMu.Unlock()
}

// CanonicalSnapshot returns a deep copy of the current rules and scope
// overrides. One cache entry is retained for ten seconds and concurrent cold
// loads are collapsed into a single database read pair.
func (r *CVERuleRepo) CanonicalSnapshot() (CVERuleCanonicalSnapshot, error) {
	if snapshot, ok := r.cachedCanonicalSnapshot(); ok {
		return snapshot, nil
	}
	value, err, _ := r.snapshotFlight.Do("canonical", func() (any, error) {
		if snapshot, ok := r.cachedCanonicalSnapshot(); ok {
			return snapshot, nil
		}
		for {
			generation := r.canonicalSnapshotGeneration()
			snapshot, err := r.loadCanonicalSnapshot()
			if err != nil {
				return nil, err
			}

			r.snapshotMu.Lock()
			if generation != r.snapshotGeneration {
				r.snapshotMu.Unlock()
				continue
			}
			r.snapshot = &cveCanonicalSnapshotEntry{
				value:     snapshot,
				expiresAt: time.Now().Add(cveCanonicalSnapshotTTL),
			}
			r.snapshotMu.Unlock()
			return snapshot, nil
		}
	})
	if err != nil {
		return CVERuleCanonicalSnapshot{}, err
	}
	return cloneCVERuleCanonicalSnapshot(value.(CVERuleCanonicalSnapshot)), nil
}

// InvalidateCanonicalSnapshot invalidates both a warm entry and any in-flight
// load generation. An in-flight loader retries before publishing stale data.
func (r *CVERuleRepo) InvalidateCanonicalSnapshot() {
	r.snapshotMu.Lock()
	r.snapshot = nil
	r.snapshotGeneration++
	r.snapshotMu.Unlock()
}

func (r *CVERuleRepo) cachedCanonicalSnapshot() (CVERuleCanonicalSnapshot, bool) {
	r.snapshotMu.RLock()
	entry := r.snapshot
	fresh := entry != nil && time.Now().Before(entry.expiresAt)
	r.snapshotMu.RUnlock()
	if !fresh {
		return CVERuleCanonicalSnapshot{}, false
	}
	return cloneCVERuleCanonicalSnapshot(entry.value), true
}

func (r *CVERuleRepo) canonicalSnapshotGeneration() uint64 {
	r.snapshotMu.RLock()
	generation := r.snapshotGeneration
	r.snapshotMu.RUnlock()
	return generation
}

func (r *CVERuleRepo) loadCanonicalSnapshot() (CVERuleCanonicalSnapshot, error) {
	var rules []cve.CVERuleModel
	if err := r.db.Order("id DESC").Limit(cveCanonicalSnapshotRuleLimit).Find(&rules).Error; err != nil {
		return CVERuleCanonicalSnapshot{}, err
	}

	overridesByRule := make(map[uint][]store.CVERuleScopeOverride)
	if len(rules) == 0 {
		return CVERuleCanonicalSnapshot{Rules: rules, OverridesByRule: overridesByRule}, nil
	}
	ruleIDs := make([]uint, 0, len(rules))
	for i := range rules {
		ruleIDs = append(ruleIDs, rules[i].ID)
	}
	var overrides []store.CVERuleScopeOverride
	if err := r.db.Where("rule_id IN ?", ruleIDs).Find(&overrides).Error; err != nil {
		return CVERuleCanonicalSnapshot{}, err
	}
	for i := range overrides {
		item := overrides[i]
		overridesByRule[item.RuleID] = append(overridesByRule[item.RuleID], item)
	}
	return CVERuleCanonicalSnapshot{Rules: rules, OverridesByRule: overridesByRule}, nil
}

func cloneCVERuleCanonicalSnapshot(source CVERuleCanonicalSnapshot) CVERuleCanonicalSnapshot {
	cloned := CVERuleCanonicalSnapshot{
		Rules:           append([]cve.CVERuleModel(nil), source.Rules...),
		OverridesByRule: make(map[uint][]store.CVERuleScopeOverride, len(source.OverridesByRule)),
	}
	for ruleID, overrides := range source.OverridesByRule {
		items := make([]store.CVERuleScopeOverride, len(overrides))
		for i := range overrides {
			items[i] = cloneCVERuleScopeOverride(overrides[i])
		}
		cloned.OverridesByRule[ruleID] = items
	}
	return cloned
}

func cloneCVERuleScopeOverride(source store.CVERuleScopeOverride) store.CVERuleScopeOverride {
	cloned := source
	if source.Enabled != nil {
		value := *source.Enabled
		cloned.Enabled = &value
	}
	if source.Action != nil {
		value := *source.Action
		cloned.Action = &value
	}
	if source.Sensitivity != nil {
		value := *source.Sensitivity
		cloned.Sensitivity = &value
	}
	if source.StatusCode != nil {
		value := *source.StatusCode
		cloned.StatusCode = &value
	}
	if source.RedirectTo != nil {
		value := *source.RedirectTo
		cloned.RedirectTo = &value
	}
	if source.CaptchaType != nil {
		value := *source.CaptchaType
		cloned.CaptchaType = &value
	}
	return cloned
}

// CVERuleFilter holds query filters for listing CVE rules.
type CVERuleFilter struct {
	Category string
	Severity string
	Enabled  *bool
	Source   string
	Query    string
}

func (r *CVERuleRepo) List(offset, limit int, f CVERuleFilter) ([]cve.CVERuleModel, int64, error) {
	q := r.db.Model(&cve.CVERuleModel{})
	if f.Category != "" {
		q = q.Where("category = ?", f.Category)
	}
	if f.Severity != "" {
		q = q.Where("severity = ?", f.Severity)
	}
	if f.Enabled != nil {
		q = q.Where("enabled = ?", *f.Enabled)
	}
	if f.Source != "" {
		q = q.Where("source = ?", f.Source)
	}
	if strings.TrimSpace(f.Query) != "" {
		like := "%" + strings.ToLower(strings.TrimSpace(f.Query)) + "%"
		q = q.Where("LOWER(cve_id) LIKE ? OR LOWER(description) LIKE ?", like, like)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var items []cve.CVERuleModel
	if err := q.Offset(offset).Limit(limit).Order("id DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *CVERuleRepo) Get(id uint) (*cve.CVERuleModel, error) {
	var item cve.CVERuleModel
	return &item, r.db.First(&item, id).Error
}

func (r *CVERuleRepo) Create(item *cve.CVERuleModel) error {
	if err := r.db.Create(item).Error; err != nil {
		return err
	}
	r.InvalidateCanonicalSnapshot()
	return nil
}

func (r *CVERuleRepo) Update(item *cve.CVERuleModel) error {
	if err := r.db.Save(item).Error; err != nil {
		return err
	}
	r.InvalidateCanonicalSnapshot()
	return nil
}

func (r *CVERuleRepo) Delete(id uint) error {
	err := r.db.Transaction(func(tx *gorm.DB) error {
		// 作用域覆盖没有数据库级外键约束；删除自定义规则时必须在同一事务
		// 中清理覆盖，否则重建同一规则会继续携带已删除规则的旧配置。
		if err := tx.Where("rule_id = ?", id).Delete(&store.CVERuleScopeOverride{}).Error; err != nil {
			return err
		}
		return tx.Delete(&cve.CVERuleModel{}, id).Error
	})
	if err != nil {
		return err
	}
	r.InvalidateCanonicalSnapshot()
	return nil
}

func (r *CVERuleRepo) Toggle(id uint, enabled bool) error {
	if err := r.db.Model(&cve.CVERuleModel{}).Where("id = ?", id).Update("enabled", enabled).Error; err != nil {
		return err
	}
	r.InvalidateCanonicalSnapshot()
	return nil
}

// PendingApprovalCount returns the number of rules that are not yet approved.
func (r *CVERuleRepo) PendingApprovalCount() (int64, error) {
	var count int64
	err := r.db.Model(&cve.CVERuleModel{}).Where("approved = ?", false).Count(&count).Error
	return count, err
}

func (r *CVERuleRepo) DB() *gorm.DB { return r.db }

type CVESyncLogRepo struct{ db *gorm.DB }

func NewCVESyncLogRepo(db *gorm.DB) *CVESyncLogRepo {
	return &CVESyncLogRepo{db: db}
}

func (r *CVESyncLogRepo) Create(item *store.CVESyncLog) error {
	return r.db.Create(item).Error
}

func (r *CVESyncLogRepo) Latest(limit int) ([]store.CVESyncLog, error) {
	var items []store.CVESyncLog
	err := r.db.Order("id DESC").Limit(limit).Find(&items).Error
	return items, err
}
