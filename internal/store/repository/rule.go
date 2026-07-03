package repository

import (
	"errors"
	"strings"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type RuleFilter struct {
	PolicyID *uint
	Query    string
}

const ruleExecutionOrderClause = "CASE phase WHEN 'acl' THEN 1 WHEN 'signature' THEN 2 WHEN 'custom' THEN 3 ELSE 99 END ASC, priority ASC, id ASC"

type RuleRepo struct{ db *gorm.DB }

func NewRuleRepo(db *gorm.DB) *RuleRepo { return &RuleRepo{db: db} }

func (r *RuleRepo) BatchCreate(items []store.Rule) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		return tx.Create(&items).Error
	})
}

func (r *RuleRepo) List(offset, limit int) ([]store.Rule, int64, error) {
	return r.ListFiltered(offset, limit, RuleFilter{})
}

func (r *RuleRepo) ListFiltered(offset, limit int, f RuleFilter) ([]store.Rule, int64, error) {
	var items []store.Rule
	var total int64
	q := r.db.Model(&store.Rule{})
	if f.PolicyID != nil {
		q = q.Where("policy_id = ?", *f.PolicyID)
	}
	if strings.TrimSpace(f.Query) != "" {
		like := "%" + strings.TrimSpace(f.Query) + "%"
		q = q.Where("name LIKE ? OR pattern LIKE ?", like, like)
	}
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := q.Offset(offset).Limit(limit).Order(ruleExecutionOrderClause).Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *RuleRepo) ListByPolicy(policyID uint) ([]store.Rule, error) {
	var items []store.Rule
	return items, r.db.Where("policy_id = ?", policyID).Order(ruleExecutionOrderClause).Find(&items).Error
}

func (r *RuleRepo) FindPriorityConflict(policyID uint, phase store.RulePhase, priority int, excludeID uint) (*store.Rule, error) {
	var item store.Rule
	q := r.db.
		Where("policy_id = ? AND phase = ? AND priority = ?", policyID, phase, priority).
		Order("id ASC")
	if excludeID != 0 {
		q = q.Where("id <> ?", excludeID)
	}
	if err := q.First(&item).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &item, nil
}

func (r *RuleRepo) Get(id uint) (*store.Rule, error) {
	var item store.Rule
	return &item, r.db.First(&item, id).Error
}

func (r *RuleRepo) Create(item *store.Rule) error { return r.db.Create(item).Error }

func (r *RuleRepo) Update(item *store.Rule) error { return r.db.Save(item).Error }

func (r *RuleRepo) Delete(id uint) error { return r.db.Delete(&store.Rule{}, id).Error }
