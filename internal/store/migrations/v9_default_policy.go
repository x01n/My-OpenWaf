package migrations

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

type v9Policy struct {
	ID          uint
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt
	Name        string
	Description string
	DefaultSlot *uint
}

func (v9Policy) TableName() string { return "policies" }

// V9EnsureDefaultPolicy repairs legacy policy references and establishes one explicit default policy.
func V9EnsureDefaultPolicy(db *gorm.DB) error {
	if !db.Migrator().HasTable("policies") || !db.Migrator().HasColumn("policies", "default_slot") {
		return nil
	}
	return db.Transaction(func(tx *gorm.DB) error {
		// 唯一默认槽必须只由活动策略持有；软删除行保留槽会阻止创建或切换默认策略。
		if err := tx.Unscoped().Model(&v9Policy{}).
			Where("deleted_at IS NOT NULL AND default_slot IS NOT NULL").
			Update("default_slot", nil).Error; err != nil {
			return fmt.Errorf("release deleted default policy slots: %w", err)
		}

		var defaults []v9Policy
		if err := tx.Where("default_slot = ?", 1).Order("id ASC").Find(&defaults).Error; err != nil {
			return err
		}
		var defaultID uint
		if len(defaults) == 0 {
			item := v9Policy{Name: "Default Policy", Description: "System default policy", DefaultSlot: uintPtr(1)}
			if err := tx.Create(&item).Error; err != nil {
				return fmt.Errorf("create default policy: %w", err)
			}
			defaultID = item.ID
		} else {
			defaultID = defaults[0].ID
			if len(defaults) > 1 {
				ids := make([]uint, 0, len(defaults)-1)
				for _, item := range defaults[1:] {
					ids = append(ids, item.ID)
				}
				if err := tx.Model(&v9Policy{}).Where("id IN ?", ids).Update("default_slot", nil).Error; err != nil {
					return err
				}
			}
		}

		if tx.Migrator().HasTable("rules") {
			if err := tx.Exec(`UPDATE rules SET policy_id = ? WHERE policy_id IS NULL OR policy_id = 0 OR NOT EXISTS (SELECT 1 FROM policies p WHERE p.id = rules.policy_id AND p.deleted_at IS NULL)`, defaultID).Error; err != nil {
				return fmt.Errorf("repair rule policy references: %w", err)
			}
		}
		if tx.Migrator().HasTable("sites") {
			if err := tx.Exec(`UPDATE sites SET policy_id = NULL WHERE policy_id = 0 OR (policy_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM policies p WHERE p.id = sites.policy_id AND p.deleted_at IS NULL))`).Error; err != nil {
				return fmt.Errorf("repair site policy references: %w", err)
			}
		}
		return nil
	})
}

func uintPtr(value uint) *uint { return &value }
