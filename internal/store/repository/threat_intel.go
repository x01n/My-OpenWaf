package repository

import (
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

// ThreatIntelRepo 提供威胁情报订阅源及其派生 IP 条目的持久化操作。
type ThreatIntelRepo struct{ db *gorm.DB }

// NewThreatIntelRepo 构造威胁情报订阅源仓库。
func NewThreatIntelRepo(db *gorm.DB) *ThreatIntelRepo { return &ThreatIntelRepo{db: db} }

// List 返回全部订阅源，按 ID 倒序。
func (r *ThreatIntelRepo) List() ([]store.ThreatIntelFeed, error) {
	var items []store.ThreatIntelFeed
	return items, r.db.Order("id DESC").Find(&items).Error
}

// Get 按主键返回单个订阅源。
func (r *ThreatIntelRepo) Get(id uint) (*store.ThreatIntelFeed, error) {
	var item store.ThreatIntelFeed
	return &item, r.db.First(&item, id).Error
}

// ListEnabled 返回所有已启用的订阅源。
func (r *ThreatIntelRepo) ListEnabled() ([]store.ThreatIntelFeed, error) {
	var items []store.ThreatIntelFeed
	return items, r.db.Where("enabled = ?", true).Find(&items).Error
}

// Create 新建订阅源。
func (r *ThreatIntelRepo) Create(item *store.ThreatIntelFeed) error {
	return r.db.Create(item).Error
}

// Update 全量保存订阅源。
func (r *ThreatIntelRepo) Update(item *store.ThreatIntelFeed) error {
	return r.db.Save(item).Error
}

// Delete 删除订阅源，同时清除其派生的所有 IP 条目（事务保证一致性）。
func (r *ThreatIntelRepo) Delete(id uint) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("feed_id = ?", id).Delete(&store.IPListEntry{}).Error; err != nil {
			return err
		}
		return tx.Delete(&store.ThreatIntelFeed{}, id).Error
	})
}

// ReplaceFeedEntries 以事务方式全量替换某订阅源的 IP 条目：
// 先删除该 feed 的旧条目，再插入新条目。用于每次同步后落库。
func (r *ThreatIntelRepo) ReplaceFeedEntries(feedID uint, entries []store.IPListEntry) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("feed_id = ?", feedID).Delete(&store.IPListEntry{}).Error; err != nil {
			return err
		}
		if len(entries) == 0 {
			return nil
		}
		return tx.Create(&entries).Error
	})
}

// CountFeedEntries 统计某订阅源当前的 IP 条目数量。
func (r *ThreatIntelRepo) CountFeedEntries(feedID uint) int {
	var count int64
	r.db.Model(&store.IPListEntry{}).Where("feed_id = ?", feedID).Count(&count)
	return int(count)
}
