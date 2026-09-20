package repository

import (
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

// JSPluginRepo 管理自定义 JavaScript 边缘脚本。
type JSPluginRepo struct {
	db *gorm.DB
}

func NewJSPluginRepo(db *gorm.DB) *JSPluginRepo { return &JSPluginRepo{db: db} }

// List 返回全部脚本，按阶段与优先级排序。
func (r *JSPluginRepo) List() ([]store.JSPlugin, error) {
	var items []store.JSPlugin
	err := r.db.Order("stage ASC, priority ASC, id ASC").Find(&items).Error
	return items, err
}

// ListEnabled 返回启用的脚本，供运行时加载。
func (r *JSPluginRepo) ListEnabled() ([]store.JSPlugin, error) {
	var items []store.JSPlugin
	err := r.db.Where("enabled = ?", true).
		Order("stage ASC, priority ASC, id ASC").
		Find(&items).Error
	return items, err
}

func (r *JSPluginRepo) Get(id uint) (*store.JSPlugin, error) {
	var item store.JSPlugin
	return &item, r.db.First(&item, id).Error
}

// Create 新建脚本。
func (r *JSPluginRepo) Create(item *store.JSPlugin) error {
	return r.db.Create(item).Error
}

func (r *JSPluginRepo) Update(item *store.JSPlugin) error {
	return r.db.Save(item).Error
}

func (r *JSPluginRepo) Delete(id uint) error {
	return r.db.Delete(&store.JSPlugin{}, id).Error
}

// Toggle 切换启用状态。
func (r *JSPluginRepo) Toggle(id uint, enabled bool) error {
	return r.db.Model(&store.JSPlugin{}).Where("id = ?", id).
		UpdateColumn("enabled", enabled).Error
}
