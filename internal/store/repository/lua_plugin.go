package repository

import (
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

// LuaPluginRepo 管理自定义 Lua 策略脚本。
type LuaPluginRepo struct {
	db *gorm.DB
}

func NewLuaPluginRepo(db *gorm.DB) *LuaPluginRepo { return &LuaPluginRepo{db: db} }

// List 返回全部脚本，按阶段与优先级排序。
func (r *LuaPluginRepo) List() ([]store.LuaPlugin, error) {
	var items []store.LuaPlugin
	err := r.db.Order("stage ASC, priority ASC, id ASC").Find(&items).Error
	return items, err
}

// ListEnabled 返回启用的脚本，供 snapshot 编译。
// 排序决定同阶段内的执行顺序，必须稳定：priority 相同时按 id 兜底。
func (r *LuaPluginRepo) ListEnabled() ([]store.LuaPlugin, error) {
	var items []store.LuaPlugin
	err := r.db.Where("enabled = ?", true).
		Order("stage ASC, priority ASC, id ASC").
		Find(&items).Error
	return items, err
}

func (r *LuaPluginRepo) Get(id uint) (*store.LuaPlugin, error) {
	var item store.LuaPlugin
	return &item, r.db.First(&item, id).Error
}

// Create 新建脚本。
//
// Enabled 带 gorm default:true，插入 false 会被当作零值改用默认值，
// 故显式禁用时需在插入后回写该列（与 ApplicationRouteRuleRepo.Create 同一处理）。
func (r *LuaPluginRepo) Create(item *store.LuaPlugin) error {
	enabled := item.Enabled
	if err := r.db.Create(item).Error; err != nil {
		return err
	}
	if !enabled {
		if err := r.db.Model(item).UpdateColumn("enabled", false).Error; err != nil {
			return err
		}
		item.Enabled = false
	}
	return nil
}

func (r *LuaPluginRepo) Update(item *store.LuaPlugin) error {
	return r.db.Save(item).Error
}

func (r *LuaPluginRepo) Delete(id uint) error {
	return r.db.Delete(&store.LuaPlugin{}, id).Error
}

// Toggle 切换启用状态。
func (r *LuaPluginRepo) Toggle(id uint, enabled bool) error {
	return r.db.Model(&store.LuaPlugin{}).Where("id = ?", id).
		UpdateColumn("enabled", enabled).Error
}
