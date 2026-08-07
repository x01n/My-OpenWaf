package store

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"My-OpenWaf/internal/store/migrations"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

/**
 * BackupData 是完整配置备份的容器。
 *
 * 仅包含"配置类"数据，不含运行日志、会话、管理员凭证。恢复时保留原始主键
 * 以维持模型间的外键关联（Site.CertID → Certificate.ID 等）。
 */
type BackupData struct {
	Version         int       `json:"version"`
	ExportedAt      time.Time `json:"exported_at"`
	DefaultPolicyID *uint     `json:"default_policy_id,omitempty"`

	Certificates      []Certificate          `json:"certificates"`
	Policies          []Policy               `json:"policies"`
	Rules             []Rule                 `json:"rules"`
	Sites             []Site                 `json:"sites"`
	SiteListeners     []SiteListener         `json:"site_listeners"`
	IPListEntries     []IPListEntry          `json:"ip_list_entries"`
	ThreatIntelFeeds  []ThreatIntelFeed      `json:"threat_intel_feeds"`
	CVERuleRecords    []CVERuleRecord        `json:"cve_rule_records"`
	ApplicationRoutes []ApplicationRouteRule `json:"application_routes"`
	SiteAccessConfigs []SiteAccessConfig     `json:"site_access_configs"`
	AccessProviders   []AccessProvider       `json:"access_providers"`
	AccessUsers       []AccessUser           `json:"access_users"`
	AccessPathRules   []AccessPathRule       `json:"access_path_rules"`
	LuaPlugins        []LuaPlugin            `json:"lua_plugins"`
	JSPlugins         []JSPlugin             `json:"js_plugins"`
	SystemSettings    []SystemSettings       `json:"system_settings"`
}

// BackupVersion 是当前备份格式版本号。
const BackupVersion = 1

/**
 * BackupModels 返回 BackupData 覆盖的全部模型，顺序按外键依赖排列（被引用者在前）。
 *
 * 存在的意义是消灭「手写迁移清单」：ExportBackup 会逐表查询，任一表缺失就整体失败，
 * 而失败发生在导出阶段、报的是 "no such table"，不易一眼联想到迁移漏了模型。
 * 测试库请用它做 AutoMigrate，不要各自维护列表——新增备份模型时才不会漏。
 * TestBackupModelsCoverBackupData 会用反射守住它与 BackupData 的一致性。
 */
func BackupModels() []interface{} {
	return []interface{}{
		&Certificate{}, &Policy{}, &Rule{}, &Site{}, &SiteListener{},
		&IPListEntry{}, &ThreatIntelFeed{}, &CVERuleRecord{},
		&ApplicationRouteRule{}, &SiteAccessConfig{}, &AccessProvider{},
		&AccessUser{}, &AccessPathRule{}, &LuaPlugin{}, &JSPlugin{}, &SystemSettings{},
	}
}

/**
 * ExportBackup 从数据库导出全部配置类数据。
 *
 * @param db 数据库句柄。
 * @return 填充完毕的备份数据；查询失败时返回错误。
 */
func ExportBackup(db *gorm.DB) (*BackupData, error) {
	data := &BackupData{
		Version:    BackupVersion,
		ExportedAt: time.Now(),
	}

	// 依次加载各配置表；任一失败即整体失败。
	if err := db.Find(&data.Certificates).Error; err != nil {
		return nil, err
	}
	if err := db.Find(&data.Policies).Error; err != nil {
		return nil, err
	}
	for i := range data.Policies {
		if data.Policies[i].DefaultSlot != nil && *data.Policies[i].DefaultSlot == 1 {
			id := data.Policies[i].ID
			data.DefaultPolicyID = &id
			break
		}
	}
	if err := db.Find(&data.Rules).Error; err != nil {
		return nil, err
	}
	if err := db.Find(&data.Sites).Error; err != nil {
		return nil, err
	}
	if err := db.Find(&data.SiteListeners).Error; err != nil {
		return nil, err
	}
	if err := db.Find(&data.IPListEntries).Error; err != nil {
		return nil, err
	}
	if err := db.Find(&data.ThreatIntelFeeds).Error; err != nil {
		return nil, err
	}
	if err := db.Find(&data.CVERuleRecords).Error; err != nil {
		return nil, err
	}
	if err := db.Find(&data.ApplicationRoutes).Error; err != nil {
		return nil, err
	}
	if err := db.Find(&data.SiteAccessConfigs).Error; err != nil {
		return nil, err
	}
	if err := db.Find(&data.AccessProviders).Error; err != nil {
		return nil, err
	}
	if err := db.Find(&data.AccessUsers).Error; err != nil {
		return nil, err
	}
	if err := db.Find(&data.AccessPathRules).Error; err != nil {
		return nil, err
	}
	if err := db.Find(&data.LuaPlugins).Error; err != nil {
		return nil, err
	}
	if err := db.Find(&data.JSPlugins).Error; err != nil {
		return nil, err
	}
	if err := db.Find(&data.SystemSettings).Error; err != nil {
		return nil, err
	}

	return data, nil
}

/**
 * ImportBackup 将备份数据恢复到数据库，全过程在单个事务中执行。
 *
 * @param db          数据库句柄。
 * @param data        待恢复的备份数据。
 * @param replaceMode true=先清空所有配置表再导入（整体替换）；
 *                    false=保留现有记录并按主键 upsert（合并）。
 * @return 任一步骤失败则整体回滚并返回错误。
 */
func ImportBackup(db *gorm.DB, data *BackupData, replaceMode bool) error {
	sites := normalizeBackupSiteXFFModes(data.Sites)

	return db.Transaction(func(tx *gorm.DB) error {
		if replaceMode {
			if err := clearConfigTables(tx); err != nil {
				return err
			}
		}

		defaultPolicyID := data.DefaultPolicyID
		policies := append([]Policy(nil), data.Policies...)
		for i := range policies {
			if defaultPolicyID == nil && policies[i].DefaultSlot != nil && *policies[i].DefaultSlot == 1 {
				id := policies[i].ID
				defaultPolicyID = &id
			}
			// 先清空导入行的唯一默认槽，避免合并恢复时与目标库当前默认策略冲突。
			policies[i].DefaultSlot = nil
			policies[i].IsDefault = false
		}

		// 按依赖顺序插入：被引用的表在前。
		// 使用 upsert（主键冲突时更新）以保留原始 ID 并支持合并模式。
		ordered := []interface{}{
			data.Certificates,
			policies,
			data.ThreatIntelFeeds,
			sites,
			data.SiteListeners,
			data.Rules,
			data.IPListEntries,
			data.ApplicationRoutes,
			data.CVERuleRecords,
			data.SiteAccessConfigs,
			data.AccessProviders,
			data.AccessUsers,
			data.AccessPathRules,
			// LuaPlugins 与 JSPlugins 排在 Sites 之后：SiteID 非空时指向具体站点。
			data.LuaPlugins,
			data.JSPlugins,
		}
		for _, records := range ordered {
			if err := upsertSlice(tx, records); err != nil {
				return err
			}
		}
		if defaultPolicyID != nil {
			var count int64
			if err := tx.Model(&Policy{}).Where("id = ?", *defaultPolicyID).Count(&count).Error; err != nil {
				return err
			}
			if count != 1 {
				return fmt.Errorf("default_policy_id %d does not reference an imported policy", *defaultPolicyID)
			}
			if err := tx.Unscoped().Model(&Policy{}).Where("default_slot = ?", 1).Update("default_slot", nil).Error; err != nil {
				return err
			}
			one := uint(1)
			if err := tx.Model(&Policy{}).Where("id = ?", *defaultPolicyID).Update("default_slot", &one).Error; err != nil {
				return err
			}
		}

		// SystemSettings 以 key 为唯一键 upsert。
		for i := range data.SystemSettings {
			s := data.SystemSettings[i]
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "key"}},
				DoUpdates: clause.AssignmentColumns([]string{"value"}),
			}).Create(&s).Error; err != nil {
				return err
			}
		}

		// 旧备份可能没有显式默认策略，或带有 0、孤儿和软删除策略引用。
		// 在同一事务内复用幂等迁移，保证恢复完成时引用立即可用。
		if err := migrations.V9EnsureDefaultPolicy(tx); err != nil {
			return fmt.Errorf("repair imported policy references: %w", err)
		}
		return nil
	})
}

func normalizeBackupSiteXFFModes(sites []Site) []Site {
	normalized := make([]Site, len(sites))
	copy(normalized, sites)
	for i := range normalized {
		switch normalized[i].XFFMode {
		case XFFModeStrip, XFFModeTrustOuter:
		default:
			normalized[i].XFFMode = XFFModeStrip
		}
	}
	return normalized
}

/**
 * upsertSlice 对一批记录执行主键冲突时更新的 upsert。
 * 传入的 records 必须是某个模型的切片（如 []Certificate）。
 */
func upsertSlice(tx *gorm.DB, records interface{}) error {
	// 空切片直接跳过，避免 GORM 对空 batch 报错。
	switch v := records.(type) {
	case []Certificate:
		if len(v) == 0 {
			return nil
		}
		return upsertBatch(tx, v)
	case []Policy:
		if len(v) == 0 {
			return nil
		}
		return upsertBatch(tx, v)
	case []Rule:
		if len(v) == 0 {
			return nil
		}
		return upsertBatch(tx, v)
	case []Site:
		if len(v) == 0 {
			return nil
		}
		return upsertBatch(tx, v)
	case []SiteListener:
		if len(v) == 0 {
			return nil
		}
		return upsertBatch(tx, v)
	case []IPListEntry:
		if len(v) == 0 {
			return nil
		}
		return upsertBatch(tx, v)
	case []ThreatIntelFeed:
		if len(v) == 0 {
			return nil
		}
		return upsertBatch(tx, v)
	case []CVERuleRecord:
		if len(v) == 0 {
			return nil
		}
		return upsertBatch(tx, v)
	case []ApplicationRouteRule:
		if len(v) == 0 {
			return nil
		}
		return upsertBatch(tx, v)
	case []SiteAccessConfig:
		if len(v) == 0 {
			return nil
		}
		return upsertBatch(tx, v)
	case []AccessProvider:
		if len(v) == 0 {
			return nil
		}
		return upsertBatch(tx, v)
	case []AccessUser:
		if len(v) == 0 {
			return nil
		}
		return upsertBatch(tx, v)
	case []AccessPathRule:
		if len(v) == 0 {
			return nil
		}
		return upsertBatch(tx, v)
	case []LuaPlugin:
		if len(v) == 0 {
			return nil
		}
		return upsertBatch(tx, v)
	case []JSPlugin:
		if len(v) == 0 {
			return nil
		}
		return upsertBatch(tx, v)
	}
	return nil
}

/**
 * upsertBatch 用主键冲突全列更新的方式批量插入记录，保留原始 ID。
 */
func upsertBatch[T any](tx *gorm.DB, records []T) error {
	// 先留快照：GORM 在 Create 过程中会把「带 default 且当前为零值」的字段
	// 就地改写成默认值（callbacks/create.go 中的
	// field.Set(ctx, rv, field.DefaultValueInterface)），插入之后就读不到原始值了。
	original := make([]T, len(records))
	copy(original, records)

	if err := tx.Clauses(clause.OnConflict{
		UpdateAll: true,
	}).Create(&records).Error; err != nil {
		return err
	}
	return restoreZeroValuedDefaults(tx, records, original)
}

/**
 * restoreZeroValuedDefaults 把「带 default 标签且备份中为零值」的字段显式写回。
 *
 * GORM 在 INSERT 时不会写入这类字段的零值：`callbacks/create.go` 的
 * ConvertToCreateValues 判到 isZero 后，会用 `field.DefaultValueInterface` 顶替，
 * 落库拿到的是默认值而不是备份里的值。`OnConflict{UpdateAll}` 也补不回来——
 * 它的更新列以 `!field.HasDefaultValue` 排除了这类字段。只能在插入后再 UPDATE 一次。
 *
 * 影响的正是「用户主动关掉或清零」的配置，不修就会在恢复时被静默逆转：
 * 停用的站点重新对外服务（`Site.Enabled` 默认 true）、`Rule.Priority` 从 0 变 100
 * 改变规则执行顺序（规则按 priority ASC, ID ASC 排序）、`Site.MaxBodyBytes` 从 0 变
 * 10 MB、停用的 Lua 策略被重新启用。
 *
 * @param inserted 插入后的记录，用于取主键（新记录的主键此时才确定）。
 * @param original 插入前的快照，用于取未被 GORM 改写的原始值。两者按下标一一对应。
 * @return 任一条更新失败即返回错误，由调用方回滚整个导入。
 */
func restoreZeroValuedDefaults[T any](tx *gorm.DB, inserted, original []T) error {
	if len(original) == 0 || len(inserted) != len(original) {
		return nil
	}

	stmt := &gorm.Statement{DB: tx}
	if err := stmt.Parse(&original[0]); err != nil {
		return err
	}
	sch := stmt.Schema
	if sch == nil || sch.PrioritizedPrimaryField == nil {
		return nil
	}

	candidates := ZeroDefaultCandidates(sch)
	if len(candidates) == 0 {
		return nil
	}

	ctx := context.Background()
	pkField := sch.PrioritizedPrimaryField
	for i := range original {
		origVal := reflect.Indirect(reflect.ValueOf(&original[i]))
		updates := make(map[string]interface{}, len(candidates))
		for _, f := range candidates {
			if _, isZero := f.ValueOf(ctx, origVal); isZero {
				updates[f.DBName] = reflect.Zero(f.FieldType).Interface()
			}
		}
		if len(updates) == 0 {
			continue
		}
		pk, zero := pkField.ValueOf(ctx, reflect.Indirect(reflect.ValueOf(&inserted[i])))
		if zero {
			// 没有主键就无法定位记录，跳过好过发出无条件 UPDATE。
			continue
		}
		if err := tx.Model(&inserted[i]).Where(pkField.DBName+" = ?", pk).
			UpdateColumns(updates).Error; err != nil {
			return err
		}
	}
	return nil
}

/**
 * clearConfigTables 按外键逆序清空所有配置表（依赖方在前）。
 * 用于整体替换模式。不触及日志、会话、管理员凭证表。
 */
func clearConfigTables(tx *gorm.DB) error {
	// 逆序：先删引用他表的记录，再删被引用的记录。
	models := []interface{}{
		// JSPlugin 与 LuaPlugin 都可引用 Site，须在 Site 之前清空。
		&JSPlugin{},
		&LuaPlugin{},
		&AccessPathRule{},
		&AccessUser{},
		&AccessProvider{},
		&SiteAccessConfig{},
		&ApplicationRouteRule{},
		&CVERuleRecord{},
		&IPListEntry{},
		&Rule{},
		&SiteListener{},
		&Site{},
		&ThreatIntelFeed{},
		&Policy{},
		&Certificate{},
	}
	for _, m := range models {
		// 使用 Where("1 = 1") 允许全表删除（GORM 默认阻止无条件删除）。
		if err := tx.Where("1 = 1").Delete(m).Error; err != nil {
			return err
		}
	}
	return nil
}
