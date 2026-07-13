package store

import (
	"time"

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
	Version    int       `json:"version"`
	ExportedAt time.Time `json:"exported_at"`

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
	SystemSettings    []SystemSettings       `json:"system_settings"`
}

// BackupVersion 是当前备份格式版本号。
const BackupVersion = 1

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
	return db.Transaction(func(tx *gorm.DB) error {
		if replaceMode {
			if err := clearConfigTables(tx); err != nil {
				return err
			}
		}

		// 按依赖顺序插入：被引用的表在前。
		// 使用 upsert（主键冲突时更新）以保留原始 ID 并支持合并模式。
		ordered := []interface{}{
			data.Certificates,
			data.Policies,
			data.ThreatIntelFeeds,
			data.Sites,
			data.SiteListeners,
			data.Rules,
			data.IPListEntries,
			data.ApplicationRoutes,
			data.CVERuleRecords,
			data.SiteAccessConfigs,
			data.AccessProviders,
			data.AccessUsers,
			data.AccessPathRules,
		}
		for _, records := range ordered {
			if err := upsertSlice(tx, records); err != nil {
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

		return nil
	})
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
	}
	return nil
}

/**
 * upsertBatch 用主键冲突全列更新的方式批量插入记录，保留原始 ID。
 */
func upsertBatch[T any](tx *gorm.DB, records []T) error {
	return tx.Clauses(clause.OnConflict{
		UpdateAll: true,
	}).Create(&records).Error
}

/**
 * clearConfigTables 按外键逆序清空所有配置表（依赖方在前）。
 * 用于整体替换模式。不触及日志、会话、管理员凭证表。
 */
func clearConfigTables(tx *gorm.DB) error {
	// 逆序：先删引用他表的记录，再删被引用的记录。
	models := []interface{}{
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
