package snapshot

import (
	"time"

	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/luaplugin"
)

/**
 * loadLuaPlugins 读取启用的 Lua 脚本并编译。
 *
 * 单个脚本编译失败不返回错误，而是记入 errors 映射：一处语法错误不应导致
 * 整次配置重载失败、进而让其他正常配置也无法生效。调用方通过
 * Snapshot.LuaPluginErrors 把失败暴露给管理端。
 *
 * @param db 数据库句柄。
 * @return 已编译脚本、按脚本名索引的编译错误。表不存在或查询失败时返回两个 nil。
 */
func loadLuaPlugins(db *gorm.DB) ([]*luaplugin.Script, map[string]string) {
	var rows []store.LuaPlugin
	// 排序决定同阶段内的执行顺序，priority 相同时按 id 兜底以保证稳定。
	if err := db.Where("enabled = ?", true).
		Order("stage ASC, priority ASC, id ASC").
		Find(&rows).Error; err != nil {
		// 查询失败（最常见是表尚未迁移）不返回错误：Build 失败会让整个 WAF
		// 起不来，而自定义插件缺失只应导致该功能不可用。与 site_access_configs、
		// ip_list_entries 等可选表的加载保持同一容错策略。
		return nil, nil
	}
	if len(rows) == 0 {
		return nil, nil
	}

	scripts := make([]*luaplugin.Script, 0, len(rows))
	var errs map[string]string

	for i := range rows {
		row := &rows[i]
		stage := luaplugin.Stage(row.Stage)
		if !stage.Valid() {
			if errs == nil {
				errs = make(map[string]string)
			}
			errs[row.Name] = "unsupported stage " + row.Stage + " (want pre or post)"
			continue
		}

		script, err := luaplugin.Compile(row.Name, stage, row.Source)
		if err != nil {
			if errs == nil {
				errs = make(map[string]string)
			}
			errs[row.Name] = err.Error()
			continue
		}
		script.SetID(row.ID)
		script.SetSiteID(row.SiteID)
		if row.TimeoutMS > 0 {
			script.SetTimeout(time.Duration(row.TimeoutMS) * time.Millisecond)
		}
		scripts = append(scripts, script)
	}

	return scripts, errs
}
