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
 * @return 已编译脚本、按脚本名索引的编译错误、数据库查询错误。单个脚本编译错误仍记录在 errors 映射中。
 */
func loadLuaPlugins(db *gorm.DB) ([]*luaplugin.Script, map[string]string, error) {
	if !db.Migrator().HasTable(&store.LuaPlugin{}) {
		return nil, nil, nil
	}
	var rows []store.LuaPlugin
	// 排序决定同阶段内的执行顺序，priority 相同时按 id 兜底以保证稳定。
	if err := db.Where("enabled = ?", true).
		Order("stage ASC, priority ASC, id ASC").
		Find(&rows).Error; err != nil {
		return nil, nil, err
	}
	if len(rows) == 0 {
		return nil, nil, nil
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

	return scripts, errs, nil
}
