package snapshot

import (
	"fmt"
	"strconv"
	"time"

	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/jsplugin"
)

// loadJSPlugins 读取启用的 JavaScript 脚本并编译。
//
// fail-open 脚本的编译错误只记录诊断；request-stage fail-closed 脚本编译失败时载入固定失败守卫，
// 使其他脚本仍可随 snapshot 原子发布，同时确保该脚本命中的请求不会静默放行。
const jsFailClosedBuildGuardSource = `export default {
  fetch() {
    throw new Error("jsplugin: fail-closed build guard")
  }
}`

const jsMaxTimeoutMS = 1000

// JSPluginErrorKey 返回 JSPluginErrors 使用的稳定脚本标识。
func JSPluginErrorKey(id uint) string {
	return strconv.FormatUint(uint64(id), 10)
}

func loadJSPlugins(db *gorm.DB) ([]*jsplugin.Script, map[string]string, error) {
	if !db.Migrator().HasTable(&store.JSPlugin{}) {
		return nil, nil, nil
	}
	var rows []store.JSPlugin
	if err := db.Where("enabled = ?", true).
		Order("stage ASC, priority ASC, id ASC").
		Find(&rows).Error; err != nil {
		return nil, nil, err
	}
	if len(rows) == 0 {
		return nil, nil, nil
	}

	scripts := make([]*jsplugin.Script, 0, len(rows))
	var errs map[string]string
	addError := func(id uint, message string) {
		if errs == nil {
			errs = make(map[string]string)
		}
		errs[JSPluginErrorKey(id)] = message
	}
	for i := range rows {
		row := &rows[i]
		if row.Stage == store.JSStageResponse {
			addError(row.ID, "response stage is unavailable because response execution is not implemented")
			continue
		}
		if row.Stage != store.JSStageRequest {
			addError(row.ID, fmt.Sprintf("unsupported stage %s (want %s)", row.Stage, store.JSStageRequest))
			continue
		}
		if row.FailureMode != store.JSFailureModeOpen && row.FailureMode != store.JSFailureModeClosed {
			addError(row.ID, fmt.Sprintf("unsupported failure mode %s (want %s or %s)", row.FailureMode, store.JSFailureModeOpen, store.JSFailureModeClosed))
			continue
		}
		options := jsplugin.ScriptOptions{Name: row.Name}
		if row.SiteID != nil {
			options.SiteIDs = []uint{*row.SiteID}
		}
		metadata := jsplugin.ScriptMetadata{
			ID:          row.ID,
			Stage:       row.Stage,
			Priority:    row.Priority,
			FailureMode: row.FailureMode,
			SiteID:      row.SiteID,
		}
		if row.TimeoutMS < 0 || row.TimeoutMS > jsMaxTimeoutMS {
			addError(row.ID, fmt.Sprintf("timeout_ms must be between 0 and %d", jsMaxTimeoutMS))
			if row.Stage == store.JSStageRequest && row.FailureMode == store.JSFailureModeClosed {
				guard, guardErr := jsplugin.CompileWithMetadata(row.Name, jsFailClosedBuildGuardSource, options, metadata)
				if guardErr != nil {
					return nil, errs, fmt.Errorf("compile fail-closed request JavaScript plugin guard %d (%s): %w", row.ID, row.Name, guardErr)
				}
				scripts = append(scripts, guard)
			}
			continue
		}
		if row.TimeoutMS > 0 {
			options.Timeout = time.Duration(row.TimeoutMS) * time.Millisecond
		}
		script, err := jsplugin.CompileWithMetadata(row.Name, row.Source, options, metadata)
		if err != nil {
			addError(row.ID, err.Error())
			if row.Stage == store.JSStageRequest && row.FailureMode == store.JSFailureModeClosed {
				guard, guardErr := jsplugin.CompileWithMetadata(row.Name, jsFailClosedBuildGuardSource, options, metadata)
				if guardErr != nil {
					return nil, errs, fmt.Errorf("compile fail-closed request JavaScript plugin guard %d (%s): %w", row.ID, row.Name, guardErr)
				}
				scripts = append(scripts, guard)
			}
			continue
		}
		scripts = append(scripts, script)
	}
	return scripts, errs, nil
}
