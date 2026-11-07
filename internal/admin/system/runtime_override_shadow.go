package system

import (
	"strings"

	"gorm.io/gorm"

	"My-OpenWaf/internal/core/configoverride"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// shadowSource 是「覆盖表的值被更具体来源顶掉」的诊断取值。
type shadowSource = string

const (
	// shadowNone 表示没有被顶掉：生效值就是覆盖表的值。
	shadowNone shadowSource = ""
	// shadowProtectionRow 表示 protection 设置行存在，它在全局层整体顶掉覆盖表。
	shadowProtectionRow shadowSource = "protection_row"
	// shadowSiteOverride 表示存在启用的站点，其站点级 CVE 开关非 nil，
	// 该站点不会采用全局值。
	shadowSiteOverride shadowSource = "site_override"
)

// shadowDiagnosableKeys 是会被更具体来源顶掉的键。
//
// 只有这三个：它们的取值进入 store.ProtectionConfig（全局层可被 protection 行顶掉），
// 而该结构体又被 mergeProtection 逐站点叠加（站点层可被 site.CVEEnabled 顶掉）。
// 其余 42 个键不经过这条链，恒为 shadowNone。
var shadowDiagnosableKeys = map[string]struct{}{
	"cve_enabled":            {},
	"cve_auto_drop_critical": {},
	"cve_auto_drop_high":     {},
}

// shadowState 汇总「覆盖表被顶掉」的诊断依据。
//
// 全部依据都来自本次查询，不缓存、不落库，因此不产生第二份真相。
type shadowState struct {
	// protectionRowPresent 表示 protection 设置行存在且非空白。
	protectionRowPresent bool
	// sitesWithCVEOverride 是启用站点里 CVEEnabled 非 nil 的数量。
	sitesWithCVEOverride int64
}

/**
 * buildShadowState 读取一次诊断依据。
 *
 * 任何查询失败都按「无该来源」处理：诊断字段只服务于界面提示，
 * 它自己不能成为端点失败的原因。
 *
 * @param repo 系统设置仓储；nil 时按「无 protection 行」处理。
 * @param db   主库句柄；nil 时按「无站点级覆盖」处理。
 * @return 诊断依据。
 */
func buildShadowState(repo *repository.SystemSettingsRepo, db *gorm.DB) shadowState {
	state := shadowState{}
	if repo != nil {
		if raw, err := repo.Get("protection"); err == nil && strings.TrimSpace(raw) != "" {
			state.protectionRowPresent = true
		}
	}
	if db != nil {
		if count, err := countSitesWithCVEOverride(db); err == nil {
			state.sitesWithCVEOverride = count
		}
	}
	return state
}

/**
 * shadowFor 判定单个键当前是否被更具体来源顶掉。
 *
 * 判定顺序与真实优先序一致（自高到低）：站点级字段先于 protection 行生效，
 * 两者同时存在时报 site_override。
 *
 * 语义限定（必须按此理解，不要升级成「覆盖表已失效」）：站点级是**逐站点**的，
 * 本字段只回答「至少有一个启用站点不采用全局值」——该站点可能正是用户期望保持
 * 独立配置的那一个。要精确到站点需要前端逐站点展开，不是本诊断的职责。
 *
 * @param key   注册表键名。
 * @param entry 该键的三态解析结果。
 * @param state 诊断依据。
 * @return shadowSource 取值之一。
 */
func shadowFor(key string, entry configoverride.Entry, state shadowState) shadowSource {
	if _, ok := shadowDiagnosableKeys[key]; !ok {
		return shadowNone
	}
	if !entry.Overridden {
		// 覆盖表没写过这个键时，「被顶掉」无从谈起。
		return shadowNone
	}
	if state.sitesWithCVEOverride > 0 {
		return shadowSiteOverride
	}
	if state.protectionRowPresent {
		return shadowProtectionRow
	}
	return shadowNone
}

/**
 * countSitesWithCVEOverride 统计启用站点里站点级 CVE 开关非 nil 的数量。
 *
 * 用模型查询而不是原生列名：列名由 GORM 从字段名推导，写死字符串会在字段改名后
 * 静默失效——查一个不存在的列在 SQLite 下不报错，只会给出错误的计数。
 * 软删除的行由 GORM 自动排除，与快照构建的取数口径一致。
 *
 * @param db 主库句柄。
 * @return 站点数量，以及查询错误。
 */
func countSitesWithCVEOverride(db *gorm.DB) (int64, error) {
	var count int64
	err := db.Model(&store.Site{}).
		Where("enabled = ?", true).
		Where("cve_enabled IS NOT NULL").
		Count(&count).Error
	return count, err
}
