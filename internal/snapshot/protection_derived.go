package snapshot

import "My-OpenWaf/internal/store"

/**
 * CompileProtectionDerived 把保护配置中需要 JSON 反序列化的字段编译成只读视图。
 *
 * 这些字段（owasp_rules_config、skip_path_by_phase）的原文是大体积 JSON 文本，
 * 若在请求路径上反复 json.Unmarshal 会显著拖慢热路径。快照构建期调用一次，
 * 数据面每请求只做字符串比较与 map 查表。
 *
 * @param p 生效保护配置；nil 时返回空视图。
 * @return 只读派生视图，永不为 nil。
 */
func CompileProtectionDerived(p *store.ProtectionConfig) *ProtectionDerived {
	if p == nil {
		return &ProtectionDerived{}
	}
	return &ProtectionDerived{
		CiscoASAModeOverride: p.CiscoASAModeOverride(),
		SkipPathByPhase:      p.GetSkipPathByPhase(),
	}
}
