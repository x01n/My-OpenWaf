package repository

// CountCachePrefixInvalidator 支持按缓存命名空间失效，避免日志写入清空
// 不相关的列表和计数结果。未实现该接口的旧缓存替身仍走 CountCacheInvalidator。
type CountCachePrefixInvalidator interface {
	InvalidatePrefix(prefix string)
}

const (
	accessLogCountCachePrefix     = "al_count:v2"
	accessLogListCachePrefix      = "al_list:v1"
	securityEventCountCachePrefix = "se_count:v2"
	dropEventCountCachePrefix     = "de_count"
)

// invalidateCountCachePrefixes 优先使用命名空间失效；旧实现只支持全量失效时
// 保留原有行为，保证外部测试替身和旧部署组件仍然正确。
func invalidateCountCachePrefixes(c CountCache, prefixes ...string) {
	if c == nil {
		return
	}
	if invalidator, ok := c.(CountCachePrefixInvalidator); ok {
		for _, prefix := range prefixes {
			if prefix != "" {
				invalidator.InvalidatePrefix(prefix)
			}
		}
		return
	}
	if invalidator, ok := c.(CountCacheInvalidator); ok {
		invalidator.InvalidateAll()
	}
}
