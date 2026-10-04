package sites

import (
	"My-OpenWaf/internal/snapshot"
)

/**
 * Resolver 依据当前原子快照，把传入的 (bind, host) 映射到站点配置。
 */
type Resolver struct {
	holder *snapshot.Holder
}

// NewResolver 创建一个由给定快照 holder 支撑的解析器。
func NewResolver(h *snapshot.Holder) *Resolver {
	return &Resolver{holder: h}
}

/**
 * Match 查找 bind 地址 + host 组合对应的 SiteRuntime。
 *
 * 先做精确匹配，再做通配匹配（*.example.com）。
 */
func (r *Resolver) Match(bind string, host string) (snapshot.SiteRuntime, bool) {
	sn := r.holder.Load()
	if sn == nil {
		return snapshot.SiteRuntime{}, false
	}
	return sn.MatchSite(bind, host)
}

// MatchPtr 查找 bind 地址 + host 组合对应的 SiteRuntime 指针。
func (r *Resolver) MatchPtr(bind string, host string) (*snapshot.SiteRuntime, bool) {
	sn := r.holder.Load()
	if sn == nil {
		return nil, false
	}
	return sn.MatchSitePtr(bind, host)
}

// Snapshot 返回当前快照（首次加载前可能为 nil）。
func (r *Resolver) Snapshot() *snapshot.Snapshot {
	return r.holder.Load()
}
