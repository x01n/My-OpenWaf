package health

import (
	"context"
	"runtime"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/snapshot"

	"gorm.io/gorm"
)

// Checker 提供存活与就绪探针。
type Checker struct {
	db     *gorm.DB
	holder *snapshot.Holder
	ready  func() bool
}

// New 创建健康检查器。
func New(db *gorm.DB, holder *snapshot.Holder) *Checker {
	return &Checker{db: db, holder: holder}
}

func (c *Checker) SetReadyFunc(ready func() bool) {
	c.ready = ready
}
func (c *Checker) Alive() bool { return true }

// Ready 在数据库可达且已加载快照时返回 true。
func (c *Checker) Ready() bool {
	if c.holder.Load() == nil {
		return false
	}
	if c.ready != nil && !c.ready() {
		return false
	}
	sqlDB, err := c.db.DB()
	if err != nil {
		return false
	}
	return sqlDB.Ping() == nil
}

// LivenessHandler 返回 /healthz 的 Hertz 处理器。
func (c *Checker) LivenessHandler() app.HandlerFunc {
	return func(ctx context.Context, rc *app.RequestContext) {
		if c.Alive() {
			rc.JSON(200, map[string]string{"status": "ok"})
		} else {
			rc.JSON(503, map[string]string{"status": "unhealthy"})
		}
	}
}

// ReadinessHandler 返回 /readyz 的 Hertz 处理器。
func (c *Checker) ReadinessHandler() app.HandlerFunc {
	return func(ctx context.Context, rc *app.RequestContext) {
		if c.Ready() {
			rc.JSON(200, map[string]string{"status": "ready"})
		} else {
			rc.JSON(503, map[string]string{"status": "not ready"})
		}
	}
}

// StatusHandler 返回 /status 的 Hertz 处理器，输出运行时信息。
func (c *Checker) StatusHandler() app.HandlerFunc {
	return func(ctx context.Context, rc *app.RequestContext) {
		rc.JSON(200, c.StatusSnapshot())
	}
}

func (c *Checker) StatusSnapshot() map[string]any {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	sn := c.holder.Load()
	rev := uint64(0)
	sites := 0
	listeners := 0
	if sn != nil {
		rev = sn.Revision
		siteIDs := make(map[uint]struct{})
		listenerSet := make(map[string]bool)
		for _, site := range sn.Sites {
			siteIDs[site.Site.ID] = struct{}{}
			listenerSet[site.Bind] = true
		}
		sites = len(siteIDs)
		listeners = len(listenerSet)
	}
	return map[string]any{
		"alive":      c.Alive(),
		"ready":      c.Ready(),
		"revision":   rev,
		"sites":      sites,
		"listeners":  listeners,
		"goroutines": runtime.NumGoroutine(),
		"heap_alloc": mem.HeapAlloc,
		"go_version": runtime.Version(),
		"num_cpu":    runtime.NumCPU(),
	}
}
