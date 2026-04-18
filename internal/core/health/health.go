package health

import (
	"context"
	"runtime"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/snapshot"

	"gorm.io/gorm"
)

// Checker provides liveness and readiness probes.
type Checker struct {
	db     *gorm.DB
	holder *snapshot.Holder
}

// New creates a health checker.
func New(db *gorm.DB, holder *snapshot.Holder) *Checker {
	return &Checker{db: db, holder: holder}
}

// Alive returns true if the process is running (always true while reachable).
func (c *Checker) Alive() bool { return true }

// Ready returns true when DB is reachable and a snapshot is loaded.
func (c *Checker) Ready() bool {
	if c.holder.Load() == nil {
		return false
	}
	sqlDB, err := c.db.DB()
	if err != nil {
		return false
	}
	return sqlDB.Ping() == nil
}

// LivenessHandler returns a Hertz handler for /healthz.
func (c *Checker) LivenessHandler() app.HandlerFunc {
	return func(ctx context.Context, rc *app.RequestContext) {
		if c.Alive() {
			rc.JSON(200, map[string]string{"status": "ok"})
		} else {
			rc.JSON(503, map[string]string{"status": "unhealthy"})
		}
	}
}

// ReadinessHandler returns a Hertz handler for /readyz.
func (c *Checker) ReadinessHandler() app.HandlerFunc {
	return func(ctx context.Context, rc *app.RequestContext) {
		if c.Ready() {
			rc.JSON(200, map[string]string{"status": "ready"})
		} else {
			rc.JSON(503, map[string]string{"status": "not ready"})
		}
	}
}

// StatusHandler returns a Hertz handler for /status with runtime info.
func (c *Checker) StatusHandler() app.HandlerFunc {
	return func(ctx context.Context, rc *app.RequestContext) {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)

		sn := c.holder.Load()
		rev := uint64(0)
		sites := 0
		listeners := 0
		if sn != nil {
			rev = sn.Revision
			sites = len(sn.Sites)
			// Count unique listener bind addresses from sites
			listenerSet := make(map[string]bool)
			for _, site := range sn.Sites {
				listenerSet[site.Bind] = true
			}
			listeners = len(listenerSet)
		}
		rc.JSON(200, map[string]any{
			"alive":      c.Alive(),
			"ready":      c.Ready(),
			"revision":   rev,
			"sites":      sites,
			"listeners":  listeners,
			"goroutines": runtime.NumGoroutine(),
			"heap_alloc": mem.HeapAlloc,
			"go_version": runtime.Version(),
			"num_cpu":    runtime.NumCPU(),
		})
	}
}
