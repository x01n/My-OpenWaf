package memreclaim

import (
	"log/slog"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

// Config 控制空闲内存归还 OS 的行为。
type Config struct {
	// Interval 检查周期；<=0 时默认 2 分钟。
	Interval time.Duration
	// IdleRounds 连续多少轮 heap 无明显增长才触发 FreeOSMemory；<=0 时默认 2。
	IdleRounds int
	// MinHeapReleased 仅当 HeapIdle-HeapReleased 超过该值才归还；<=0 时默认 32MiB。
	MinHeapReleased int64
	// Logger 可选。
	Logger *slog.Logger
}

// Start 启动后台回收循环，返回 stop 函数。
// 逻辑：周期性观察 HeapInuse；若连续 IdleRounds 轮几乎不增长，且存在可归还的 idle heap，
// 则调用 debug.FreeOSMemory()，帮助高并发峰值后的 RSS 回落。
func Start(cfg Config) (stop func()) {
	interval := cfg.Interval
	if interval <= 0 {
		interval = 2 * time.Minute
	}
	idleRounds := cfg.IdleRounds
	if idleRounds <= 0 {
		idleRounds = 2
	}
	minRelease := cfg.MinHeapReleased
	if minRelease <= 0 {
		minRelease = 32 << 20
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}

	stopCh := make(chan struct{})
	var once sync.Once
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		var lastInuse uint64
		stable := 0
		first := true
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				if first {
					lastInuse = ms.HeapInuse
					first = false
					continue
				}
				// 允许小幅抖动（1MiB 内视为稳定）。
				const jitter = 1 << 20
				if ms.HeapInuse > lastInuse+jitter {
					stable = 0
				} else {
					stable++
				}
				lastInuse = ms.HeapInuse
				if stable < idleRounds {
					continue
				}
				releasable := int64(ms.HeapIdle) - int64(ms.HeapReleased)
				if releasable < minRelease {
					continue
				}
				beforeSys := ms.Sys
				debug.FreeOSMemory()
				runtime.ReadMemStats(&ms)
				log.Info("idle heap reclaimed to OS",
					slog.Uint64("heap_inuse", ms.HeapInuse),
					slog.Uint64("heap_idle", ms.HeapIdle),
					slog.Uint64("heap_released", ms.HeapReleased),
					slog.Uint64("sys_before", beforeSys),
					slog.Uint64("sys_after", ms.Sys),
					slog.Int64("releasable_before", releasable),
				)
				stable = 0
			}
		}
	}()

	return func() {
		once.Do(func() { close(stopCh) })
	}
}
