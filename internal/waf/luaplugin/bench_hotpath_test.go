package luaplugin

import (
	"sync"
	"sync/atomic"
	"testing"
)

// 本文件量化数据面热路径上「阶段是否有脚本」这一判断的固定代价。
//
// 管道里的 lua 阶段对每个请求都会先问一次 HasScripts，未配置脚本时也要问。
// 当前实现用 RWMutex 保护脚本 slice；RLock 会对同一 cache line 做原子加，
// 多核高 QPS 下产生跨核争抢。下面用等价的两种读路径做对照，判断是否值得改成
// atomic.Pointer（与项目 snapshot.Holder 的既有做法一致）。

// rwMutexBaseline 复现当前实现的读路径。
type rwMutexBaseline struct {
	mu   sync.RWMutex
	pre  []*Script
	post []*Script
}

func (r *rwMutexBaseline) hasScripts(stage Stage) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if stage == StagePre {
		return len(r.pre) > 0
	}
	return len(r.post) > 0
}

// benchScriptSet 是无锁方案里不可变的脚本集合。
type benchScriptSet struct {
	pre  []*Script
	post []*Script
}

// atomicCandidate 复现无锁方案的读路径。
type atomicCandidate struct {
	set atomic.Pointer[benchScriptSet]
}

func (a *atomicCandidate) hasScripts(stage Stage) bool {
	s := a.set.Load()
	if s == nil {
		return false
	}
	if stage == StagePre {
		return len(s.pre) > 0
	}
	return len(s.post) > 0
}

// BenchmarkHotPathRWMutexEmpty 是当前实现在「无脚本」时的读路径代价。
func BenchmarkHotPathRWMutexEmpty(b *testing.B) {
	r := &rwMutexBaseline{}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if r.hasScripts(StagePre) {
				b.Fatal("空集合不应报告有脚本")
			}
		}
	})
}

// BenchmarkHotPathAtomicEmpty 是无锁方案在「无脚本」时的读路径代价。
func BenchmarkHotPathAtomicEmpty(b *testing.B) {
	a := &atomicCandidate{}
	a.set.Store(&benchScriptSet{})
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if a.hasScripts(StagePre) {
				b.Fatal("空集合不应报告有脚本")
			}
		}
	})
}

// BenchmarkHotPathRWMutexWithReload 在读的同时持续写入，模拟配置热重载与
// 请求流量并发：RWMutex 的写锁会阻塞全部读者，这是比空载更接近真实的场景。
func BenchmarkHotPathRWMutexWithReload(b *testing.B) {
	r := &rwMutexBaseline{}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				r.mu.Lock()
				r.pre = nil
				r.mu.Unlock()
			}
		}
	}()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = r.hasScripts(StagePre)
		}
	})
	close(stop)
	wg.Wait()
}

// BenchmarkHotPathAtomicWithReload 是无锁方案在同等写入压力下的表现。
func BenchmarkHotPathAtomicWithReload(b *testing.B) {
	a := &atomicCandidate{}
	a.set.Store(&benchScriptSet{})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				a.set.Store(&benchScriptSet{})
			}
		}
	}()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = a.hasScripts(StagePre)
		}
	})
	close(stop)
	wg.Wait()
}

// BenchmarkEngineHasScriptsEmpty 直接量化生产实现，作为上面对照的落地参照。
func BenchmarkEngineHasScriptsEmpty(b *testing.B) {
	e := silentEngine(nil)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if e.HasScripts(StagePre) {
				b.Fatal("空引擎不应报告有脚本")
			}
		}
	})
}
