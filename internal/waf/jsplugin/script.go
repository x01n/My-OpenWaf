package jsplugin

import (
	"context"
	"sync/atomic"
	"time"
)

// Script 是已校验的 JavaScript 策略脚本。
type Script struct {
	name        string
	source      string
	siteIDs     map[uint]bool
	memoryLimit uint64
	stackLimit  uint64
	timeout     time.Duration
	runs        atomic.Int64
	failures    atomic.Int64
	timeouts    atomic.Int64
	totalNanos  atomic.Int64
}

// Name 返回脚本名称。
func (s *Script) Name() string {
	if s == nil {
		return ""
	}
	return s.name
}

// Stats 返回执行次数、失败次数、超时次数和平均耗时。
func (s *Script) Stats() (runs, failures, timeouts int64, average time.Duration) {
	if s == nil {
		return 0, 0, 0, 0
	}
	runs = s.runs.Load()
	failures = s.failures.Load()
	timeouts = s.timeouts.Load()
	if runs > 0 {
		average = time.Duration(s.totalNanos.Load() / runs)
	}
	return
}

// Executor 描述脚本执行器的最小接口，便于未来接入其他后端。
type Executor interface {
	Execute(context.Context, *Script, RequestSnapshot) (MutationPlan, error)
}
