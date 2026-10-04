package jsplugin

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Script 是已校验的 JavaScript 策略脚本。
type Script struct {
	name            string
	source          string
	stage           string
	priority        int
	failureMode     string
	siteID          *uint
	siteIDs         map[uint]bool
	memoryLimit     uint64
	stackLimit      uint64
	timeout         time.Duration
	timeoutOverride bool
	id              uint
	runs            atomic.Int64
	failures        atomic.Int64
	timeouts        atomic.Int64
	totalNanos      atomic.Int64

	// faultMu 保护 fault：请求路径的执行器在脚本失败时写入，管理端读取。
	// 失败是罕见路径，互斥锁比原子结构更直白。
	faultMu sync.Mutex
	fault   faultState
}

// Name 返回脚本名称。
func (s *Script) Name() string {
	if s == nil {
		return ""
	}
	return s.name
}

/**
 * ScriptMetadata 描述脚本的 snapshot 只读元数据。
 */
type ScriptMetadata struct {
	ID          uint
	Stage       string
	Priority    int
	FailureMode string
	SiteID      *uint
}

// CompileWithMetadata 编译脚本并绑定 snapshot 提供的只读元数据。
func CompileWithMetadata(name, source string, opts ScriptOptions, metadata ScriptMetadata) (*Script, error) {
	script, err := Compile(name, source, opts)
	if err != nil {
		return nil, err
	}
	script.setMetadata(metadata)
	return script, nil
}

func (s *Script) setMetadata(metadata ScriptMetadata) {
	if s == nil {
		return
	}
	s.id = metadata.ID
	s.stage = metadata.Stage
	s.priority = metadata.Priority
	s.failureMode = metadata.FailureMode
	if metadata.SiteID == nil {
		s.siteID = nil
		return
	}
	id := *metadata.SiteID
	s.siteID = &id
}

// Stage 返回脚本执行阶段。
func (s *Script) Stage() string {
	if s == nil {
		return ""
	}
	return s.stage
}

// Priority 返回脚本优先级。
func (s *Script) Priority() int {
	if s == nil {
		return 0
	}
	return s.priority
}

// FailureMode 返回脚本执行失败时的处理模式。
func (s *Script) FailureMode() string {
	if s == nil {
		return ""
	}
	return s.failureMode
}

// SiteID 返回脚本的站点作用域；nil 表示全局脚本。
func (s *Script) SiteID() *uint {
	if s == nil || s.siteID == nil {
		return nil
	}
	id := *s.siteID
	return &id
}

// Metadata 返回脚本元数据的只读副本。
func (s *Script) Metadata() map[string]any {
	if s == nil {
		return nil
	}
	metadata := map[string]any{
		"stage":        s.stage,
		"priority":     s.priority,
		"failure_mode": s.failureMode,
		"site_id":      nil,
	}
	if s.siteID != nil {
		metadata["site_id"] = *s.siteID
	}
	return metadata
}

// ID 返回数据库记录 ID（供统计与管理端展示）。
func (s *Script) ID() uint {
	if s == nil {
		return 0
	}
	return s.id
}

// Stats 返回脚本执行统计。
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

/**
 * ValidateExecutionStage 在脚本进入执行器前校验阶段与执行入口的一致性。
 *
 * 没有元数据的脚本仍可用于 dry-run 和接口级测试。
 *
 * @param script 待执行的脚本。
 * @param wantStage 本次执行入口对应的阶段。
 * @return 阶段不匹配时返回错误。
 */
func ValidateExecutionStage(script *Script, wantStage string) error {
	return validateExecutionStage(script, wantStage)
}

/**
 * NewScriptForTest 构造只带元数据的脚本，供无 QuickJS 的构建验证接口层行为。
 *
 * 正常路径应使用 Compile / CompileWithMetadata；这里不校验源码，调用方
 * 只应把它用于失败记录、统计与元数据相关的测试。
 *
 * @param id 持久化插件标识。
 * @param name 脚本名。
 * @param stage 执行阶段。
 * @param failureMode 失败处理方式。
 * @return 仅带元数据的 Script。
 */
func NewScriptForTest(id uint, name, stage, failureMode string) *Script {
	script := &Script{name: name}
	script.id = id
	script.stage = stage
	script.failureMode = failureMode
	return script
}

/**
 * validateExecutionStage 在脚本进入执行器前校验阶段与执行入口的一致性。
 *
 * 没有元数据的脚本仍可用于 dry-run 和接口级测试。
 *
 * @param script 待执行的脚本。
 * @param wantStage 本次执行入口对应的阶段。
 * @return 阶段不匹配时返回错误。
 */
func validateExecutionStage(script *Script, wantStage string) error {
	if script != nil && script.Stage() != "" && script.Stage() != wantStage {
		return fmt.Errorf("jsplugin: stage %s script cannot use the %s executor", script.Stage(), wantStage)
	}
	return nil
}

// Executor 描述请求阶段脚本执行器的最小接口，便于未来接入其他后端。
type Executor interface {
	Execute(context.Context, *Script, RequestSnapshot) (MutationPlan, error)
}

// ResponseExecutor 描述响应阶段脚本执行器的最小接口，便于未来接入其他后端。
type ResponseExecutor interface {
	ExecuteResponse(context.Context, *Script, ResponseSnapshot) (ResponseMutationPlan, error)
}

var _ Executor = (*Engine)(nil)
var _ ResponseExecutor = (*Engine)(nil)
