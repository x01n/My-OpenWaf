//go:build !cgo || !quickjs

package jsplugin

import (
	"context"
	"log/slog"

	"My-OpenWaf/internal/store"
)

// RuntimeBackend 报告本二进制没有可执行的 JavaScript 后端。
func RuntimeBackend() string { return BackendUnavailable }

// RuntimeAvailable 报告本构建能否创建 JavaScript 执行器。
func RuntimeAvailable() bool { return false }

// Compile 在禁用 cgo 的构建中保留同一接口，但明确返回不可用错误。
func Compile(name, source string, opts ScriptOptions) (*Script, error) {
	return nil, ErrCGODisabled
}

// NewEngine 返回明确的 stub 错误。当前版本不接入 QuickJS 绑定。
func NewEngine(opts EngineOptions) (*Engine, error) {
	return nil, ErrCGODisabled
}

// NewEngineWithLogger 与 NewEngine 保持同一不可用语义。
func NewEngineWithLogger(opts EngineOptions, log *slog.Logger) (*Engine, error) {
	return nil, ErrCGODisabled
}

/**
 * Engine 是当前版本不可执行的占位类型。
 *
 * log 与真实后端同名同义：脚本失败的记录与日志路径在两种构建下共用同一份
 * 实现（recordFault 定义在 faults.go）。
 */
type Engine struct {
	log *slog.Logger
}

// Execute 为不可用的 QuickJS 后端实现 Executor 接口。
func (e *Engine) Execute(ctx context.Context, script *Script, req RequestSnapshot) (MutationPlan, error) {
	return e.Evaluate(ctx, script, req)
}

// Evaluate 保留 API 形状并返回不可用错误。
func (e *Engine) Evaluate(ctx context.Context, script *Script, req RequestSnapshot) (MutationPlan, error) {
	if err := validateExecutionStage(script, store.JSStageRequest); err != nil {
		return MutationPlan{}, err
	}
	return MutationPlan{}, ErrCGODisabled
}

// Validate 报告同样的运行时不可用，且不改动统计。
func (e *Engine) Validate(ctx context.Context, script *Script, req RequestSnapshot) (MutationPlan, error) {
	if err := validateExecutionStage(script, store.JSStageRequest); err != nil {
		return MutationPlan{}, err
	}
	return MutationPlan{}, ErrCGODisabled
}

// ExecuteResponse 为不可用的 QuickJS 后端实现 ResponseExecutor 接口。
func (e *Engine) ExecuteResponse(ctx context.Context, script *Script, resp ResponseSnapshot) (ResponseMutationPlan, error) {
	return e.EvaluateResponse(ctx, script, resp)
}

// EvaluateResponse 保留响应阶段 API 形状并返回不可用错误。
func (e *Engine) EvaluateResponse(ctx context.Context, script *Script, resp ResponseSnapshot) (ResponseMutationPlan, error) {
	if err := validateExecutionStage(script, store.JSStageResponse); err != nil {
		return ResponseMutationPlan{}, err
	}
	return ResponseMutationPlan{}, ErrCGODisabled
}

// ValidateResponse 报告同样的运行时不可用，且不改动统计。
func (e *Engine) ValidateResponse(ctx context.Context, script *Script, resp ResponseSnapshot) (ResponseMutationPlan, error) {
	if err := validateExecutionStage(script, store.JSStageResponse); err != nil {
		return ResponseMutationPlan{}, err
	}
	return ResponseMutationPlan{}, ErrCGODisabled
}

// Close 使调用方可以统一清理未来的真实实现和当前 stub。
func (e *Engine) Close() error {
	return nil
}

func newScript(source string, opts ScriptOptions) *Script {
	return &Script{name: opts.Name, source: source}
}
