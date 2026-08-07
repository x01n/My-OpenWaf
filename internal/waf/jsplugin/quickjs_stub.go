//go:build !cgo

package jsplugin

import (
	"context"
)

// Compile 在禁用 cgo 的构建中保留同一接口，但明确返回不可用错误。
func Compile(name, source string, opts ScriptOptions) (*Script, error) {
	return nil, ErrCGODisabled
}

// NewEngine 返回明确的 stub 错误。当前版本不接入 QuickJS 绑定。
func NewEngine(opts EngineOptions) (*Engine, error) {
	return nil, ErrCGODisabled
}

// Engine 是当前版本不可执行的占位类型。
type Engine struct{}

// Evaluate 保留 API 形状并返回不可用错误。
func (e *Engine) Evaluate(ctx context.Context, script *Script, req RequestSnapshot) (MutationPlan, error) {
	return MutationPlan{}, ErrCGODisabled
}

// Close 使调用方可以统一清理未来的真实实现和当前 stub。
func (e *Engine) Close() error {
	return nil
}

func newScript(source string, opts ScriptOptions) *Script {
	return &Script{name: opts.Name, source: source}
}
