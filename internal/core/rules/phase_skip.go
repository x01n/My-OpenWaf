package rules

import (
	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/waf/owasp"
)

/**
 * skipByPathPhase 按请求路径决定是否跳过被包装的 phase。
 *
 * 语义要点：命中跳过列表时返回 (action.Pass(), false)。action.Pass() 的
 * Matched 为零值 false，故 pipeline.Run 既不把它记为 observe 命中，也不短路，
 * 而是继续执行链上其余 phase——这正是"跳过这一个检测"而非"放行整个请求"。
 *
 * 用包装而非独立前置 phase：独立前置 phase 只能表达"跳过其后全部检测"，
 * 无法表达"跳过 OWASP 但保留 CVE 与 Bot"。
 */
type skipByPathPhase struct {
	inner pipeline.Phase
	paths []string
}

/**
 * NewSkipByPathPhase 包装一个 phase，使其仅在原始路径和最终路径都命中 paths 时被跳过。
 *
 * @param inner 被包装的 phase，不可为 nil。
 * @param paths 跳过路径列表；为空时直接返回 inner，避免热路径上多一层无用调用。
 * @return 包装后的 phase；其 Name() 透传 inner.Name()，日志与判定字段语义不变。
 */
func NewSkipByPathPhase(inner pipeline.Phase, paths []string) pipeline.Phase {
	if inner == nil || len(paths) == 0 {
		return inner
	}
	return &skipByPathPhase{inner: inner, paths: paths}
}

func (p *skipByPathPhase) Name() string { return p.inner.Name() }

func (p *skipByPathPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	originalPath := ctx.OriginalPath
	if originalPath == "" {
		originalPath = ctx.Path
	}
	if owasp.MatchPathList(originalPath, p.paths) && owasp.MatchPathList(ctx.Path, p.paths) {
		return action.Pass(), false
	}
	return p.inner.Execute(ctx)
}
