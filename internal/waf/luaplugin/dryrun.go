package luaplugin

import (
	"context"
	"time"
)

// DryRunResult 是试运行的结果。
type DryRunResult struct {
	// CompileError 非空表示脚本未通过编译，此时其余字段无意义。
	CompileError string `json:"compile_error,omitempty"`
	// RuntimeError 非空表示脚本执行出错（含超时）。
	RuntimeError string `json:"runtime_error,omitempty"`
	// Decision 是脚本给出的判定；Action 为空表示未判定。
	Decision Decision `json:"decision"`
	// ElapsedMS 是执行耗时（毫秒），供用户评估脚本开销。
	ElapsedMS float64 `json:"elapsed_ms"`
	// Iteration 是本结果对应的第几次样例请求，单次试运行时为 1。
	Iteration int `json:"iteration"`
}

// DryRunBatchResult 是连续试运行的结果。
type DryRunBatchResult struct {
	CompileError string         `json:"compile_error,omitempty"`
	RuntimeError string         `json:"runtime_error,omitempty"`
	Decision     Decision       `json:"decision"`
	ElapsedMS    float64        `json:"elapsed_ms"`
	Iteration    int            `json:"iteration"`
	Iterations   int            `json:"iterations"`
	KVAvailable  bool           `json:"kv_available"`
	Runs         []DryRunResult `json:"runs,omitempty"`
}

/**
 * DryRun 用给定的样例请求试运行一段脚本源码，不影响线上配置。
 *
 * 让用户在保存前就看到脚本对具体请求的判定与耗时——策略脚本的错误往往
 * 只在真实请求形态下才暴露，光有语法校验不够。
 *
 * 每次调用使用独立的状态机池，不与线上共享，避免试运行污染生产状态机。
 *
 * @param stage   执行阶段，影响脚本可读到的 phase/action 字段语义。
 * @param source  Lua 源码。
 * @param req     样例请求。
 * @param kv      跨请求存储，可为 nil（此时脚本侧 kv.available() 为 false）。
 * @param timeout 执行超时，非正值时用默认值。
 * @return 试运行结果，永不返回 error——所有失败都体现在结果字段里。
 */
func DryRun(stage Stage, source string, req RequestView, kv KVBackend, timeout time.Duration) DryRunResult {
	batch := DryRunN(stage, source, req, kv, timeout, 1)
	if len(batch.Runs) == 0 {
		return DryRunResult{CompileError: batch.CompileError, RuntimeError: batch.RuntimeError, Iteration: 1}
	}
	return batch.Runs[0]
}

// DryRunNContext 使用调用方 context 试运行脚本；请求取消会中断 Lua 执行。
func DryRunNContext(ctx context.Context, stage Stage, source string, req RequestView, kv KVBackend, timeout time.Duration, iterations int) DryRunBatchResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if iterations <= 0 {
		iterations = 1
	}
	if iterations > 100 {
		iterations = 100
	}
	script, err := Compile("dryrun", stage, source)
	if err != nil {
		return DryRunBatchResult{CompileError: err.Error(), Iterations: iterations, KVAvailable: kv != nil && kv.Available()}
	}
	script.SetTimeout(timeout)

	pool := newVMPool()
	out := DryRunBatchResult{
		Iterations:  iterations,
		KVAvailable: kv != nil && kv.Available(),
		Runs:        make([]DryRunResult, 0, iterations),
	}
	for i := 0; i < iterations; i++ {
		if err := ctx.Err(); err != nil {
			out.RuntimeError = err.Error()
			break
		}
		start := time.Now()
		dec, runErr := script.Run(ctx, pool, req, kv)
		elapsed := time.Since(start)
		one := DryRunResult{Decision: dec, ElapsedMS: float64(elapsed.Nanoseconds()) / 1e6, Iteration: i + 1}
		if runErr != nil {
			one.RuntimeError = runErr.Error()
		}
		out.Runs = append(out.Runs, one)
		out.ElapsedMS += one.ElapsedMS
		out.Iteration = one.Iteration
		out.Decision = one.Decision
		out.RuntimeError = one.RuntimeError
		if one.RuntimeError != "" || one.Decision.HasAction() {
			break
		}
	}
	return out
}

func DryRunN(stage Stage, source string, req RequestView, kv KVBackend, timeout time.Duration, iterations int) DryRunBatchResult {
	return DryRunNContext(context.Background(), stage, source, req, kv, timeout, iterations)
}

/**
 * Validate 只做编译校验，不执行脚本。
 *
 * 用于保存前的快速校验：编译能捕获语法错误与缺少 handle 之外的结构问题，
 * 但不会有执行副作用。
 *
 * @param stage  执行阶段。
 * @param source Lua 源码。
 * @return 校验错误，nil 表示通过。
 */
func Validate(stage Stage, source string) error {
	_, err := Compile("validate", stage, source)
	return err
}
