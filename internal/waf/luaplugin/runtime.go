// Package luaplugin 提供基于 Lua 的自定义策略插件运行时。
//
// 设计约束：
//   - 沙箱优先：默认只开放必要的标准库，禁用 io/os/debug/package 等一切能触达
//     文件系统、子进程与运行时内部的能力。脚本无法越出 WAF 进程。
//   - 有界执行：每次调用受 wall-clock 超时与指令数双重限制，防止 while true 卡死
//     数据面。超时按「放行」处理——自定义策略出问题不应导致站点整体不可用。
//   - 池化复用：Lua 状态机创建成本高（约几十微秒），每请求新建会直接压垮吞吐。
//     用 sync.Pool 复用，并在归还前清理脚本可能留下的全局状态。
//   - panic 隔离：脚本触发的 panic 一律 recover，绝不允许打崩数据面。
package luaplugin

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// Stage 标识插件的执行时机。
type Stage string

const (
	// StagePre 在 ACL 之后、OWASP 之前执行，可在昂贵检测前提早放行或拦截。
	StagePre Stage = "pre"
	// StagePost 在全部内置阶段之后执行，能读到检测结果。
	StagePost Stage = "post"
)

// Valid 报告 stage 取值是否受支持。
func (s Stage) Valid() bool { return s == StagePre || s == StagePost }

const (
	// defaultTimeout 是单次脚本执行的挂钟上限。
	//
	// 取 50ms：数据面每请求同步执行，再长会显著拉高 P99 延迟；
	// 而正常的策略脚本（读若干字段 + 少量字符串判断）耗时在微秒级，
	// 50ms 足以覆盖含 KV 往返的场景。
	defaultTimeout = 50 * time.Millisecond

	// maxScriptBytes 限制脚本体积，避免超大脚本拖慢编译与占用内存。
	maxScriptBytes = 256 * 1024
)

// ErrScriptTooLarge 表示脚本超过体积上限。
var ErrScriptTooLarge = errors.New("luaplugin: script exceeds size limit")

// Decision 是脚本返回的判定结果。
type Decision struct {
	// Action 为空表示脚本未做判定（继续后续阶段）。
	Action string
	// Message 供日志与拦截页展示，不参与判定。
	Message string
	// RedirectTo 仅当 Action 为 redirect 时有意义。
	RedirectTo string
	// StatusCode 覆盖拦截响应码，0 表示用默认值。
	StatusCode int
	// SetHeaders 是脚本要求追加/覆盖的转发请求头。
	SetHeaders map[string]string
	// Tags 是脚本打的标签，仅用于日志与下游观测。
	Tags []string
}

// HasAction 报告脚本是否给出了判定。
func (d Decision) HasAction() bool { return d.Action != "" }

// KVBackend 是脚本可用的跨请求存储。由调用方注入，通常复用 Redis/本地缓存。
//
// 所有方法都必须能安全并发调用；Available 为 false 时脚本侧的 kv.* 调用
// 会返回 nil/false 而非报错，使 Redis 不可用时策略降级而非站点不可用。
type KVBackend interface {
	Available() bool
	Get(key string) ([]byte, bool)
	Set(key string, value []byte, ttl time.Duration) error
	Delete(key string)
	Incr(key string, ttl time.Duration) (int64, error)
}

// Script 是一段已编译的插件脚本。
//
// 编译产物（*lua.FunctionProto）在多个 Lua 状态机间共享，故只编译一次。
type Script struct {
	name  string
	stage Stage
	proto *lua.FunctionProto

	// timeout 允许按脚本覆盖默认超时。
	timeout time.Duration

	// 运行统计，供 /metrics 与管理端展示。
	runs     atomic.Int64
	failures atomic.Int64
	timeouts atomic.Int64
	totalNs  atomic.Int64
}

// Name 返回脚本名。
func (s *Script) Name() string { return s.name }

// Stage 返回脚本的执行时机。
func (s *Script) Stage() Stage { return s.stage }

// Stats 返回累计运行统计：执行次数、失败次数、超时次数、平均耗时。
func (s *Script) Stats() (runs, failures, timeouts int64, avg time.Duration) {
	runs = s.runs.Load()
	failures = s.failures.Load()
	timeouts = s.timeouts.Load()
	if runs > 0 {
		avg = time.Duration(s.totalNs.Load() / runs)
	}
	return
}

// Compile 编译脚本源码。
//
// 编译期即拒绝超限脚本与语法错误，使配置错误在保存时暴露而非运行时才发现。
//
// @param name   脚本名，用于日志与统计。
// @param stage  执行时机。
// @param source Lua 源码，必须定义全局函数 handle(ctx)。
// @return 已编译脚本；语法错误或超限时返回错误。
func Compile(name string, stage Stage, source string) (*Script, error) {
	if !stage.Valid() {
		return nil, fmt.Errorf("luaplugin: invalid stage %q (want pre or post)", stage)
	}
	if len(source) > maxScriptBytes {
		return nil, fmt.Errorf("%w: %d > %d bytes", ErrScriptTooLarge, len(source), maxScriptBytes)
	}

	proto, err := compileProto(name, source)
	if err != nil {
		return nil, fmt.Errorf("luaplugin: compile %q: %w", name, err)
	}

	return &Script{
		name:    name,
		stage:   stage,
		proto:   proto,
		timeout: defaultTimeout,
	}, nil
}

// SetTimeout 覆盖该脚本的执行超时。非正值表示保留默认。
func (s *Script) SetTimeout(timeout time.Duration) {
	if timeout > 0 {
		s.timeout = timeout
	}
}
