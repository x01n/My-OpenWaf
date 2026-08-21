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
	"context"
	"errors"
	"fmt"
	"net/url"
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
	minTimeout     = 1 * time.Millisecond
	maxTimeout     = 1000 * time.Millisecond

	// maxScriptBytes 限制脚本体积，避免超大脚本拖慢编译与占用内存。
	maxScriptBytes = 256 * 1024

	// 运行时 API 的资源上限，避免脚本通过大量表项或回调放大请求开销。
	// 运行时 API 的资源上限，避免脚本通过大量表项或回调放大请求开销。
	maxAPICalls       = 128
	maxAPIMapEntries  = 256
	maxAPIStringBytes = 16 * 1024
	maxHeaderValue    = 4 * 1024
	maxResponseBody   = 16 * 1024

	// decisionFromTable 的返回值会继续流入日志、响应与后续请求处理，
	// 因此不能把 Lua 表里的字符串和条目数原样带出沙箱。
	maxDecisionActionBytes      = 64
	maxDecisionMessageBytes     = 512
	maxDecisionRedirectBytes    = 2048
	maxDecisionHeaders          = 32
	maxDecisionHeaderNameBytes  = 256
	maxDecisionHeaderValueBytes = 2048
	maxDecisionTags             = 32
	maxDecisionTagBytes         = 128
	maxDecisionTableEntries     = 128
	minDecisionStatusCode       = 100
	maxDecisionStatusCode       = 599
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
	// SetHeaders 是脚本要求追加/覆盖的受控响应头。
	SetHeaders map[string]string
	// ResponseBody 是可选的受限响应体覆盖。
	ResponseBody string
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

// ContextKVBackend 是支持请求取消的 KVBackend 扩展。实现该接口的后端会收到脚本执行的
// runCtx，使调用方取消、脚本超时和请求作用域值传递到 KV I/O；未实现时按不可用处理，
// 防止无法响应取消的同步 I/O 阻塞数据面请求。
type ContextKVBackend interface {
	KVBackend
	AvailableContext(ctx context.Context) bool
	GetContext(ctx context.Context, key string) ([]byte, bool)
	SetContext(ctx context.Context, key string, value []byte, ttl time.Duration) error
	DeleteContext(ctx context.Context, key string)
	IncrContext(ctx context.Context, key string, ttl time.Duration) (int64, error)
}

// Script 是一段已编译的插件脚本。
//
// 编译产物（*lua.FunctionProto）在多个 Lua 状态机间共享，故只编译一次。
type Script struct {
	id    uint
	name  string
	stage Stage
	proto *lua.FunctionProto

	// siteID 为 nil 表示全局脚本；非 nil 时仅对指定站点执行。
	siteID *uint

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

// ID 返回持久化插件标识，用于关联运行时统计。
func (s *Script) ID() uint {
	if s == nil {
		return 0
	}
	return s.id
}

// SetID 设置持久化插件标识。
func (s *Script) SetID(id uint) {
	if s != nil {
		s.id = id
	}
}

// ParseQueryParams 将原始查询串转换为 Lua 可见的查询参数。
// 重复键保留第一个值；非法编码返回 nil。
func ParseQueryParams(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil
	}
	params := make(map[string]string, len(values))
	for key, values := range values {
		if len(values) > 0 {
			params[key] = values[0]
		}
	}
	return params
}

// SetSiteID 设置脚本的站点作用域。nil 表示全局脚本。
func (s *Script) SetSiteID(siteID *uint) {
	if s == nil {
		return
	}
	if siteID == nil {
		s.siteID = nil
		return
	}
	id := *siteID
	s.siteID = &id
}

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

// SetTimeout 覆盖该脚本的执行超时。非正值保留默认值，正值钳制到 1..1000ms。
func (s *Script) SetTimeout(timeout time.Duration) {
	if timeout <= 0 {
		s.timeout = defaultTimeout
		return
	}
	if timeout < minTimeout {
		timeout = minTimeout
	}
	if timeout > maxTimeout {
		timeout = maxTimeout
	}
	s.timeout = timeout
}
