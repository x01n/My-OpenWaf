package luaplugin

import (
	"context"
	"errors"
	"fmt"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// handlerName 是脚本必须定义的入口函数名。
const handlerName = "handle"

// ErrNoHandler 表示脚本未定义入口函数。
var ErrNoHandler = errors.New("luaplugin: script must define a global function " + handlerName + "(ctx)")

// RequestView 是暴露给脚本的请求快照（只读）。
//
// 传值而非传指针：脚本拿到的是当次请求的副本视图，无法通过它改写 WAF 内部状态。
// Headers 为已归一化的小写键映射。
type RequestView struct {
	RequestID   string
	ClientIP    string
	Method      string
	Path        string
	RawQuery    string
	Host        string
	UserAgent   string
	SiteID      uint
	ContentType string
	Headers     map[string]string
	QueryParams map[string]string
	Body        string
	TLSVersion  string
	TLSJA3      string
	TLSJA4      string
	TLSSNI      string
	// Phase/Action 是内置阶段的判定结果，仅 post 阶段有值。
	// 让后置脚本能基于「内置引擎怎么判的」做二次决策，例如对特定误报路径放行。
	Phase  string
	Action string
}

// Run 执行脚本并返回判定。
//
// 失败语义一律为「不判定」（返回零值 Decision 且 err 非 nil），由调用方决定是否
// 放行——自定义策略出错不应使站点整体不可用。
//
// @param ctx 调用方 context，其取消会中断脚本执行。
// @param pool 状态机池。
// @param req  请求视图。
// @param kv   跨请求存储，可为 nil。
// @return 判定结果与错误。
func (s *Script) Run(ctx context.Context, pool *vmPool, req RequestView, kv KVBackend) (Decision, error) {
	start := time.Now()
	s.runs.Add(1)
	defer func() { s.totalNs.Add(int64(time.Since(start))) }()

	L := pool.get()
	if L == nil {
		s.failures.Add(1)
		return Decision{}, errors.New("luaplugin: failed to acquire lua state")
	}
	defer pool.put(L)

	// 超时与指令上限双闸：context 负责挂钟超时，指令钩子兜住紧密循环
	// （紧密计算循环可能长时间不触发 context 检查点）。
	runCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	L.SetContext(runCtx)
	defer L.RemoveContext()

	dec, err := s.callHandler(L, req, kv)
	if err == nil {
		return dec, nil
	}

	// gopher-lua 把 context 错误包装成 *lua.ApiError（形如 "x:1: context deadline
	// exceeded"），Unwrap 链已断，errors.Is 判不出来。改为直接看 context 自身状态：
	// 它是权威来源，且不依赖运行时的错误文案。
	if ctxErr := runCtx.Err(); ctxErr != nil {
		s.timeouts.Add(1)
		return Decision{}, fmt.Errorf("luaplugin: %q exceeded %s: %w", s.name, s.timeout, ctxErr)
	}

	s.failures.Add(1)
	return Decision{}, err
}

// callHandler 在受保护的环境中调用脚本入口，并把 panic 转为错误。
//
// gopher-lua 在栈溢出等情形下会 panic；不 recover 会直接打崩数据面。
func (s *Script) callHandler(L *lua.LState, req RequestView, kv KVBackend) (dec Decision, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("luaplugin: %q panicked: %v", s.name, r)
		}
	}()

	resetGlobals(L)

	// 载入已编译原型并执行顶层代码（定义 handle 等）。
	L.Push(L.NewFunctionFromProto(s.proto))
	if err := L.PCall(0, lua.MultRet, nil); err != nil {
		return Decision{}, fmt.Errorf("luaplugin: %q init failed: %w", s.name, err)
	}

	handler, ok := L.GetGlobal(handlerName).(*lua.LFunction)
	if !ok {
		return Decision{}, ErrNoHandler
	}

	ctxTable := buildContextTable(L, req, kv)
	L.Push(handler)
	L.Push(ctxTable)
	if err := L.PCall(1, 1, nil); err != nil {
		return Decision{}, fmt.Errorf("luaplugin: %q handle() failed: %w", s.name, err)
	}

	ret := L.Get(-1)
	L.Pop(1)
	return decisionFromLua(ret)
}

// decisionFromLua 把脚本返回值转换为 Decision。
//
// 返回 nil / false 表示不判定；返回字符串等价于只给 action；
// 返回表可携带 message / redirect_to / status_code / headers / tags。
func decisionFromLua(v lua.LValue) (Decision, error) {
	switch val := v.(type) {
	case *lua.LNilType:
		return Decision{}, nil
	case lua.LBool:
		// false 表示不判定；true 无明确语义，同样视为不判定以免误拦。
		return Decision{}, nil
	case lua.LString:
		return Decision{Action: string(val)}, nil
	case *lua.LTable:
		return decisionFromTable(val)
	default:
		return Decision{}, fmt.Errorf("luaplugin: handle() returned unsupported type %s", v.Type())
	}
}

func decisionFromTable(tbl *lua.LTable) (Decision, error) {
	dec := Decision{}
	if s, ok := tbl.RawGetString("action").(lua.LString); ok {
		dec.Action = string(s)
	}
	if s, ok := tbl.RawGetString("message").(lua.LString); ok {
		dec.Message = string(s)
	}
	if s, ok := tbl.RawGetString("redirect_to").(lua.LString); ok {
		dec.RedirectTo = string(s)
	}
	if n, ok := tbl.RawGetString("status_code").(lua.LNumber); ok {
		dec.StatusCode = int(n)
	}
	if hdrs, ok := tbl.RawGetString("headers").(*lua.LTable); ok {
		dec.SetHeaders = make(map[string]string, hdrs.Len())
		hdrs.ForEach(func(k, val lua.LValue) {
			ks, kok := k.(lua.LString)
			vs, vok := val.(lua.LString)
			if kok && vok {
				dec.SetHeaders[string(ks)] = string(vs)
			}
		})
	}
	if tags, ok := tbl.RawGetString("tags").(*lua.LTable); ok {
		tags.ForEach(func(_, val lua.LValue) {
			if s, isStr := val.(lua.LString); isStr {
				dec.Tags = append(dec.Tags, string(s))
			}
		})
	}
	return dec, nil
}
