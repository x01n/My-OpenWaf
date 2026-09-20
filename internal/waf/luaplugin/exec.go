package luaplugin

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
	"golang.org/x/net/http/httpguts"
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
	QueryValues map[string][]string
	Body        string
	TLSVersion  string
	TLSJA3      string
	TLSJA4      string
	TLSSNI      string
	// Phase/Action 是内置阶段的判定结果，仅 post 阶段有值。
	Phase  string
	Action string
	// Verdict 是仅在 post 阶段注入的安全内置判定元数据。
	Verdict VerdictView

	// Response 是可选的上游响应快照；pre 阶段通常为空。
	Response ResponseView
	// Config 是由受信任调用方注入的只读外部配置。
	Config map[string]string
	// Runtime 是由受信任调用方注入的只读运行时参数。
	Runtime map[string]string
	// Metrics 是由受信任调用方注入的只读指标快照。
	Metrics map[string]float64
	// Log/Debug 只允许写入宿主统一日志；nil 时对应 Lua API 为安全空操作。
	Log   func(level, message string)
	Debug func(message string)
}

// ResponseView 是可选的、受限的上游响应快照。
type ResponseView struct {
	StatusCode  int
	ContentType string
	Headers     map[string]string
	Body        string
}

// VerdictView is the safe subset of the builtin verdict exposed to post scripts.
type VerdictView struct {
	Matched    bool
	Phase      string
	Action     string
	Category   string
	RuleID     uint
	RuleIDStr  string
	StatusCode int
	RedirectTo string
	Tags       []string
}

// SetRuntimeHooks 注入每次脚本调用可使用的受控观测回调。
// 回调只在当前请求执行期间使用，不会进入 Lua 全局状态。
func (r *RequestView) SetRuntimeHooks(logFn func(string, string), debugFn func(string)) {
	if r == nil {
		return
	}
	r.Log = logFn
	r.Debug = debugFn
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
	L.SetTop(0)
	defer func() {
		L.SetTop(0)
		pool.put(L)
	}()

	// 超时与指令上限双闸：context 负责挂钟超时，指令钩子兜住紧密循环
	// （紧密计算循环可能长时间不触发 context 检查点）。
	runCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	L.SetContext(runCtx)
	defer L.RemoveContext()

	dec, err := s.callHandler(L, runCtx, req, kv)
	if err == nil {
		if ctxErr := runCtx.Err(); ctxErr != nil {
			s.timeouts.Add(1)
			return Decision{}, fmt.Errorf("luaplugin: %q exceeded %s: %w", s.name, s.timeout, ctxErr)
		}
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
func (s *Script) callHandler(L *lua.LState, runCtx context.Context, req RequestView, kv KVBackend) (dec Decision, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("luaplugin: %q panicked: %v", s.name, r)
		}
	}()

	// 载入已编译原型并执行顶层代码（定义 handle 等）。
	L.Push(L.NewFunctionFromProto(s.proto))
	// Top-level chunks only define the handler. Discard all chunk return values
	// so a script's previous results cannot remain below the handler call.
	if err := L.PCall(0, 0, nil); err != nil {
		return Decision{}, fmt.Errorf("luaplugin: %q init failed: %w", s.name, err)
	}

	handler, ok := L.GetGlobal(handlerName).(*lua.LFunction)
	if !ok {
		return Decision{}, ErrNoHandler
	}

	ctxTable := buildContextTable(L, runCtx, req, kv, &apiBudget{})
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
// 返回表可携带 message / redirect_to / status_code / headers / response_body / tags。
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
		dec.Action = truncateString(string(s), maxDecisionActionBytes)
	}
	if s, ok := tbl.RawGetString("message").(lua.LString); ok {
		if value := truncateString(string(s), maxDecisionMessageBytes); !containsSensitiveDecisionText(value) {
			dec.Message = value
		}
	}
	if s, ok := tbl.RawGetString("redirect_to").(lua.LString); ok {
		dec.RedirectTo = safeRedirectTarget(truncateString(string(s), maxDecisionRedirectBytes))
	}
	if n, ok := tbl.RawGetString("status_code").(lua.LNumber); ok {
		status := int(n)
		if n == lua.LNumber(status) && status >= minDecisionStatusCode && status <= maxDecisionStatusCode {
			dec.StatusCode = status
		}
	}
	if s, ok := tbl.RawGetString("response_body").(lua.LString); ok {
		if value := truncateString(string(s), maxResponseBody); !containsSensitiveDecisionText(value) {
			dec.ResponseBody = value
		}
	}
	if hdrs, ok := tbl.RawGetString("headers").(*lua.LTable); ok {
		dec.SetHeaders = make(map[string]string, maxDecisionHeaders)
		entries := 0
		visited := 0
		hdrs.ForEach(func(k, val lua.LValue) {
			if entries >= maxDecisionHeaders || visited >= maxDecisionTableEntries {
				return
			}
			visited++
			ks, kok := k.(lua.LString)
			vs, vok := val.(lua.LString)
			if !kok || !vok || len(ks) == 0 || len(ks) > maxDecisionHeaderNameBytes {
				return
			}
			name := string(ks)
			value := string(vs)
			if !httpguts.ValidHeaderFieldName(name) || !allowedDecisionHeader(name) ||
				strings.ContainsAny(value, "\r\n") || containsSensitiveDecisionText(value) {
				return
			}
			dec.SetHeaders[name] = truncateString(value, maxDecisionHeaderValueBytes)
			entries++
		})
		if len(dec.SetHeaders) == 0 {
			dec.SetHeaders = nil
		}
	}
	if tags, ok := tbl.RawGetString("tags").(*lua.LTable); ok {
		dec.Tags = make([]string, 0, maxDecisionTags)
		visited := 0
		tags.ForEach(func(_, val lua.LValue) {
			if len(dec.Tags) >= maxDecisionTags || visited >= maxDecisionTableEntries {
				return
			}
			visited++
			if s, isStr := val.(lua.LString); isStr {
				value := truncateString(string(s), maxDecisionTagBytes)
				if !containsSensitiveDecisionText(value) {
					dec.Tags = append(dec.Tags, value)
				}
			}
		})
		if len(dec.Tags) == 0 {
			dec.Tags = nil
		}
	}
	return dec, nil
}

// containsSensitiveDecisionText 报告 Lua Decision 输出是否含明显认证秘密。
// 请求上下文仍按用户决策保留原始可读；净化只发生在返回宿主、进入日志/响应前。
func containsSensitiveDecisionText(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"authorization", "cookie", "set-cookie", "bearer"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// allowedDecisionHeader 限制 Lua 只能设置普通端到端响应头。
// 敏感认证头、逐跳头和实体长度头由宿主统一生成，避免脚本破坏响应边界。
func allowedDecisionHeader(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "www-authenticate", "proxy-authenticate",
		"connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
		"content-length", "location":
		return false
	default:
		return true
	}
}

func safeRedirectTarget(raw string) string {
	value := strings.TrimSpace(truncateString(raw, maxAPIStringBytes))
	if value == "" || strings.ContainsAny(value, "\r\n") || strings.HasPrefix(value, "//") {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return ""
	}
	if parsed.IsAbs() && parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	if !parsed.IsAbs() && !strings.HasPrefix(value, "/") {
		return ""
	}
	return value
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
