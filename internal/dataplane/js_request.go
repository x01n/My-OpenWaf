package dataplane

import (
	"context"
	"io"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/core/rules"
	"My-OpenWaf/internal/proxy"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/jsplugin"
)

// jsRequestState 是依次执行的请求阶段脚本共享的可变请求视图。
type jsRequestState struct {
	method      string
	path        string
	rawQuery    string
	body        string
	bodyLoaded  bool
	bodySet     bool
	userAgent   string
	contentType string

	// verdict 是脚本给出的裁决；decisionSet 为 false 表示脚本只改了请求、
	// 没有裁决。终止裁决会短路整条 WAF 管道，请求不再走上游。
	verdict     action.Result
	decisionSet bool
}

// Verdict 返回脚本裁决；第二个返回值报告是否存在裁决。
func (s jsRequestState) Verdict() (action.Result, bool) {
	return s.verdict, s.decisionSet
}

func ensureLuaQueryParams(reqCtx *pipeline.RequestCtx) {
	if reqCtx == nil {
		return
	}
	if reqCtx.QueryParams == nil && reqCtx.QueryValues == nil {
		rules.PopulateLuaQueryParams(reqCtx)
	}
}

/**
 * executeJSRequestStage 按快照顺序执行请求阶段脚本。fail-open
 * 脚本在执行或改写失败时被跳过；fail-closed 则把脚本与错误一并
 * 返回，让调用方终止请求且不泄露内部细节。
 */
func executeJSRequestStage(
	ctx context.Context,
	c *app.RequestContext,
	reqCtx *pipeline.RequestCtx,
	scripts []*jsplugin.Script,
	executor jsplugin.Executor,
) (jsRequestState, *jsplugin.Script, error) {
	state := jsRequestState{
		method:      reqCtx.Method,
		path:        reqCtx.Path,
		rawQuery:    reqCtx.RawQuery,
		userAgent:   reqCtx.UserAgent,
		contentType: reqCtx.ContentType,
	}
	for _, script := range scripts {
		if script == nil || script.Stage() != store.JSStageRequest || !script.AppliesTo(reqCtx.SiteID) {
			continue
		}

		ensureLuaQueryParams(reqCtx)

		if !state.bodyLoaded {
			state.body = string(reqCtx.Body)
			state.bodyLoaded = true
		}
		request := jsplugin.RequestSnapshot{
			RequestID:   reqCtx.RequestID,
			SiteID:      reqCtx.SiteID,
			Method:      state.method,
			Path:        state.path,
			RawQuery:    state.rawQuery,
			Host:        reqCtx.Host,
			ClientIP:    clientIPString(reqCtx),
			UserAgent:   state.userAgent,
			ContentType: state.contentType,
			Body:        state.body,
			Headers:     cloneStringMap(reqCtx.Headers),
			QueryParams: cloneStringMap(reqCtx.QueryParams),
		}

		var (
			plan jsplugin.MutationPlan
			err  error
		)
		engineExecutor, isEngine := executor.(*jsplugin.Engine)
		if executor == nil || isEngine && engineExecutor == nil {
			err = jsplugin.ErrCGODisabled
		} else {
			plan, err = executor.Execute(ctx, script, request)
		}
		if err != nil {
			jsplugin.ObserveScriptFault(executor, script, store.JSStageRequest, err)
			if script.FailureMode() == store.JSFailureModeOpen {
				continue
			}
			return state, script, err
		}

		next, err := applyJSMutationPlan(c, reqCtx, state, plan)
		if err != nil {
			// 执行器已成功返回但计划无法应用（校验或写回失败）同样要可见：
			// 这是用户最常遇到的失败形态——字段名写错导致计划被拒。
			jsplugin.ObserveScriptFault(executor, script, store.JSStageRequest, err)
			if script.FailureMode() == store.JSFailureModeOpen {
				continue
			}
			return state, script, err
		}
		state = next
		if verdict, ok := jsMutationVerdict(script, plan); ok {
			// 终止裁决短路后续脚本与整条 WAF 管道：脚本已经明确给出了请求的
			// 最终处置，再跑内置检测只会让更严重的检测结果盖掉脚本意图。
			state.verdict = verdict
			state.decisionSet = true
			return state, script, nil
		}
	}
	return state, nil, nil
}

/**
 * jsMutationVerdict 把脚本的裁决字段转成 action.Result。
 *
 * 动作字符串在这里再经一次 action.Normalize：校验层已保证它可识别，这里做
 * 归一化是为了把 legacy 写法（block/log_only）解析成规范动作，与内置规则
 * 和 Lua 插件走同一条路。
 */
func jsMutationVerdict(script *jsplugin.Script, plan jsplugin.MutationPlan) (action.Result, bool) {
	if plan.Action == nil {
		return action.Result{}, false
	}
	verdict := action.Result{
		Type:      action.Normalize(action.Type(*plan.Action)),
		Matched:   true,
		Phase:     "js_plugin",
		Category:  "js_plugin",
		RuleID:    script.ID(),
		RuleIDStr: script.Name(),
	}
	if plan.Message != nil {
		verdict.MatchDesc = *plan.Message
	}
	if plan.RedirectTo != nil {
		verdict.RedirectTo = *plan.RedirectTo
	}
	if plan.StatusCode != nil {
		verdict.StatusCode = *plan.StatusCode
	}
	if plan.ResponseBody != nil {
		body := *plan.ResponseBody
		verdict.ResponseBody = &body
	}
	if plan.Tags != nil {
		tags := append([]string(nil), (*plan.Tags)...)
		verdict.Tags = &tags
	}
	if plan.SetHeaders != nil {
		// 头变更要在拦截响应上生效，必须走 SetHeaders 而不是直接写 hertz 响应：
		// 数据面渲染拦截页时会重建响应头，直接写入的临时头会被覆盖。
		headers := make(map[string]string, len(plan.SetHeaders))
		for name, value := range plan.SetHeaders {
			headers[name] = value
		}
		verdict.SetHeaders = &headers
	}
	return verdict, true
}

func applyJSMutationPlan(
	c *app.RequestContext,
	reqCtx *pipeline.RequestCtx,
	state jsRequestState,
	plan jsplugin.MutationPlan,
) (jsRequestState, error) {
	if err := jsplugin.ValidateMutationPlan(plan); err != nil {
		return state, err
	}

	next := state
	if plan.Method != nil {
		next.method = *plan.Method
	}
	if plan.Path != nil {
		next.path = *plan.Path
	}
	if plan.RawQuery != nil {
		next.rawQuery = *plan.RawQuery
	}
	if plan.Body != nil {
		next.body = *plan.Body
		next.bodyLoaded = true
		next.bodySet = true
	}

	headers := cloneStringMap(reqCtx.Headers)
	if len(plan.SetHeaders) > 0 && headers == nil {
		headers = make(map[string]string, len(plan.SetHeaders))
	}
	setNames := make(map[string]string, len(plan.SetHeaders))
	for name, value := range plan.SetHeaders {
		key := strings.ToLower(name)
		setNames[key] = name
		headers[key] = value
	}
	for _, name := range plan.DeleteHeaders {
		delete(headers, strings.ToLower(name))
	}
	if value, ok := headers["user-agent"]; ok {
		next.userAgent = value
	} else {
		next.userAgent = ""
	}
	if value, ok := headers["content-type"]; ok {
		next.contentType = value
	} else {
		next.contentType = ""
	}

	requestURI := next.path
	if next.rawQuery != "" {
		requestURI += "?" + next.rawQuery
	}
	c.Request.SetMethod(next.method)
	c.Request.SetRequestURI(requestURI)
	for _, name := range plan.DeleteHeaders {
		c.Request.Header.Del(name)
	}
	for lower, original := range setNames {
		c.Request.Header.Set(original, headers[lower])
	}
	if plan.Body != nil {
		previousSnapshot, _ := requestBodySnapshotFromContext(c)
		c.Request.SetBodyString(next.body)
		if closer, ok := previousSnapshot.original.(io.Closer); ok {
			_ = closer.Close()
		}
		// SetBodyString 用可重放的缓冲替换了流。要阻止外层的
		// 请求体清理逻辑把流还原成改写前的那一个。
		c.Set(requestBodySnapshotContextKey, requestBodySnapshot{
			prefetched: []byte(next.body),
			size:       int64(len(next.body)),
		})
		c.Request.Header.SetContentLength(len(next.body))
	}

	reqCtx.Method = next.method
	reqCtx.Path = next.path
	reqCtx.RawQuery = next.rawQuery
	if plan.Body != nil {
		reqCtx.Body = []byte(next.body)
	}
	reqCtx.UserAgent = next.userAgent
	reqCtx.ContentType = next.contentType
	reqCtx.ResetMutationCaches()
	populateRequestCtxHeaders(reqCtx, c)
	reqCtx.UserAgent = next.userAgent
	reqCtx.ContentType = next.contentType
	reqCtx.QueryParams = nil
	reqCtx.QueryValues = nil
	rules.PopulateLuaQueryParams(reqCtx)
	if c != nil {
		join := reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") })
		c.Set(wafReqCtxHeaderOrderCacheKey, &join)
	}
	return next, nil
}

/**
 * pipelineMutationToJSPlan 把管道上下文里的 Lua 请求改写意图转成相同形状的
 * JS 变更计划。
 *
 * 两者字段一一对应，转换只做搬运：数据面对两阶段的写回必须走同一条路径
 * （applyJSMutationPlan），否则校验与头处理会出现第二套实现。
 */
func pipelineMutationToJSPlan(mutation pipeline.RequestMutator) jsplugin.MutationPlan {
	plan := jsplugin.MutationPlan{
		Method:        mutation.Method,
		Path:          mutation.Path,
		RawQuery:      mutation.RawQuery,
		Body:          mutation.Body,
		SetHeaders:    mutation.SetHeaders,
		DeleteHeaders: mutation.DeleteHeaders,
	}
	return plan
}

func cloneStringMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func clientIPString(reqCtx *pipeline.RequestCtx) string {
	if reqCtx == nil || reqCtx.ClientIP == nil {
		return ""
	}
	return reqCtx.ClientIP.String()
}

/**
 * luaResponseRuntimeKey 保存本次请求的 Lua post 响应改写，由 proxy 的响应
 * 变换链按站点读取。数据面与 proxy 的依赖方向是 dataplane → proxy，改写
 * 意图因此经请求上下文传递，而不是让 proxy 反向依赖 luaplugin。
 */
const luaResponseRuntimeKey = "dataplane_lua_response_mutations"

// ContextWithLuaResponseMutations 把 Lua post 的响应改写挂到请求上下文。
func ContextWithLuaResponseMutations(c *app.RequestContext, mutations []pipeline.ResponseMutator) {
	if c == nil || len(mutations) == 0 {
		return
	}
	c.Set(luaResponseRuntimeKey, mutations)
}

// LuaResponseMutationsFromRequestContext 取回本次请求的 Lua 响应改写。
func LuaResponseMutationsFromRequestContext(c *app.RequestContext, siteID uint) []proxy.LuaResponseRewrite {
	if c == nil {
		return nil
	}
	value, ok := c.Get(luaResponseRuntimeKey)
	if !ok {
		return nil
	}
	mutations, _ := value.([]pipeline.ResponseMutator)
	if len(mutations) == 0 {
		return nil
	}
	// siteID 目前未参与过滤：改写由本次请求自己的脚本产生，天然属于该站点。
	// 参数保留是为了让查找函数签名与 JS 侧一致，将来若需要按站点分桶无需改接口。
	_ = siteID
	rewrites := make([]proxy.LuaResponseRewrite, 0, len(mutations))
	for _, mutation := range mutations {
		rewrites = append(rewrites, proxy.LuaResponseRewrite{
			StatusCode:    mutation.StatusCode,
			Body:          mutation.Body,
			SetHeaders:    mutation.SetHeaders,
			DeleteHeaders: mutation.DeleteHeaders,
		})
	}
	return rewrites
}

const dataplaneJSResponseRuntimeKey = "dataplane_js_response_runtime"

/**
 * ContextWithJSResponseRuntime 把响应阶段执行器与脚本挂到 hertz 请求上下文，
 * 供 internal/proxy 的响应变换链读取。executor 为 nil 等价于运行时不可用，
 * 变换链按 fail-open 跳过。
 */
func ContextWithJSResponseRuntime(c *app.RequestContext, executor jsplugin.ResponseExecutor, scripts []*jsplugin.Script) {
	if c == nil {
		return
	}
	c.Set(dataplaneJSResponseRuntimeKey, jsResponseRuntime{Executor: executor, Scripts: scripts})
}

// jsResponseRuntime 是响应阶段执行编排所需的两件套（请求上下文值）。
type jsResponseRuntime struct {
	Executor jsplugin.ResponseExecutor
	Scripts  []*jsplugin.Script
}

// JSResponseRuntimeFromRequestContext 取回数据面附着在请求上的响应运行时。
func JSResponseRuntimeFromRequestContext(c *app.RequestContext) (jsplugin.ResponseExecutor, []*jsplugin.Script) {
	if c == nil {
		return nil, nil
	}
	value, ok := c.Get(dataplaneJSResponseRuntimeKey)
	if !ok {
		return nil, nil
	}
	runtimeValue, _ := value.(jsResponseRuntime)
	return runtimeValue.Executor, runtimeValue.Scripts
}

/**
 * jspluginEngineAsResponseExecutor 把请求执行器转为响应执行器视图。
 *
 * jsplugin.Engine 同时实现 Executor 与 ResponseExecutor；此处仅做类型断言，
 * 避免在 handler 中重复。executor 为 nil 或未实现 ResponseExecutor 时返回 nil。
 */
func jspluginEngineAsResponseExecutor(executor jsplugin.Executor) jsplugin.ResponseExecutor {
	responseExecutor, _ := executor.(jsplugin.ResponseExecutor)
	return responseExecutor
}
