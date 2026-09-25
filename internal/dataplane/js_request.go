package dataplane

import (
	"context"
	"io"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/core/rules"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/jsplugin"
)

// jsRequestState is the mutable request view shared by sequential request-stage scripts.
type jsRequestState struct {
	method      string
	path        string
	rawQuery    string
	body        string
	bodyLoaded  bool
	bodySet     bool
	userAgent   string
	contentType string
}

func ensureLuaQueryParams(reqCtx *pipeline.RequestCtx) {
	if reqCtx == nil {
		return
	}
	if reqCtx.QueryParams == nil && reqCtx.QueryValues == nil {
		rules.PopulateLuaQueryParams(reqCtx)
	}
}

// executeJSRequestStage executes request-stage scripts in snapshot order. A fail-open
// script is skipped on execution or mutation failure; fail-closed returns the script
// and error so the caller can terminate the request without exposing internals.
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
			if script.FailureMode() == store.JSFailureModeOpen {
				continue
			}
			return state, script, err
		}

		next, err := applyJSMutationPlan(c, reqCtx, state, plan)
		if err != nil {
			if script.FailureMode() == store.JSFailureModeOpen {
				continue
			}
			return state, script, err
		}
		state = next
	}
	return state, nil, nil
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
		// SetBodyString replaces the stream with a replayable buffer. Prevent the
		// outer request-body cleanup from restoring the pre-mutation stream.
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

const dataplaneJSResponseRuntimeKey = "dataplane_js_response_runtime"

// ContextWithJSResponseRuntime 把响应阶段执行器与脚本挂到 hertz 请求上下文，
// 供 internal/proxy 的响应变换链读取。executor 为 nil 等价于运行时不可用，
// 变换链按 fail-open 跳过。
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

// jspluginEngineAsResponseExecutor 把请求执行器转为响应执行器视图。
//
// jsplugin.Engine 同时实现 Executor 与 ResponseExecutor；此处仅做类型断言，
// 避免在 handler 中重复。executor 为 nil 或未实现 ResponseExecutor 时返回 nil。
func jspluginEngineAsResponseExecutor(executor jsplugin.Executor) jsplugin.ResponseExecutor {
	responseExecutor, _ := executor.(jsplugin.ResponseExecutor)
	return responseExecutor
}
