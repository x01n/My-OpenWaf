package proxy

import (
	"context"
	"net"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/jsplugin"
)

// jsResponseRuntimeLookup 由数据面启动时注入：从 hertz 请求上下文取回
// 响应阶段执行器与脚本。proxy 无法导入 dataplane（反向会成环），注入一个
// 查找函数打破依赖方向，未注入时响应阶段按 fail-open 跳过。
var jsResponseRuntimeLookup func(c *app.RequestContext) (jsplugin.ResponseExecutor, []*jsplugin.Script)

// SetJSResponseRuntimeLookup 注册数据面的响应阶段运行时查找函数。
func SetJSResponseRuntimeLookup(lookup func(c *app.RequestContext) (jsplugin.ResponseExecutor, []*jsplugin.Script)) {
	jsResponseRuntimeLookup = lookup
}

// LuaResponseRewrite 描述 Lua post 脚本对上游响应的改写意图。
//
// 定义在 proxy 侧而不是复用 luaplugin 的类型：数据面把 Decision 里的
// ResponseMutation 拆成这些字段交给 proxy，proxy 不需要认识 luaplugin
// （那会引入 waf/luaplugin → ... → proxy 的潜在环）。
type LuaResponseRewrite struct {
	StatusCode    int
	Body          *string
	SetHeaders    map[string]string
	DeleteHeaders []string
}

// luaResponseRewriteLookup 由数据面注入：按站点取回 Lua post 脚本的响应改写。
// 返回 nil 表示该站点本次请求没有可用的改写。
var luaResponseRewriteLookup func(c *app.RequestContext, siteID uint) []LuaResponseRewrite

// SetLuaResponseRewriteLookup 注册 Lua post 响应改写的查找函数。
func SetLuaResponseRewriteLookup(lookup func(c *app.RequestContext, siteID uint) []LuaResponseRewrite) {
	luaResponseRewriteLookup = lookup
}

// jsPluginResponseTransformer 实现 identityResponseTransformer，把
// response 阶段脚本并入动态保护/browser sign 同一条身份响应变换链。
//
// 变换顺序说明：本变换器排在 dynamic 变换之后（见
// responseEntityTransformerForSiteWithClient 的组合方式），原因是响应脚本
// 需要看到接近最终形态的 body/headers，且它只追加修改不反向编码。流式
// (SSE/WS) 路径不使用 identity 响应实体，不受此变换影响，属可接受边界。
//
// response 阶段不引入裁决语义：脚本在这里改的是响应本身（status/body/
// headers），请求走向早已确定，action 之类的字段只会是静默失效的开关。
// 需要裁决的脚本属于 request 阶段。
type jsPluginResponseTransformer struct {
	siteID   uint
	scripts  []*jsplugin.Script
	executor jsplugin.ResponseExecutor
}

func (t *jsPluginResponseTransformer) Transform(entity identityResponseEntity) (identityResponseEntity, error) {
	if t == nil || t.executor == nil || len(t.scripts) == 0 {
		return entity, nil
	}
	request := entity.Request
	body := entity.Body
	statusCode := currentResponseStatus(request)
	for _, script := range t.scripts {
		if script == nil {
			continue
		}
		snapshot := jsplugin.ResponseSnapshot{
			RequestID:      responseRequestID(request),
			SiteID:         t.siteID,
			Status:         statusCode,
			Path:           entity.Path,
			ContentType:    entity.ContentType,
			Body:           string(body),
			Headers:        responseHeadersLower(request),
			Method:         jsPluginRequestMethod(request),
			RawQuery:       requestRawQuery(request),
			ClientIP:       clientIPLabel(entity.ClientIP),
			RequestHeaders: requestHeadersLower(request),
		}
		plan, err := t.executor.ExecuteResponse(context.Background(), script, snapshot)
		if err != nil {
			jsplugin.ObserveScriptFault(t.executor, script, store.JSStageResponse, err)
			if script.FailureMode() == store.JSFailureModeClosed {
				return entity, err
			}
			continue
		}
		nextStatus, nextBody, err := applyJSResponsePlan(request, statusCode, body, plan)
		if err != nil {
			jsplugin.ObserveScriptFault(t.executor, script, store.JSStageResponse, err)
			if script.FailureMode() == store.JSFailureModeClosed {
				return entity, err
			}
			continue
		}
		statusCode = nextStatus
		body = nextBody
	}
	if request != nil && statusCode != request.Response.StatusCode() {
		request.Response.SetStatusCode(statusCode)
	}
	entity.Body = body
	return entity, nil
}

// transformLuaResponseRewrites 在 JS 响应脚本之后应用 Lua post 脚本的响应改写。
//
// 顺序：Lua post 在管道之后、代理之前就已经算出了改写意图，但真正的写入必须
// 等到响应体到手；放在链尾可以让它看到 JS 脚本改写后的最终形态，与「post 是
// 最后一道策略」的语义一致。
//
// 失败语义为 fail-safe：单条改写非法时跳过该条并继续，其余改写照常生效——
// 自定义策略的笔误不应把上游正常响应变成错误页。
func transformLuaResponseRewrites(c *app.RequestContext, siteID uint, entity identityResponseEntity) identityResponseEntity {
	if c == nil || luaResponseRewriteLookup == nil {
		return entity
	}
	rewrites := luaResponseRewriteLookup(c, siteID)
	if len(rewrites) == 0 {
		return entity
	}
	statusCode := currentResponseStatus(c)
	body := entity.Body
	for _, rewrite := range rewrites {
		nextStatus, nextBody, headers, deleted, ok := sanitizeLuaResponseRewrite(rewrite)
		if !ok {
			continue
		}
		for name, value := range headers {
			c.Response.Header.Set(name, value)
		}
		for _, name := range deleted {
			c.Response.Header.Del(name)
		}
		statusCode = nextStatus
		if nextBody != nil {
			body = []byte(*nextBody)
		}
	}
	if statusCode != c.Response.StatusCode() {
		c.Response.SetStatusCode(statusCode)
	}
	entity.Body = body
	return entity
}

// sanitizeLuaResponseRewrite 校验单条 Lua 响应改写。
//
// 返回 ok=false 表示该条改写不可用（状态码越界、头名非法等），调用方跳过它。
// 校验与 luaplugin 的解析层重复一次是有意的：proxy 是最后一道写入方，不能
// 假设上游数据面已经过滤干净。
func sanitizeLuaResponseRewrite(rewrite LuaResponseRewrite) (int, *string, map[string]string, []string, bool) {
	statusCode := rewrite.StatusCode
	if statusCode != 0 && (statusCode < 100 || statusCode > 999) {
		return 0, nil, nil, nil, false
	}
	headers := make(map[string]string, len(rewrite.SetHeaders))
	for name, value := range rewrite.SetHeaders {
		if !validRewriteHeaderName(name) || strings.ContainsAny(value, "\r\n") {
			return 0, nil, nil, nil, false
		}
		headers[name] = value
	}
	deleted := make([]string, 0, len(rewrite.DeleteHeaders))
	for _, name := range rewrite.DeleteHeaders {
		if !validRewriteHeaderName(name) {
			return 0, nil, nil, nil, false
		}
		deleted = append(deleted, name)
	}
	return statusCode, rewrite.Body, headers, deleted, true
}

// validRewriteHeaderName 校验响应头名是 HTTP token。
func validRewriteHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		default:
			return false
		}
	}
	return true
}

// applyJSResponsePlan 校验并应用单个脚本的响应变更计划；body/status 以
// 返回值继续累积，头变更直接落在 hertz 响应视图。
func applyJSResponsePlan(c *app.RequestContext, statusCode int, body []byte, plan jsplugin.ResponseMutationPlan) (int, []byte, error) {
	if err := jsplugin.ValidateResponseMutationPlan(plan); err != nil {
		return statusCode, body, err
	}
	if c != nil {
		for _, name := range plan.DeleteHeaders {
			c.Response.Header.Del(name)
		}
		for name, value := range plan.SetHeaders {
			c.Response.Header.Set(name, value)
		}
	}
	nextStatus := statusCode
	if plan.Status != nil {
		nextStatus = *plan.Status
	}
	nextBody := body
	if plan.Body != nil {
		nextBody = []byte(*plan.Body)
	}
	return nextStatus, nextBody, nil
}

// jsPluginResponseTransformerFor 为站点构建响应阶段 JS 变换器；没有响应
// 脚本、运行时不可用或请求上下文缺失时返回 nil，不引入任何请求开销。
func jsPluginResponseTransformerFor(c *app.RequestContext, rt snapshot.SiteRuntime) identityResponseTransformer {
	if c == nil || jsResponseRuntimeLookup == nil {
		return nil
	}
	executor, scripts := jsResponseRuntimeLookup(c)
	if executor == nil || len(scripts) == 0 {
		return nil
	}
	filtered := make([]*jsplugin.Script, 0, len(scripts))
	for _, script := range scripts {
		if script == nil || script.Stage() != store.JSStageResponse || !script.AppliesTo(rt.Site.ID) {
			continue
		}
		filtered = append(filtered, script)
	}
	if len(filtered) == 0 {
		return nil
	}
	return &jsPluginResponseTransformer{siteID: rt.Site.ID, scripts: filtered, executor: executor}
}

// currentResponseStatus 读取变换链开始时的 hertz 响应状态码。
func currentResponseStatus(c *app.RequestContext) int {
	if c == nil {
		return 0
	}
	return c.Response.StatusCode()
}

// jsPluginRequestMethod 读取请求方法；request 为 nil 时给空串。
func jsPluginRequestMethod(c *app.RequestContext) string {
	if c == nil {
		return ""
	}
	return string(c.Method())
}

// responseRequestID 取数据面在请求入口写入的 X-Request-ID 响应头；
// 该头在 proxy 路径已由 handler 预先设置。
func responseRequestID(c *app.RequestContext) string {
	if c == nil {
		return ""
	}
	return string(c.Response.Header.Peek("X-Request-ID"))
}

// requestRawQuery 从 RequestURI 剥出 query 部分；无 query 时返回空串。
func requestRawQuery(c *app.RequestContext) string {
	if c == nil {
		return ""
	}
	uri := string(c.Request.RequestURI())
	if index := strings.IndexByte(uri, '?'); index >= 0 {
		return uri[index+1:]
	}
	return ""
}

// clientIPLabel 把变换实体上的客户端 IP 转成快照字段；nil 时给空串。
func clientIPLabel(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// responseHeadersLower 返回小写键的响应头单值映射（map[string]string 契约）。
func responseHeadersLower(c *app.RequestContext) map[string]string {
	if c == nil {
		return nil
	}
	headers := make(map[string]string)
	c.Response.Header.VisitAll(func(key, value []byte) {
		headers[strings.ToLower(string(key))] = string(value)
	})
	return headers
}

// requestHeadersLower 返回小写键的请求头单值映射。
func requestHeadersLower(c *app.RequestContext) map[string]string {
	if c == nil {
		return nil
	}
	headers := make(map[string]string)
	c.Request.Header.VisitAll(func(key, value []byte) {
		headers[strings.ToLower(string(key))] = string(value)
	})
	return headers
}
