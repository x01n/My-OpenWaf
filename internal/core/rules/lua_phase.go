package rules

import (
	"context"
	"net/url"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/waf/luaplugin"
)

// LuaPluginEvaluator 抽象 Lua 插件引擎，避免 rules 包直接依赖具体实现，
// 也便于测试注入。
type LuaPluginEvaluator interface {
	HasScripts(stage luaplugin.Stage) bool
	Evaluate(ctx context.Context, stage luaplugin.Stage, req luaplugin.RequestView) luaplugin.Decision
}

// luaPhase 在管道中执行自定义 Lua 策略。
type luaPhase struct {
	engine LuaPluginEvaluator
	stage  luaplugin.Stage
}

// NewLuaPhase 创建 Lua 插件阶段。
//
// stage 决定执行时机：StagePre 在昂贵检测（OWASP/CVE）之前，可提早放行或拦截；
// StagePost 在全部内置阶段之后，能读到内置引擎的判定结果。
func NewLuaPhase(engine LuaPluginEvaluator, stage luaplugin.Stage) pipeline.Phase {
	return &luaPhase{engine: engine, stage: stage}
}

func (p *luaPhase) Name() string {
	if p.stage == luaplugin.StagePre {
		return "lua_pre"
	}
	return "lua_post"
}

/**
 * Execute 运行该阶段的全部脚本并把判定转换为管道结果。
 *
 * 脚本返回的动作经 action.Normalize 归一化并校验：不认识的动作一律忽略
 * （按未判定处理），避免脚本笔误导致意外拦截。allow 在此阶段等同放行并
 * 短路后续阶段，与 ACL 的 allow 语义一致。
 */
func (p *luaPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	if p.engine == nil || !p.engine.HasScripts(p.stage) {
		return action.Result{}, false
	}

	runCtx := ctx.ContextOrBackground()
	if runCtx.Err() != nil {
		return action.Result{}, false
	}

	dec := p.engine.Evaluate(runCtx, p.stage, BuildLuaRequestView(ctx))
	if runCtx.Err() != nil || !dec.HasAction() {
		return action.Result{}, false
	}

	act := action.Normalize(action.Type(dec.Action))
	if !action.IsValid(act) {
		// 脚本给了无法识别的动作：忽略而非拦截。自定义策略的笔误
		// 不应升级为对正常流量的误封。
		return action.Result{}, false
	}

	res := action.Result{
		Type:      act,
		Matched:   true,
		Phase:     p.Name(),
		Category:  "lua_plugin",
		MatchDesc: dec.Message,
	}
	if dec.RedirectTo != "" {
		res.RedirectTo = dec.RedirectTo
	}
	if dec.StatusCode > 0 {
		res.StatusCode = dec.StatusCode
	}
	if len(dec.SetHeaders) > 0 {
		headers := dec.SetHeaders
		res.SetHeaders = &headers
	}
	if dec.ResponseBody != "" {
		body := dec.ResponseBody
		res.ResponseBody = &body
	}
	if len(dec.Tags) > 0 {
		tags := dec.Tags
		res.Tags = &tags
	}

	// tag 与 observe 是非终止动作，交由上层记录后继续；其余为终止动作。
	terminal := act != action.Tag && act != action.Observe
	return res, terminal
}

// BuildLuaRequestView 把管道上下文转为脚本可见的只读视图。
//
// 导出供 engine 包在管道之外执行后置脚本时复用——后置阶段需读到内置判定，
// 无法作为普通管道阶段实现。
//
// 传副本而非指针：脚本无法借它改写 WAF 内部状态。Body 按管道已截断的
// 检查窗口传递，不额外读取。
func BuildLuaRequestView(ctx *pipeline.RequestCtx) luaplugin.RequestView {
	if ctx.QueryParams == nil && ctx.QueryValues == nil {
		PopulateLuaQueryParams(ctx)
	}
	view := luaplugin.RequestView{
		RequestID:   ctx.RequestID,
		Method:      ctx.Method,
		Path:        ctx.Path,
		RawQuery:    ctx.RawQuery,
		Host:        ctx.Host,
		UserAgent:   ctx.UserAgent,
		SiteID:      ctx.SiteID,
		ContentType: ctx.ContentType,
		Headers:     ctx.Headers,
		QueryParams: ctx.QueryParams,
		QueryValues: ctx.QueryValues,
		TLSVersion:  ctx.TLS.TLSVersion,
		TLSJA3:      ctx.TLS.JA3Hash,
		TLSJA4:      ctx.TLS.JA4,
		TLSSNI:      ctx.TLS.SNI,
	}
	if ctx.ClientIP != nil {
		view.ClientIP = ctx.ClientIP.String()
	}
	if len(ctx.Body) > 0 {
		view.Body = string(ctx.Body)
	}
	return view
}

// PopulateLuaQueryParams parses the raw query once for Lua request contexts.
// QueryParams preserves the first value for existing scripts, while QueryValues
// preserves every decoded value in request order for new scripts.
func PopulateLuaQueryParams(ctx *pipeline.RequestCtx) {
	if ctx == nil || ctx.RawQuery == "" {
		return
	}
	values, err := url.ParseQuery(ctx.RawQuery)
	if err != nil {
		return
	}
	ctx.QueryParams = make(map[string]string, len(values))
	ctx.QueryValues = make(map[string][]string, len(values))
	for key, items := range values {
		if len(items) == 0 {
			continue
		}
		ctx.QueryParams[key] = items[0]
		ctx.QueryValues[key] = append([]string(nil), items...)
	}
}
