package engine

import (
	"net"
	"sync"
	"sync/atomic"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/core/rules"
	"My-OpenWaf/internal/core/sites"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/antireplay"
	"My-OpenWaf/internal/waf/bot/geoip"
	"My-OpenWaf/internal/waf/cve"
	"My-OpenWaf/internal/waf/drop"
	"My-OpenWaf/internal/waf/escalation"
	"My-OpenWaf/internal/waf/iprep"
	"My-OpenWaf/internal/waf/jsplugin"
	"My-OpenWaf/internal/waf/luaplugin"
	"My-OpenWaf/internal/waf/ratelimit"
)

// compiledRules 保存某站点预编译、预分区的规则。
type compiledRules struct {
	ACL       []rules.Compiled
	Signature []rules.Compiled
	Custom    []rules.Compiled
}

// compiledSnapshot 是编译规则缓存的不可变快照。
// 经 atomic.Pointer 访问，热路径上实现无锁读取。
type compiledRulesKey struct {
	siteID   uint
	policyID uint
}

type compiledSnapshot struct {
	revision uint64
	cache    map[compiledRulesKey]*compiledRules
}

/**
 * phasesEntry 保存预构建的阶段链，以及构建它时所依据的防护配置指针与
 * Lua 脚本代次。
 *
 * 之所以用「代次」而不是只比 revision：ProtectionConfig 在单个快照内
 * 不可变，指针相等即可判定防护配置部分是否仍需重建；但脚本被增删改时
 * 快照 revision 可能不变，此时必须靠 Lua 代次让缓存的阶段链失效。
 */
type phasesEntry struct {
	prot        *store.ProtectionConfig
	lua         *luaplugin.Engine
	luaRevision uint64
	deps        *phaseRuntimeConfig
	phases      []pipeline.Phase
}

type phasesCacheKey struct {
	policyID          uint
	siteID            uint
	antiReplayEnabled bool
}

// phasesSnapshot 是阶段链缓存的不可变快照。
// 经 atomic.Pointer 访问，热路径上实现无锁读取。
type phasesSnapshot struct {
	revision uint64
	cache    map[phasesCacheKey]*phasesEntry
}

// phaseRuntimeConfig 是阶段链依赖的不可变打包体。
// 运行时 setter 变更时整体原子替换，使请求路径读到的始终是一致快照。
type phaseRuntimeConfig struct {
	reqRateLimiter ratelimit.RateLimiterBackend
	antiReplay     *antireplay.AntiReplayManager
	geoResolver    *geoip.MaxMindResolver
	botThreshold   int
}

// Engine 编排每个请求的完整 WAF 处理管道。
type Engine struct {
	resolver       *sites.Resolver
	errRateLimiter ratelimit.RateLimiterBackend
	ipRep          *iprep.IPReputation

	// phaseDeps 是折叠进阶段链构建的运行时依赖不可变打包体。setter 原子替换它，
	// 使请求路径读到的始终是一致快照。
	phaseDeps atomic.Pointer[phaseRuntimeConfig]

	cveDetector  *cve.CVEDetector              // CVE 专项漏洞检测
	dropExecutor *drop.DropExecutor            // TCP 丢包执行器
	escalation   *escalation.EscalationManager // 分级响应升级

	// 无锁的编译规则缓存。热路径读取只用一次 atomic.Pointer.Load()，不触发
	// 缓存行争用；写入由 compiledWriteMu 串行化，并通过 Store() 发布新的不可变快照。
	compiledPtr     atomic.Pointer[compiledSnapshot]
	compiledWriteMu sync.Mutex

	// 无锁的阶段链缓存，模式与 compiledPtr 相同。
	phasesPtr     atomic.Pointer[phasesSnapshot]
	phasesWriteMu sync.Mutex

	// luaPlugins 为自定义 Lua 策略引擎，可为 nil（未启用）。
	// 请求路径并发读、reload 路径写，故用 atomic.Pointer 而非裸指针：后者在此处
	// 会构成数据竞争。引擎内部的脚本集合替换有自己的锁。
	luaPlugins atomic.Pointer[luaplugin.Engine]
	// jsPlugins 为自定义 JavaScript 策略引擎，可为 nil（未启用）。
	// 请求路径并发读、reload 路径写，故用 atomic.Pointer 而非裸指针：后者在此处
	// 会构成数据竞争。引擎内部的脚本集合替换有自己的锁。
	jsPlugins atomic.Pointer[jsplugin.Engine]
}

// New 创建由给定快照 holder 与限流后端支撑的 WAF 引擎。
func New(holder *snapshot.Holder, reqRL, errRL ratelimit.RateLimiterBackend, ipRep *iprep.IPReputation) *Engine {
	e := &Engine{
		resolver:       sites.NewResolver(holder),
		errRateLimiter: errRL,
		ipRep:          ipRep,
		cveDetector:    cve.NewCVEDetector(),
	}
	e.compiledPtr.Store(&compiledSnapshot{cache: make(map[compiledRulesKey]*compiledRules)})
	e.phasesPtr.Store(&phasesSnapshot{cache: make(map[phasesCacheKey]*phasesEntry)})
	e.phaseDeps.Store(&phaseRuntimeConfig{reqRateLimiter: reqRL, botThreshold: 80})
	return e
}

func (e *Engine) loadPhaseDeps() *phaseRuntimeConfig {
	if e == nil {
		return nil
	}
	if deps := e.phaseDeps.Load(); deps != nil {
		return deps
	}
	deps := &phaseRuntimeConfig{botThreshold: 80}
	if e.phaseDeps.CompareAndSwap(nil, deps) {
		return deps
	}
	if current := e.phaseDeps.Load(); current != nil {
		return current
	}
	return deps
}

func (e *Engine) updatePhaseDeps(mutator func(*phaseRuntimeConfig)) {
	if e == nil || mutator == nil {
		return
	}
	for {
		current := e.loadPhaseDeps()
		next := *current
		mutator(&next)
		if e.phaseDeps.CompareAndSwap(current, &next) {
			return
		}
	}
}

// SetGeoResolver 挂载 MaxMind GeoIP 解析器，供 bot 两阶段评分使用。
func (e *Engine) SetGeoResolver(geo *geoip.MaxMindResolver, threshold int) {
	if e == nil {
		return
	}
	e.updatePhaseDeps(func(deps *phaseRuntimeConfig) {
		deps.geoResolver = geo
		if threshold > 0 {
			deps.botThreshold = threshold
		}
	})
}

func (e *Engine) SetBotThreshold(threshold int) {
	if e == nil || threshold <= 0 {
		return
	}
	e.updatePhaseDeps(func(deps *phaseRuntimeConfig) {
		deps.botThreshold = threshold
	})
}

// IPReputation 返回底层的 IP 声誉系统。
func (e *Engine) IPReputation() *iprep.IPReputation { return e.ipRep }

// SetLuaPlugins 设置或热替换自定义 Lua 策略引擎。传 nil 即停用插件。
func (e *Engine) SetLuaPlugins(lp *luaplugin.Engine) {
	if e == nil {
		return
	}
	e.luaPlugins.Store(lp)
}

// LuaPlugins 返回当前的 Lua 策略引擎，可能为 nil。
func (e *Engine) LuaPlugins() *luaplugin.Engine {
	if e == nil {
		return nil
	}
	return e.luaPlugins.Load()
}

// SetJSPlugins 设置或热替换自定义 JavaScript 策略引擎。传 nil 即停用插件。
func (e *Engine) SetJSPlugins(jp *jsplugin.Engine) {
	if e == nil {
		return
	}
	e.jsPlugins.Store(jp)
}

// JSPlugins 返回当前的 JavaScript 策略引擎，可能为 nil。
func (e *Engine) JSPlugins() *jsplugin.Engine {
	if e == nil {
		return nil
	}
	return e.jsPlugins.Load()
}

/**
 * applyPostLuaDecision 让后置脚本在拿到内置判定后决定是否覆盖它。
 *
 * 后置策略不能作为普通管道阶段实现：管道遇终止动作即 return，链尾阶段
 * 永远读不到「已被拦截」的判定，也就无法实现「对误报放行」这一核心用例。
 *
 * 覆盖规则刻意收紧：
 *   - 只有 allow 能推翻内置的终止判定
 *   - 其余动作仅在内置未给出终止判定时生效，避免脚本绕过内置的终止优先级
 *     语义（drop > intercept > rate_limit > challenge > redirect）
 *   - 无法识别的动作一律忽略：自定义策略的笔误不应升级为误封
 *
 * @param lp      Lua 引擎。
 * @param reqCtx  请求上下文。
 * @param builtin 内置管道给出的判定。
 * @return 最终判定。
 */
func applyPostLuaDecision(lp *luaplugin.Engine, reqCtx *pipeline.RequestCtx, builtin action.Result) action.Result {
	view := rules.BuildLuaRequestView(reqCtx)
	view.Runtime = rules.BuildLuaPostRuntimeView(reqCtx)
	view.Phase = builtin.Phase
	if builtin.Matched {
		view.Action = string(builtin.Type)
	}
	view.Verdict = luaplugin.VerdictView{
		Matched:    builtin.Matched,
		Phase:      builtin.Phase,
		Action:     view.Action,
		Category:   builtin.Category,
		RuleID:     builtin.RuleID,
		RuleIDStr:  builtin.RuleIDStr,
		StatusCode: builtin.StatusCode,
		RedirectTo: builtin.RedirectTo,
	}
	if builtin.Tags != nil {
		view.Verdict.Tags = append([]string(nil), (*builtin.Tags)...)
	}

	runCtx := reqCtx.ContextOrBackground()
	if runCtx.Err() != nil {
		return builtin
	}

	dec := lp.Evaluate(runCtx, luaplugin.StagePost, view)
	if runCtx.Err() != nil {
		return builtin
	}
	if dec.ResponseMutation != nil {
		reqCtx.AppendResponseMutation(pipeline.ResponseMutator{
			ScriptName:    dec.ScriptName,
			StatusCode:    dec.ResponseMutation.StatusCode,
			Body:          dec.ResponseMutation.Body,
			SetHeaders:    dec.ResponseMutation.SetHeaders,
			DeleteHeaders: dec.ResponseMutation.DeleteHeaders,
		})
	}
	if !dec.HasAction() {
		return builtin
	}
	act := action.Normalize(action.Type(dec.Action))
	if !action.IsValid(act) {
		return builtin
	}

	makeResult := func(result action.Result) action.Result {
		if len(dec.SetHeaders) > 0 {
			headers := dec.SetHeaders
			result.SetHeaders = &headers
		}
		if dec.ResponseBody != "" {
			body := dec.ResponseBody
			result.ResponseBody = &body
		}
		if len(dec.Tags) > 0 {
			tags := dec.Tags
			result.Tags = &tags
		}
		return result
	}

	if act == action.Allow {
		// 放行：清空内置判定，请求继续走向上游。
		return makeResult(action.Result{RuleID: dec.ScriptID, RuleIDStr: dec.ScriptName, Phase: "lua_post", Category: "lua_plugin", MatchDesc: dec.Message})
	}
	if builtin.IsTerminal() {
		// 内置已判终止且脚本未要求放行：保留内置判定。
		return builtin
	}

	res := makeResult(action.Result{
		Type:      act,
		RuleID:    dec.ScriptID,
		RuleIDStr: dec.ScriptName,
		Matched:   true,
		Phase:     "lua_post",
		Category:  "lua_plugin",
		MatchDesc: dec.Message,
	})
	if dec.RedirectTo != "" {
		res.RedirectTo = dec.RedirectTo
	}
	if dec.StatusCode > 0 {
		res.StatusCode = dec.StatusCode
	}
	return res
}

type ProcessResult struct {
	Action      action.Result
	Site        *snapshot.SiteRuntime
	ObserveHits []action.Result
	Maintenance bool
}

func (e *Engine) processResolved(sn *snapshot.Snapshot, rt *snapshot.SiteRuntime, reqCtx *pipeline.RequestCtx) ProcessResult {
	if sn == nil || rt == nil {
		return ProcessResult{}
	}

	// 维护模式闸门：全局或按站点。
	if sn.Protection.MaintenanceGlobalEnabled || rt.MaintenanceEnabled {
		return ProcessResult{
			Action: action.Result{
				Type:      action.Intercept,
				Phase:     "maintenance",
				MatchDesc: "maintenance mode active",
				Matched:   true,
			},
			Site:        rt,
			Maintenance: true,
		}
	}

	// 使用预编译、预分区的规则（每个快照 revision、每个策略只编译一次）。
	cr := e.getCompiledRules(sn, rt)

	// 使用按站点生效的防护配置（全局与站点覆盖合并后的结果）。
	prot := &sn.Protection
	if rt.EffectiveProtection != nil {
		prot = rt.EffectiveProtection
	}

	// 预分配容量：最多 11 个阶段（IPReputation、AntiReplay、ACL、LuaPre、OWASP、
	// CVE、Bot、BrowserSign、RateLimit、Signature、Custom，按启用情况入链）。
	phases := e.getOrBuildPhases(sn, rt, cr, prot)

	runResult := pipeline.Run(phases, reqCtx)
	res := runResult.Action

	// 后置 Lua 策略在此执行而非作为管道阶段：管道遇终止动作即 return，
	// 挂在链尾的阶段永远读不到「已被拦截」的判定，也就无法实现
	// 「对特定误报放行」这一核心用例。放在这里才能拿到完整结果并覆盖它。
	if lp := e.luaPlugins.Load(); lp != nil && lp.HasScripts(luaplugin.StagePost) {
		res = applyPostLuaDecision(lp, reqCtx, res)
	}

	return ProcessResult{
		Action:      res,
		Site:        rt,
		ObserveHits: runResult.ObserveHits,
	}
}

/**
 * getCompiledRules 返回某站点预编译、预分区的规则，每个快照 revision、
 * 每个策略只编译一次。
 *
 * 热路径读取：单次 atomic.Pointer.Load()，不加锁、无争用。
 */
func (e *Engine) getCompiledRules(sn *snapshot.Snapshot, rt *snapshot.SiteRuntime) *compiledRules {
	rev := sn.Revision
	key := compiledRulesKey{siteID: rt.Site.ID, policyID: rt.PolicyID}

	// 无锁快路径：加载不可变快照并查缓存。
	snap := e.compiledPtr.Load()
	if snap.revision == rev {
		if cr, ok := snap.cache[key]; ok {
			return cr
		}
	}

	// 缓存未命中——编译规则（开销较大，但每个站点每个 revision 至多发生一次）。
	all := convertAndCompile(rt.Rules)
	cr := &compiledRules{}
	for i := range all {
		switch all[i].Phase {
		case "acl":
			cr.ACL = append(cr.ACL, all[i])
		case "signature":
			cr.Signature = append(cr.Signature, all[i])
		case "custom":
			cr.Custom = append(cr.Custom, all[i])
		}
	}

	// 串行化写入：先对不可变 map 做写时复制，再原子 Store。
	e.compiledWriteMu.Lock()
	current := e.compiledPtr.Load()
	var newCache map[compiledRulesKey]*compiledRules
	if current.revision != rev {
		// revision 已变化——从头重建。
		newCache = make(map[compiledRulesKey]*compiledRules)
	} else {
		// revision 相同——复制现有条目并加入新条目。
		newCache = make(map[compiledRulesKey]*compiledRules, len(current.cache)+1)
		for k, v := range current.cache {
			newCache[k] = v
		}
	}
	newCache[key] = cr
	e.compiledPtr.Store(&compiledSnapshot{revision: rev, cache: newCache})
	e.compiledWriteMu.Unlock()

	return cr
}

/**
 * getOrBuildPhases 返回给定站点的缓存阶段链，没有则构建一条。
 *
 * 缓存键由按站点的阶段输入构成；只要快照 revision、生效防护配置指针与站点级
 * 阶段开关不变，链就持续有效。
 *
 * 热路径读取：单次 atomic.Pointer.Load()，不加锁、无缓存行争用。
 */
func (e *Engine) getOrBuildPhases(sn *snapshot.Snapshot, rt *snapshot.SiteRuntime, cr *compiledRules, prot *store.ProtectionConfig) []pipeline.Phase {
	if e == nil {
		return nil
	}
	rev := sn.Revision
	key := phasesCacheKey{
		policyID:          rt.PolicyID,
		siteID:            rt.Site.ID,
		antiReplayEnabled: rt.AntiReplayEnabled,
	}
	lp := e.luaPlugins.Load()
	var luaRevision uint64
	if lp != nil {
		luaRevision = lp.Revision()
	}
	deps := e.loadPhaseDeps()

	// 无锁快路径。
	snap := e.phasesPtr.Load()
	if snap.revision == rev {
		if entry, ok := snap.cache[key]; ok && entry.prot == prot && entry.lua == lp && entry.luaRevision == luaRevision && entry.deps == deps {
			return entry.phases
		}
	}

	// 构建新链。按最大规模预分配容量。
	phases := make([]pipeline.Phase, 0, 11)

	// 按 phase 跳过检测：配了跳过路径的 phase 会被包一层按路径短路的装饰器，
	// 未配置的 phase 原样入链，热路径不引入额外分支。
	skipMap := prot.GetSkipPathByPhase()
	addPhase := func(ph pipeline.Phase) {
		if len(skipMap) > 0 {
			ph = rules.NewSkipByPathPhase(ph, skipMap[ph.Name()])
		}
		phases = append(phases, ph)
	}

	if e.ipRep != nil {
		addPhase(rules.NewIPReputationPhase(e.ipRep, rt.SiteIPWhitelist, rt.SiteIPBlacklist))
	}
	if deps.antiReplay != nil && rt.AntiReplayEnabled {
		addPhase(rules.NewAntiReplayPhase(deps.antiReplay))
	}

	if len(cr.ACL) > 0 {
		addPhase(rules.NewACLPhasePrecompiled(cr.ACL))
	}

	// 前置 Lua 策略：位于 ACL 之后、OWASP 之前，可在昂贵检测前提早判定。
	// 后置策略不在此处——它需读到内置判定，见 applyPostLuaDecision。
	if lp := e.luaPlugins.Load(); lp != nil && lp.HasScripts(luaplugin.StagePre) {
		addPhase(rules.NewLuaPhase(lp, luaplugin.StagePre))
	}

	if prot.OWASPEnabled {
		addPhase(rules.NewOWASPPhase(prot))
	}
	if prot.CVEEnabled && e.cveDetector != nil {
		addPhase(rules.NewCVEPhase(prot, e.cveDetector))
	}

	if prot.BotDetectionEnabled {
		// 行为模块需要限流窗口的请求计数；未启用限流时传 nil，行为分恒 0。
		var botLimiter ratelimit.RateLimiterBackend
		if deps.reqRateLimiter != nil && deps.reqRateLimiter.Enabled() {
			botLimiter = deps.reqRateLimiter
		}
		addPhase(rules.NewBotPhaseWithGeoAndLimiter(e.ipRep, deps.geoResolver, deps.botThreshold, botLimiter, prot.RequestRateLimitMax))
	}

	// 浏览器签名校验：对 API 特征请求校验页面挂载 JS 写入的短时效签名头。
	if prot.BrowserSignEnabled {
		addPhase(rules.NewBrowserSignPhase(prot))
	}

	if prot.RequestRateLimitEnabled && deps.reqRateLimiter != nil {
		act := action.Type(prot.RequestRateLimitAction)
		addPhase(rules.NewReqRateLimitPhase(deps.reqRateLimiter, act))
	}

	// signature 与 custom 是用户自建规则，不参与按 phase 跳过（停用规则本身即可），
	// 故直接 append 而不走 addPhase。
	if len(cr.Signature) > 0 {
		phases = append(phases, rules.NewSignaturePhasePrecompiled(cr.Signature))
	}
	if len(cr.Custom) > 0 {
		phases = append(phases, rules.NewCustomPhasePrecompiled(cr.Custom))
	}

	// 串行化写入：先对不可变 map 做写时复制，再原子 Store。
	e.phasesWriteMu.Lock()
	current := e.phasesPtr.Load()
	var newCache map[phasesCacheKey]*phasesEntry
	if current.revision != rev {
		newCache = make(map[phasesCacheKey]*phasesEntry)
	} else {
		newCache = make(map[phasesCacheKey]*phasesEntry, len(current.cache)+1)
		for k, v := range current.cache {
			newCache[k] = v
		}
	}
	newCache[key] = &phasesEntry{prot: prot, lua: lp, luaRevision: luaRevision, deps: deps, phases: phases}
	e.phasesPtr.Store(&phasesSnapshot{revision: rev, cache: newCache})
	e.phasesWriteMu.Unlock()

	return phases
}

// Process 让请求依次经过维护检查、站点解析与 WAF 管道。
func (e *Engine) Process(reqCtx *pipeline.RequestCtx) ProcessResult {
	sn := e.resolver.Snapshot()
	if sn == nil {
		return ProcessResult{}
	}

	rt, ok := sn.MatchSitePtr(reqCtx.Bind, reqCtx.Host)
	if !ok {
		return ProcessResult{}
	}
	return e.processResolved(sn, rt, reqCtx)
}

/**
 * ProcessResolved 为已完成站点解析的请求运行 WAF 管道。
 *
 * 数据面在预检查之前已解析过 bind+host，复用该结果可避免第二次 MatchSite
 * 查找及其附带的每请求拷贝。
 */
func (e *Engine) ProcessResolved(sn *snapshot.Snapshot, rt *snapshot.SiteRuntime, reqCtx *pipeline.RequestCtx) ProcessResult {
	return e.processResolved(sn, rt, reqCtx)
}

// Evaluate 只对已完成站点解析的请求运行 WAF 规则链（测试辅助方法）。
func (e *Engine) Evaluate(clientIP net.IP, path, rawQuery string, siteRules []snapshot.CompiledRule) action.Result {
	compiled := convertAndCompile(siteRules)
	ctx := &pipeline.RequestCtx{
		ClientIP: clientIP,
		Path:     path,
		RawQuery: rawQuery,
	}
	pipe := pipeline.New(
		rules.NewACLPhase(compiled),
		rules.NewSignaturePhase(compiled),
		rules.NewCustomPhase(compiled),
	)
	return pipe.Run(ctx).Action
}

func (e *Engine) Resolver() *sites.Resolver                    { return e.resolver }
func (e *Engine) ErrRateLimiter() ratelimit.RateLimiterBackend { return e.errRateLimiter }
func (e *Engine) CVEDetector() *cve.CVEDetector                { return e.cveDetector }
func (e *Engine) DropExecutor() *drop.DropExecutor             { return e.dropExecutor }
func (e *Engine) AntiReplay() *antireplay.AntiReplayManager {
	deps := e.loadPhaseDeps()
	if deps == nil {
		return nil
	}
	return deps.antiReplay
}
func (e *Engine) Escalation() *escalation.EscalationManager { return e.escalation }

// SetDropExecutor 为引擎挂载丢包执行器。
func (e *Engine) SetDropExecutor(d *drop.DropExecutor) {
	e.dropExecutor = d
}

// SetAntiReplayManager 为引擎挂载防重放管理器。
func (e *Engine) SetAntiReplayManager(m *antireplay.AntiReplayManager) {
	if e == nil {
		return
	}
	e.updatePhaseDeps(func(deps *phaseRuntimeConfig) {
		deps.antiReplay = m
	})
}

// SetEscalationManager 为引擎挂载分级升级管理器。
func (e *Engine) SetEscalationManager(m *escalation.EscalationManager) {
	e.escalation = m
}

// convertAndCompile 把快照里的 CompiledRule 转为引擎可直接使用的 rules.Compiled。
// 供 Evaluate（测试辅助）与 getCompiledRules（按快照缓存）共用。
func convertAndCompile(sr []snapshot.CompiledRule) []rules.Compiled {
	storeRules := make([]store.Rule, len(sr))
	for i, r := range sr {
		// 复合规则把原始 JSON 存进 arg，此处还原为原始 pattern。
		pattern := r.Kind + ":" + r.Arg
		if r.Kind == "compound" {
			pattern = r.Arg // 复合规则的 pattern 是原始 JSON，以 "{" 开头
		}
		storeRules[i] = store.Rule{
			Phase:       r.Phase,
			Pattern:     pattern,
			Action:      r.Action,
			Priority:    r.Priority,
			Enabled:     true,
			StatusCode:  r.StatusCode,
			RedirectTo:  r.RedirectTo,
			CaptchaType: r.CaptchaType,
		}
		storeRules[i].ID = r.ID
	}
	return rules.Compile(storeRules)
}
