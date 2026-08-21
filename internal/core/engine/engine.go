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
	"My-OpenWaf/internal/waf/bot"
	"My-OpenWaf/internal/waf/cve"
	"My-OpenWaf/internal/waf/drop"
	"My-OpenWaf/internal/waf/escalation"
	"My-OpenWaf/internal/waf/iprep"
	"My-OpenWaf/internal/waf/jsplugin"
	"My-OpenWaf/internal/waf/luaplugin"
	"My-OpenWaf/internal/waf/ratelimit"
)

// compiledRules holds pre-compiled, pre-partitioned rules for a site.
type compiledRules struct {
	ACL       []rules.Compiled
	Signature []rules.Compiled
	Custom    []rules.Compiled
}

// compiledSnapshot is an immutable snapshot of the compiled rules cache.
// Accessed via atomic.Pointer for lock-free reads on the hot path.
type compiledRulesKey struct {
	siteID   uint
	policyID uint
}

type compiledSnapshot struct {
	revision uint64
	cache    map[compiledRulesKey]*compiledRules
}

// phasesEntry holds a pre-built phase chain along with the protection-config
// pointer and Lua script generation it was built from. Because ProtectionConfig
// is immutable per snapshot, pointer equality is enough for the protection
// portion; the Lua generation also invalidates a chain when scripts are added,
// removed, or replaced without a snapshot revision change.
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

// phasesSnapshot is an immutable snapshot of the phases cache.
// Accessed via atomic.Pointer for lock-free reads on the hot path.
type phasesSnapshot struct {
	revision uint64
	cache    map[phasesCacheKey]*phasesEntry
}

// phaseRuntimeConfig is the immutable bundle of phase-chain dependencies.
// It is replaced atomically when runtime setters change so request-path reads
// always see a consistent snapshot.
type phaseRuntimeConfig struct {
	reqRateLimiter ratelimit.RateLimiterBackend
	antiReplay     *antireplay.AntiReplayManager
	geoResolver    *bot.MaxMindResolver
	botThreshold   int
}

// Engine orchestrates the full WAF processing pipeline for each request.
type Engine struct {
	resolver       *sites.Resolver
	errRateLimiter ratelimit.RateLimiterBackend
	ipRep          *iprep.IPReputation

	// phaseDeps is the immutable bundle of runtime dependencies folded into
	// phase-chain construction. Setters replace it atomically so request-path
	// reads observe a consistent snapshot.
	phaseDeps atomic.Pointer[phaseRuntimeConfig]

	cveDetector  *cve.CVEDetector              // CVE-specific vulnerability detection
	dropExecutor *drop.DropExecutor            // TCP drop executor
	escalation   *escalation.EscalationManager // step-up response escalation

	// Lock-free compiled rules cache. Hot-path reads use atomic.Pointer.Load()
	// (single atomic load, no cache-line bouncing). Writes are serialized by
	// compiledWriteMu and publish a new immutable snapshot via Store().
	compiledPtr     atomic.Pointer[compiledSnapshot]
	compiledWriteMu sync.Mutex

	// Lock-free phase chain cache. Same pattern as compiledPtr.
	phasesPtr     atomic.Pointer[phasesSnapshot]
	phasesWriteMu sync.Mutex

	// luaPlugins 为自定义 Lua 策略引擎，可为 nil（未启用）。
	//
	// 请求路径并发读、reload 路径写，故用 atomic.Pointer 而非裸指针：
	// 后者在此处会构成数据竞争。引擎内部的脚本集合替换有自己的锁。
	luaPlugins atomic.Pointer[luaplugin.Engine]
	// jsPlugins 为自定义 JavaScript 策略引擎，可为 nil（未启用）。
	//
	// 请求路径并发读、reload 路径写，故用 atomic.Pointer 而非裸指针：
	// 后者在此处会构成数据竞争。引擎内部的脚本集合替换有自己的锁。
	jsPlugins atomic.Pointer[jsplugin.Engine]
}

// New creates a WAF engine backed by the given snapshot holder and rate limiters.
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

// SetGeoResolver attaches a MaxMind GeoIP resolver for bot two-phase scoring.
func (e *Engine) SetGeoResolver(geo *bot.MaxMindResolver, threshold int) {
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

// IPReputation returns the underlying IP reputation system.
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
	// 把内置判定暴露给脚本，使其能针对具体阶段与动作做决策。
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
	if runCtx.Err() != nil || !dec.HasAction() {
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
		return makeResult(action.Result{Phase: "lua_post", Category: "lua_plugin", MatchDesc: dec.Message})
	}
	if builtin.IsTerminal() {
		// 内置已判终止且脚本未要求放行：保留内置判定。
		return builtin
	}

	res := makeResult(action.Result{
		Type:      act,
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

	// Maintenance gate: global or per-site.
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

	// Use pre-compiled, pre-partitioned rules (compiled once per snapshot revision per policy).
	cr := e.getCompiledRules(sn, rt)

	// Use per-site effective protection (merged global + site overrides).
	prot := &sn.Protection
	if rt.EffectiveProtection != nil {
		prot = rt.EffectiveProtection
	}

	// Pre-allocated capacity: up to 11 phases (IPReputation, AntiReplay, ACL,
	// LuaPre, OWASP, CVE, Bot, BrowserSign, RateLimit, Signature, Custom).
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

// getCompiledRules returns pre-compiled, pre-partitioned rules for a site,
// compiling them once per snapshot revision per policy.
// Hot-path read: single atomic.Pointer.Load() — no lock, no contention.
func (e *Engine) getCompiledRules(sn *snapshot.Snapshot, rt *snapshot.SiteRuntime) *compiledRules {
	rev := sn.Revision
	key := compiledRulesKey{siteID: rt.Site.ID, policyID: rt.PolicyID}

	// Lock-free fast path: load immutable snapshot and check cache.
	snap := e.compiledPtr.Load()
	if snap.revision == rev {
		if cr, ok := snap.cache[key]; ok {
			return cr
		}
	}

	// Cache miss — compile rules (expensive, but happens at most once per site per revision).
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

	// Serialize writes: copy-on-write the immutable map, then atomic Store.
	e.compiledWriteMu.Lock()
	current := e.compiledPtr.Load()
	var newCache map[compiledRulesKey]*compiledRules
	if current.revision != rev {
		// Revision changed — start fresh.
		newCache = make(map[compiledRulesKey]*compiledRules)
	} else {
		// Same revision — copy existing entries + add new one.
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

// getOrBuildPhases returns a cached phase chain for the given site or builds
// one. The chain is keyed by per-site phase inputs and stays valid as long as
// the snapshot revision, effective protection pointer and site-level phase
// toggles do not change.
//
// Hot-path read: single atomic.Pointer.Load() — no lock, no cache-line bouncing.
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

	// Lock-free fast path.
	snap := e.phasesPtr.Load()
	if snap.revision == rev {
		if entry, ok := snap.cache[key]; ok && entry.prot == prot && entry.lua == lp && entry.luaRevision == luaRevision && entry.deps == deps {
			return entry.phases
		}
	}

	// Build a fresh chain. Pre-allocate capacity for the maximum size.
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
		addPhase(rules.NewBotPhaseWithGeo(e.ipRep, deps.geoResolver, deps.botThreshold))
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

	// Serialize writes: copy-on-write the immutable map, then atomic Store.
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

// Process runs a request through maintenance check, site resolution, and WAF pipeline.
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

// ProcessResolved runs the WAF pipeline for an already-resolved site.
// The dataplane already resolves bind+host before pre-checks; reusing that
// result avoids a second MatchSite lookup and the associated per-request copy.
func (e *Engine) ProcessResolved(sn *snapshot.Snapshot, rt *snapshot.SiteRuntime, reqCtx *pipeline.RequestCtx) ProcessResult {
	return e.processResolved(sn, rt, reqCtx)
}

// Evaluate runs only the WAF rule chain for an already-resolved site (testing helper).
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

// SetDropExecutor attaches a drop executor to the engine.
func (e *Engine) SetDropExecutor(d *drop.DropExecutor) {
	e.dropExecutor = d
}

// SetAntiReplayManager attaches an anti-replay manager to the engine.
func (e *Engine) SetAntiReplayManager(m *antireplay.AntiReplayManager) {
	if e == nil {
		return
	}
	e.updatePhaseDeps(func(deps *phaseRuntimeConfig) {
		deps.antiReplay = m
	})
}

// SetEscalationManager attaches an escalation manager to the engine.
func (e *Engine) SetEscalationManager(m *escalation.EscalationManager) {
	e.escalation = m
}

// convertAndCompile converts snapshot CompiledRules to engine-ready rules.Compiled.
// Used by Evaluate (testing helper) and getCompiledRules (cached per snapshot).
func convertAndCompile(sr []snapshot.CompiledRule) []rules.Compiled {
	storeRules := make([]store.Rule, len(sr))
	for i, r := range sr {
		// Compound rules store raw JSON as arg; reconstruct the original pattern.
		pattern := r.Kind + ":" + r.Arg
		if r.Kind == "compound" {
			pattern = r.Arg // compound patterns are raw JSON starting with "{"
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
