package engine

import (
	"net"
	"sync"

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
	"My-OpenWaf/internal/waf/ratelimit"
)

// compiledRules holds pre-compiled, pre-partitioned rules for a site.
type compiledRules struct {
	ACL       []rules.Compiled
	Signature []rules.Compiled
	Custom    []rules.Compiled
}

// phasesEntry holds a pre-built phase chain along with the protection-config
// pointer it was built from. Because ProtectionConfig is immutable per snapshot,
// pointer equality is enough to detect when the cached chain is still valid.
type phasesEntry struct {
	prot   *store.ProtectionConfig
	phases []pipeline.Phase
}

type phasesCacheKey struct {
	policyID          uint
	antiReplayEnabled bool
}

// Engine orchestrates the full WAF processing pipeline for each request.
type Engine struct {
	resolver       *sites.Resolver
	reqRateLimiter ratelimit.RateLimiterBackend
	errRateLimiter ratelimit.RateLimiterBackend
	ipRep          *iprep.IPReputation
	geoResolver    *bot.MaxMindResolver          // nil when GeoIP DB is unavailable
	botThreshold   int                           // score threshold for bot blocking
	cveDetector    *cve.CVEDetector              // CVE-specific vulnerability detection
	dropExecutor   *drop.DropExecutor            // TCP drop executor
	antiReplay     *antireplay.AntiReplayManager // nonce-based replay prevention
	escalation     *escalation.EscalationManager // step-up response escalation

	// Per-snapshot rule compilation cache. Key: snapshotRevision<<32 | policyID.
	// Cleared on snapshot change via revision check.
	compiledMu       sync.RWMutex
	compiledRevision uint64
	compiledCache    map[uint]*compiledRules

	// Per-snapshot phase chain cache. Key: site-level phase-affecting inputs.
	// Invalidated when revision changes.
	phasesMu       sync.RWMutex
	phasesRevision uint64
	phasesCache    map[phasesCacheKey]*phasesEntry
}

// New creates a WAF engine backed by the given snapshot holder and rate limiters.
func New(holder *snapshot.Holder, reqRL, errRL ratelimit.RateLimiterBackend, ipRep *iprep.IPReputation) *Engine {
	return &Engine{
		resolver:       sites.NewResolver(holder),
		reqRateLimiter: reqRL,
		errRateLimiter: errRL,
		ipRep:          ipRep,
		botThreshold:   80,
		cveDetector:    cve.NewCVEDetector(),
		compiledCache:  make(map[uint]*compiledRules),
		phasesCache:    make(map[phasesCacheKey]*phasesEntry),
	}
}

// SetGeoResolver attaches a MaxMind GeoIP resolver for bot two-phase scoring.
func (e *Engine) SetGeoResolver(geo *bot.MaxMindResolver, threshold int) {
	e.geoResolver = geo
	e.SetBotThreshold(threshold)
}

func (e *Engine) SetBotThreshold(threshold int) {
	if threshold > 0 {
		e.botThreshold = threshold
	}
}

// IPReputation returns the underlying IP reputation system.
func (e *Engine) IPReputation() *iprep.IPReputation { return e.ipRep }

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

	// Pre-allocated capacity: up to ~9 phases (IPReputation, AntiReplay,
	// ACL, OWASP, CVE, Bot, RateLimit, Signature, Custom).
	phases := e.getOrBuildPhases(sn, rt, cr, prot)

	runResult := pipeline.Run(phases, reqCtx)
	return ProcessResult{
		Action:      runResult.Action,
		Site:        rt,
		ObserveHits: runResult.ObserveHits,
	}
}

// getCompiledRules returns pre-compiled, pre-partitioned rules for a site,
// compiling them once per snapshot revision per policy.
func (e *Engine) getCompiledRules(sn *snapshot.Snapshot, rt *snapshot.SiteRuntime) *compiledRules {
	rev := sn.Revision
	policyID := rt.PolicyID

	e.compiledMu.RLock()
	if e.compiledRevision == rev {
		if cr, ok := e.compiledCache[policyID]; ok {
			e.compiledMu.RUnlock()
			return cr
		}
	}
	e.compiledMu.RUnlock()

	// Compile rules (this is the expensive operation we want to do only once).
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

	e.compiledMu.Lock()
	if e.compiledRevision != rev {
		// Snapshot changed — clear old cache.
		e.compiledCache = make(map[uint]*compiledRules)
		e.compiledRevision = rev
	}
	e.compiledCache[policyID] = cr
	e.compiledMu.Unlock()

	return cr
}

// getOrBuildPhases returns a cached phase chain for the given site or builds
// one. The chain is keyed by per-site phase inputs and stays valid as long as
// the snapshot revision, effective protection pointer and site-level phase
// toggles do not change.
//
// Hot path optimisation: this avoids allocating ~10 phase structs and a slice
// on every request. The cache hit cost is one RLock + one map lookup.
func (e *Engine) getOrBuildPhases(sn *snapshot.Snapshot, rt *snapshot.SiteRuntime, cr *compiledRules, prot *store.ProtectionConfig) []pipeline.Phase {
	rev := sn.Revision
	key := phasesCacheKey{
		policyID:          rt.PolicyID,
		antiReplayEnabled: rt.AntiReplayEnabled,
	}

	e.phasesMu.RLock()
	if e.phasesRevision == rev {
		if entry, ok := e.phasesCache[key]; ok && entry.prot == prot {
			e.phasesMu.RUnlock()
			return entry.phases
		}
	}
	e.phasesMu.RUnlock()

	// Build a fresh chain. Pre-allocate capacity for the maximum size.
	phases := make([]pipeline.Phase, 0, 9)

	if e.ipRep != nil {
		phases = append(phases, rules.NewIPReputationPhase(e.ipRep))
	}
	if e.antiReplay != nil && rt.AntiReplayEnabled {
		phases = append(phases, rules.NewAntiReplayPhase(e.antiReplay))
	}

	if len(cr.ACL) > 0 {
		phases = append(phases, rules.NewACLPhasePrecompiled(cr.ACL))
	}

	if prot.OWASPEnabled {
		phases = append(phases, rules.NewOWASPPhase(prot))
	}
	if prot.CVEEnabled && e.cveDetector != nil {
		phases = append(phases, rules.NewCVEPhase(prot, e.cveDetector))
	}

	if prot.BotDetectionEnabled {
		phases = append(phases, rules.NewBotPhaseWithGeo(e.ipRep, e.geoResolver, e.botThreshold))
	}

	if prot.RequestRateLimitEnabled && e.reqRateLimiter != nil {
		act := action.Type(prot.RequestRateLimitAction)
		phases = append(phases, rules.NewReqRateLimitPhase(e.reqRateLimiter, act))
	}

	if len(cr.Signature) > 0 {
		phases = append(phases, rules.NewSignaturePhasePrecompiled(cr.Signature))
	}
	if len(cr.Custom) > 0 {
		phases = append(phases, rules.NewCustomPhasePrecompiled(cr.Custom))
	}

	e.phasesMu.Lock()
	if e.phasesRevision != rev {
		e.phasesCache = make(map[phasesCacheKey]*phasesEntry)
		e.phasesRevision = rev
	}
	e.phasesCache[key] = &phasesEntry{prot: prot, phases: phases}
	e.phasesMu.Unlock()

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
func (e *Engine) AntiReplay() *antireplay.AntiReplayManager    { return e.antiReplay }
func (e *Engine) Escalation() *escalation.EscalationManager    { return e.escalation }

// SetDropExecutor attaches a drop executor to the engine.
func (e *Engine) SetDropExecutor(d *drop.DropExecutor) {
	e.dropExecutor = d
}

// SetAntiReplayManager attaches an anti-replay manager to the engine.
func (e *Engine) SetAntiReplayManager(m *antireplay.AntiReplayManager) {
	e.antiReplay = m
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
			Phase:      r.Phase,
			Pattern:    pattern,
			Action:     r.Action,
			Priority:   r.Priority,
			Enabled:    true,
			StatusCode: r.StatusCode,
			RedirectTo: r.RedirectTo,
		}
		storeRules[i].ID = r.ID
	}
	return rules.Compile(storeRules)
}
