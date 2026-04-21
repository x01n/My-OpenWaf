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
	"My-OpenWaf/internal/waf"
)

// compiledRules holds pre-compiled, pre-partitioned rules for a site.
type compiledRules struct {
	ACL       []rules.Compiled
	Signature []rules.Compiled
	Custom    []rules.Compiled
}

// Engine orchestrates the full WAF processing pipeline for each request.
type Engine struct {
	resolver       *sites.Resolver
	reqRateLimiter *waf.RateLimiter
	errRateLimiter *waf.RateLimiter
	ipRep          *waf.IPReputation
	geoResolver    *waf.MaxMindResolver // nil when GeoIP DB is unavailable
	botThreshold   int                  // score threshold for bot blocking
	cveDetector    *waf.CVEDetector     // CVE-specific vulnerability detection
	dropExecutor   *waf.DropExecutor    // TCP drop executor

	// Per-snapshot rule compilation cache. Key: snapshotRevision<<32 | policyID.
	// Cleared on snapshot change via revision check.
	compiledMu       sync.RWMutex
	compiledRevision uint64
	compiledCache    map[uint]*compiledRules
}

// New creates a WAF engine backed by the given snapshot holder and rate limiters.
func New(holder *snapshot.Holder, reqRL, errRL *waf.RateLimiter, ipRep *waf.IPReputation) *Engine {
	return &Engine{
		resolver:       sites.NewResolver(holder),
		reqRateLimiter: reqRL,
		errRateLimiter: errRL,
		ipRep:          ipRep,
		botThreshold:   80,
		cveDetector:    waf.NewCVEDetector(),
		compiledCache:  make(map[uint]*compiledRules),
	}
}

// SetGeoResolver attaches a MaxMind GeoIP resolver for bot two-phase scoring.
func (e *Engine) SetGeoResolver(geo *waf.MaxMindResolver, threshold int) {
	e.geoResolver = geo
	if threshold > 0 {
		e.botThreshold = threshold
	}
}

// IPReputation returns the underlying IP reputation system.
func (e *Engine) IPReputation() *waf.IPReputation { return e.ipRep }

type ProcessResult struct {
	Action      action.Result
	Site        *snapshot.SiteRuntime
	ObserveHits []action.Result
	Maintenance bool
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

// Process runs a request through maintenance check, site resolution, and WAF pipeline.
func (e *Engine) Process(reqCtx *pipeline.RequestCtx) ProcessResult {
	sn := e.resolver.Snapshot()
	if sn == nil {
		return ProcessResult{}
	}

	rt, ok := sn.MatchSite(reqCtx.Bind, reqCtx.Host)
	if !ok {
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
			Site:        &rt,
			Maintenance: true,
		}
	}

	// Use pre-compiled, pre-partitioned rules (compiled once per snapshot revision per policy).
	cr := e.getCompiledRules(sn, &rt)

	var phases []pipeline.Phase

	// IP reputation runs first: whitelist short-circuits, blacklist blocks.
	if e.ipRep != nil {
		phases = append(phases, rules.NewIPReputationPhase(e.ipRep))
	}

	phases = append(phases, rules.NewACLPhasePrecompiled(cr.ACL))

	// Bot detection before rate limiting (malicious tools should be blocked early).
	if sn.Protection.BotDetectionEnabled {
		if e.geoResolver != nil {
			phases = append(phases, rules.NewBotPhaseWithGeo(e.ipRep, e.geoResolver, e.botThreshold))
		} else {
			phases = append(phases, rules.NewBotPhase(e.ipRep))
		}
	}

	if sn.Protection.RequestRateLimitEnabled && e.reqRateLimiter != nil {
		act := action.Type(sn.Protection.RequestRateLimitAction)
		phases = append(phases, rules.NewReqRateLimitPhase(e.reqRateLimiter, act))
	}

	if sn.Protection.OWASPEnabled {
		phases = append(phases, rules.NewOWASPPhase(sn.Protection))
	}

	// CVE detection runs after OWASP (OWASP covers generic attacks, CVE covers targeted exploits).
	if sn.Protection.CVEEnabled && e.cveDetector != nil {
		phases = append(phases, rules.NewCVEPhase(sn.Protection, e.cveDetector))
	}

	phases = append(phases,
		rules.NewSignaturePhasePrecompiled(cr.Signature),
		rules.NewCustomPhasePrecompiled(cr.Custom),
	)

	pipe := pipeline.New(phases...)
	runResult := pipe.Run(reqCtx)
	return ProcessResult{
		Action:      runResult.Action,
		Site:        &rt,
		ObserveHits: runResult.ObserveHits,
	}
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

func (e *Engine) Resolver() *sites.Resolver        { return e.resolver }
func (e *Engine) ErrRateLimiter() *waf.RateLimiter { return e.errRateLimiter }
func (e *Engine) CVEDetector() *waf.CVEDetector    { return e.cveDetector }
func (e *Engine) DropExecutor() *waf.DropExecutor  { return e.dropExecutor }

// SetDropExecutor attaches a drop executor to the engine.
func (e *Engine) SetDropExecutor(d *waf.DropExecutor) {
	e.dropExecutor = d
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
			Phase:    r.Phase,
			Pattern:  pattern,
			Action:   r.Action,
			Priority: r.Priority,
			Enabled:  true,
		}
		storeRules[i].ID = r.ID
	}
	return rules.Compile(storeRules)
}
