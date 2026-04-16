package engine

import (
	"net"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/core/rules"
	"My-OpenWaf/internal/core/sites"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf"
)

// Engine orchestrates the full WAF processing pipeline for each request.
type Engine struct {
	resolver       *sites.Resolver
	reqRateLimiter *waf.RateLimiter
	errRateLimiter *waf.RateLimiter
	ipRep          *waf.IPReputation
}

// New creates a WAF engine backed by the given snapshot holder and rate limiters.
func New(holder *snapshot.Holder, reqRL, errRL *waf.RateLimiter, ipRep *waf.IPReputation) *Engine {
	return &Engine{
		resolver:       sites.NewResolver(holder),
		reqRateLimiter: reqRL,
		errRateLimiter: errRL,
		ipRep:          ipRep,
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

// Process runs a request through maintenance check, site resolution, and WAF pipeline.
func (e *Engine) Process(reqCtx *pipeline.RequestCtx) ProcessResult {
	sn := e.resolver.Snapshot()
	if sn == nil {
		return ProcessResult{}
	}

	rt, ok := sn.MatchSite(reqCtx.ListenerID, reqCtx.Host)
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

	compiled := convertAndCompile(rt.Rules)

	var phases []pipeline.Phase

	// IP reputation runs first: whitelist short-circuits, blacklist blocks.
	if e.ipRep != nil {
		phases = append(phases, rules.NewIPReputationPhase(e.ipRep))
	}

	phases = append(phases, rules.NewACLPhase(compiled))

	// Bot detection before rate limiting (malicious tools should be blocked early).
	if sn.Protection.BotDetectionEnabled {
		phases = append(phases, rules.NewBotPhase(e.ipRep))
	}

	if sn.Protection.RequestRateLimitEnabled && e.reqRateLimiter != nil {
		act := action.Type(sn.Protection.RequestRateLimitAction)
		phases = append(phases, rules.NewReqRateLimitPhase(e.reqRateLimiter, act))
	}

	if sn.Protection.OWASPEnabled {
		phases = append(phases, rules.NewOWASPPhase(sn.Protection))
	}

	phases = append(phases,
		rules.NewSignaturePhase(compiled),
		rules.NewCustomPhase(compiled),
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
