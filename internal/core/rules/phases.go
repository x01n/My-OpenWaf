package rules

import (
	"net"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf"
)

// MatchCtx is the subset of request data matchers need.
type MatchCtx struct {
	ClientIP net.IP
	Path     string
	Query    string
	Headers  map[string]string
}

func ctxFromPipeline(ctx *pipeline.RequestCtx) MatchCtx {
	return MatchCtx{ClientIP: ctx.ClientIP, Path: ctx.Path, Query: ctx.RawQuery, Headers: ctx.Headers}
}

// ── ACL phase ──

type aclPhase struct{ rules []Compiled }

func NewACLPhase(rules []Compiled) pipeline.Phase { return &aclPhase{rules: filterPhase(rules, "acl")} }

func (p *aclPhase) Name() string { return "acl" }

func (p *aclPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	mc := ctxFromPipeline(ctx)
	for i := range p.rules {
		if p.rules[i].Match(mc) {
			r := hit(p.rules[i])
			if action.Normalize(r.Type) == action.Allow {
				return r, true // allow = short-circuit, skip remaining phases
			}
			return r, r.IsTerminal()
		}
	}
	return action.Pass(), false
}

// ── Signature phase ──

type signaturePhase struct{ rules []Compiled }

func NewSignaturePhase(rules []Compiled) pipeline.Phase {
	return &signaturePhase{rules: filterPhase(rules, "signature")}
}

func (p *signaturePhase) Name() string { return "signature" }

func (p *signaturePhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	mc := ctxFromPipeline(ctx)
	for i := range p.rules {
		if p.rules[i].Match(mc) {
			r := hit(p.rules[i])
			return r, r.IsTerminal()
		}
	}
	return action.Pass(), false
}

// ── Custom phase ──

type customPhase struct{ rules []Compiled }

func NewCustomPhase(rules []Compiled) pipeline.Phase {
	return &customPhase{rules: filterPhase(rules, "custom")}
}

func (p *customPhase) Name() string { return "custom" }

func (p *customPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	mc := ctxFromPipeline(ctx)
	for i := range p.rules {
		if p.rules[i].Match(mc) {
			r := hit(p.rules[i])
			return r, r.IsTerminal()
		}
	}
	return action.Pass(), false
}

// ── Request Rate Limit phase ──

type reqRateLimitPhase struct {
	limiter *waf.RateLimiter
	act     action.Type
}

func NewReqRateLimitPhase(limiter *waf.RateLimiter, act action.Type) pipeline.Phase {
	return &reqRateLimitPhase{limiter: limiter, act: act}
}

func (p *reqRateLimitPhase) Name() string { return "rate_limit" }

func (p *reqRateLimitPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	if p.limiter == nil || !p.limiter.Enabled() {
		return action.Pass(), false
	}
	key := ""
	if ctx.ClientIP != nil {
		key = ctx.ClientIP.String()
	}
	key += "|" + ctx.Host
	if p.limiter.Allow(key) {
		return action.Pass(), false
	}
	result := action.Result{
		Type:      p.act,
		Phase:     "rate_limit",
		MatchDesc: "request rate limit exceeded",
		Matched:   true,
	}
	return result, result.IsTerminal()
}

// ── OWASP Default phase ──

type owaspPhase struct {
	cfg store.ProtectionConfig
}

func NewOWASPPhase(cfg store.ProtectionConfig) pipeline.Phase {
	return &owaspPhase{cfg: cfg}
}

func (p *owaspPhase) Name() string { return "owasp_default" }

func (p *owaspPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	if !p.cfg.OWASPEnabled {
		return action.Pass(), false
	}
	hits := waf.CheckOWASP(p.cfg.OWASPSensitivity, ctx.Path, ctx.RawQuery, ctx.Headers)
	if len(hits) == 0 {
		return action.Pass(), false
	}
	best := hits[0]
	act := action.Type(p.cfg.OWASPAction)
	result := action.Result{
		Type:      act,
		RuleIDStr: best.RuleID,
		Phase:     "owasp_default",
		MatchDesc: best.Desc,
		Matched:   true,
		Category:  string(best.Category),
	}
	return result, result.IsTerminal()
}

// ── helpers ──

func filterPhase(rules []Compiled, phase string) []Compiled {
	var out []Compiled
	for _, r := range rules {
		if r.Phase == phase {
			out = append(out, r)
		}
	}
	return out
}

func hit(c Compiled) action.Result {
	return action.Result{
		Type:      action.Normalize(c.Action),
		RuleID:    c.ID,
		Phase:     c.Phase,
		MatchDesc: c.Kind + ":" + c.Arg,
		Matched:   true,
	}
}
