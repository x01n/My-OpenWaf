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

// ── IP Reputation phase ──

type ipReputationPhase struct {
	rep *waf.IPReputation
}

func NewIPReputationPhase(rep *waf.IPReputation) pipeline.Phase {
	return &ipReputationPhase{rep: rep}
}

func (p *ipReputationPhase) Name() string { return "ip_reputation" }

func (p *ipReputationPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	if p.rep == nil || ctx.ClientIP == nil {
		return action.Pass(), false
	}
	d := p.rep.Check(ctx.ClientIP)
	if !d.Matched {
		return action.Pass(), false
	}
	if d.Allowed {
		// Whitelist: pass through but mark.
		return action.Result{
			Type:      action.Allow,
			Phase:     "ip_reputation",
			MatchDesc: "whitelist: " + d.Reason,
			Matched:   true,
			Category:  "whitelist",
		}, true
	}
	// Blocked.
	result := action.Result{
		Type:      action.Intercept,
		Phase:     "ip_reputation",
		MatchDesc: d.Category + ": " + d.Reason,
		Matched:   true,
		Category:  d.Category,
		RuleIDStr: "iprep:" + d.Category,
	}
	return result, true
}

// ── Bot Detection phase ──

type botPhase struct {
	rep *waf.IPReputation // optional, for recording violations
}

func NewBotPhase(rep *waf.IPReputation) pipeline.Phase {
	return &botPhase{rep: rep}
}

func (p *botPhase) Name() string { return "bot_detection" }

func (p *botPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	br := waf.NewBotRequest(ctx.Method, ctx.Path, ctx.Headers)
	v := waf.CheckBot(br)
	if v.Category == "malicious" {
		if p.rep != nil && ctx.ClientIP != nil {
			p.rep.RecordViolation(ctx.ClientIP)
		}
		result := action.Result{
			Type:      action.Intercept,
			Phase:     "bot_detection",
			MatchDesc: v.Reason,
			Matched:   true,
			Category:  "bot_malicious",
			RuleIDStr: v.RuleID,
		}
		return result, true
	}
	if v.Category == "suspicious" {
		result := action.Result{
			Type:      action.Observe,
			Phase:     "bot_detection",
			MatchDesc: v.Reason,
			Matched:   true,
			Category:  "bot_suspicious",
			RuleIDStr: v.RuleID,
		}
		return result, false
	}
	return action.Pass(), false
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
