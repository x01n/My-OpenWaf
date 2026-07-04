package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/url"
	"strings"
	"time"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/antireplay"
	"My-OpenWaf/internal/waf/bot"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/cve"
	"My-OpenWaf/internal/waf/iprep"
	"My-OpenWaf/internal/waf/owasp"
	"My-OpenWaf/internal/waf/ratelimit"
)

// MatchCtx is the subset of request data matchers need.
type MatchCtx struct {
	ClientIP         net.IP
	Method           string
	Path             string
	Query            string
	Headers          map[string]string
	HeadersLowercase bool
	Host             string
	HeaderOrder      string
	TLSALPN          string
	TLSCipherSuites  string
	TLS              *bot.TLSClientFingerprint
	Body             []byte
}

func fillMatchCtxFromPipeline(ctx *pipeline.RequestCtx, needsDerivedHeaders bool, mc *MatchCtx) {
	mc.ClientIP = ctx.ClientIP
	mc.Method = ctx.Method
	mc.Path = ctx.Path
	mc.Query = ctx.RawQuery
	mc.Headers = ctx.Headers
	mc.HeadersLowercase = ctx.HeadersLowercase
	mc.Host = ctx.Host
	mc.TLS = &ctx.TLS
	mc.Body = ctx.Body
	if needsDerivedHeaders {
		if len(ctx.TLS.ALPN) > 0 {
			mc.TLSALPN = strings.Join(ctx.TLS.ALPN, ",")
		}
		if len(ctx.TLS.CipherSuites) > 0 {
			mc.TLSCipherSuites = formatTLSCipherSuitesHeaderValue(ctx.TLS.CipherSuites)
		}
		if len(ctx.HeaderKeys) > 0 {
			mc.HeaderOrder = strings.Join(ctx.HeaderKeys, ",")
		}
	}
}

func ctxFromPipeline(ctx *pipeline.RequestCtx, needsDerivedHeaders bool) MatchCtx {
	var mc MatchCtx
	fillMatchCtxFromPipeline(ctx, needsDerivedHeaders, &mc)
	return mc
}

func executeCompiledPhase(ctx *pipeline.RequestCtx, rules []Compiled, allowShortCircuit bool, needsDerivedHeaders bool) (action.Result, bool) {
	if len(rules) == 0 {
		return action.Pass(), false
	}

	var mc MatchCtx
	fillMatchCtxFromPipeline(ctx, needsDerivedHeaders, &mc)

	for i := range rules {
		if !rules[i].Match(mc) {
			continue
		}
		r := hit(rules[i])
		if allowShortCircuit && r.Type == action.Allow {
			return r, true
		}
		return r, r.IsTerminal()
	}

	return action.Pass(), false
}

// ── ACL phase ──

type aclPhase struct {
	rules               []Compiled
	needsDerivedHeaders bool
}

func NewACLPhase(rules []Compiled) pipeline.Phase {
	filtered := filterPhase(rules, "acl")
	return &aclPhase{rules: filtered, needsDerivedHeaders: compiledRulesNeedDerivedHeaders(filtered)}
}

// NewACLPhasePrecompiled creates an ACL phase from already-partitioned rules (no filtering needed).
func NewACLPhasePrecompiled(rules []Compiled) pipeline.Phase {
	return &aclPhase{rules: ensureCompiledMetadata(rules), needsDerivedHeaders: compiledRulesNeedDerivedHeaders(rules)}
}

func (p *aclPhase) Name() string { return "acl" }

func (p *aclPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	return executeCompiledPhase(ctx, p.rules, true, p.needsDerivedHeaders)
}

// ── ACL allow precheck phase ──

type aclAllowPrecheckPhase struct {
	rules               []Compiled
	needsDerivedHeaders bool
}

func NewACLAllowPrecheckPhasePrecompiled(rules []Compiled) pipeline.Phase {
	return &aclAllowPrecheckPhase{rules: ensureCompiledMetadata(rules), needsDerivedHeaders: compiledRulesNeedDerivedHeaders(rules)}
}

func (p *aclAllowPrecheckPhase) Name() string { return "acl_allow_precheck" }

func (p *aclAllowPrecheckPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	mc := ctxFromPipeline(ctx, p.needsDerivedHeaders)
	for i := range p.rules {
		if p.rules[i].runtimeAction != action.Allow {
			continue
		}
		if p.rules[i].Match(mc) {
			return hit(p.rules[i]), true
		}
	}
	return action.Pass(), false
}

// ── Signature phase ──

type signaturePhase struct {
	rules               []Compiled
	needsDerivedHeaders bool
}

func NewSignaturePhase(rules []Compiled) pipeline.Phase {
	filtered := filterPhase(rules, "signature")
	return &signaturePhase{rules: filtered, needsDerivedHeaders: compiledRulesNeedDerivedHeaders(filtered)}
}

// NewSignaturePhasePrecompiled creates a signature phase from already-partitioned rules.
func NewSignaturePhasePrecompiled(rules []Compiled) pipeline.Phase {
	return &signaturePhase{rules: ensureCompiledMetadata(rules), needsDerivedHeaders: compiledRulesNeedDerivedHeaders(rules)}
}

func (p *signaturePhase) Name() string { return "signature" }

func (p *signaturePhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	return executeCompiledPhase(ctx, p.rules, false, p.needsDerivedHeaders)
}

// ── Custom phase ──

type customPhase struct {
	rules               []Compiled
	needsDerivedHeaders bool
}

func NewCustomPhase(rules []Compiled) pipeline.Phase {
	filtered := filterPhase(rules, "custom")
	return &customPhase{rules: filtered, needsDerivedHeaders: compiledRulesNeedDerivedHeaders(filtered)}
}

// NewCustomPhasePrecompiled creates a custom phase from already-partitioned rules.
func NewCustomPhasePrecompiled(rules []Compiled) pipeline.Phase {
	return &customPhase{rules: ensureCompiledMetadata(rules), needsDerivedHeaders: compiledRulesNeedDerivedHeaders(rules)}
}

func (p *customPhase) Name() string { return "custom" }

func (p *customPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	return executeCustomPhase(ctx, p.rules, p.needsDerivedHeaders)
}

func executeCustomPhase(ctx *pipeline.RequestCtx, rules []Compiled, needsDerivedHeaders bool) (action.Result, bool) {
	fmt.Printf("[DEBUG] executeCustomPhase: ctx.TLS.ALPN=%v ctx.TLS.HasValue=%v needsDerivedHeaders=%v\n", ctx.TLS.ALPN, ctx.TLS.HasValue(), needsDerivedHeaders)
	if len(rules) == 0 {
		return action.Pass(), false
	}

	var mc MatchCtx
	fillMatchCtxFromPipeline(ctx, needsDerivedHeaders, &mc)
	var observeHits []action.Result

	for i := range rules {
		if !rules[i].Match(mc) {
			continue
		}
		r := hit(rules[i])
		if r.ShouldLog() && !r.IsTerminal() {
			observeHits = append(observeHits, r)
			continue
		}
		if len(observeHits) > 0 {
			ctx.AppendPhaseObserveHits(observeHits)
		}
		return r, r.IsTerminal()
	}

	if len(observeHits) == 0 {
		return action.Pass(), false
	}
	if len(observeHits) > 1 {
		ctx.AppendPhaseObserveHits(observeHits[1:])
	}
	return observeHits[0], false
}

func compiledRulesNeedDerivedHeaders(rules []Compiled) bool {
	for i := range rules {
		if ruleNeedsDerivedHeaders(rules[i].Kind, rules[i].Arg) {
			return true
		}
	}
	return false
}

func ruleNeedsDerivedHeaders(kind string, arg string) bool {
	switch kind {
	case "tls_alpn",
		"tls_cipher_suite",
		"tls_cipher_suites",
		"header_order_contains",
		"header_order_regex":
		return true
	case "compound":
		return compoundNeedsDerivedHeaders(arg)
	default:
		return false
	}
}

func compoundNeedsDerivedHeaders(raw string) bool {
	var cond compoundCondition
	if err := json.Unmarshal([]byte(raw), &cond); err != nil {
		return false
	}
	return compoundConditionNeedsDerivedHeaders(cond)
}

func compoundConditionNeedsDerivedHeaders(cond compoundCondition) bool {
	op := strings.ToLower(strings.TrimSpace(cond.Op))
	switch op {
	case "and", "or":
		for i := range cond.Children {
			if compoundConditionNeedsDerivedHeaders(cond.Children[i]) {
				return true
			}
		}
		return false
	case "not", "cc_rate":
		if len(cond.Children) == 0 {
			return false
		}
		return compoundConditionNeedsDerivedHeaders(cond.Children[0])
	case "if", "if_else", "ifelse":
		if cond.If != nil && compoundConditionNeedsDerivedHeaders(*cond.If) {
			return true
		}
		if cond.Then != nil && compoundConditionNeedsDerivedHeaders(*cond.Then) {
			return true
		}
		if cond.Else != nil && compoundConditionNeedsDerivedHeaders(*cond.Else) {
			return true
		}
		return false
	default:
		if cond.If != nil && cond.Then != nil {
			if compoundConditionNeedsDerivedHeaders(*cond.If) {
				return true
			}
			if compoundConditionNeedsDerivedHeaders(*cond.Then) {
				return true
			}
			if cond.Else != nil && compoundConditionNeedsDerivedHeaders(*cond.Else) {
				return true
			}
			return false
		}
		if cond.Kind == "" {
			return false
		}
		return ruleNeedsDerivedHeaders(cond.Kind, cond.Arg)
	}
}

// ── Request Rate Limit phase ──

type reqRateLimitPhase struct {
	limiter ratelimit.RateLimiterBackend
	act     action.Type
}

func NewReqRateLimitPhase(limiter ratelimit.RateLimiterBackend, act action.Type) pipeline.Phase {
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
	act := normalizeConfiguredAction(string(p.act))
	if act == "" {
		act = action.RateLimit
	}
	result := action.Result{
		Type:      act,
		Phase:     "rate_limit",
		RuleIDStr: "request_rate_limit",
		MatchDesc: "request rate limit exceeded",
		Matched:   true,
		Category:  "rate_limit",
	}
	if act == action.RateLimit {
		result.StatusCode = 429
	}
	return result, result.IsTerminal()
}

// ── IP Reputation phase ──

type ipReputationPhase struct {
	rep *iprep.IPReputation
}

func NewIPReputationPhase(rep *iprep.IPReputation) pipeline.Phase {
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

// ── Bot Detection phase (two-phase: PreScreen → DeepScore) ──

type botPhase struct {
	rep       *iprep.IPReputation  // optional, for recording violations
	geo       *bot.MaxMindResolver // optional, for GeoIP scoring
	threshold int                  // score threshold for blocking
}

// NewBotPhase creates a bot-detection pipeline phase using the legacy
// single-pass check (no GeoIP weighting). Kept for backward compatibility.
func NewBotPhase(rep *iprep.IPReputation) pipeline.Phase {
	return &botPhase{rep: rep, threshold: 80}
}

// NewBotPhaseWithGeo creates a bot-detection pipeline phase that uses the
// two-phase PreScreen → DeepScore flow with GeoIP weighting.
func NewBotPhaseWithGeo(rep *iprep.IPReputation, geo *bot.MaxMindResolver, threshold int) pipeline.Phase {
	if threshold <= 0 {
		threshold = 80
	}
	return &botPhase{rep: rep, geo: geo, threshold: threshold}
}

func (p *botPhase) Name() string { return "bot_detection" }

func (p *botPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	// Skip challenge for requests that already passed a signed verification cookie.
	if cookie, ok := lookupHeaderValue(ctx.Headers, "cookie"); ok && challenge.VerifyChallengePassCookieWithClaims(cookie, challenge.ChallengePassClaims{Host: ctx.Host, ClientIP: ctx.ClientIP, UserAgent: ctx.UserAgent, SiteID: ctx.SiteID, Bind: ctx.Bind}, time.Now()) {
		return action.Pass(), false
	}

	br := bot.NewBotRequest(ctx.Method, ctx.Path, ctx.Headers)
	br.ClientIP = ctx.ClientIP
	br.HeaderKeys = ctx.HeaderKeys
	br.TLS = ctx.TLS

	// If GeoIP resolver is available, use the two-phase flow.
	if p.geo != nil {
		v, bs := bot.CheckBotTwoPhase(br, p.rep, p.geo, p.threshold)
		p.storeBotScore(ctx, v, bs)
		return p.verdictToResult(v, ctx)
	}

	// Fallback: legacy single-pass check.
	v := bot.CheckBot(br)
	p.storeBotScore(ctx, v, bot.BotScore{Total: v.Score})
	return p.verdictToResult(v, ctx)
}

func (p *botPhase) storeBotScore(ctx *pipeline.RequestCtx, v bot.BotVerdict, bs bot.BotScore) {
	if v.Category == "human" || v.Category == "good" {
		return // Don't log benign traffic to save DB writes
	}
	actionStr := "allow"
	switch v.Category {
	case "malicious":
		if v.Score >= p.threshold {
			actionStr = "drop"
		} else {
			actionStr = "block"
		}
	case "suspicious":
		suspiciousThreshold := p.threshold * 60 / 100
		if v.Score >= suspiciousThreshold {
			actionStr = "challenge"
		} else {
			actionStr = "observe"
		}
	}
	detailStr := ""
	if bs.IsHighRisk && len(bs.Details) > 0 {
		if data, err := json.Marshal(bs.Details); err == nil {
			detailStr = string(data)
		}
	}
	ctx.BotScoreResult = &pipeline.BotScoreInfo{
		TotalScore:       bs.Total,
		GeoIPScore:       bs.GeoIPScore,
		FingerprintScore: bs.FingerprintScore,
		BehaviorScore:    bs.BehaviorScore,
		IPRepScore:       bs.IPRepScore,
		IsHighRisk:       bs.IsHighRisk,
		Action:           actionStr,
		Details:          detailStr,
	}
}

func (p *botPhase) verdictToResult(v bot.BotVerdict, ctx *pipeline.RequestCtx) (action.Result, bool) {
	if v.Category == "malicious" {
		if p.rep != nil && ctx.ClientIP != nil {
			p.rep.RecordViolation(ctx.ClientIP)
		}
		actType := action.Type(action.Intercept)
		if v.Score >= p.threshold {
			actType = action.Drop
		}
		result := action.Result{
			Type:      actType,
			Phase:     "bot_detection",
			MatchDesc: v.Reason,
			Matched:   true,
			Category:  "bot_malicious",
			RuleIDStr: v.RuleID,
		}
		return result, true
	}
	if v.Category == "suspicious" {
		// High-score suspicious bots get a JS challenge; low-score get observe.
		suspiciousThreshold := p.threshold * 60 / 100
		if v.Score >= suspiciousThreshold {
			result := action.Result{
				Type:      action.Challenge,
				Phase:     "bot_detection",
				MatchDesc: v.Reason,
				Matched:   true,
				Category:  "bot_suspicious",
				RuleIDStr: v.RuleID,
			}
			return result, true
		}
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
	cfg                 *store.ProtectionConfig
	categorySensitivity map[string]string
	overrides           map[string]owasp.OWASPRuleOverride
	fileUploadEnabled   bool
	protoEnabled        bool
}

func NewOWASPPhase(cfg *store.ProtectionConfig) pipeline.Phase {
	phase := &owaspPhase{cfg: cfg}
	if cfg != nil {
		phase.categorySensitivity = cfg.EffectiveCategorySensitivity()
		phase.overrides = owasp.ParseOWASPRulesConfig(cfg.OWASPRulesConfig)
		_, phase.fileUploadEnabled = owasp.CategoryThreshold(cfg.OWASPSensitivity, owasp.CatFileUpload, phase.categorySensitivity)
		_, phase.protoEnabled = owasp.CategoryThreshold(cfg.OWASPSensitivity, owasp.CatProtoViol, phase.categorySensitivity)
	}
	return phase
}

func (p *owaspPhase) Name() string { return "owasp_default" }

func (p *owaspPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	if !p.cfg.OWASPEnabled {
		return action.Pass(), false
	}

	categorySensitivity := p.categorySensitivity
	overrides := p.overrides
	fileUploadEnabled := p.fileUploadEnabled
	protoEnabled := p.protoEnabled

	// Check file uploads in multipart form data.
	ct := strings.ToLower(ctx.ContentType)
	if fileUploadEnabled && strings.Contains(ct, "multipart/form-data") && len(ctx.Body) > 0 {
		filenames, contentTypes := extractMultipartFilenames(ctx.Body, ctx.ContentType)
		for i, fname := range filenames {
			fct := ""
			if i < len(contentTypes) {
				fct = contentTypes[i]
			}
			if uploadHit, ok := owasp.CheckFileUpload(fname, fct); ok {
				if owasp.ShouldSkipRule(uploadHit.RuleID, ctx.Path, overrides) {
					continue
				}
				result := owaspHitResult(uploadHit, p.cfg, overrides)
				return result, result.IsTerminal()
			}
		}
		// Fallback: scan raw body for filenames that Go's multipart parser
		// may miss (path traversal stripped by filepath.Base, space-extension bypass).
		if uploadHit, ok := owasp.CheckRawMultipartFilenames(ctx.Body); ok {
			if !owasp.ShouldSkipRule(uploadHit.RuleID, ctx.Path, overrides) {
				result := owaspHitResult(uploadHit, p.cfg, overrides)
				return result, result.IsTerminal()
			}
		}
	}

	if !ctx.BodyTargetsDone {
		ctx.BodyTargets = extractBodyTargets(ctx.Body, ctx.ContentType)
		ctx.BodyTargetsDone = true
	}
	bodyTargets := ctx.BodyTargets

	// Check HTTP method for unusual/dangerous methods before full OWASP scan.
	if protoEnabled {
		if methodHit, ok := owasp.CheckMethodViolation(ctx.Method, ctx.Headers); ok {
			if !owasp.ShouldSkipRule(methodHit.RuleID, ctx.Path, overrides) {
				result := owaspHitResult(methodHit, p.cfg, overrides)
				return result, result.IsTerminal()
			}
		}
	}

	hits := owasp.CheckOWASP(p.cfg.OWASPSensitivity, ctx.Path, ctx.RawQuery, ctx.Headers, bodyTargets, categorySensitivity)

	// Apply per-rule overrides and path whitelists.
	if len(hits) > 0 {
		hits = owasp.FilterHits(hits, ctx.Path, overrides, categorySensitivity)
	}

	if len(hits) == 0 {
		return action.Pass(), false
	}
	result := owaspHitResult(hits[0], p.cfg, overrides)
	return result, result.IsTerminal()
}

func owaspHitResult(hit owasp.OWASPHit, cfg *store.ProtectionConfig, overrides map[string]owasp.OWASPRuleOverride) action.Result {
	act := normalizeConfiguredAction(cfg.OWASPAction)
	override := owasp.RuleOverride(hit.RuleID, overrides)
	if override.Action != "" {
		act = normalizeConfiguredAction(override.Action)
	}
	result := action.Result{
		Type:       action.Normalize(act),
		RuleIDStr:  hit.RuleID,
		Phase:      "owasp_default",
		MatchDesc:  hit.Desc,
		Matched:    true,
		Category:   string(hit.Category),
		StatusCode: override.StatusCode,
		RedirectTo: override.RedirectTo,
	}
	return result
}

// ── CVE Detection phase ──

type cvePhase struct {
	cfg                 *store.ProtectionConfig
	detector            *cve.CVEDetector
	categorySensitivity map[string]string
	ruleOverrides       map[string]cve.CVERuleOverride
	cachedConfig        bool
}

func newCVEPhase(cfg *store.ProtectionConfig, detector *cve.CVEDetector) *cvePhase {
	phase := &cvePhase{cfg: cfg, detector: detector, cachedConfig: true}
	if cfg != nil {
		phase.categorySensitivity = cfg.EffectiveCategorySensitivity()
		phase.ruleOverrides = cve.ParseCVERuleOverrides(cfg.CVERulesConfig)
	}
	return phase
}

// NewCVEPhase creates a pipeline phase that runs CVE-specific detection.
func NewCVEPhase(cfg *store.ProtectionConfig, detector *cve.CVEDetector) pipeline.Phase {
	return newCVEPhase(cfg, detector)
}

func (p *cvePhase) Name() string { return "cve_detection" }

func (p *cvePhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	if !p.cfg.CVEEnabled || p.detector == nil {
		return action.Pass(), false
	}

	categorySensitivity := p.categorySensitivity
	if !p.cachedConfig {
		categorySensitivity = p.cfg.EffectiveCategorySensitivity()
	}

	if !cve.HasRawCVESuspiciousContent(ctx.Path, ctx.RawQuery, ctx.Headers, ctx.Body, ctx.ContentType) {
		return action.Pass(), false
	}

	var req cve.CVERequest
	cve.BuildCVERequestInto(&req, ctx.Path, ctx.RawQuery, ctx.Headers, ctx.Body, ctx.ContentType)
	best, ok := p.detector.DetectFirst(&req, categorySensitivity)
	if !ok {
		return action.Pass(), false
	}

	// Default: use configured CVE action, then rule-level action, then auto-drop.
	cveAction := p.cfg.CVEAction
	if cveAction == "" {
		cveAction = "intercept"
	}
	act := normalizeConfiguredAction(cveAction)
	statusCode := 0
	redirectTo := ""
	explicitAction := false
	if best.Action != "" {
		act = normalizeConfiguredAction(best.Action)
		explicitAction = true
	}
	overrides := p.ruleOverrides
	if !p.cachedConfig {
		overrides = cve.ParseCVERuleOverrides(p.cfg.CVERulesConfig)
	}
	if len(overrides) > 0 {
		for _, key := range []string{best.CVEID, "cve:" + best.CVEID} {
			if ov, ok := overrides[key]; ok {
				if ov.Action != "" {
					act = normalizeConfiguredAction(ov.Action)
					explicitAction = true
				}
				statusCode = ov.StatusCode
				redirectTo = ov.RedirectTo
				break
			}
		}
	}

	// Auto-escalate to Drop for critical/high severity CVEs when enabled and the rule did not choose an action.
	if !explicitAction {
		switch best.Severity {
		case "critical":
			if p.cfg.CVEAutoDropCritical && action.TerminalPriority(action.Drop) > action.TerminalPriority(act) {
				act = action.Drop
			}
		case "high":
			if p.cfg.CVEAutoDropHigh && action.TerminalPriority(action.Drop) > action.TerminalPriority(act) {
				act = action.Drop
			}
		}
	}

	result := action.Result{
		Type:       action.Normalize(act),
		RuleIDStr:  "cve:" + best.CVEID,
		Phase:      "cve_detection",
		MatchDesc:  best.Description + " [" + best.Pattern + "]",
		Matched:    true,
		Category:   "cve_" + best.Category,
		StatusCode: statusCode,
		RedirectTo: redirectTo,
	}
	return result, result.IsTerminal()
}

// looksLikeJSON returns true if the first non-whitespace byte is { or [.
func looksLikeJSON(body []byte) bool {
	for _, b := range body {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// looksLikeFormEncoded returns true if the body contains key=value&... patterns.
func looksLikeFormEncoded(body []byte) bool {
	if len(body) == 0 || len(body) > 65536 {
		return false
	}
	hasEq := false
	for _, b := range body {
		if b == '=' {
			hasEq = true
		}
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			return false
		}
	}
	return hasEq
}

func shouldScanOpaqueBodyTarget(body []byte) bool {
	for _, b := range body {
		switch b {
		case '<', '>', '`', ';', '|', '\\', '{', '}', '[', ']':
			return true
		}
	}
	s := string(body)
	return containsFoldASCII(s, "%0d") ||
		containsFoldASCII(s, "%0a") ||
		containsFoldASCII(s, "%3c") ||
		containsFoldASCII(s, "%3e") ||
		containsFoldASCII(s, "%27") ||
		containsFoldASCII(s, "%22") ||
		containsFoldASCII(s, "javascript:") ||
		containsFoldASCII(s, "vbscript:") ||
		containsFoldASCII(s, "document.") ||
		containsFoldASCII(s, "onerror") ||
		containsFoldASCII(s, "onload") ||
		containsFoldASCII(s, "onmouse") ||
		containsFoldASCII(s, "onfocus") ||
		containsFoldASCII(s, "alert(") ||
		containsFoldASCII(s, " union ") ||
		containsFoldASCII(s, " select ") ||
		containsFoldASCII(s, " or ") ||
		containsFoldASCII(s, " and ") ||
		containsFoldASCII(s, "sleep(") ||
		containsFoldASCII(s, "benchmark(") ||
		containsFoldASCII(s, "../") ||
		containsFoldASCII(s, "127.0.") ||
		containsFoldASCII(s, "localhost") ||
		containsFoldASCII(s, "169.254.169.254") ||
		containsFoldASCII(s, "metadata.google") ||
		containsFoldASCII(s, "aced0005") ||
		containsFoldASCII(s, "ro0ab") ||
		containsFoldASCII(s, "objectinputstream") ||
		containsFoldASCII(s, "deserializ")
}

// extractBodyTargets parses the request body based on content type and returns
// individual values to scan for attack payloads.
// When Content-Type is missing or misleading, the body is also sniffed to detect
// the actual format and prevent evasion via header manipulation.
func extractBodyTargets(body []byte, contentType string) []string {
	if len(body) == 0 {
		return nil
	}
	ct := contentType

	var primary []string
	parsedOK := false
	skipRawFallback := false

	switch {
	case containsFoldASCII(ct, "application/x-www-form-urlencoded"):
		primary = extractFormValues(string(body))
		parsedOK = len(primary) > 0
	case containsFoldASCII(ct, "application/json"):
		primary = extractJSONValues(body)
		parsedOK = len(primary) > 0
	case containsFoldASCII(ct, "multipart/form-data"):
		primary = extractMultipartFieldValues(body, contentType)
		parsedOK = len(primary) > 0
	case containsFoldASCII(ct, "text/") || containsFoldASCII(ct, "application/xml") || containsFoldASCII(ct, "application/soap"):
		limit := 8192
		if len(body) < limit {
			limit = len(body)
		}
		primary = []string{string(body[:limit])}
		parsedOK = true
	default:
		limit := snapshot.WAFBodyScanLimit
		if len(body) < limit {
			limit = len(body)
		}
		if ct == "" {
			primary = []string{string(body[:limit])}
			parsedOK = true
		} else {
			sample := body
			if len(sample) > 512 {
				sample = body[:512]
			}
			printable := 0
			for _, b := range sample {
				if b >= 0x20 && b <= 0x7E || b == '\n' || b == '\r' || b == '\t' {
					printable++
				}
			}
			if float64(printable)/float64(len(sample)) >= 0.9 && shouldScanOpaqueBodyTarget(body[:limit]) {
				primary = []string{string(body[:limit])}
				parsedOK = true
			} else {
				skipRawFallback = true
			}
		}
	}

	// Fallback: if the declared Content-Type parser returned nothing (e.g. body
	// is base64-wrapped but Content-Type says application/json), always scan the
	// raw body so normalizeWithDecode can peel the base64 layer.
	if !parsedOK && !skipRawFallback && len(body) > 0 {
		limit := snapshot.WAFBodyScanLimit
		if len(body) < limit {
			limit = len(body)
		}
		primary = []string{string(body[:limit])}
	}

	// Content-Type-independent sniffing: also try alternate parsers to prevent
	// evasion via wrong Content-Type header.
	if !containsFoldASCII(ct, "application/json") && looksLikeJSON(body) {
		if extra := extractJSONValues(body); len(extra) > 0 {
			primary = append(primary, extra...)
		}
	}
	if !containsFoldASCII(ct, "form-urlencoded") && !containsFoldASCII(ct, "multipart/form-data") && ct != "" && looksLikeFormEncoded(body) {
		if extra := extractFormValues(string(body)); len(extra) > 0 {
			primary = append(primary, extra...)
		}
	}

	return dedupeBodyTargets(primary)
}

func dedupeBodyTargets(targets []string) []string {
	if len(targets) < 2 {
		return targets
	}

	duplicate := false
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if _, ok := seen[target]; ok {
			duplicate = true
			break
		}
		seen[target] = struct{}{}
	}
	if !duplicate {
		return targets
	}

	seen = make(map[string]struct{}, len(targets))
	out := targets[:0]
	for _, target := range targets {
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	return out
}

// extractFormValues splits form-urlencoded body into individual decoded values.
// Both parameter names (keys) and values are scanned — attackers may inject
// payloads via key names (e.g. `1 UNION SELECT--=x`).
func extractFormValues(body string) []string {
	var vals []string
	for body != "" {
		pair := body
		if i := strings.IndexByte(pair, '&'); i >= 0 {
			pair, body = pair[:i], pair[i+1:]
		} else {
			body = ""
		}
		if pair == "" {
			continue
		}
		paramKey, value, hasEq := strings.Cut(pair, "=")
		if hasEq {
			dv, err := url.QueryUnescape(value)
			if err != nil {
				dv = value
			}
			if dv != "" {
				vals = append(vals, dv)
			}
		}
		// Also scan the parameter name for injected payloads.
		dk, err := url.QueryUnescape(paramKey)
		if err != nil {
			dk = paramKey
		}
		if dk != "" {
			vals = append(vals, dk)
		}
	}
	return vals
}

// extractJSONValues recursively collects all string values from a JSON object.
func extractJSONValues(body []byte) []string {
	var raw any
	if json.Unmarshal(body, &raw) != nil {
		return nil
	}
	var vals []string
	walkJSON(raw, &vals, 0)
	return vals
}

func walkJSON(v any, vals *[]string, depth int) {
	if depth > 10 || len(*vals) > 100 {
		return
	}
	switch val := v.(type) {
	case string:
		if val != "" {
			*vals = append(*vals, val)
		}
	case map[string]any:
		for k, child := range val {
			// Also scan keys: attackers may inject payloads via JSON key names.
			if k != "" {
				*vals = append(*vals, k)
			}
			walkJSON(child, vals, depth+1)
		}
	case []any:
		for _, child := range val {
			walkJSON(child, vals, depth+1)
		}
	}
}

// extractMultipartFilenames parses multipart form data to extract filenames.
func extractMultipartFilenames(body []byte, contentType string) (filenames []string, contentTypes []string) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, nil
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	for i := 0; i < 20; i++ {
		part, err := reader.NextPart()
		if err != nil {
			break
		}
		if fname := part.FileName(); fname != "" {
			filenames = append(filenames, fname)
			contentTypes = append(contentTypes, part.Header.Get("Content-Type"))
		}
		part.Close()
	}
	return filenames, contentTypes
}

// extractMultipartFieldValues parses multipart form data and returns the text
// content of non-file fields for OWASP payload scanning. File parts are skipped
// because their filenames are already checked by the file upload scanner.
func extractMultipartFieldValues(body []byte, contentType string) []string {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	var vals []string
	for i := 0; i < 20; i++ {
		part, err := reader.NextPart()
		if err != nil {
			break
		}
		// For file upload parts, scan the first bytes of content for embedded code.
		if part.FileName() != "" {
			buf, _ := io.ReadAll(io.LimitReader(part, 4096))
			part.Close()
			if len(buf) > 0 {
				vals = append(vals, string(buf))
			}
			continue
		}
		// Read field value, limited to 4096 bytes to bound regex scan time.
		buf, _ := io.ReadAll(io.LimitReader(part, 4096))
		part.Close()
		if len(buf) > 0 {
			vals = append(vals, string(buf))
		}
	}
	return vals
}

// ── Anti-Replay Nonce phase ──

type antiReplayPhase struct {
	mgr *antireplay.AntiReplayManager
}

func NewAntiReplayPhase(mgr *antireplay.AntiReplayManager) pipeline.Phase {
	return &antiReplayPhase{mgr: mgr}
}

func (p *antiReplayPhase) Name() string { return "anti_replay" }

func (p *antiReplayPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	if p.mgr == nil {
		return action.Pass(), false
	}
	// Extract nonce from X-Nonce header.
	nonce, _ := lookupHeaderValue(ctx.Headers, "x-nonce")
	if nonce == "" {
		// No nonce provided — skip replay check.
		return action.Pass(), false
	}
	clientIP := ""
	if ctx.ClientIP != nil {
		clientIP = ctx.ClientIP.String()
	}
	ttl := time.Duration(0)
	if ctx.AntiReplayTTL > 0 {
		ttl = time.Duration(ctx.AntiReplayTTL) * time.Second
	}
	valid, isReplay, _ := p.mgr.ValidateAndRotate(nonce, clientIP, ttl)
	if !valid || isReplay {
		result := action.Result{
			Type:      action.Intercept,
			Phase:     "anti_replay",
			MatchDesc: "request replay detected or invalid nonce",
			Matched:   true,
			Category:  "replay",
			RuleIDStr: "antireplay:nonce",
		}
		return result, true
	}
	return action.Pass(), false
}

// ── Parallel OWASP + CVE Detection phase ──

type parallelOWASPCVEPhase struct {
	cfg      *store.ProtectionConfig
	detector *cve.CVEDetector
	owasp    *owaspPhase
	cve      *cvePhase
}

// NewParallelOWASPCVEPhase creates a phase that runs OWASP and CVE detection
func NewParallelOWASPCVEPhase(cfg *store.ProtectionConfig, detector *cve.CVEDetector) pipeline.Phase {
	phase := &parallelOWASPCVEPhase{cfg: cfg, detector: detector}
	if cfg != nil {
		phase.owasp = NewOWASPPhase(cfg).(*owaspPhase)
		phase.cve = newCVEPhase(cfg, detector)
	}
	return phase
}

func (p *parallelOWASPCVEPhase) Name() string { return "owasp_cve_parallel" }

func (p *parallelOWASPCVEPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	owaspEnabled := p.cfg.OWASPEnabled
	cveEnabled := p.cfg.CVEEnabled && p.detector != nil

	if !owaspEnabled && !cveEnabled {
		return action.Pass(), false
	}
	if !owaspEnabled {
		return p.checkCVE(ctx)
	}

	owaspResult, owaspStop := p.checkOWASP(ctx)
	if !cveEnabled {
		return owaspResult, owaspStop
	}

	cveResult, cveStop := p.checkCVE(ctx)
	if owaspStop && cveStop {
		if action.MoreSevere(cveResult.Type, owaspResult.Type) {
			return cveResult, true
		}
		return owaspResult, true
	}
	if owaspStop {
		return owaspResult, true
	}
	if cveStop {
		return cveResult, true
	}
	return action.Pass(), false
}
func (p *parallelOWASPCVEPhase) checkOWASP(ctx *pipeline.RequestCtx) (action.Result, bool) {
	if p.owasp == nil {
		return action.Pass(), false
	}
	return p.owasp.Execute(ctx)
}

func (p *parallelOWASPCVEPhase) checkCVE(ctx *pipeline.RequestCtx) (action.Result, bool) {
	if p.cve == nil {
		return action.Pass(), false
	}
	return p.cve.Execute(ctx)
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

func normalizeConfiguredAction(value string) action.Type {
	act := action.Normalize(action.Type(value))
	if act == action.Type("log") {
		return action.Observe
	}
	if !action.IsValid(act) {
		return action.Intercept
	}
	return act
}

func hit(c Compiled) action.Result {
	act := c.runtimeAction
	if act == "" {
		act = normalizeConfiguredAction(string(c.Action))
	}
	ruleIDStr := c.ruleIDStr
	if ruleIDStr == "" {
		ruleIDStr = "rule:" + c.Phase + ":" + c.Kind
	}
	desc := c.matchDesc
	if desc == "" {
		desc = compiledMatchDesc(c.Kind, c.Arg)
	}
	return action.Result{
		Type:       act,
		RuleID:     c.ID,
		RuleIDStr:  ruleIDStr,
		Phase:      c.Phase,
		MatchDesc:  desc,
		Matched:    true,
		Category:   c.Kind,
		StatusCode: c.StatusCode,
		RedirectTo: c.RedirectTo,
	}
}
