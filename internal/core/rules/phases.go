package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf"

	"golang.org/x/sync/errgroup"
)

// MatchCtx is the subset of request data matchers need.
type MatchCtx struct {
	ClientIP net.IP
	Method   string
	Path     string
	Query    string
	Headers  map[string]string
	Host     string
	Body     []byte
}

func ctxFromPipeline(ctx *pipeline.RequestCtx) MatchCtx {
	headers := ctx.Headers
	if ctx.Host != "" {
		headers = make(map[string]string, len(ctx.Headers)+1)
		for k, v := range ctx.Headers {
			headers[k] = v
		}
		headers["Host"] = ctx.Host
	}
	return MatchCtx{
		ClientIP: ctx.ClientIP, Path: ctx.Path, Query: ctx.RawQuery,
		Headers: headers, Method: ctx.Method, Host: ctx.Host, Body: ctx.Body,
	}
}

// ── ACL phase ──

type aclPhase struct{ rules []Compiled }

func NewACLPhase(rules []Compiled) pipeline.Phase { return &aclPhase{rules: filterPhase(rules, "acl")} }

// NewACLPhasePrecompiled creates an ACL phase from already-partitioned rules (no filtering needed).
func NewACLPhasePrecompiled(rules []Compiled) pipeline.Phase { return &aclPhase{rules: rules} }

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

// ── ACL allow precheck phase ──

type aclAllowPrecheckPhase struct{ rules []Compiled }

func NewACLAllowPrecheckPhasePrecompiled(rules []Compiled) pipeline.Phase {
	return &aclAllowPrecheckPhase{rules: rules}
}

func (p *aclAllowPrecheckPhase) Name() string { return "acl_allow_precheck" }

func (p *aclAllowPrecheckPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	mc := ctxFromPipeline(ctx)
	for i := range p.rules {
		if action.Normalize(p.rules[i].Action) != action.Allow {
			continue
		}
		if p.rules[i].Match(mc) {
			return hit(p.rules[i]), true
		}
	}
	return action.Pass(), false
}

// ── Signature phase ──

type signaturePhase struct{ rules []Compiled }

func NewSignaturePhase(rules []Compiled) pipeline.Phase {
	return &signaturePhase{rules: filterPhase(rules, "signature")}
}

// NewSignaturePhasePrecompiled creates a signature phase from already-partitioned rules.
func NewSignaturePhasePrecompiled(rules []Compiled) pipeline.Phase {
	return &signaturePhase{rules: rules}
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

// NewCustomPhasePrecompiled creates a custom phase from already-partitioned rules.
func NewCustomPhasePrecompiled(rules []Compiled) pipeline.Phase {
	return &customPhase{rules: rules}
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
	limiter waf.RateLimiterBackend
	act     action.Type
}

func NewReqRateLimitPhase(limiter waf.RateLimiterBackend, act action.Type) pipeline.Phase {
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

// ── Bot Detection phase (two-phase: PreScreen → DeepScore) ──

type botPhase struct {
	rep       *waf.IPReputation    // optional, for recording violations
	geo       *waf.MaxMindResolver // optional, for GeoIP scoring
	threshold int                  // score threshold for blocking
}

// NewBotPhase creates a bot-detection pipeline phase using the legacy
// single-pass check (no GeoIP weighting). Kept for backward compatibility.
func NewBotPhase(rep *waf.IPReputation) pipeline.Phase {
	return &botPhase{rep: rep, threshold: 80}
}

// NewBotPhaseWithGeo creates a bot-detection pipeline phase that uses the
// two-phase PreScreen → DeepScore flow with GeoIP weighting.
func NewBotPhaseWithGeo(rep *waf.IPReputation, geo *waf.MaxMindResolver, threshold int) pipeline.Phase {
	if threshold <= 0 {
		threshold = 80
	}
	return &botPhase{rep: rep, geo: geo, threshold: threshold}
}

func (p *botPhase) Name() string { return "bot_detection" }

func (p *botPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	// Skip challenge for requests that already passed a signed verification cookie.
	if cookie, ok := ctx.Headers["Cookie"]; ok && waf.VerifyChallengePassCookie(cookie, ctx.Host, ctx.ClientIP, time.Now()) {
		return action.Pass(), false
	}

	br := waf.NewBotRequest(ctx.Method, ctx.Path, ctx.Headers)
	br.ClientIP = ctx.ClientIP
	br.HeaderKeys = ctx.HeaderKeys

	// If GeoIP resolver is available, use the two-phase flow.
	if p.geo != nil {
		v, bs := waf.CheckBotTwoPhase(br, p.rep, p.geo, p.threshold)
		p.storeBotScore(ctx, v, bs)
		return p.verdictToResult(v, ctx)
	}

	// Fallback: legacy single-pass check.
	v := waf.CheckBot(br)
	p.storeBotScore(ctx, v, waf.BotScore{Total: v.Score})
	return p.verdictToResult(v, ctx)
}

func (p *botPhase) storeBotScore(ctx *pipeline.RequestCtx, v waf.BotVerdict, bs waf.BotScore) {
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
	if len(bs.Details) > 0 {
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

func (p *botPhase) verdictToResult(v waf.BotVerdict, ctx *pipeline.RequestCtx) (action.Result, bool) {
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

	categorySensitivity := p.cfg.EffectiveCategorySensitivity()
	overrides := waf.ParseOWASPRulesConfig(p.cfg.OWASPRulesConfig)
	_, fileUploadEnabled := waf.CategoryThreshold(p.cfg.OWASPSensitivity, waf.CatFileUpload, categorySensitivity)
	_, protoEnabled := waf.CategoryThreshold(p.cfg.OWASPSensitivity, waf.CatProtoViol, categorySensitivity)

	// Check file uploads in multipart form data.
	ct := strings.ToLower(ctx.ContentType)
	if fileUploadEnabled && strings.Contains(ct, "multipart/form-data") && len(ctx.Body) > 0 {
		filenames, contentTypes := extractMultipartFilenames(ctx.Body, ctx.ContentType)
		for i, fname := range filenames {
			fct := ""
			if i < len(contentTypes) {
				fct = contentTypes[i]
			}
			if uploadHit, ok := waf.CheckFileUpload(fname, fct); ok {
				if waf.ShouldSkipRule(uploadHit.RuleID, ctx.Path, overrides) {
					continue
				}
				result := owaspHitResult(uploadHit, p.cfg, overrides)
				return result, result.IsTerminal()
			}
		}
		// Fallback: scan raw body for filenames that Go's multipart parser
		// may miss (path traversal stripped by filepath.Base, space-extension bypass).
		if uploadHit, ok := waf.CheckRawMultipartFilenames(ctx.Body); ok {
			if !waf.ShouldSkipRule(uploadHit.RuleID, ctx.Path, overrides) {
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
		if methodHit, ok := waf.CheckMethodViolation(ctx.Method, ctx.Headers); ok {
			if !waf.ShouldSkipRule(methodHit.RuleID, ctx.Path, overrides) {
				result := owaspHitResult(methodHit, p.cfg, overrides)
				return result, result.IsTerminal()
			}
		}
	}

	hits := waf.CheckOWASP(p.cfg.OWASPSensitivity, ctx.Path, ctx.RawQuery, ctx.Headers, bodyTargets, categorySensitivity)

	// Apply per-rule overrides and path whitelists.
	if len(hits) > 0 {
		hits = waf.FilterHits(hits, ctx.Path, overrides, categorySensitivity)
	}

	if len(hits) == 0 {
		return action.Pass(), false
	}
	result := owaspHitResult(hits[0], p.cfg, overrides)
	return result, result.IsTerminal()
}

func owaspHitResult(hit waf.OWASPHit, cfg store.ProtectionConfig, overrides map[string]waf.OWASPRuleOverride) action.Result {
	act := normalizeConfiguredAction(cfg.OWASPAction)
	override := waf.RuleOverride(hit.RuleID, overrides)
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
	cfg      store.ProtectionConfig
	detector *waf.CVEDetector
}

// NewCVEPhase creates a pipeline phase that runs CVE-specific detection.
func NewCVEPhase(cfg store.ProtectionConfig, detector *waf.CVEDetector) pipeline.Phase {
	return &cvePhase{cfg: cfg, detector: detector}
}

func (p *cvePhase) Name() string { return "cve_detection" }

func (p *cvePhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	if !p.cfg.CVEEnabled || p.detector == nil {
		return action.Pass(), false
	}

	req := waf.BuildCVERequest(ctx.Path, ctx.RawQuery, ctx.Headers, ctx.Body, ctx.ContentType)
	matches := p.detector.Detect(req, p.cfg.EffectiveCategorySensitivity())
	if len(matches) == 0 {
		return action.Pass(), false
	}

	// Use the first (highest-priority) match.
	best := matches[0]

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
	if overrides := waf.ParseCVERuleOverrides(p.cfg.CVERulesConfig); len(overrides) > 0 {
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

// extractBodyTargets parses the request body based on content type and returns
// individual values to scan for attack payloads.
// When Content-Type is missing or misleading, the body is also sniffed to detect
// the actual format and prevent evasion via header manipulation.
func extractBodyTargets(body []byte, contentType string) []string {
	if len(body) == 0 {
		return nil
	}
	ct := strings.ToLower(contentType)

	var primary []string
	parsedOK := false

	switch {
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		primary = extractFormValues(string(body))
		parsedOK = len(primary) > 0
	case strings.Contains(ct, "application/json"):
		primary = extractJSONValues(body)
		parsedOK = len(primary) > 0
	case strings.Contains(ct, "multipart/form-data"):
		primary = extractMultipartFieldValues(body, contentType)
		parsedOK = len(primary) > 0
	case strings.Contains(ct, "text/") || strings.Contains(ct, "application/xml") || strings.Contains(ct, "application/soap"):
		limit := 8192
		if len(body) < limit {
			limit = len(body)
		}
		primary = []string{string(body[:limit])}
		parsedOK = true
	default:
		limit := 48 * 1024
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
			if float64(printable)/float64(len(sample)) >= 0.9 {
				primary = []string{string(body[:limit])}
				parsedOK = true
			}
		}
	}

	// Fallback: if the declared Content-Type parser returned nothing (e.g. body
	// is base64-wrapped but Content-Type says application/json), always scan the
	// raw body so normalizeWithDecode can peel the base64 layer.
	if !parsedOK && len(body) > 0 {
		limit := 48 * 1024
		if len(body) < limit {
			limit = len(body)
		}
		primary = []string{string(body[:limit])}
	}

	// Content-Type-independent sniffing: also try alternate parsers to prevent
	// evasion via wrong Content-Type header.
	if !strings.Contains(ct, "application/json") && looksLikeJSON(body) {
		if extra := extractJSONValues(body); len(extra) > 0 {
			primary = append(primary, extra...)
		}
	}
	if !strings.Contains(ct, "form-urlencoded") && ct != "" && looksLikeFormEncoded(body) {
		if extra := extractFormValues(string(body)); len(extra) > 0 {
			primary = append(primary, extra...)
		}
	}

	return primary
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
	mgr *waf.AntiReplayManager
}

func NewAntiReplayPhase(mgr *waf.AntiReplayManager) pipeline.Phase {
	return &antiReplayPhase{mgr: mgr}
}

func (p *antiReplayPhase) Name() string { return "anti_replay" }

func (p *antiReplayPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	if p.mgr == nil {
		return action.Pass(), false
	}
	// Extract nonce from X-Nonce header.
	nonce := ctx.Headers["X-Nonce"]
	if nonce == "" {
		nonce = ctx.Headers["x-nonce"]
	}
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
	cfg      store.ProtectionConfig
	detector *waf.CVEDetector
}

// NewParallelOWASPCVEPhase creates a phase that runs OWASP and CVE detection
// concurrently using errgroup. If either hits a terminal action, the other is
// cancelled immediately.
func NewParallelOWASPCVEPhase(cfg store.ProtectionConfig, detector *waf.CVEDetector) pipeline.Phase {
	return &parallelOWASPCVEPhase{cfg: cfg, detector: detector}
}

func (p *parallelOWASPCVEPhase) Name() string { return "owasp_cve_parallel" }

func (p *parallelOWASPCVEPhase) Execute(ctx *pipeline.RequestCtx) (action.Result, bool) {
	owaspEnabled := p.cfg.OWASPEnabled
	cveEnabled := p.cfg.CVEEnabled && p.detector != nil

	if !owaspEnabled && !cveEnabled {
		return action.Pass(), false
	}

	// If only one is enabled, run it directly without goroutine overhead.
	if owaspEnabled && !cveEnabled {
		return p.checkOWASP(ctx)
	}
	if !owaspEnabled && cveEnabled {
		return p.checkCVE(ctx)
	}

	// Both enabled — run in parallel with errgroup.
	gctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, gctx := errgroup.WithContext(gctx)

	var (
		owaspResult action.Result
		owaspStop   bool
		cveResult   action.Result
		cveStop     bool
		mu          sync.Mutex
	)

	g.Go(func() error {
		select {
		case <-gctx.Done():
			return gctx.Err()
		default:
			result, stop := p.checkOWASP(ctx)
			if stop {
				mu.Lock()
				owaspResult = result
				owaspStop = true
				mu.Unlock()
				return fmt.Errorf("owasp hit")
			}
			mu.Lock()
			owaspResult = result
			mu.Unlock()
			return nil
		}
	})

	g.Go(func() error {
		select {
		case <-gctx.Done():
			return gctx.Err()
		default:
			result, stop := p.checkCVE(ctx)
			if stop {
				mu.Lock()
				cveResult = result
				cveStop = true
				mu.Unlock()
				return fmt.Errorf("cve hit")
			}
			mu.Lock()
			cveResult = result
			mu.Unlock()
			return nil
		}
	})

	_ = g.Wait()

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

// checkOWASP runs the OWASP detection logic (same as owaspPhase.Execute).
func (p *parallelOWASPCVEPhase) checkOWASP(ctx *pipeline.RequestCtx) (action.Result, bool) {
	ph := &owaspPhase{cfg: p.cfg}
	return ph.Execute(ctx)
}

// checkCVE runs the CVE detection logic (same as cvePhase.Execute).
func (p *parallelOWASPCVEPhase) checkCVE(ctx *pipeline.RequestCtx) (action.Result, bool) {
	ph := &cvePhase{cfg: p.cfg, detector: p.detector}
	return ph.Execute(ctx)
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
	desc := c.Kind + ":" + c.Arg
	if c.Kind == "compound" && len(c.Arg) > 60 {
		desc = "compound:{...}"
	}
	return action.Result{
		Type:       normalizeConfiguredAction(string(c.Action)),
		RuleID:     c.ID,
		RuleIDStr:  "rule:" + c.Phase + ":" + c.Kind,
		Phase:      c.Phase,
		MatchDesc:  desc,
		Matched:    true,
		Category:   c.Kind,
		StatusCode: c.StatusCode,
		RedirectTo: c.RedirectTo,
	}
}
