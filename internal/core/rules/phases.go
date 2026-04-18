package rules

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/url"
	"strings"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf"
)

// MatchCtx is the subset of request data matchers need.
type MatchCtx struct {
	ClientIP net.IP
	Method   string
	Path     string
	Query    string
	Headers  map[string]string
}

func ctxFromPipeline(ctx *pipeline.RequestCtx) MatchCtx {
	return MatchCtx{ClientIP: ctx.ClientIP, Path: ctx.Path, Query: ctx.RawQuery, Headers: ctx.Headers, Method: ctx.Method}
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

	// Check file uploads in multipart form data.
	ct := strings.ToLower(ctx.ContentType)
	if strings.Contains(ct, "multipart/form-data") && len(ctx.Body) > 0 {
		filenames, contentTypes := extractMultipartFilenames(ctx.Body, ctx.ContentType)
		for i, fname := range filenames {
			fct := ""
			if i < len(contentTypes) {
				fct = contentTypes[i]
			}
			if uploadHit, ok := waf.CheckFileUpload(fname, fct); ok {
				act := action.Type(p.cfg.OWASPAction)
				result := action.Result{
					Type:      act,
					RuleIDStr: uploadHit.RuleID,
					Phase:     "owasp_default",
					MatchDesc: uploadHit.Desc,
					Matched:   true,
					Category:  string(uploadHit.Category),
				}
				return result, result.IsTerminal()
			}
		}
	}

	bodyTargets := extractBodyTargets(ctx.Body, ctx.ContentType)
	hits := waf.CheckOWASP(p.cfg.OWASPSensitivity, ctx.Path, ctx.RawQuery, ctx.Headers, bodyTargets)
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

// extractBodyTargets parses the request body based on content type and returns
// individual values to scan for attack payloads.
func extractBodyTargets(body []byte, contentType string) []string {
	if len(body) == 0 {
		return nil
	}
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		return extractFormValues(string(body))
	case strings.Contains(ct, "application/json"):
		return extractJSONValues(body)
	case strings.Contains(ct, "multipart/form-data"):
		// File upload check (filename/content-type) is done in owaspPhase.Execute.
		// Here we extract text field values for OWASP content scanning.
		return extractMultipartFieldValues(body, contentType)
	case strings.Contains(ct, "text/") || strings.Contains(ct, "application/xml") || strings.Contains(ct, "application/soap"):
		// Text-like content types: scan as a single target but with a size limit.
		limit := 8192
		if len(body) < limit {
			limit = len(body)
		}
		return []string{string(body[:limit])}
	default:
		// Binary or unknown content types: only scan if the body looks like text
		// (≥90% printable ASCII in the first 512 bytes).
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
		if float64(printable)/float64(len(sample)) < 0.9 {
			return nil // Binary data — skip scanning to avoid false positives
		}
		limit := 8192
		if len(body) < limit {
			limit = len(body)
		}
		return []string{string(body[:limit])}
	}
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
		// Skip file upload parts — their filenames are checked separately.
		if part.FileName() != "" {
			part.Close()
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
	desc := c.Kind + ":" + c.Arg
	if c.Kind == "compound" && len(c.Arg) > 60 {
		desc = "compound:{...}"
	}
	return action.Result{
		Type:      action.Normalize(c.Action),
		RuleID:    c.ID,
		RuleIDStr: "rule:" + c.Phase + ":" + c.Kind,
		Phase:     c.Phase,
		MatchDesc: desc,
		Matched:   true,
		Category:  c.Kind,
	}
}
