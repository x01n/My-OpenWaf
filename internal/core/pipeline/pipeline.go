package pipeline

import (
	"net"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/waf/bot"
)

// RequestCtx carries all decoded request data through the pipeline.
type RequestCtx struct {
	RequestID string
	Bind      string // Listener bind address (e.g., ":443")
	ClientIP  net.IP
	Method    string
	Path      string
	RawQuery  string
	Host      string
	UserAgent string
	SiteID    uint
	Headers   map[string]string
	// HeadersLowercase reports that every key in Headers is already lowercase.
	HeadersLowercase bool
	HeaderKeys       []string // Ordered header keys for fingerprinting
	Body             []byte
	ContentType      string
	TLS              bot.TLSClientFingerprint

	// AntiReplayTTL is per-site nonce window in seconds (0 = engine default).
	AntiReplayTTL int

	QueryParams map[string]string

	// BodyTargets caches extracted body targets to avoid re-parsing in
	// multiple phases (OWASP + CVE both need the same targets).
	BodyTargets     []string
	BodyTargetsDone bool

	// matcherHeaders caches the matcher-visible header map derived from the
	// request headers plus Host/TLS/header-order aliases.
	matcherHeaders        map[string]string
	matcherHeadersReady   bool
	matcherHeadersAliased bool

	// BotScoreResult stores bot detection scoring for async logging in the dataplane.
	// This is set by the bot detection phase and read after pipeline execution.
	BotScoreResult *BotScoreInfo

	// phaseObserveHits stores observe-only hits emitted inside a phase before that
	// phase later returns a stronger terminal action.
	phaseObserveHits []action.Result
}

// CachedMatcherHeaders returns the per-request matcher header cache when ready.
func (ctx *RequestCtx) CachedMatcherHeaders() (map[string]string, bool) {
	if !ctx.matcherHeadersReady {
		return nil, false
	}
	return ctx.matcherHeaders, true
}

// CachedMatcherHeadersAliased reports whether the cached matcher headers still
// alias the live request header map.
func (ctx *RequestCtx) CachedMatcherHeadersAliased() bool {
	return ctx.matcherHeadersReady && ctx.matcherHeadersAliased
}

// StoreMatcherHeaders saves the per-request matcher header cache.
func (ctx *RequestCtx) StoreMatcherHeaders(headers map[string]string) {
	ctx.matcherHeaders = headers
	ctx.matcherHeadersReady = true
	ctx.matcherHeadersAliased = false
}

// StoreAliasedMatcherHeaders saves a matcher header cache that aliases the
// live request header map instead of a detached derived copy.
func (ctx *RequestCtx) StoreAliasedMatcherHeaders(headers map[string]string) {
	ctx.matcherHeaders = headers
	ctx.matcherHeadersReady = true
	ctx.matcherHeadersAliased = true
}

// ReusableMatcherHeadersBuffer returns the detached matcher header cache kept
// on the pooled RequestCtx for reuse across requests.
func (ctx *RequestCtx) ReusableMatcherHeadersBuffer() map[string]string {
	if ctx.matcherHeadersAliased {
		return nil
	}
	return ctx.matcherHeaders
}

// ClearMatcherHeadersCache drops the per-request matcher header cache.
func (ctx *RequestCtx) ClearMatcherHeadersCache() {
	if ctx.matcherHeadersAliased {
		ctx.matcherHeaders = nil
	}
	ctx.matcherHeadersReady = false
	ctx.matcherHeadersAliased = false
}

// AppendHeaderKey records the original header key.
func (ctx *RequestCtx) AppendHeaderKey(key string) {
	ctx.HeaderKeys = append(ctx.HeaderKeys, key)
}

// ClearHeaderKeys releases the recorded header keys while keeping capacity for reuse.
func (ctx *RequestCtx) ClearHeaderKeys() {
	if ctx.HeaderKeys != nil {
		ctx.HeaderKeys = ctx.HeaderKeys[:0]
	}
}

// AppendPhaseObserveHits buffers observe-only hits emitted inside a phase.
func (ctx *RequestCtx) AppendPhaseObserveHits(results []action.Result) {
	if len(results) == 0 {
		return
	}
	ctx.phaseObserveHits = append(ctx.phaseObserveHits, results...)
}

// DrainPhaseObserveHits returns and clears the buffered per-phase observe hits.
func (ctx *RequestCtx) DrainPhaseObserveHits() []action.Result {
	if len(ctx.phaseObserveHits) == 0 {
		return nil
	}
	hits := ctx.phaseObserveHits
	ctx.phaseObserveHits = ctx.phaseObserveHits[:0]
	return hits
}

// BotScoreInfo stores bot detection scoring details for logging purposes.
type BotScoreInfo struct {
	TotalScore       int
	GeoIPScore       int
	FingerprintScore int
	BehaviorScore    int
	IPRepScore       int
	IsHighRisk       bool
	Action           string
	Details          string
}

// Phase is one stage in the WAF processing pipeline.
type Phase interface {
	Name() string
	Execute(ctx *RequestCtx) (action.Result, bool)
}

// RunResult bundles the terminal action with any observe-only hits for logging.
type RunResult struct {
	Action      action.Result
	ObserveHits []action.Result
}

// Pipeline is an ordered chain of phases executed in sequence.
type Pipeline struct {
	phases []Phase
}

func New(phases ...Phase) *Pipeline {
	return &Pipeline{phases: phases}
}

// Run executes a phase slice directly without allocating a Pipeline wrapper.
// Prefer this for hot-path callers; the Pipeline.Run method now delegates here.
//
// Drop/intercept results short-circuit immediately (highest priority).
// Challenge results are deferred: pipeline continues so that subsequent phases
// (OWASP, CVE, etc.) still run. If a higher-priority terminal action appears later,
// it overrides the challenge. Otherwise the challenge is returned at the end.
func Run(phases []Phase, ctx *RequestCtx) RunResult {
	var observeHits []action.Result
	var pendingChallenge *action.Result

	for _, ph := range phases {
		result, stop := ph.Execute(ctx)
		if result.Matched && result.ShouldLog() && !result.IsTerminal() {
			observeHits = append(observeHits, result)
		}
		if extra := ctx.DrainPhaseObserveHits(); len(extra) > 0 {
			observeHits = append(observeHits, extra...)
		}
		if stop {
			if !result.IsChallenge() {
				return RunResult{Action: result, ObserveHits: observeHits}
			}
			if pendingChallenge == nil || action.TerminalPriority(result.Type) > action.TerminalPriority(pendingChallenge.Type) {
				r := result
				pendingChallenge = &r
			}
			continue
		}
		if result.Matched {
			if result.IsDrop() {
				return RunResult{Action: result, ObserveHits: observeHits}
			}
			if result.IsTerminal() {
				if result.IsChallenge() {
					if pendingChallenge == nil || action.TerminalPriority(result.Type) > action.TerminalPriority(pendingChallenge.Type) {
						r := result
						pendingChallenge = &r
					}
					continue
				}
				return RunResult{Action: result, ObserveHits: observeHits}
			}
		}
	}

	if pendingChallenge != nil {
		return RunResult{Action: *pendingChallenge, ObserveHits: observeHits}
	}
	return RunResult{Action: action.Pass(), ObserveHits: observeHits}
}

// Run executes each phase in order. Kept for backward compatibility.
func (p *Pipeline) Run(ctx *RequestCtx) RunResult {
	return Run(p.phases, ctx)
}
