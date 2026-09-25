package pipeline

import (
	"context"
	"net"
	"net/url"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/waf/bot"
)

// RequestCtx carries all decoded request data through the pipeline.
type RequestCtx struct {
	// Context 是请求生命周期上下文；为 nil 时保持测试和外部调用方的兼容行为。
	Context   context.Context
	RequestID string
	Bind      string // Listener bind address (e.g., ":443")
	ClientIP  net.IP
	Method    string
	Path      string
	// OriginalPath retains the immutable inbound path for phase skip matching after request-stage plugins mutate Path.
	OriginalPath string
	RawQuery     string
	Host         string
	UserAgent    string

	// ChallengeIdentity* retain the pre-mutation identity used to validate
	// challenge pass cookies after request-stage plugins mutate the request view.
	ChallengeIdentityCaptured  bool
	ChallengeIdentityUserAgent string
	ChallengeIdentityCookie    string
	SiteID                     uint
	Headers                    map[string]string
	// HeadersLowercase reports that every key in Headers is already lowercase.
	HeadersLowercase bool
	HeaderKeys       []string // Ordered header keys for fingerprinting
	Body             []byte
	ContentType      string
	TLS              bot.TLSClientFingerprint

	// AntiReplayTTL is per-site nonce window in seconds (0 = engine default).
	AntiReplayTTL int
	// AntiReplayConsumedNonce records a Cookie nonce already validated by the handler.
	// The pipeline skips only the same X-Nonce value; a different header nonce is still checked.
	AntiReplayConsumedNonce string

	QueryParams map[string]string
	QueryValues map[string][]string

	// BodyTargets caches extracted body targets to avoid re-parsing in
	// multiple phases (OWASP + CVE both need the same targets).
	BodyTargets     []string
	BodyTargetsDone bool

	// matcherJSONBody / matcherQueryValues 是编译后规则匹配器的懒解析缓存：
	// bodyJSONPath 类规则复用同一份 JSON 对象解析，queryParam 类规则复用
	// 同一份 query values 解析。字段非导出，仅经 Cached*/Store* 访问，
	// 由 ReleaseCtx 与 ResetMutationCaches 清零。
	matcherJSONBody      map[string]any
	matcherJSONBodyDone  bool
	matcherQueryValues   url.Values
	matcherQueryValuesOK bool

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

	// observeHitsBuf is a reusable buffer for collecting observe hits during
	// pipeline.Run, avoiding per-request slice allocation.
	observeHitsBuf []action.Result

	// Derived header string cache: computed once per request, reused across phases.
	derivedALPN         string
	derivedALPNDone     bool
	derivedHeaderOrder  string
	derivedHeaderDone   bool
	derivedCipherSuites string
	derivedCipherDone   bool
}

/**
 * ResetMutationCaches clears request-derived values after a pre-pipeline mutation.
 *
 * @return void
 */
func (ctx *RequestCtx) ResetMutationCaches() {
	if ctx == nil {
		return
	}
	ctx.BodyTargets = nil
	ctx.BodyTargetsDone = false
	ctx.matcherJSONBody = nil
	ctx.matcherJSONBodyDone = false
	ctx.matcherQueryValues = nil
	ctx.matcherQueryValuesOK = false
	ctx.matcherHeaders = nil
	ctx.matcherHeadersReady = false
	ctx.matcherHeadersAliased = false
	ctx.derivedHeaderOrder = ""
	ctx.derivedHeaderDone = false
}

// ContextOrBackground 返回请求上下文；对直接构造 RequestCtx 的调用方回退到 Background。
func (ctx *RequestCtx) ContextOrBackground() context.Context {
	if ctx == nil || ctx.Context == nil {
		return context.Background()
	}
	return ctx.Context
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

// CachedJSONBodyObject returns the lazily parsed JSON object for the request
// body, computed and stored once per request by bodyJSONPath-style matchers.
// 解析失败也计入 Done，避免同一请求重复尝试。
func (ctx *RequestCtx) CachedJSONBodyObject() (map[string]any, bool) {
	return ctx.matcherJSONBody, ctx.matcherJSONBodyDone
}

// StoreJSONBodyObject saves the parsed JSON object of the request body.
func (ctx *RequestCtx) StoreJSONBodyObject(obj map[string]any) {
	ctx.matcherJSONBody = obj
	ctx.matcherJSONBodyDone = true
}

// CachedMatcherQueryValues returns the lazily parsed query values shared by
// queryParam-style matchers. ok 为 false 表示尚未解析。
func (ctx *RequestCtx) CachedMatcherQueryValues() (url.Values, bool) {
	return ctx.matcherQueryValues, ctx.matcherQueryValuesOK
}

// StoreMatcherQueryValues saves the parsed query values for queryParam-style
// matchers. values 保持 nil-safe：nil 时以 Done 语义跳过重复解析。
func (ctx *RequestCtx) StoreMatcherQueryValues(values url.Values) {
	ctx.matcherQueryValues = values
	ctx.matcherQueryValuesOK = true
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

// DerivedALPN returns the cached ALPN join string, computing it on first call.
func (ctx *RequestCtx) DerivedALPN(compute func() string) string {
	if !ctx.derivedALPNDone {
		ctx.derivedALPN = compute()
		ctx.derivedALPNDone = true
	}
	return ctx.derivedALPN
}

// DerivedHeaderOrder returns the cached header order join string, computing it on first call.
func (ctx *RequestCtx) DerivedHeaderOrder(compute func() string) string {
	if !ctx.derivedHeaderDone {
		ctx.derivedHeaderOrder = compute()
		ctx.derivedHeaderDone = true
	}
	return ctx.derivedHeaderOrder
}

// DerivedCipherSuites returns the cached cipher suites format string, computing it on first call.
func (ctx *RequestCtx) DerivedCipherSuites(compute func() string) string {
	if !ctx.derivedCipherDone {
		ctx.derivedCipherSuites = compute()
		ctx.derivedCipherDone = true
	}
	return ctx.derivedCipherSuites
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
	Details          map[string]string
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
	observeHits := ctx.observeHitsBuf[:0]
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
