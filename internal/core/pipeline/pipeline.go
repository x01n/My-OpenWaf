package pipeline

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/waf/bot/tlsfp"
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
	TLS              tlsfp.TLSClientFingerprint

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

	// requestMutation 是管道阶段产生的待应用请求改写，由数据面在 Run 返回后
	// 写回 Hertz 请求。指针为 nil 表示本次请求没有任何改写。
	requestMutation *RequestMutator

	// responseMutations 是管道外阶段（Lua post）产生的待应用响应改写，
	// 由数据面转交给 proxy 的响应变换链。nil 表示没有改写。
	responseMutations []ResponseMutator

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

type BotScoreInfo struct {
	TotalScore       int
	UAScore          int
	GeoIPScore       int
	FingerprintScore int
	BehaviorScore    int
	IPRepScore       int
	IsHighRisk       bool
	Action           string
	Details          map[string]string

	// Dangerous 表示 bot 判定已认定该请求构成「危险」——消费方必须终止，
	// 该决定不被加权总分稀释。DangerReasons 是危险来源，供日志归因。
	Dangerous     bool
	DangerReasons []string
}

// Phase is one stage in the WAF processing pipeline.
type Phase interface {
	Name() string
	Execute(ctx *RequestCtx) (action.Result, bool)
}

// RequestMutator 是管道阶段可选的请求改写出口。
//
// 阶段在管道内运行，拿不到 Hertz 请求对象（pipeline 包不认识 hertz），
// 因此改写意图先落在 RequestCtx 上，由数据面在管道返回后写回真实请求。
// 字段与 jsplugin.MutationPlan 同构：method/path/raw_query/body 用指针区分
// 「不改」与「显式置空」，头变更用增删两张表。
type RequestMutator struct {
	Method        *string
	Path          *string
	RawQuery      *string
	Body          *string
	SetHeaders    map[string]string
	DeleteHeaders []string
}

// SetRequestMutation 记录阶段产生的请求改写；后写覆盖先写（按阶段顺序）。
func (ctx *RequestCtx) SetRequestMutation(mutation RequestMutator) {
	if ctx == nil {
		return
	}
	stored := mutation
	ctx.requestMutation = &stored
}

// ApplyRequestMutation 校验改写并在管道上下文内就地生效。
//
// 阶段（Lua pre）在管道中途产生改写时立即调用：后续阶段因此看到改写后的
// 请求，与「pre 在昂贵检测之前、可以改变检测对象」的定位一致。Hertz 请求
// 的写回不在管道内做（pipeline 不认识 hertz），由数据面在管道返回后按
// DrainRequestMutation 的意图完成。
//
// 先整体校验、再整体应用：任何一项非法都让整份改写失败且不留部分效果，
// 静默生效一半会让脚本行为无法从源码推断。
func (ctx *RequestCtx) ApplyRequestMutation(mutation RequestMutator) error {
	if ctx == nil {
		return nil
	}
	if mutation.Method != nil && !isMutationToken(*mutation.Method) {
		return errors.New("pipeline: invalid method mutation")
	}
	if mutation.Path != nil && !isMutationPath(*mutation.Path) {
		return errors.New("pipeline: invalid path mutation")
	}
	if mutation.RawQuery != nil {
		if strings.ContainsAny(*mutation.RawQuery, "#\r\n") {
			return errors.New("pipeline: invalid raw query mutation")
		}
		if _, err := url.ParseQuery(*mutation.RawQuery); err != nil {
			return errors.New("pipeline: invalid raw query mutation")
		}
	}
	normalizedHeaders := make(map[string]string, len(mutation.SetHeaders))
	for name, value := range mutation.SetHeaders {
		lower, ok := mutationHeaderName(name)
		if !ok || strings.ContainsAny(value, "\r\n") {
			return errors.New("pipeline: invalid header mutation")
		}
		normalizedHeaders[lower] = value
	}
	normalizedDeletes := make([]string, 0, len(mutation.DeleteHeaders))
	for _, name := range mutation.DeleteHeaders {
		lower, ok := mutationHeaderName(name)
		if !ok {
			return errors.New("pipeline: invalid header deletion")
		}
		normalizedDeletes = append(normalizedDeletes, lower)
	}

	if mutation.Method != nil {
		ctx.Method = *mutation.Method
	}
	if mutation.Path != nil {
		ctx.Path = *mutation.Path
	}
	if mutation.RawQuery != nil {
		ctx.RawQuery = *mutation.RawQuery
	}
	if mutation.Body != nil {
		ctx.Body = []byte(*mutation.Body)
	}
	if len(normalizedHeaders) > 0 || len(normalizedDeletes) > 0 {
		if ctx.Headers == nil {
			ctx.Headers = make(map[string]string, len(normalizedHeaders))
		}
		for name, value := range normalizedHeaders {
			ctx.Headers[name] = value
		}
		for _, name := range normalizedDeletes {
			delete(ctx.Headers, name)
		}
		ctx.HeadersLowercase = true
		if value, ok := ctx.Headers["user-agent"]; ok {
			ctx.UserAgent = value
		}
		if value, ok := ctx.Headers["content-type"]; ok {
			ctx.ContentType = value
		}
	}
	ctx.QueryParams = nil
	ctx.QueryValues = nil
	ctx.ResetMutationCaches()
	return nil
}

// mutationHeaderName 归一化头名；非法或属于保留头时 ok=false。
//
// 保留头表与 jsplugin 的 isForbiddenJSHeader、luaplugin 的 allowedRequestHeader
// 逐项一致：Host 决定路由与站点匹配，Content-Length 与 Transfer-Encoding 决定
// 消息边界，逐跳头由传输层生成。管道阶段在改写生效前先挡住它们——这里写入的
// Headers 会被后续阶段（规则匹配、指纹）直接读到。
func mutationHeaderName(name string) (string, bool) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || !isMutationToken(trimmed) {
		return "", false
	}
	lower := strings.ToLower(trimmed)
	switch lower {
	case "host", "content-length", "transfer-encoding", "connection", "keep-alive",
		"te", "trailer", "upgrade", "proxy-authenticate", "proxy-authorization", "proxy-connection":
		return "", false
	}
	return lower, true
}

// isMutationToken 报告字符串是合法 HTTP token。
func isMutationToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		default:
			return false
		}
	}
	return true
}

// isMutationPath 报告路径是合法的站内相对路径。
func isMutationPath(path string) bool {
	if path == "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return false
	}
	if strings.ContainsAny(path, "?#\r\n") {
		return false
	}
	for i := 0; i < len(path); i++ {
		if path[i] < 0x20 || path[i] == 0x7f {
			return false
		}
	}
	return true
}

// DrainRequestMutation 取出并清空待应用的请求改写。
func (ctx *RequestCtx) DrainRequestMutation() (RequestMutator, bool) {
	if ctx == nil || ctx.requestMutation == nil {
		return RequestMutator{}, false
	}
	mutation := *ctx.requestMutation
	ctx.requestMutation = nil
	return mutation, true
}

// ResponseMutator 是管道外阶段（Lua post）产生的响应改写意图。
//
// 与 RequestMutator 对称：post 阶段在代理之前算完，但响应体要等代理回来才有，
// 因此意图先挂在 RequestCtx 上，由数据面转交给 proxy 的响应变换链消费。
type ResponseMutator struct {
	// ScriptName 是产生改写的脚本，仅用于诊断与日志。
	ScriptName string
	// StatusCode 为 0 表示不改状态码。
	StatusCode int
	// Body 为 nil 表示不改响应体。
	Body *string
	// SetHeaders/DeleteHeaders 是响应头的增删。
	SetHeaders    map[string]string
	DeleteHeaders []string
}

// AppendResponseMutation 追加一条待应用的响应改写，保持脚本执行顺序。
func (ctx *RequestCtx) AppendResponseMutation(mutation ResponseMutator) {
	if ctx == nil {
		return
	}
	ctx.responseMutations = append(ctx.responseMutations, mutation)
}

// DrainResponseMutations 取出并清空全部待应用响应改写。
func (ctx *RequestCtx) DrainResponseMutations() []ResponseMutator {
	if ctx == nil || len(ctx.responseMutations) == 0 {
		return nil
	}
	mutations := ctx.responseMutations
	ctx.responseMutations = nil
	return mutations
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
