package pipeline

import (
	"net"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/waf/bot"
)

// RequestCtx carries all decoded request data through the pipeline.
type RequestCtx struct {
	RequestID   string
	Bind        string // Listener bind address (e.g., ":443")
	ClientIP    net.IP
	Method      string
	Path        string
	RawQuery    string
	Host        string
	UserAgent   string
	SiteID      uint
	Headers     map[string]string
	HeaderKeys  []string // Ordered header keys for fingerprinting
	Body        []byte
	ContentType string
	TLS         bot.TLSClientFingerprint

	// AntiReplayTTL is per-site nonce window in seconds (0 = engine default).
	AntiReplayTTL int

	QueryParams map[string]string

	// BodyTargets caches extracted body targets to avoid re-parsing in
	// multiple phases (OWASP + CVE both need the same targets).
	BodyTargets     []string
	BodyTargetsDone bool

	// BotScoreResult stores bot detection scoring for async logging in the dataplane.
	// This is set by the bot detection phase and read after pipeline execution.
	BotScoreResult *BotScoreInfo
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
			if result.ShouldLog() {
				observeHits = append(observeHits, result)
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
