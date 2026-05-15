package pipeline

import (
	"net"

	"My-OpenWaf/internal/core/action"
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
	Headers     map[string]string
	HeaderKeys  []string // Ordered header keys for fingerprinting
	Body        []byte
	ContentType string

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

// Run executes each phase in order.
// Drop/intercept results short-circuit immediately (highest priority).
// Challenge results are deferred: pipeline continues so that subsequent phases
// (OWASP, CVE, etc.) still run. If a higher-priority terminal action appears later,
// it overrides the challenge. Otherwise the challenge is returned at the end.
func (p *Pipeline) Run(ctx *RequestCtx) RunResult {
	var observeHits []action.Result
	var pendingChallenge *action.Result

	for _, ph := range p.phases {
		result, stop := ph.Execute(ctx)
		if stop {
			// If stop is explicitly requested AND it's not a challenge, short-circuit.
			if !result.IsChallenge() {
				return RunResult{Action: result, ObserveHits: observeHits}
			}
			// Challenge with explicit stop: record it but continue pipeline.
			if pendingChallenge == nil || action.TerminalPriority(result.Type) > action.TerminalPriority(pendingChallenge.Type) {
				r := result
				pendingChallenge = &r
			}
			continue
		}
		if result.Matched {
			// Drop is highest priority — immediate short-circuit.
			if result.IsDrop() {
				return RunResult{Action: result, ObserveHits: observeHits}
			}
			if result.IsTerminal() {
				if result.IsChallenge() {
					// Defer challenge, continue pipeline.
					if pendingChallenge == nil || action.TerminalPriority(result.Type) > action.TerminalPriority(pendingChallenge.Type) {
						r := result
						pendingChallenge = &r
					}
					continue
				}
				// Non-challenge terminal (intercept, rate_limit, redirect) — short-circuit.
				return RunResult{Action: result, ObserveHits: observeHits}
			}
			if result.ShouldLog() {
				observeHits = append(observeHits, result)
			}
		}
	}

	// All phases executed. Return deferred challenge if any, otherwise pass.
	if pendingChallenge != nil {
		return RunResult{Action: *pendingChallenge, ObserveHits: observeHits}
	}
	return RunResult{Action: action.Pass(), ObserveHits: observeHits}
}
