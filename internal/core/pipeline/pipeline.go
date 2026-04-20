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
	Body        []byte
	ContentType string

	QueryParams map[string]string
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
// Drop results short-circuit immediately (highest priority, TCP close).
// Intercept results short-circuit immediately; observe results are collected for logging.
func (p *Pipeline) Run(ctx *RequestCtx) RunResult {
	var observeHits []action.Result
	for _, ph := range p.phases {
		result, stop := ph.Execute(ctx)
		if stop {
			return RunResult{Action: result, ObserveHits: observeHits}
		}
		if result.Matched {
			// Drop is highest priority — immediate short-circuit.
			if result.IsDrop() {
				return RunResult{Action: result, ObserveHits: observeHits}
			}
			if result.IsTerminal() {
				return RunResult{Action: result, ObserveHits: observeHits}
			}
			if result.ShouldLog() {
				observeHits = append(observeHits, result)
			}
		}
	}
	return RunResult{Action: action.Pass(), ObserveHits: observeHits}
}
