package rules

import (
	"testing"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/waf/owasp"
)

type skipByPathRecordingPhase struct {
	name   string
	result action.Result
	stop   bool
	calls  int
}

func (p *skipByPathRecordingPhase) Name() string { return p.name }

func (p *skipByPathRecordingPhase) Execute(*pipeline.RequestCtx) (action.Result, bool) {
	p.calls++
	return p.result, p.stop
}

func TestSkipByPathPhaseMatchReturnsPassAndContinuesPipeline(t *testing.T) {
	inner := &skipByPathRecordingPhase{
		name:   "owasp_default",
		result: action.Result{Type: action.Intercept, Matched: true},
		stop:   true,
	}
	decorated := NewSkipByPathPhase(inner, []string{"/public/*"})
	ctx := &pipeline.RequestCtx{
		OriginalPath: "/public/index.html",
		Path:         "/public/rewritten.html",
	}

	result, stop := decorated.Execute(ctx)
	if result != action.Pass() || stop {
		t.Fatalf("matched skip returned (%#v, %v), want (Pass, false)", result, stop)
	}
	if inner.calls != 0 {
		t.Fatalf("matched skip invoked inner phase %d times, want 0", inner.calls)
	}

	next := &skipByPathRecordingPhase{name: "next", result: action.Pass()}
	pipeline.Run([]pipeline.Phase{decorated, next}, ctx)
	if next.calls != 1 {
		t.Fatalf("phase after matched skip ran %d times, want 1", next.calls)
	}
	if inner.calls != 0 {
		t.Fatalf("pipeline run invoked skipped inner phase %d times, want 0", inner.calls)
	}
}

func TestSkipByPathPhaseDoesNotSkipRewrittenFinalPath(t *testing.T) {
	inner := &skipByPathRecordingPhase{
		name:   "owasp_default",
		result: action.Result{Type: action.Intercept, Matched: true},
		stop:   true,
	}
	decorated := NewSkipByPathPhase(inner, []string{"/public/*"})

	result, stop := decorated.Execute(&pipeline.RequestCtx{
		OriginalPath: "/public/index.html",
		Path:         "/private",
	})
	if result != inner.result || !stop {
		t.Fatalf("rewritten final path returned (%#v, %v), want delegated result and stop", result, stop)
	}
	if inner.calls != 1 {
		t.Fatalf("rewritten final path invoked inner phase %d times, want 1", inner.calls)
	}
}

func TestSkipByPathPhaseMissDelegatesToInnerPhase(t *testing.T) {
	wantResult := action.Result{
		Type:      action.Intercept,
		Phase:     "owasp_default",
		MatchDesc: "delegated",
		Matched:   true,
	}
	inner := &skipByPathRecordingPhase{name: "owasp_default", result: wantResult, stop: true}
	decorated := NewSkipByPathPhase(inner, []string{"/public/*"})

	gotResult, gotStop := decorated.Execute(&pipeline.RequestCtx{
		OriginalPath: "/private",
		Path:         "/public/index.html",
	})
	if gotResult != wantResult || !gotStop {
		t.Fatalf("miss returned (%#v, %v), want (%#v, true)", gotResult, gotStop, wantResult)
	}
	if inner.calls != 1 {
		t.Fatalf("miss invoked inner phase %d times, want 1", inner.calls)
	}
}

func TestSkipByPathPhaseUsesMatchPathListNormalizationAndFailClosedRules(t *testing.T) {
	paths := []string{"  /static/*  "}
	tests := []struct {
		name        string
		path        string
		wantSkipped bool
	}{
		{name: "normalized percent encoding", path: "/STATIC/%61pp.js", wantSkipped: true},
		{name: "traversal escapes prefix", path: "/static/%2e%2e/admin", wantSkipped: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := owasp.MatchPathList(tt.path, paths); got != tt.wantSkipped {
				t.Fatalf("MatchPathList(%q) = %v, want %v", tt.path, got, tt.wantSkipped)
			}

			inner := &skipByPathRecordingPhase{
				name:   "owasp_default",
				result: action.Result{Type: action.Intercept, Matched: true},
				stop:   true,
			}
			result, stop := NewSkipByPathPhase(inner, paths).Execute(&pipeline.RequestCtx{Path: tt.path})
			if tt.wantSkipped {
				if result != action.Pass() || stop || inner.calls != 0 {
					t.Fatalf("normalized match returned (%#v, %v), inner calls %d", result, stop, inner.calls)
				}
				return
			}
			if result.Type != action.Intercept || !stop || inner.calls != 1 {
				t.Fatalf("fail-closed path returned (%#v, %v), inner calls %d", result, stop, inner.calls)
			}
		})
	}
}
