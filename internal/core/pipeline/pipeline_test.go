package pipeline

import (
	"context"
	"testing"

	"My-OpenWaf/internal/core/action"
)

// stubPhase is a test double implementing the Phase interface.
type stubPhase struct {
	name   string
	result action.Result
	stop   bool
}

func (p *stubPhase) Name() string { return p.name }
func (p *stubPhase) Execute(_ *RequestCtx) (action.Result, bool) {
	return p.result, p.stop
}

func passPhase(name string) *stubPhase {
	return &stubPhase{name: name, result: action.Result{Type: action.Allow}, stop: false}
}

func interceptPhase(name string) *stubPhase {
	return &stubPhase{
		name:   name,
		result: action.Result{Type: action.Intercept, Matched: true},
		stop:   true,
	}
}

func challengePhase(name string) *stubPhase {
	return &stubPhase{
		name:   name,
		result: action.Result{Type: action.CaptchaChallenge, Matched: true},
		stop:   true,
	}
}

func TestRunEmptyPhasesPasses(t *testing.T) {
	ctx := &RequestCtx{}
	result := Run(nil, ctx)
	if result.Action.Type != action.Allow {
		t.Errorf("Run(nil phases) = %v, want Allow", result.Action.Type)
	}
}

func TestRunSinglePassPhasePasses(t *testing.T) {
	ctx := &RequestCtx{}
	result := Run([]Phase{passPhase("acl")}, ctx)
	if result.Action.Type != action.Allow {
		t.Errorf("Run([passPhase]) = %v, want Allow", result.Action.Type)
	}
}

func TestRunInterceptPhaseShortsCircuit(t *testing.T) {
	ctx := &RequestCtx{}
	result := Run([]Phase{interceptPhase("waf"), passPhase("log")}, ctx)
	if result.Action.Type != action.Intercept {
		t.Errorf("Run([intercept, pass]) = %v, want Intercept", result.Action.Type)
	}
}

func TestRunChallengeDeferred(t *testing.T) {
	ctx := &RequestCtx{}
	// challenge 之后还有 pass 阶段，challenge 应在最后返回
	result := Run([]Phase{challengePhase("bot"), passPhase("custom")}, ctx)
	if result.Action.Type != action.CaptchaChallenge {
		t.Errorf("Run([challenge, pass]) = %v, want CaptchaChallenge", result.Action.Type)
	}
}

func TestRunInterceptOverridesChallenge(t *testing.T) {
	ctx := &RequestCtx{}
	result := Run([]Phase{challengePhase("bot"), interceptPhase("owasp")}, ctx)
	if result.Action.Type != action.Intercept {
		t.Errorf("Intercept should override challenge; got %v", result.Action.Type)
	}
}

func TestNewPipelineRunMatchesFreeRun(t *testing.T) {
	ctx1 := &RequestCtx{}
	ctx2 := &RequestCtx{}
	phases := []Phase{passPhase("acl"), passPhase("owasp")}

	r1 := Run(phases, ctx1)
	p := New(phases...)
	r2 := p.Run(ctx2)

	if r1.Action.Type != r2.Action.Type {
		t.Errorf("New().Run() = %v, Run() = %v, should match", r2.Action.Type, r1.Action.Type)
	}
}

func TestReleaseCtxClearsRequestContext(t *testing.T) {
	ctx := AcquireCtx()
	ctx.Context = context.Background()
	ReleaseCtx(ctx)

	ctx = AcquireCtx()
	defer ReleaseCtx(ctx)
	if ctx.Context != nil {
		t.Fatal("ReleaseCtx must clear request Context before reuse")
	}
}

// ── RequestCtx method tests ──

func TestCachedMatcherHeadersMissWhenNotReady(t *testing.T) {
	ctx := &RequestCtx{}
	_, ok := ctx.CachedMatcherHeaders()
	if ok {
		t.Error("CachedMatcherHeaders should return !ok before StoreMatcherHeaders")
	}
}

func TestStoreAndCachedMatcherHeaders(t *testing.T) {
	ctx := &RequestCtx{}
	headers := map[string]string{"host": "example.com", "user-agent": "bot"}
	ctx.StoreMatcherHeaders(headers)

	got, ok := ctx.CachedMatcherHeaders()
	if !ok {
		t.Fatal("CachedMatcherHeaders should return ok after StoreMatcherHeaders")
	}
	if got["host"] != "example.com" {
		t.Errorf("CachedMatcherHeaders host = %q, want \"example.com\"", got["host"])
	}
}

func TestCachedMatcherHeadersAliasedFalseByDefault(t *testing.T) {
	ctx := &RequestCtx{}
	ctx.StoreMatcherHeaders(map[string]string{"x": "y"})
	if ctx.CachedMatcherHeadersAliased() {
		t.Error("CachedMatcherHeadersAliased should be false when stored via StoreMatcherHeaders")
	}
}

func TestStoreAliasedMatcherHeaders(t *testing.T) {
	ctx := &RequestCtx{}
	ctx.StoreAliasedMatcherHeaders(map[string]string{"x-forwarded-for": "1.2.3.4"})
	if !ctx.CachedMatcherHeadersAliased() {
		t.Error("CachedMatcherHeadersAliased should be true after StoreAliasedMatcherHeaders")
	}
}

func TestClearMatcherHeadersCache(t *testing.T) {
	ctx := &RequestCtx{}
	ctx.StoreMatcherHeaders(map[string]string{"a": "b"})
	ctx.ClearMatcherHeadersCache()
	_, ok := ctx.CachedMatcherHeaders()
	if ok {
		t.Error("CachedMatcherHeaders should return !ok after ClearMatcherHeadersCache")
	}
}

func TestAppendAndClearHeaderKeys(t *testing.T) {
	ctx := &RequestCtx{}
	ctx.AppendHeaderKey("Content-Type")
	ctx.AppendHeaderKey("Accept")
	if len(ctx.HeaderKeys) != 2 {
		t.Errorf("HeaderKeys length = %d, want 2", len(ctx.HeaderKeys))
	}
	ctx.ClearHeaderKeys()
	if len(ctx.HeaderKeys) != 0 {
		t.Error("HeaderKeys should be empty after ClearHeaderKeys")
	}
}

func TestAppendAndDrainPhaseObserveHits(t *testing.T) {
	ctx := &RequestCtx{}
	hits := []action.Result{
		{Type: action.Observe, Matched: true},
		{Type: action.Observe, Matched: true},
	}
	ctx.AppendPhaseObserveHits(hits)
	drained := ctx.DrainPhaseObserveHits()
	if len(drained) != 2 {
		t.Errorf("DrainPhaseObserveHits returned %d hits, want 2", len(drained))
	}
	// 第二次 drain 应为空
	second := ctx.DrainPhaseObserveHits()
	if len(second) != 0 {
		t.Errorf("second DrainPhaseObserveHits returned %d hits, want 0", len(second))
	}
}
