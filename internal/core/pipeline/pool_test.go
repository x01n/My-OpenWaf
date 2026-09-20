package pipeline

import (
	"strconv"
	"testing"

	"My-OpenWaf/internal/core/action"
)

func TestReleaseCtxClearsMatcherHeadersCache(t *testing.T) {
	ctx := AcquireCtx()
	ctx.Headers["User-Agent"] = "Mozilla/5.0"
	ctx.AppendHeaderKey("Host")
	ctx.AppendHeaderKey("User-Agent")
	ctx.BodyTargets = []string{"body"}
	ctx.BodyTargetsDone = true
	ctx.ChallengeIdentityCaptured = true
	ctx.ChallengeIdentityUserAgent = "original-agent"
	ctx.ChallengeIdentityCookie = "original-cookie"
	ctx.OriginalPath = "/inbound"
	ctx.StoreMatcherHeaders(map[string]string{"X-OWAF-TLS-SNI": "login.example.com"})
	ctx.AppendPhaseObserveHits([]action.Result{{RuleID: 7, Matched: true, Type: action.Observe}})

	ReleaseCtx(ctx)

	if _, ok := ctx.CachedMatcherHeaders(); ok {
		t.Fatal("matcher headers cache should be cleared on release")
	}
	if len(ctx.Headers) != 0 {
		t.Fatalf("headers should be cleared on release, got %#v", ctx.Headers)
	}
	if len(ctx.HeaderKeys) != 0 {
		t.Fatalf("header keys should be cleared on release, got %#v", ctx.HeaderKeys)
	}
	if ctx.BodyTargets != nil || ctx.BodyTargetsDone {
		t.Fatalf("body target cache should be cleared on release, got %#v / %v", ctx.BodyTargets, ctx.BodyTargetsDone)
	}
	if ctx.ChallengeIdentityCaptured || ctx.ChallengeIdentityUserAgent != "" || ctx.ChallengeIdentityCookie != "" {
		t.Fatalf("challenge identity should be cleared on release, got captured=%v ua=%q cookie=%q", ctx.ChallengeIdentityCaptured, ctx.ChallengeIdentityUserAgent, ctx.ChallengeIdentityCookie)
	}
	if ctx.OriginalPath != "" {
		t.Fatalf("original path should be cleared on release, got %q", ctx.OriginalPath)
	}
	if len(ctx.DrainPhaseObserveHits()) != 0 {
		t.Fatal("phase observe hits should be cleared on release")
	}
}

func TestReleaseCtxClearsAntiReplayConsumedNonce(t *testing.T) {
	ctx := AcquireCtx()
	ctx.AntiReplayConsumedNonce = "nonce-to-clear"
	ReleaseCtx(ctx)

	next := AcquireCtx()
	defer ReleaseCtx(next)
	if next.AntiReplayConsumedNonce != "" {
		t.Fatalf("reused context AntiReplayConsumedNonce = %q, want empty", next.AntiReplayConsumedNonce)
	}
}

func TestAcquireCtxReusesHeaderMapCapacity(t *testing.T) {
	ctx := AcquireCtx()
	if ctx.Headers == nil {
		t.Fatal("expected pooled ctx to initialize headers map")
	}
	ctx.Headers["User-Agent"] = "Mozilla/5.0"
	ctx.AppendHeaderKey("User-Agent")
	ReleaseCtx(ctx)

	next := AcquireCtx()
	if next.Headers == nil {
		t.Fatal("expected pooled ctx to preserve headers map")
	}
	if len(next.Headers) != 0 {
		t.Fatalf("expected cleared headers map, got %#v", next.Headers)
	}
	ReleaseCtx(next)
}

func TestReleaseCtxShrinksOversizedBuffers(t *testing.T) {
	ctx := AcquireCtx()
	for i := 0; i < maxPooledHeaderMapLen+10; i++ {
		k := "X-H-" + strconv.Itoa(i)
		ctx.Headers[k] = "v"
		ctx.AppendHeaderKey(k)
	}
	ctx.observeHitsBuf = make([]action.Result, 0, maxPooledObserveHitsCap+8)
	ReleaseCtx(ctx)

	next := AcquireCtx()
	if cap(next.HeaderKeys) > maxPooledHeaderKeysCap {
		t.Fatalf("HeaderKeys cap should shrink, got %d", cap(next.HeaderKeys))
	}
	if cap(next.observeHitsBuf) > maxPooledObserveHitsCap {
		t.Fatalf("observeHitsBuf cap should shrink, got %d", cap(next.observeHitsBuf))
	}
	if len(next.Headers) != 0 {
		t.Fatalf("headers should be empty after oversized rebuild, got %d", len(next.Headers))
	}
	ReleaseCtx(next)
}
