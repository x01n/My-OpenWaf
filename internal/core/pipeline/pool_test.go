package pipeline

import (
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
	if len(ctx.DrainPhaseObserveHits()) != 0 {
		t.Fatal("phase observe hits should be cleared on release")
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
