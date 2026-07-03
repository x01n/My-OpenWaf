package pipeline

import (
	"sync"

	"My-OpenWaf/internal/waf/bot"
)

// ctxPool reuses RequestCtx allocations to reduce GC pressure on the hot path.
var ctxPool = sync.Pool{
	New: func() any {
		return &RequestCtx{
			Headers:    make(map[string]string, 32),
			HeaderKeys: make([]string, 0, 16),
		}
	},
}

// AcquireCtx gets a RequestCtx from the pool, pre-allocated with header map.
func AcquireCtx() *RequestCtx {
	ctx := ctxPool.Get().(*RequestCtx)
	return ctx
}

// ReleaseCtx returns a RequestCtx to the pool after clearing its fields.
func ReleaseCtx(ctx *RequestCtx) {
	ctx.RequestID = ""
	ctx.Bind = ""
	ctx.ClientIP = nil
	ctx.Method = ""
	ctx.Path = ""
	ctx.RawQuery = ""
	ctx.Host = ""
	ctx.UserAgent = ""
	ctx.SiteID = 0
	ctx.HeadersLowercase = false
	ctx.Body = nil
	ctx.ContentType = ""
	ctx.TLS = bot.TLSClientFingerprint{}
	ctx.AntiReplayTTL = 0
	ctx.QueryParams = nil
	ctx.BodyTargets = nil
	ctx.BodyTargetsDone = false
	ctx.ClearMatcherHeadersCache()
	ctx.BotScoreResult = nil
	if ctx.phaseObserveHits != nil {
		ctx.phaseObserveHits = ctx.phaseObserveHits[:0]
	}
	if len(ctx.Headers) > 0 {
		clear(ctx.Headers)
	}
	ctx.ClearHeaderKeys()
	ctxPool.Put(ctx)
}
