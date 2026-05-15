package pipeline

import "sync"

// ctxPool reuses RequestCtx allocations to reduce GC pressure on the hot path.
var ctxPool = sync.Pool{
	New: func() any {
		return &RequestCtx{
			Headers:    make(map[string]string, 16),
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
	ctx.Body = nil
	ctx.ContentType = ""
	ctx.AntiReplayTTL = 0
	ctx.QueryParams = nil
	ctx.BodyTargets = nil
	ctx.BodyTargetsDone = false
	ctx.BotScoreResult = nil
	ctx.HeaderKeys = ctx.HeaderKeys[:0]
	for k := range ctx.Headers {
		delete(ctx.Headers, k)
	}
	ctxPool.Put(ctx)
}
