package pipeline

import (
	"sync"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/waf/bot"
)

// 池对象容量上限：超过则在 Release 时重建，避免高并发偶发超大请求
// 把 map/slice 永久抬高，造成峰值后 RSS 不回落。
const (
	maxPooledHeaderMapLen   = 128
	maxPooledHeaderKeysCap  = 64
	maxPooledObserveHitsCap = 32
)

// ctxPool reuses RequestCtx allocations to reduce GC pressure on the hot path.
var ctxPool = sync.Pool{
	New: func() any {
		return &RequestCtx{
			Headers:        make(map[string]string, 32),
			HeaderKeys:     make([]string, 0, 16),
			observeHitsBuf: make([]action.Result, 0, 4),
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
	ctx.Context = nil
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
	ctx.QueryValues = nil
	ctx.BodyTargets = nil
	ctx.BodyTargetsDone = false
	ctx.ClearMatcherHeadersCache()
	// 非 alias 的 matcherHeaders 若曾装入大量键，直接丢弃，避免 map bucket 残留。
	if ctx.matcherHeaders != nil && !ctx.matcherHeadersAliased && len(ctx.matcherHeaders) > maxPooledHeaderMapLen {
		ctx.matcherHeaders = nil
	}
	ctx.BotScoreResult = nil
	if ctx.phaseObserveHits != nil {
		if cap(ctx.phaseObserveHits) > maxPooledObserveHitsCap {
			ctx.phaseObserveHits = nil
		} else {
			ctx.phaseObserveHits = ctx.phaseObserveHits[:0]
		}
	}
	if ctx.observeHitsBuf != nil {
		if cap(ctx.observeHitsBuf) > maxPooledObserveHitsCap {
			ctx.observeHitsBuf = make([]action.Result, 0, 4)
		} else {
			ctx.observeHitsBuf = ctx.observeHitsBuf[:0]
		}
	}
	ctx.derivedALPN = ""
	ctx.derivedALPNDone = false
	ctx.derivedHeaderOrder = ""
	ctx.derivedHeaderDone = false
	ctx.derivedCipherSuites = ""
	ctx.derivedCipherDone = false

	// Headers：先看 clear 前的 len，过多则重建；否则 clear 后复用。
	if ctx.Headers != nil && len(ctx.Headers) > maxPooledHeaderMapLen {
		ctx.Headers = make(map[string]string, 32)
	} else if ctx.Headers != nil {
		if len(ctx.Headers) > 0 {
			clear(ctx.Headers)
		}
	} else {
		ctx.Headers = make(map[string]string, 32)
	}

	// HeaderKeys：超限缩回默认 cap，否则只截断长度。
	if ctx.HeaderKeys != nil && cap(ctx.HeaderKeys) > maxPooledHeaderKeysCap {
		ctx.HeaderKeys = make([]string, 0, 16)
	} else {
		ctx.ClearHeaderKeys()
	}
	ctxPool.Put(ctx)
}
