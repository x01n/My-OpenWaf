package dataplane

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/dataplane/logredact"
	dpreqid "My-OpenWaf/internal/dataplane/reqid"
	proxytransport "My-OpenWaf/internal/proxy/transport"
	"My-OpenWaf/internal/security"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/tlsmeta"
	"My-OpenWaf/internal/visitorfusion"
	"My-OpenWaf/internal/waf/bot/tlsfp"
	"My-OpenWaf/internal/waf/pages"
)

func logAccess(log *slog.Logger, reqID string, method string, path string, host string, statusCode int, wafAction string) {
	if !log.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	log.Debug("access",
		slog.String("request_id", reqID),
		slog.String("method", method),
		slog.String("path", path),
		slog.String("host", host),
		slog.Int("status", statusCode),
		slog.String("waf_action", wafAction),
	)
}

var dropConsoleLogCounter atomic.Uint64

var noSiteMatchConsoleLogCounter atomic.Uint64

func shouldLogConsoleSampleCount(count uint64) bool {
	return count <= 16 || count%1024 == 0
}

func shouldLogDropConsoleCount(count uint64) bool {
	return shouldLogConsoleSampleCount(count)
}

func shouldLogDropConsole() bool {
	return shouldLogDropConsoleCount(dropConsoleLogCounter.Add(1))
}

func shouldLogNoSiteMatchConsoleCount(count uint64) bool {
	return shouldLogConsoleSampleCount(count)
}

func shouldLogNoSiteMatchConsole() bool {
	return shouldLogNoSiteMatchConsoleCount(noSiteMatchConsoleLogCounter.Add(1))
}

var accessLogSampleCounter atomic.Uint32

type accessLogInfo struct {
	SiteID               uint
	RequestID            string
	ClientIP             string
	Host                 string
	Path                 string
	QueryString          string
	Method               string
	UserAgent            string
	StatusCode           int
	WAFAction            string
	CacheState           string
	Upstream             string
	HTTPProtocol         string
	UpstreamHTTPProtocol string
	// ZeroRTT 标记该请求来自 HTTP/3 0-RTT（early data）。0-RTT 数据可被重放，
	// 审计时必须能与 1-RTT 请求区分。
	ZeroRTT        bool
	TLSFingerprint tlsfp.TLSClientFingerprint
	// HeaderOrder 是已 join 的请求头顺序字符串，主路径直接复用 DerivedHeaderOrder，避免再次 Join。
	HeaderOrder          string
	UpstreamLatencyMs    int64
	ResponseSize         int64
	ResponseSizeKnown    bool
	RequestHeaders       string
	RequestBodyPreview   string
	RequestBodyTruncated bool
	RequestSize          int64
	ResponseHeaders      string
	// ForceRecord 保留请求体预取期间客户端连接中断的审计记录。
	ForceRecord bool
	// Minimal 仅记录状态、路由身份和指纹，早退时不得读取请求体或响应体。
	Minimal  bool
	Detailed bool

	VisitorFusionEligible bool
	VisitorFusionAction   action.Result
	VisitorFusionBotScore *pipeline.BotScoreInfo
}

func shouldRecordDetailedSecurityEvent(ev store.SecurityEvent) bool {
	switch action.Normalize(action.Type(ev.Action)) {
	case action.Drop, action.Intercept, action.RateLimit, action.Challenge, action.CaptchaChallenge, action.ShieldChallenge, action.ChainChallenge, action.Redirect:
		return true
	default:
		return ev.StatusCode >= 400
	}
}

func recordSecurityEvent(c *app.RequestContext, opts Options, ev store.SecurityEvent) {
	if opts.Writer == nil {
		return
	}
	if ev.QueryString == "" {
		ev.QueryString = string(c.URI().QueryString())
	}
	ev.QueryString = logredact.SanitizeQueryString(ev.QueryString)
	if fp, ok := tlsFingerprintFromRequestContext(c); ok {
		if ev.TLSJA3 == "" {
			ev.TLSJA3 = fp.JA3
		}
		if ev.TLSJA3Hash == "" {
			ev.TLSJA3Hash = fp.JA3Hash
		}
		if ev.TLSJA4 == "" {
			ev.TLSJA4 = fp.JA4
		}
		if ev.TLSVersion == "" {
			ev.TLSVersion = fp.TLSVersion
		}
		if ev.TLSSNI == "" {
			ev.TLSSNI = fp.SNI
		}
		if ev.TLSSNIPresence == "" {
			ev.TLSSNIPresence = fp.SNIPresence()
		}
		if ev.TLSALPN == "" && len(fp.ALPN) > 0 {
			ev.TLSALPN = strings.Join(fp.ALPN, ",")
		}
		if ev.TLSCipherSuites == "" && len(fp.CipherSuites) > 0 {
			ev.TLSCipherSuites = tlsmeta.FormatCipherSuites(fp.CipherSuites)
		}
		if ev.TLSExtensions == "" && len(fp.Extensions) > 0 {
			ev.TLSExtensions = formatUint16Slice(fp.Extensions)
		}
		if ev.TLSCurves == "" && len(fp.Curves) > 0 {
			ev.TLSCurves = formatUint16Slice(fp.Curves)
		}
		if ev.TLSPointFormats == "" && len(fp.PointFormats) > 0 {
			ev.TLSPointFormats = formatUint8Slice(fp.PointFormats)
		}
	}
	if ev.HeaderOrder == "" {
		if reqCtxCache, ok := headerOrderFromContext(c); ok {
			ev.HeaderOrder = reqCtxCache
		}
	}
	if ev.HeaderOrder == "" {
		ev.HeaderOrder = strings.Join(requestHeaderOrder(c), ",")
	}
	if shouldRecordDetailedSecurityEvent(ev) {
		reqBody, truncated, size := requestBodyPreview(c)
		ev.RequestHeaders = valueOrFallback(ev.RequestHeaders, requestHeadersJSON(c))
		ev.RequestBodyPreview = valueOrFallback(ev.RequestBodyPreview, reqBody)
		ev.RequestBodyTruncated = ev.RequestBodyTruncated || truncated
		ev.RequestSize = firstPositive(ev.RequestSize, size)
	}
	ev.RequestHeaders = logredact.SanitizeLogText(ev.RequestHeaders)
	ev.RequestBodyPreview = logredact.SanitizeLogText(ev.RequestBodyPreview)
	// 匹配片段直接来自请求内容，可能包含凭据类键值，按与请求头/请求体
	// 相同的脱敏规则处理；长度上限由检测层（snippet.MaxLen）保证。
	if ev.MatchSnippet != "" {
		ev.MatchSnippet = logredact.SanitizeLogText(ev.MatchSnippet)
	}
	opts.Writer.RecordEvent(ev)
}

type accessLogRecorder interface {
	RecordAccessLog(store.AccessLog)
}

func buildAccessLogEntry(c *app.RequestContext, info accessLogInfo) store.AccessLog {
	if info.HTTPProtocol == "" {
		info.HTTPProtocol = requestProtocol(c)
	}
	if info.UpstreamHTTPProtocol == "" {
		info.UpstreamHTTPProtocol = proxytransport.UpstreamHTTPProtocol(c)
	}
	if isInternalHTTP3Request(c) {
		// 0-RTT 标记来自 h3 回环内部头（已校验回环来源），只对 h3 请求有意义。
		info.ZeroRTT = info.ZeroRTT || isInternalHTTP3ZeroRTT(c)
		if fp, ok := tlsFingerprintFromRequestContext(c); ok {
			info.TLSFingerprint = fp
		} else {
			info.TLSFingerprint = tlsfp.TLSClientFingerprint{}
		}
	} else {
		if fp, ok := tlsFingerprintFromRequestContext(c); ok {
			info.TLSFingerprint = mergeTLSFingerprint(info.TLSFingerprint, fp)
		}
	}
	if !info.Minimal && info.HeaderOrder == "" {
		if reqCtxCache, ok := headerOrderFromContext(c); ok {
			info.HeaderOrder = reqCtxCache
		}
	}
	if !info.Minimal && info.HeaderOrder == "" {
		info.HeaderOrder = strings.Join(requestHeaderOrder(c), ",")
	}
	requestBody := info.RequestBodyPreview
	requestBodyTruncated := info.RequestBodyTruncated
	requestSize := info.RequestSize
	requestHeaders := info.RequestHeaders
	responseHeaders := info.ResponseHeaders
	responseSize := info.ResponseSize
	if !info.Minimal && requestSize == 0 {
		_, sampledBodyTruncated, sampledRequestSize := requestBodySample(c)
		requestSize = sampledRequestSize
		requestBodyTruncated = requestBodyTruncated || sampledBodyTruncated
	}
	if !info.Minimal && !info.ResponseSizeKnown && responseSize == 0 && c.Response.Header.Get("Trailer") == "" && string(c.Request.Method()) != "HEAD" {
		if cl := int64(c.Response.Header.ContentLength()); cl > 0 {
			responseSize = cl
		} else if !c.Response.IsBodyStream() {
			responseSize = int64(len(c.Response.Body()))
		}
	}
	if info.Detailed {
		if requestBody == "" || requestSize == 0 {
			var bodyTruncated bool
			requestBody, bodyTruncated, requestSize = requestBodyPreview(c)
			requestBodyTruncated = requestBodyTruncated || bodyTruncated
		}
		requestHeaders = valueOrFallback(requestHeaders, requestHeadersJSON(c))
		responseHeaders = valueOrFallback(responseHeaders, responseHeadersJSON(c))
	}
	if logredact.IsDynamicProtectionKeyPath(c, info.Path) {
		requestBody = "[redacted]"
	}
	requestBody = logredact.SanitizeLogText(requestBody)
	requestHeaders = logredact.SanitizeLogText(requestHeaders)
	responseHeaders = logredact.SanitizeLogText(responseHeaders)

	var fusion visitorfusion.Result
	if shouldEvaluateVisitorFusion(info) {
		fusion = buildVisitorFusionResult(c, info)
	}
	entry := store.AccessLog{
		// 在请求收尾时就固定时间戳，而不是等 GORM 落库时补。
		// Redis 日志链路（pushToRedis）在落库之前执行，若这里留零值，
		// Redis 中的记录 created_at 恒为 0001-01-01，既无法排序也无法
		// 作为查询源。GORM 对非零 CreatedAt 不再覆盖，因此 DB 与 Redis
		// 会写入同一个时刻。
		CreatedAt:            time.Now(),
		SiteID:               info.SiteID,
		RequestID:            info.RequestID,
		ClientIP:             info.ClientIP,
		Host:                 info.Host,
		Path:                 info.Path,
		QueryString:          logredact.SanitizeQueryString(info.QueryString),
		Method:               info.Method,
		StatusCode:           info.StatusCode,
		WAFAction:            info.WAFAction,
		CacheState:           info.CacheState,
		Upstream:             logredact.SanitizeUpstreamURL(info.Upstream),
		UserAgent:            info.UserAgent,
		RequestHeaders:       requestHeaders,
		RequestBodyPreview:   requestBody,
		RequestBodyTruncated: requestBodyTruncated,
		RequestSize:          requestSize,
		ResponseHeaders:      responseHeaders,
		HTTPProtocol:         info.HTTPProtocol,
		UpstreamHTTPProtocol: info.UpstreamHTTPProtocol,
		ZeroRTT:              info.ZeroRTT,
		TLSVersion:           info.TLSFingerprint.TLSVersion,
		TLSSNI:               info.TLSFingerprint.SNI,
		TLSSNIPresence:       info.TLSFingerprint.SNIPresence(),
		TLSALPN:              strings.Join(info.TLSFingerprint.ALPN, ","),
		TLSJA3:               info.TLSFingerprint.JA3,
		TLSJA3Hash:           info.TLSFingerprint.JA3Hash,
		TLSJA4:               info.TLSFingerprint.JA4,
		TLSCipherSuites:      tlsmeta.FormatCipherSuites(info.TLSFingerprint.CipherSuites),
		TLSExtensions:        formatUint16Slice(info.TLSFingerprint.Extensions),
		TLSCurves:            formatUint16Slice(info.TLSFingerprint.Curves),
		TLSPointFormats:      formatUint8Slice(info.TLSFingerprint.PointFormats),
		HeaderOrder:          info.HeaderOrder,
		UpstreamLatencyMs:    info.UpstreamLatencyMs,
		ResponseSize:         responseSize,
	}
	if fusion.IsPersistable() {
		entry.VisitorFusionClass = string(fusion.Classification)
		entry.VisitorFusionScore = fusion.Score
		entry.VisitorFusionClientFamily = string(fusion.ClientFamily)
		entry.VisitorFusionUAClaim = string(fusion.UAClaim)
		entry.VisitorFusionConsistency = string(fusion.Consistency)
		entry.VisitorFusionEvidenceSufficient = fusion.EvidenceSufficient
		entry.VisitorFusionReasons = strings.Join(fusion.Reasons, ",")
	}
	return entry
}

func shouldEvaluateVisitorFusion(info accessLogInfo) bool {
	return info.VisitorFusionEligible && info.TLSFingerprint.TLSVersion != "" && !info.VisitorFusionAction.IsTerminal()
}

func buildVisitorFusionResult(c *app.RequestContext, info accessLogInfo) visitorfusion.Result {
	botScores := visitorfusion.ExistingBotScores{}
	if info.VisitorFusionBotScore != nil {
		botScores = visitorfusion.ExistingBotScores{
			Available:        true,
			GeoIPScore:       info.VisitorFusionBotScore.GeoIPScore,
			FingerprintScore: info.VisitorFusionBotScore.FingerprintScore,
			BehaviorScore:    info.VisitorFusionBotScore.BehaviorScore,
			IPRepScore:       info.VisitorFusionBotScore.IPRepScore,
		}
	}
	accept := strings.ToLower(string(c.GetHeader("Accept")))
	acceptEncoding := strings.ToLower(string(c.GetHeader("Accept-Encoding")))
	return visitorfusion.Evaluate(visitorfusion.Input{
		HTTPS:            info.VisitorFusionEligible && info.TLSFingerprint.TLSVersion != "",
		WAFAction:        info.VisitorFusionAction,
		UserAgent:        info.UserAgent,
		Method:           info.Method,
		HasClientHints:   len(c.GetHeader("Sec-CH-UA")) > 0,
		HasFetchMetadata: len(c.GetHeader("Sec-Fetch-Site")) > 0 || len(c.GetHeader("Sec-Fetch-Mode")) > 0 || len(c.GetHeader("Sec-Fetch-Dest")) > 0,
		AcceptsHTML:      strings.Contains(accept, "text/html"),
		AcceptsBrotli:    strings.Contains(acceptEncoding, "br"),
		HeaderOrder:      info.HeaderOrder,
		TLS: visitorfusion.TLSFeatures{
			JA3:          info.TLSFingerprint.JA3,
			JA4:          info.TLSFingerprint.JA4,
			TLSVersion:   info.TLSFingerprint.TLSVersion,
			ALPN:         info.TLSFingerprint.ALPN,
			CipherSuites: len(info.TLSFingerprint.CipherSuites),
			Extensions:   len(info.TLSFingerprint.Extensions),
			Curves:       len(info.TLSFingerprint.Curves),
		},
		ExistingBotScores: botScores,
	})
}

func mergeTLSFingerprint(base tlsfp.TLSClientFingerprint, extra tlsfp.TLSClientFingerprint) tlsfp.TLSClientFingerprint {
	if base.JA3 == "" {
		base.JA3 = extra.JA3
	}
	if base.JA3Hash == "" {
		base.JA3Hash = extra.JA3Hash
	}
	if base.JA4 == "" {
		base.JA4 = extra.JA4
	}
	if base.TLSVersion == "" {
		base.TLSVersion = extra.TLSVersion
	}
	if base.SNI == "" {
		base.SNI = extra.SNI
	}
	if len(base.ALPN) == 0 {
		base.ALPN = extra.ALPN
	}
	if len(base.ALPNRaw) == 0 {
		base.ALPNRaw = extra.ALPNRaw
	}
	if len(base.CipherSuites) == 0 {
		base.CipherSuites = extra.CipherSuites
	}
	if len(base.Extensions) == 0 {
		base.Extensions = extra.Extensions
	}
	if len(base.Curves) == 0 {
		base.Curves = extra.Curves
	}
	if len(base.PointFormats) == 0 {
		base.PointFormats = extra.PointFormats
	}
	return base
}

func formatUint16Slice(s []uint16) string {
	if len(s) == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s) * 6)
	for i, v := range s {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	return b.String()
}

func formatUint8Slice(s []uint8) string {
	if len(s) == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s) * 4)
	for i, v := range s {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	return b.String()
}

const (
	logBodyPreviewLimit  = 8192
	logHeaderValueLimit  = 2048
	logHeaderValuesLimit = 32
)

func requestHeadersJSON(c *app.RequestContext) string {
	headers := make(map[string][]string)
	c.Request.Header.VisitAll(func(k, v []byte) {
		key := string(k)
		// toLowerASCII 对已是小写的输入零分配直接返回原串，header 名绝大多数如此。
		lower := logredact.ToLowerASCII(key)
		if logredact.IsSensitiveLogKeyLowered(lower) {
			headers[key] = []string{"[redacted]"}
			return
		}
		values := headers[key]
		if len(values) >= logHeaderValuesLimit {
			return
		}
		headers[key] = append(values, logredact.TruncateLogValue(logredact.SanitizeLogText(string(v)), logHeaderValueLimit))
	})
	data, err := json.Marshal(headers)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func responseHeadersJSON(c *app.RequestContext) string {
	headers := make(map[string][]string)
	c.Response.Header.VisitAll(func(k, v []byte) {
		key := string(k)
		// toLowerASCII 对已是小写的输入零分配直接返回原串，header 名绝大多数如此。
		lower := logredact.ToLowerASCII(key)
		if logredact.IsSensitiveLogKeyLowered(lower) {
			headers[key] = []string{"[redacted]"}
			return
		}
		values := headers[key]
		if len(values) >= logHeaderValuesLimit {
			return
		}
		headers[key] = append(values, logredact.TruncateLogValue(logredact.SanitizeLogText(string(v)), logHeaderValueLimit))
	})
	data, err := json.Marshal(headers)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func requestBodyPreview(c *app.RequestContext) (string, bool, int64) {
	body, truncated, size := requestBodySample(c)
	if len(body) > logBodyPreviewLimit {
		body = body[:logBodyPreviewLimit]
		truncated = true
	}
	if logredact.IsDynamicProtectionKeyPath(c, "") {
		return "[redacted]", truncated, size
	}
	if len(body) == 0 {
		return "", truncated, size
	}
	contentType := strings.ToLower(strings.TrimSpace(string(c.Request.Header.ContentType())))
	return logredact.SanitizeBodyPreview(string(body), contentType), truncated, size
}

func valueOrFallback(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func firstPositive(value, fallback int64) int64 {
	if value > 0 {
		return value
	}
	return fallback
}

func tlsFingerprintFromRequestContext(c *app.RequestContext) (tlsfp.TLSClientFingerprint, bool) {
	if value, ok := c.Get(tlsFingerprintContextKey); ok {
		if fp, ok := value.(tlsfp.TLSClientFingerprint); ok && fp.HasValue() {
			return fp, true
		}
	}
	if isInternalHTTP3Request(c) {
		return tlsfp.TLSClientFingerprint{}, false
	}
	if fp, ok := tlsfp.TLSFingerprintFromConn(c.GetConn()); ok {
		c.Set(tlsFingerprintContextKey, fp)
		return fp, true
	}
	return tlsfp.TLSClientFingerprint{}, false
}

func enqueueAccessLog(writer accessLogRecorder, al store.AccessLog) {
	writer.RecordAccessLog(al)
}

func recordAccessLog(c *app.RequestContext, opts Options, info accessLogInfo) {
	if c != nil {
		// 在采样/写入器判定之前先标记请求，避免终结器重复写入一条
		// 本就被采样丢弃的记录。
		c.Set(dataplaneAccessRecordedContextKey, true)
	}
	if opts.Writer == nil || !shouldRecordAccessLog(info, opts.AccessLogSamplingRate) {
		return
	}
	if !info.Minimal {
		info.Detailed = shouldRecordDetailedAccessLog(info)
	}
	enqueueAccessLog(opts.Writer, buildAccessLogEntry(c, info))
}

/**
 * finalizeUnrecordedAccessLog 为那些发生在常规站点/WAF 流程之前的提前退出
 * 写一条最小审计记录（静态资产、质询端点、快照缺失）。协议/路由层面的拒绝
 * 会显式标记自身；常规路径则通过 recordAccessLog 标记自身，因此本函数既不
 * 改变它们的采样，也不会产生重复记录。客户端主动取消的普通代理请求在
 * RST_STREAM 之后以状态码 0 记录，而不是伪造一行 200；显式的 4xx/5xx 提前
 * 失败仍保留其原状态码。
 */
func finalizeUnrecordedAccessLog(ctx context.Context, c *app.RequestContext, opts Options, fallbackRequestID string) {
	if c == nil || opts.Writer == nil {
		return
	}
	if value, ok := c.Get(dataplaneAccessRecordedContextKey); ok {
		if recorded, ok := value.(bool); ok && recorded {
			return
		}
	}
	requestID := strings.TrimSpace(string(c.Response.Header.Peek("X-Request-ID")))
	if requestID == "" {
		requestID = fallbackRequestID
	}
	statusCode := c.Response.StatusCode()
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	// 客户端在响应交付前断开时不伪造一个成功的 200；使用状态 0 保留
	// 协议层中断事实，同时继续携带请求指纹。明确的 4xx/5xx 保持原状态。
	if statusCode < http.StatusBadRequest && isClientGoneForPlainAccessLog(ctx, "none") {
		statusCode = 0
	}
	fingerprint, _ := tlsFingerprintFromRequestContext(c)
	siteID, clientIP := earlyAccessIdentity(c, opts)
	recordAccessLog(c, opts, accessLogInfo{
		SiteID:            siteID,
		RequestID:         requestID,
		ClientIP:          clientIPStr(clientIP),
		Host:              string(c.Host()),
		Path:              accessPath(c),
		QueryString:       string(c.URI().QueryString()),
		Method:            string(c.Method()),
		UserAgent:         string(c.UserAgent()),
		StatusCode:        statusCode,
		WAFAction:         "none",
		CacheState:        "bypass",
		TLSFingerprint:    fingerprint,
		ResponseSizeKnown: false,
		ForceRecord:       true,
		Minimal:           true,
	})
}

/**
 * recordEarlyAccessLog 为尚未解析站点或尚未进入 WAF 流程的请求写入最小审计行。
 *
 * @param c 请求上下文。
 * @param opts 数据面选项。
 * @param requestID 当前请求标识。
 * @param statusCode 已发送的响应状态。
 * @param wafAction 早退原因分类。
 */
func recordEarlyAccessLog(c *app.RequestContext, opts Options, requestID string, statusCode int, wafAction string) {
	if c == nil {
		return
	}
	fingerprint, _ := tlsFingerprintFromRequestContext(c)
	siteID, clientIP := earlyAccessIdentity(c, opts)
	recordAccessLog(c, opts, accessLogInfo{
		SiteID:            siteID,
		RequestID:         requestID,
		ClientIP:          clientIPStr(clientIP),
		Host:              string(c.Host()),
		Path:              accessPath(c),
		QueryString:       string(c.URI().QueryString()),
		Method:            string(c.Method()),
		UserAgent:         string(c.UserAgent()),
		StatusCode:        statusCode,
		WAFAction:         wafAction,
		CacheState:        "bypass",
		TLSFingerprint:    fingerprint,
		ResponseSizeKnown: false,
		ForceRecord:       true,
		Minimal:           true,
	})
}

/**
 * recordChallengeVerifyAccessLog 为挑战验证端点写入独立的内部审计动作。
 *
 * 验证端点在站点匹配前处理，不能进入常规 WAF 访问日志路径；统一在端点返回后
 * 记录当前响应状态、站点归属、可信客户端地址和 TLS 指纹，并阻止外层兜底再次写入
 * waf_action=none 的误导性行。
 *
 * @param c 当前请求上下文。
 * @param opts 数据面选项。
 */
func recordChallengeVerifyAccessLog(c *app.RequestContext, opts Options) {
	if c == nil {
		return
	}
	requestID := strings.TrimSpace(string(c.Response.Header.Peek("X-Request-ID")))
	if requestID == "" {
		requestID = dpreqid.FastRequestID()
		c.Response.Header.Set("X-Request-ID", requestID)
	}
	statusCode := c.Response.StatusCode()
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	actionName := "challenge_verify"
	if statusCode >= http.StatusBadRequest {
		actionName = "challenge_verify_error"
	}
	recordEarlyAccessLog(c, opts, requestID, statusCode, actionName)
}

/**
 * earlyAccessIdentity 为早期端点日志解析站点归属和可信客户端地址。
 *
 * @param c 请求上下文。
 * @param opts 数据面选项。
 * @return 站点 ID（未命中时为 0）和按站点代理配置解析的客户端地址。
 */
func earlyAccessIdentity(c *app.RequestContext, opts Options) (uint, net.IP) {
	if c == nil {
		return 0, nil
	}
	if opts.Holder == nil {
		return 0, security.ResolveClientIP(c, store.XFFModeStrip, "", nil)
	}
	host := string(c.Host())
	bind := listenerBind(c)
	if bind == "" {
		bind = opts.Bind
	}
	sn := opts.Holder.Load()
	if sn == nil {
		return 0, security.ResolveClientIP(c, store.XFFModeStrip, "", nil)
	}
	rt, ok := sn.MatchSite(bind, host)
	if !ok {
		return 0, security.ResolveClientIP(c, store.XFFModeStrip, "", nil)
	}
	return rt.Site.ID, security.ResolveClientIP(c, rt.XFFMode, rt.TrustedCIDR, rt.ClientIPHeaderOrder)
}

func shouldRecordDetailedAccessLog(info accessLogInfo) bool {
	return info.WAFAction != "none" || info.StatusCode >= 400
}

/**
 * isClientGoneForPlainAccessLog 判定这条「纯正常访问」是否因客户端提前断开而不应记录。
 *
 * ctx 来自 bindStreamCloseNotifyContext：它把连接/流的 CloseNotify 通道绑到派生
 * context 上，客户端发出 HTTP/2 RST_STREAM 或关闭连接时该 context 即被取消。上游取消
 * 也走同一个 context，所以此处判定与「上游响应被取消」是同一事实的两面。
 *
 * 仅对 wafAction=="none" 生效。observe 命中即使响应未送达也要留档，否则误报排查会
 * 丢失证据；其余动作（intercept/challenge/drop/redirect 等）在别处记录，不经过这里。
 *
 * @param ctx       请求派生 context，已绑定客户端断开信号。
 * @param wafAction 本次请求的 WAF 结论。
 * @return 应跳过记录时为 true。
 */
func isClientGoneForPlainAccessLog(ctx context.Context, wafAction string) bool {
	if wafAction != "none" {
		return false
	}
	return ctx != nil && ctx.Err() != nil
}

func shouldRecordAccessLog(info accessLogInfo, rate uint32) bool {
	if rate == 0 {
		// 取样关闭（禁用记录）时例外路径仍须留档：强记、WAF 动作或 4xx/5xx。
		return info.ForceRecord || info.WAFAction != "none" || info.StatusCode >= 400
	}
	if info.ForceRecord || info.WAFAction != "none" || info.StatusCode >= 400 || rate <= 1 {
		// rate<=1（默认全量）与例外三条件并列后恒为真，等价折叠为快速路径，
		// 不改变任何判定结果；rate>1 时才落入采样取模。
		return true
	}
	return accessLogSampleCounter.Add(1)%rate == 0
}

func siteErrorPage(rt *snapshot.SiteRuntime, statusCode int) *pages.ErrorPageConfig {
	if rt == nil || strings.TrimSpace(rt.Site.CustomErrorPages) == "" || rt.Site.CustomErrorPages == "{}" {
		return nil
	}
	epMap := make(map[string]pages.ErrorPageConfig)
	if err := json.Unmarshal([]byte(rt.Site.CustomErrorPages), &epMap); err != nil {
		return nil
	}
	cfg, ok := epMap[strconv.Itoa(statusCode)]
	if !ok {
		return nil
	}
	if cfg.StatusCode == 0 {
		cfg.StatusCode = statusCode
	}
	return &cfg
}

func accessPath(c *app.RequestContext) string {
	if rawPath := c.Request.URI().PathOriginal(); len(rawPath) > 0 {
		return string(rawPath)
	}
	return string(c.Path())
}

func accessStatusCode(c *app.RequestContext, wafAction string) int {
	if wafAction == "drop" {
		return 0
	}
	return c.Response.StatusCode()
}
