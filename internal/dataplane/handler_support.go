package dataplane

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/appresource"
	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/core/rules"
	"My-OpenWaf/internal/dataplane/logredact"
	dpmetrics "My-OpenWaf/internal/dataplane/metrics"
	"My-OpenWaf/internal/observability"
	"My-OpenWaf/internal/proxy"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/approute"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/upstream"
	"My-OpenWaf/internal/waf/bot/tlsfp"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/drop"
)

// Options 配置单个数据平面监听器的处理器。
type Options struct {
	Holder                *snapshot.Holder
	Engine                *engine.Engine
	Metrics               *dpmetrics.Metrics
	Writer                *observability.UnifiedWriter
	ResponseCache         *cache.ResponseCache
	Log                   *slog.Logger
	Bind                  string
	CaptchaManager        *challenge.CaptchaManager
	ShieldManager         *challenge.ShieldManager
	ChainManager          *challenge.ChainChallengeManager
	ACMEChallengeResponse func(token string) (string, bool)
	// ResourceAggregator 将 AppRoute 命中在内存中按资源唯一键聚合后批量落库，
	// 替代每命中一次 spawn goroutine + 同步 Upsert 的写放大。为 nil 时回退为不记录。
	ResourceAggregator    *recordedResourceAggregator
	Upstreams             *upstream.Pool
	AccessLogSamplingRate uint32
	// StreamCloseNotifyDisabled 置 true 时跳过每请求的 CloseNotify reflect 探测。
	// 仅当数据面 listener 未注册 HTTP/2 协议栈时启用：h1/h3 的 hertz conn 与
	// quic 流永不含 CloseNotify，探测只会完整空跑递归扫描。
	StreamCloseNotifyDisabled bool
	// AccessControlRepo 用于访问控制网关的用户密码校验与 OAuth 提供方配置读取。
	AccessControlRepo *repository.AccessControlRepo
	// JWTSecret 用于解密 OAuth client_secret（与 Admin 层加密保持一致）。
	JWTSecret []byte
}

const (
	bindContextKey                     = "dataplane_bind"
	tlsFingerprintContextKey           = "dataplane_tls_fingerprint"
	dataplaneAccessRecordedContextKey  = "dataplane_access_recorded"
	dataplaneAccessSiteIDContextKey    = "dataplane_access_site_id"
	dynamicProtectionKeyRequestBodyMax = 20 * 1024
)

type tlsFingerprintContextValueKey struct{}

func ContextWithTLSFingerprint(ctx context.Context, fp tlsfp.TLSClientFingerprint) context.Context {
	if !fp.HasValue() {
		return ctx
	}
	return context.WithValue(ctx, tlsFingerprintContextValueKey{}, fp)
}

func ContextWithTLSHandshakeInfo(ctx context.Context, version string, sni string, alpn string) context.Context {
	fp, _ := tlsFingerprintFromContext(ctx)
	if version != "" {
		fp.TLSVersion = version
	}
	if sni != "" {
		fp.SNI = sni
	}
	// 只写协商结果（ALPN）；ALPNRaw 是 ClientHello 声明列表，保持只读。
	fp.SetNegotiatedALPN(alpn)
	return ContextWithTLSFingerprint(ctx, fp)
}

func tlsFingerprintFromContext(ctx context.Context) (tlsfp.TLSClientFingerprint, bool) {
	fp, ok := ctx.Value(tlsFingerprintContextValueKey{}).(tlsfp.TLSClientFingerprint)
	return fp, ok && fp.HasValue()
}

func HandlerForBind(bind string, handler app.HandlerFunc) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		c.Set(bindContextKey, bind)
		handler(ctx, c)
	}
}

func listenerBind(c *app.RequestContext) string {
	if value, ok := c.Get(bindContextKey); ok {
		if bind, ok := value.(string); ok {
			return bind
		}
	}
	return ""
}

func scrubResponseHopByHopHeaders(c *app.RequestContext) {
	for _, key := range []string{"Connection", "Keep-Alive", "Proxy-Connection", "TE", "Transfer-Encoding", "Upgrade"} {
		c.Response.Header.Del(key)
	}
}

/**
 * applyLuaResponse 应用 Lua 已通过运行时校验的响应控制字段。
 * 仅普通 Lua 终止拦截响应调用；挑战、重定向、丢弃和上游响应不允许被 Lua 改写。
 */
func applyLuaResponse(c *app.RequestContext, result action.Result, statusCode int) bool {
	if c == nil || result.SetHeaders == nil && result.ResponseBody == nil {
		return false
	}
	if result.SetHeaders != nil {
		for key, value := range *result.SetHeaders {
			c.Response.Header.Set(key, value)
		}
	}
	if result.ResponseBody == nil {
		return false
	}
	c.SetStatusCode(statusCode)
	if len(c.Response.Header.ContentType()) == 0 {
		c.Response.Header.SetContentType("text/plain; charset=utf-8")
	}
	c.SetBodyString(*result.ResponseBody)
	return true
}

func isUnsafeRequestMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	default:
		return true
	}
}

func pickUpstream(urls []string, pool *upstream.Pool, next func(uint32) uint32) (string, bool) {
	return upstream.PickByProtocolPreference(urls, pool, next)
}

func tryRecordAppRouteResource(c *app.RequestContext, opts Options, rt *snapshot.SiteRuntime, sn *snapshot.Snapshot, reqCtx *pipeline.RequestCtx, clientIP net.IP, statusCode int, isLocalResponse bool, responseBody []byte, upstreamHeader http.Header) {
	if opts.ResourceAggregator == nil || len(rt.AppRouteRules) == 0 || hasExcludedHeader(c, sn.ExcludeRecordHeaders) {
		return
	}
	var reqBody []byte
	if reqCtx != nil {
		reqBody = reqCtx.Body
	}
	matchRespBody := responseBody
	if len(matchRespBody) == 0 && !c.Response.IsBodyStream() {
		matchRespBody = c.Response.Body()
	}
	recordRespBody := matchRespBody
	if isLocalResponse {
		matchRespBody = nil
		if statusCode == http.StatusForbidden {
			recordRespBody = append([]byte("访问被拒绝\n"), recordRespBody...)
		}
		upstreamHeader = nil
	}
	var matTLS appresource.TLSMetadata
	if fp, ok := tlsFingerprintFromRequestContext(c); ok {
		matTLS = appresource.TLSMetadata{
			TLSVersion: fp.TLSVersion,
			TLSSNI:     fp.SNI,
			TLSALPN:    strings.Join(fp.ALPN, ","),
			JA3Hash:    fp.JA3Hash,
			JA4:        fp.JA4,
		}
	}
	mat := appresource.BuildMaterialFromRequestBody(c, clientIP, matTLS, reqBody, recordRespBody, upstreamHeader, !isLocalResponse)
	if mat == nil {
		return
	}
	mat.StatusCode = statusCode
	var headerFn func(string) string
	if reqCtx != nil {
		headerFn = func(key string) string { return reqCtx.Headers[key] }
	} else {
		headerFn = appresource.RequestHeaderLookup(c)
	}
	ids := appresource.MatchedRuleIDs(rt.AppRouteRules, mat, headerFn)
	// 命中站点资源规则才记录：未命中的请求不代表任何被管理资源，记录会稀释数据。
	if len(ids) > 0 {
		recordMat := *mat
		recordMat.QueryString = logredact.SanitizeQueryString(string(c.URI().QueryString()))
		opts.ResourceAggregator.Record(rt.Site.ID, ids, &recordMat)
	}
}

func shouldRecordAppRouteResponseBody(rt *snapshot.SiteRuntime) bool {
	if rt == nil || len(rt.AppRouteRules) == 0 {
		return false
	}
	for _, rule := range rt.AppRouteRules {
		switch rule.Target {
		case approute.AppRouteTargetResponseBody, approute.AppRouteTargetFullHTTPResponse:
			return true
		}
	}
	return false
}

func bufferedResponseBody(resp *proxy.HTTPResponse) []byte {
	if resp == nil || len(resp.Body) == 0 {
		return nil
	}
	return resp.Body
}

/**
 * hasExcludedHeader 检查请求是否携带了 bot_settings.exclude_record_headers
 * 中配置的任一请求头。若携带，该请求不应被记录为应用路由资源。
 */
func hasExcludedHeader(c *app.RequestContext, excluded []string) bool {
	if len(excluded) == 0 {
		return false
	}
	for _, name := range excluded {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if len(c.GetHeader(name)) > 0 {
			return true
		}
	}
	return false
}

func hasConditionalOrRangeHeaders(c *app.RequestContext) bool {
	return len(c.GetHeader("Range")) > 0 ||
		len(c.GetHeader("If-None-Match")) > 0 ||
		len(c.GetHeader("If-Modified-Since")) > 0 ||
		len(c.GetHeader("If-Match")) > 0 ||
		len(c.GetHeader("If-Unmodified-Since")) > 0 ||
		len(c.GetHeader("If-Range")) > 0
}

/**
 * wafReqCtxHeaderOrderCacheKey 主路径把「populate 记录序一次 Join」的结果
 * 寄存在请求上下文，后续 WAF/访问记录复用，避免每行日志重复 VisitAll。
 */
const wafReqCtxHeaderOrderCacheKey = "owaf.dataplane.header_order_cache"

/**
 * requestHeaderOrder 返回原字面顺序的请求头键列表。
 *
 * 与 populateRequestCtxHeaders 的同一次顺序记录对齐：该列表与内部顺序头槽的
 * 差异仅无关头聚合（Cookie 折叠、Connection 合成行），对 HeaderOrder 语义
 * 无影响。性能上把每请求 1 次遍历的次数控制为 1（有 reqCtx 时）或 0，
 * 未进入 WAF 流程的记录路径仍按原有方式枚举。
 */
func requestHeaderOrder(c *app.RequestContext) []string {
	keys := make([]string, 0, 16)
	c.Request.Header.VisitAll(func(k, _ []byte) {
		keys = append(keys, string(k))
	})
	return keys
}

func headerOrderFromContext(c *app.RequestContext) (string, bool) {
	if c == nil {
		return "", false
	}
	v, ok := c.Get(wafReqCtxHeaderOrderCacheKey)
	if !ok {
		return "", false
	}
	sp, _ := v.(*string)
	if sp == nil {
		return "", false
	}
	return *sp, true
}

func isInternalHTTP3Request(c *app.RequestContext) bool {
	if value, ok := c.Get(internalHTTP3ContextKey); ok {
		if b, ok := value.(bool); ok && b {
			return true
		}
	}
	return false
}

func requestProtocol(c *app.RequestContext) string {
	if isInternalHTTP3Request(c) {
		return "h3"
	}
	if proto := normalizeHTTPProtocol(c.Request.Header.GetProtocol()); proto != "" {
		return proto
	}
	if fp, ok := tlsFingerprintFromRequestContext(c); ok {
		if negotiated := fp.NegotiatedALPN(); negotiated != "" {
			return strings.ToLower(negotiated)
		}
		return "https"
	}
	return "http"
}

func normalizeHTTPProtocol(proto string) string {
	switch strings.ToUpper(proto) {
	case "HTTP/2.0", "HTTP/2":
		return "h2"
	case "HTTP/1.1":
		return "http/1.1"
	case "HTTP/1.0":
		return "http/1.0"
	case "H2":
		return "h2"
	case "H2C":
		return "h2c"
	case "H3":
		return "h3"
	default:
		return ""
	}
}

func recordDropEvent(opts Options, siteID uint, clientIP net.IP, reason drop.DropReason) {
	if opts.Writer == nil {
		return
	}
	opts.Writer.RecordDropEvent(store.DropEvent{
		SiteID:    siteID,
		ClientIP:  clientIPStr(clientIP),
		Source:    reason.Source,
		RuleID:    reason.RuleID,
		Detail:    reason.Detail,
		Host:      reason.Host,
		Path:      reason.Path,
		CreatedAt: reason.Timestamp,
	})
}

func dropEnabled(eng *engine.Engine) bool {
	dropExec := eng.DropExecutor()
	return dropExec != nil && dropExec.Enabled()
}

func rateLimitKey(bind string, siteID uint, clientIP net.IP, host string) string {
	return rules.RateLimitKey(bind, siteID, host, clientIP)
}

/**
 * errorRateLimitWhitelisted 判断该客户端是否应在错误限流上豁免。
 *
 * @param eng              引擎，可为 nil（此时只看站点白名单）。
 * @param siteIPWhitelisted 调用方预先计算的站点白名单结果。
 * @param clientIP         客户端 IP，可为 nil。
 * @return 应豁免（回落管道）时返回 true。
 */
func errorRateLimitWhitelisted(eng *engine.Engine, siteIPWhitelisted bool, clientIP net.IP) bool {
	if siteIPWhitelisted {
		return true
	}
	if eng == nil || clientIP == nil {
		return false
	}
	rep := eng.IPReputation()
	return rep != nil && rep.IsWhitelisted(clientIP)
}

func shouldApplyErrorRateLimit(eng *engine.Engine, prot store.ProtectionConfig, key string) bool {
	if eng == nil || !errorRateLimitConfigEnabled(prot) {
		return false
	}
	errRL := eng.ErrRateLimiter()
	return errRL != nil && errRL.Enabled() && errRL.IsOverLimit(key)
}

/**
 * errorRateLimitConfigEnabled 判断当前快照是否提供了可执行的错误限流配置。
 *
 * 运行时 backend 可能在热重载期间暂时保留上一代状态，因此不能只依据
 * backend.Enabled()；快照开关、窗口和配额必须同时有效，才能产生或累加 429。
 */
func errorRateLimitConfigEnabled(prot store.ProtectionConfig) bool {
	return prot.ErrorRateLimitEnabled && prot.ErrorRateLimitWindow > 0 && prot.ErrorRateLimitMax > 0
}

/**
 * errorRateLimitAction 把站点配置的错误限流动作编译成运行时判定结果。
 *
 * 配置可能来自直改数据库或历史版本，因此归一化后仍可能是未注册动作名；
 * 这类值既不终止管道也不写安全日志，会让错误限流静默失效，故兜底为
 * intercept——与 rules.normalizeConfiguredAction 的兜底语义保持一致。
 * 空配置表示“未指定”，仍按默认的 rate_limit 处理。
 *
 * @param configured 配置中的动作名，可为空串或遗留别名。
 * @return 带 error_rate_limit 标识的判定结果；仅 rate_limit 附带 429 状态码。
 */
func errorRateLimitAction(configured string) action.Result {
	act := action.Normalize(action.Type(configured))
	if act == "" {
		act = action.RateLimit
	} else if !action.IsValid(act) {
		act = action.Intercept
	}
	res := action.Result{
		Type:      act,
		Phase:     "error_rate_limit",
		RuleIDStr: "error_rate_limit",
		MatchDesc: "error rate limit exceeded",
		Matched:   true,
		Category:  "rate_limit",
	}
	if act == action.RateLimit {
		res.StatusCode = 429
	}
	return res
}

func incrementErrorRateLimitBlock(eng *engine.Engine, prot store.ProtectionConfig, key string) {
	if !prot.ErrorRateLimitCountBlock || !errorRateLimitConfigEnabled(prot) {
		return
	}
	incrementErrorRateLimit(eng, prot, key)
}

func incrementErrorRateLimitStatus(eng *engine.Engine, prot store.ProtectionConfig, key string, statusCode int) {
	if !errorRateLimitConfigEnabled(prot) {
		return
	}
	switch {
	case prot.ErrorRateLimitCount4xx && statusCode >= 400 && statusCode < 500:
		incrementErrorRateLimit(eng, prot, key)
	case prot.ErrorRateLimitCount5xx && statusCode >= 500:
		incrementErrorRateLimit(eng, prot, key)
	}
}

func incrementErrorRateLimit(eng *engine.Engine, prot store.ProtectionConfig, key string) {
	if eng == nil || !errorRateLimitConfigEnabled(prot) {
		return
	}
	errRL := eng.ErrRateLimiter()
	if errRL != nil && errRL.Enabled() {
		errRL.Increment(key)
	}
}

func clientIPStr(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func hasUpstreamServerHeader(c *app.RequestContext) bool {
	sv := string(c.Response.Header.Peek("Server"))
	return sv != "" && sv != "hertz"
}

func isTimeoutError(err error) bool {
	if err == context.DeadlineExceeded {
		return true
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline") {
		return true
	}
	return false
}

// requestProtoFromContext 从连接协商结果（TLS 状态或已认证的 HTTP/3 元数据）提取请求
// scheme。客户端自带的转发头不得参与：该结果会拼进 OAuth redirect_uri 等绝对 URL。
func requestProtoFromContext(c *app.RequestContext) string {
	return TrustedInboundForwardedProto(c)
}
