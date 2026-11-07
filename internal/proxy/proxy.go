package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/network"
	http2 "github.com/x01n/http2"

	"My-OpenWaf/internal/cache"
	proxytransport "My-OpenWaf/internal/proxy/transport"
	"My-OpenWaf/internal/security"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/dynamic"
)

// HTTPResponse 是缓存路径使用的已缓冲上游响应。
type HTTPResponse struct {
	StatusCode           int
	ContentType          string
	Body                 []byte
	Header               http.Header
	UpstreamHTTPProtocol string

	remainingBody    io.Reader
	closeBody        func() error
	upstreamResponse *http.Response
	decodedBody      bool
}

func (r *HTTPResponse) HasRemainingBody() bool {
	return r != nil && r.remainingBody != nil
}

type identityResponseEntity struct {
	Path           string
	ContentType    string
	Body           []byte
	Request        *app.RequestContext
	ClientIP       net.IP
	DynamicVariant bool
	ImageVariant   bool
	VaryAccept     bool
	ScriptNonces   []string
}

type identityResponseTransformer interface {
	Transform(identityResponseEntity) (identityResponseEntity, error)
}

type identityResponseTransformerFunc func(identityResponseEntity) (identityResponseEntity, error)

func (fn identityResponseTransformerFunc) Transform(entity identityResponseEntity) (identityResponseEntity, error) {
	return fn(entity)
}

// responseEntityTransformerForSiteAndClient 在动态保护之外并入 response
// 阶段 JS 插件与 Lua post 脚本的响应改写；jsPluginResponseTransformerFor
// 内部直接从 hertz 请求上下文读取执行器与脚本，因此即便 rt 无任何动态能力
// 也能仅返回 JS 变换器。
//
// HTML → Markdown 协商命中时短路整条链：Markdown 是客户端显式请求的表示
// 形式，优先级高于服务端可选的混淆策略，且其输出不携带脚本、不是 HTML，
// 后续各阶段对它都无的放矢。
func responseEntityTransformerForSiteAndClient(rt snapshot.SiteRuntime, c *app.RequestContext, clientIP net.IP) identityResponseTransformer {
	return responseEntityTransformerForSiteAndClientWithContext(context.Background(), rt, c, clientIP)
}

/**
 * responseEntityTransformerForSiteAndClientWithContext 与前者相同，但显式接收
 * 请求上下文，供图像转换的墙钟预算继承调用方的取消信号。
 *
 * @param ctx 请求上下文；图像转换的超时从它派生。
 * @param rt 站点运行时。
 * @param c Hertz 请求上下文。
 * @param clientIP 客户端 IP。
 * @return 组合后的变换器。
 */
func responseEntityTransformerForSiteAndClientWithContext(ctx context.Context, rt snapshot.SiteRuntime, c *app.RequestContext, clientIP net.IP) identityResponseTransformer {
	if ctx == nil {
		ctx = context.Background()
	}
	// HTML → Markdown 协商优先于一切响应改写：客户端显式要 Markdown 时，
	// 动态混淆产出的是密文、脚本改写面向的是 HTML 形态，两者都无意义。
	// 该分支短路整条链，命中即返回。
	if mdT := htmlToMarkdownTransformerFor(c, rt); mdT != nil {
		return mdT
	}
	jsT := jsPluginResponseTransformerFor(c, rt)
	luaRewrite := luaResponseRewriteTransformer(c, rt.Site.ID)
	if t := responseEntityTransformerForSiteWithClient(rt, clientIP, ctx); t != nil {
		return identityResponseTransformerFunc(func(entity identityResponseEntity) (identityResponseEntity, error) {
			entity, err := t.Transform(entity)
			if err != nil {
				return entity, err
			}
			return applyLuaResponseRewriteStage(c, rt.Site.ID, luaRewrite, jsT, entity)
		})
	}
	if jsT == nil && luaRewrite == nil {
		return nil
	}
	return identityResponseTransformerFunc(func(entity identityResponseEntity) (identityResponseEntity, error) {
		return applyLuaResponseRewriteStage(c, rt.Site.ID, luaRewrite, jsT, entity)
	})
}

// luaResponseRewriteTransformer 报告该请求是否存在 Lua post 响应改写。
func luaResponseRewriteTransformer(c *app.RequestContext, siteID uint) identityResponseTransformer {
	if luaResponseRewriteLookup == nil {
		return nil
	}
	if len(luaResponseRewriteLookup(c, siteID)) == 0 {
		return nil
	}
	return identityResponseTransformerFunc(func(entity identityResponseEntity) (identityResponseEntity, error) {
		return transformLuaResponseRewrites(c, siteID, entity), nil
	})
}

// applyLuaResponseRewriteStage 组合 JS 变换与 Lua 改写。
//
// 顺序固定为 JS → Lua：Lua post 是策略链的最后一道，让它在自己算出的改写里
// 看到 JS 脚本改写后的最终响应形态。两者都可能为 nil，任一存在都要生效。
func applyLuaResponseRewriteStage(
	c *app.RequestContext,
	siteID uint,
	luaRewrite identityResponseTransformer,
	jsT identityResponseTransformer,
	entity identityResponseEntity,
) (identityResponseEntity, error) {
	if jsT != nil {
		next, err := jsT.Transform(entity)
		if err != nil {
			return next, err
		}
		entity = next
	}
	if luaRewrite != nil {
		next, err := luaRewrite.Transform(entity)
		if err != nil {
			return next, err
		}
		entity = next
	}
	return entity, nil
}

func responseEntityTransformerForSiteWithClient(rt snapshot.SiteRuntime, clientIP net.IP, ctx context.Context) identityResponseTransformer {
	dynCfg := rt.DynamicProtection
	browserSignEnabled := false
	browserSignTTL := 300
	if rt.EffectiveProtection != nil {
		browserSignEnabled = rt.EffectiveProtection.BrowserSignEnabled
		if rt.EffectiveProtection.BrowserSignTTL > 0 {
			browserSignTTL = rt.EffectiveProtection.BrowserSignTTL
		}
	}
	dynEnabled := dynCfg.HTMLObfuscationEnabled || dynCfg.JSObfuscationEnabled || dynCfg.ImageWatermarkEnabled
	imageEnabled := rt.ImageTransform.Enabled
	if !dynEnabled && !browserSignEnabled && !imageEnabled {
		return nil
	}

	siteID := rt.Site.ID
	bind := rt.Bind
	return identityResponseTransformerFunc(func(entity identityResponseEntity) (identityResponseEntity, error) {
		body := entity.Body
		// 图像转换必须排在动态防护之前：水印与格式转换都需要上游原图，
		// 一旦先被 dynamic 处理过就不再是原图。
		if imageEnabled {
			entity = applyImageTransform(ctx, entity, rt, entity.Request)
			body = entity.Body
		}
		if browserSignEnabled && isHTMLContentType(entity.ContentType) {
			ticket := challenge.IssueBrowserSignTicket(siteID, browserSignTTL)
			body = challenge.InjectBrowserSignIntoHTML(body, ticket)
			if ticket.CSPNonce != "" {
				entity.ScriptNonces = append(entity.ScriptNonces, ticket.CSPNonce)
			}
		}
		if dynEnabled {
			kind := dynamic.ShouldProcessContentType(entity.ContentType)
			if kind == "html" || kind == "js" {
				claims := dynamicProtectionClaimsFromEntity(entity, siteID, bind)
				if claims.ClientIP == nil {
					claims.ClientIP = clientIP
				}
				if entity.Request != nil && challenge.VerifyDynamicProtectionSessionCookieWithClaims(string(entity.Request.Request.Header.Peek("Cookie")), claims, time.Now()) {
					entity.Body = body
					entity.DynamicVariant = true
					return entity, nil
				}
				proc := dynamic.NewProcessorWithKeyTicketSigner(dynCfg, func(key string, ttl int, kekB64 string) string {
					return challenge.SignDynamicProtectionKeyTicket(challenge.DynamicProtectionKeyClaims{DynamicProtectionClaims: claims, Key: key}, time.Now(), time.Duration(ttl)*time.Second, kekB64)
				})
				var transformed []byte
				var scriptNonce string
				var err error
				if kind == "html" {
					transformed, scriptNonce, err = proc.ProcessHTMLWithScriptNonce(body)
				} else {
					transformed, err = proc.Process(entity.Path, entity.ContentType, body)
				}
				if err != nil {
					return entity, err
				}
				if scriptNonce != "" {
					entity.ScriptNonces = append(entity.ScriptNonces, scriptNonce)
				}
				body = transformed
			} else {
				proc := dynamic.NewProcessor(dynCfg)
				transformed, err := proc.Process(entity.Path, entity.ContentType, body)
				if err != nil {
					return entity, err
				}
				body = transformed
			}
		}
		entity.Body = body
		return entity, nil
	})
}

func dynamicProtectionClaimsFromEntity(entity identityResponseEntity, siteID uint, bind string) challenge.DynamicProtectionClaims {
	claims := challenge.DynamicProtectionClaims{ClientIP: entity.ClientIP, SiteID: siteID, Bind: bind}
	if entity.Request != nil {
		claims.Host = string(entity.Request.Host())
		claims.UserAgent = string(entity.Request.UserAgent())
	}
	return claims
}

func markDynamicResponseVariant(c *app.RequestContext) {
	if c == nil {
		return
	}
	c.Response.Header.Set("Cache-Control", "no-store")
	vary := string(c.Response.Header.Peek("Vary"))
	for _, item := range strings.Split(vary, ",") {
		if strings.EqualFold(strings.TrimSpace(item), "Cookie") {
			return
		}
	}
	if vary == "" {
		c.Response.Header.Set("Vary", "Cookie")
		return
	}
	c.Response.Header.Set("Vary", vary+", Cookie")
}

func isHTMLContentType(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct == "text/html" || ct == "application/xhtml+xml"
}

func shouldTransformIdentityResponse(c *app.RequestContext, statusCode int) bool {
	if c == nil || statusCode != http.StatusOK {
		return false
	}
	if requestCacheControlHasNoTransform(c.Request.Header.PeekAll("Cache-Control")) {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(string(c.Request.Method())), http.MethodHead) {
		return false
	}
	if len(c.Request.Header.Peek("Range")) > 0 || len(c.Request.Header.Peek("If-Range")) > 0 {
		return false
	}
	if len(trimASCIIHeaderSpaceBytes(c.Response.Header.Peek("Content-Range"))) > 0 {
		return false
	}
	if cacheControlHasNoTransformBytes(c.Response.Header.Peek("Cache-Control")) {
		return false
	}
	if _, supported := parseContentEncodingsBytes(c.Response.Header.ContentEncoding()); !supported {
		return false
	}
	contentType := strings.ToLower(strings.TrimSpace(string(c.Response.Header.ContentType())))
	return !strings.HasPrefix(contentType, "text/event-stream")
}

func transformIdentityResponseBody(c *app.RequestContext, statusCode int, body []byte, transformer identityResponseTransformer, clientIP net.IP) ([]byte, bool, error) {
	if transformer == nil || !shouldTransformIdentityResponse(c, statusCode) {
		return body, false, nil
	}
	entity, err := transformer.Transform(identityResponseEntity{
		Path:        requestPath(c),
		ContentType: string(c.Response.Header.ContentType()),
		Body:        body,
		Request:     c,
		ClientIP:    clientIP,
	})
	if err != nil {
		return nil, false, err
	}
	if entity.Body == nil {
		entity.Body = []byte{}
	}
	if bytes.Equal(entity.Body, body) && (entity.ContentType == "" || entity.ContentType == string(c.Response.Header.ContentType())) {
		if entity.DynamicVariant {
			// 动态变体标记只对 HTML 表示成立，Markdown 路径自带 Vary: Accept。
			applyResponseVariantHeaders(c, entity)
		}
		return body, false, nil
	}
	if entity.ContentType != "" {
		c.Response.Header.SetContentType(entity.ContentType)
	}
	invalidateTransformedEntityHeaders(c)
	applyResponseVariantHeaders(c, entity)
	applyDynamicProtectionCSPNonce(c, entity.ScriptNonces)
	return entity.Body, true, nil
}

func invalidateTransformedEntityHeaders(c *app.RequestContext) {
	if c == nil {
		return
	}
	for _, header := range []string{
		"Content-Encoding",
		"Content-Length",
		"ETag",
		"Digest",
		"Content-Digest",
		"Content-MD5",
		"Accept-Ranges",
	} {
		c.Response.Header.Del(header)
	}
}

func applyDynamicProtectionCSPNonce(c *app.RequestContext, nonces []string) {
	if c == nil || len(nonces) == 0 {
		return
	}
	rawPolicies := c.Response.Header.PeekAll("Content-Security-Policy")
	if len(rawPolicies) == 0 {
		return
	}
	policies := make([]string, len(rawPolicies))
	for i, policy := range rawPolicies {
		policies[i] = string(policy)
		for _, nonce := range nonces {
			if nonce != "" {
				policies[i] = cspWithScriptNonce(policies[i], nonce)
			}
		}
	}
	c.Response.Header.Del("Content-Security-Policy")
	for _, policy := range policies {
		c.Response.Header.Add("Content-Security-Policy", policy)
	}
}

func cspWithScriptNonce(policy, nonce string) string {
	nonceToken := "'nonce-" + nonce + "'"
	directives := strings.Split(policy, ";")
	defaultSrc := ""
	scriptSrcFound := false
	scriptSrcElemFound := false
	for i, directive := range directives {
		trimmed := strings.TrimSpace(directive)
		if trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "default-src":
			defaultSrc = strings.Join(fields[1:], " ")
		case "script-src":
			scriptSrcFound = true
			directives[i] = cspDirectiveWithToken(trimmed, nonceToken)
		case "script-src-elem":
			scriptSrcElemFound = true
			directives[i] = cspDirectiveWithToken(trimmed, nonceToken)
		}
	}
	if !scriptSrcFound && !scriptSrcElemFound {
		base := "script-src"
		if defaultSrc != "" {
			base += " " + defaultSrc
		}
		directives = append(directives, cspDirectiveWithToken(base, nonceToken))
	}
	return strings.Join(directives, ";")
}

func cspDirectiveWithToken(directive, token string) string {
	fields := strings.Fields(directive)
	for _, field := range fields[1:] {
		if field == token {
			return directive
		}
	}
	return directive + " " + token
}

func writeResponseTransformFailure(c *app.RequestContext) {
	c.Response.Reset()
	c.Response.Header.Set("Cache-Control", "no-store")
	c.Response.Header.SetContentType("text/plain; charset=utf-8")
	c.Response.SetStatusCode(http.StatusBadGateway)
	c.Response.SetBodyString("response transformation failed")
}

var upstreamErrorLogCounter atomic.Uint64

// shouldLogUpstreamErrorCount 保留最初的错误证据，对重复失败改为抽样记录。
func shouldLogUpstreamErrorCount(count uint64) bool {
	return count <= 16 || count%1024 == 0
}

func upstreamErrorReason(err error) string {
	if err == nil {
		return ""
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err.Error()
	}
	return err.Error()
}

func upstreamLogPath(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	const limit = 160
	if len(path) <= limit {
		return path
	}
	return path[:limit] + "..."
}

func logUpstreamRequestError(ctx context.Context, mode string, req *http.Request, origHost string, err error) {
	logger := slog.Default()
	if !logger.Enabled(ctx, slog.LevelWarn) {
		return
	}
	count := upstreamErrorLogCounter.Add(1)
	if !shouldLogUpstreamErrorCount(count) {
		return
	}

	method := ""
	scheme := ""
	upstreamHost := ""
	queryLen := 0
	if req != nil {
		method = req.Method
		if req.URL != nil {
			scheme = req.URL.Scheme
			upstreamHost = req.URL.Host
			queryLen = len(req.URL.RawQuery)
		}
	}
	logger.LogAttrs(ctx, slog.LevelWarn, "upstream "+mode+" request failed",
		slog.String("method", method),
		slog.String("scheme", scheme),
		slog.String("upstream_host", upstreamHost),
		slog.String("path", upstreamLogPath(req)),
		slog.Int("query_len", queryLen),
		slog.String("host", origHost),
		slog.String("upstream_protocol", upstreamProtocolFromScheme(scheme)),
		slog.Uint64("failure_count", count),
		slog.String("err", upstreamErrorReason(err)),
	)
}

func upstreamProtocolFromScheme(scheme string) string {
	switch strings.ToLower(scheme) {
	case "https":
		return "h3"
	case "h2c":
		return "h2c"
	case "h3":
		return "h3"
	default:
		return scheme
	}
}

func requestPath(c *app.RequestContext) string {
	if rawPath := c.Request.URI().PathOriginal(); len(rawPath) > 0 {
		return string(rawPath)
	}
	path := string(c.Path())
	if path == "" {
		return "/"
	}
	return path
}

func upstreamRequestURL(c *app.RequestContext, base string) string {
	path := c.Request.URI().PathOriginal()
	if len(path) == 0 {
		path = c.Path()
	}
	pathLen := len(path)
	if pathLen == 0 {
		pathLen = 1
	}
	if sanitized := sanitizeRawPercentEscapes(path); sanitized != nil {
		path = sanitized
		pathLen = len(sanitized)
	}
	q := c.URI().QueryString()
	baseLen := len(base)
	for baseLen > 0 && base[baseLen-1] == '/' {
		baseLen--
	}

	// 用 append 直接拼装，避免 strings.Builder.Grow 的临时缓冲复制：
	// base/path/query 三段的长度精确已知，一次分配即可，不受 Grow 的
	// 2*cap+n 预留策略影响。
	total := baseLen + pathLen + querySuffixLen(q)
	p := make([]byte, 0, total)
	p = append(p, base[:baseLen]...)
	if len(path) > 0 {
		p = append(p, path...)
	} else {
		p = append(p, '/')
	}
	if len(q) > 0 {
		p = append(p, '?')
		p = append(p, q...)
	}
	return string(p)
}

func querySuffixLen(q []byte) int {
	if len(q) == 0 {
		return 0
	}
	return 1 + len(q)
}

func requestMethod(c *app.RequestContext) string {
	method := c.Method()
	switch len(method) {
	case len("GET"):
		if bytes.Equal(method, []byte("GET")) {
			return "GET"
		}
		if bytes.Equal(method, []byte("PUT")) {
			return "PUT"
		}
	case len("POST"):
		if bytes.Equal(method, []byte("POST")) {
			return "POST"
		}
		if bytes.Equal(method, []byte("HEAD")) {
			return "HEAD"
		}
	case len("PATCH"):
		if bytes.Equal(method, []byte("PATCH")) {
			return "PATCH"
		}
		if bytes.Equal(method, []byte("TRACE")) {
			return "TRACE"
		}
	case len("DELETE"):
		if bytes.Equal(method, []byte("DELETE")) {
			return "DELETE"
		}
	case len("OPTIONS"):
		if bytes.Equal(method, []byte("OPTIONS")) {
			return "OPTIONS"
		}
		if bytes.Equal(method, []byte("CONNECT")) {
			return "CONNECT"
		}
	}
	return string(method)
}

func inboundProto(c *app.RequestContext) string {
	if v := forwardedProtoFromHeader(c.GetHeader("X-Forwarded-Proto")); v != "" {
		return v
	}
	if bytes.EqualFold(c.Request.Header.Peek("Upgrade"), []byte("websocket")) {
		if bytes.HasPrefix(bytes.ToLower(c.Request.Header.Peek("Origin")), []byte("https://")) {
			return "https"
		}
		return "http"
	}
	if string(c.Request.Scheme()) == "https" {
		return "https"
	}
	return "http"
}

func buildUpstreamRequest(ctx context.Context, c *app.RequestContext, base string, clientIP net.IP, origHost string, preserveOriginalHost bool) (*http.Request, error) {
	full := upstreamRequestURL(c, base)

	isStream := c.Request.IsBodyStream()
	hertzContentLength := c.Request.Header.ContentLength()
	var rdr io.Reader
	var bodyBytes []byte
	var bodyLen int64

	if isStream {
		stream := c.Request.BodyStream()
		if stream != nil {
			rdr = stream
			bodyLen = int64(c.Request.Header.ContentLength())
			if bodyLen < 0 {
				bodyLen = -1
			}
		}
	} else {
		bodyBytes = c.Request.Body()
		if len(bodyBytes) > 0 {
			rdr = &proxytransport.ByteSliceReadCloser{Data: bodyBytes}
			bodyLen = int64(len(bodyBytes))
		}
	}

	req, err := http.NewRequestWithContext(ctx, requestMethod(c), full, rdr)
	if err != nil {
		return nil, err
	}
	if rdr != nil {
		req.ContentLength = bodyLen
		if !isStream && len(bodyBytes) > 0 && hertzContentLength >= 0 {
			req.GetBody = func() (io.ReadCloser, error) {
				return &proxytransport.ByteSliceReadCloser{Data: bodyBytes}, nil
			}
		}
	}

	connStripper := NewRequestConnectionHeaderStripper(c)
	var rawTE string
	c.Request.Header.VisitAll(func(k, v []byte) {
		if isHopByHopBytes(k) {
			if asciiEqualFoldBytes(k, "te") {
				rawTE = string(v)
			}
			return
		}
		if asciiEqualFoldBytes(k, "host") {
			return
		}
		if connStripper.ShouldStrip(k) {
			return
		}
		addUpstreamHeader(req.Header, k, v)
	})

	if te := forwardableTEValue(rawTE); te != "" {
		req.Header.Set("TE", te)
	}

	ce := req.Header.Get("Content-Encoding")
	// 数据面在采样阶段已判定这段请求体解不动（压缩炸弹触发上限、或解码器都
	// 建不起来）时按降级语义处理：不解压、保留原 Content-Encoding，原始压缩
	// 字节直接转发给上游。用户裁定「超窗降级而不是拒绝」，且重复解压一遍正是
	// 压缩炸弹想要的 CPU/内存开销，因此这里不再尝试解码。
	if ce != "" && rdr != nil && !SkippedRequestBodyDecode(c) {
		if isStream && BufferedCompressedBody(c) {
			buffered, readErr := io.ReadAll(req.Body)
			if readErr != nil {
				ObserveUpstreamRequestBodyDecodeFailure(c, ce, readErr)
				req.Body = io.NopCloser(bytes.NewReader(buffered))
				req.ContentLength = int64(len(buffered))
				req.GetBody = nil
			} else if decoded, didDecode, decErr := decodeUpstreamRequestBody(buffered, ce); decErr != nil {
				ObserveUpstreamRequestBodyDecodeFailure(c, ce, decErr)
				req.Body = io.NopCloser(bytes.NewReader(buffered))
				req.ContentLength = int64(len(buffered))
				req.GetBody = nil
			} else if didDecode {
				req.Header.Del("Content-Encoding")
				req.Header.Del("Content-Length")
				req.Body = io.NopCloser(bytes.NewReader(decoded))
				req.ContentLength = int64(len(decoded))
				req.GetBody = nil
			} else {
				// 未识别出编码：按原始字节回放，语义与不解压一致。
				req.Body = io.NopCloser(bytes.NewReader(buffered))
				req.ContentLength = int64(len(buffered))
				req.GetBody = nil
			}
		} else if isStream {
			decoded, didDecode, decErr := decodeUpstreamRequestBodyStreamBytesWithTrip(req.Body, []byte(ce), func() {
				ObserveUpstreamRequestBodyDecodeFailure(c, ce, errDecompressionLimitExceeded)
			})
			if decErr != nil {
				// 畸形压缩体：记录事件后按原始字节放行（不解压、保留原
				// Content-Encoding），不再返回 502。解压产物由
				// decompressionGuard 在读到超限时中断，超限同样走这条降级。
				ObserveUpstreamRequestBodyDecodeFailure(c, ce, decErr)
			} else if didDecode {
				req.Header.Del("Content-Encoding")
				req.Header.Del("Content-Length")
				req.Body = decoded
				req.ContentLength = -1
				req.GetBody = nil
			}
		} else if len(bodyBytes) > 0 {
			decoded, didDecode, decErr := decodeUpstreamRequestBody(bodyBytes, ce)
			if decErr != nil {
				ObserveUpstreamRequestBodyDecodeFailure(c, ce, decErr)
			} else if didDecode {
				req.Header.Del("Content-Encoding")
				req.Header.Del("Content-Length")
				req.Body = io.NopCloser(bytes.NewReader(decoded))
				req.ContentLength = int64(len(decoded))
				req.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(decoded)), nil
				}
			}
		}
	}

	if trailer := hertzRequestTrailer(c); trailer != nil {
		req.Trailer = trailer
		if req.ContentLength >= 0 {
			req.ContentLength = -1
			req.GetBody = nil
		}
		if req.Body != nil {
			req.Body = io.NopCloser(&trailerSyncBody{
				inner:   req.Body,
				hertz:   c,
				trailer: trailer,
			})
		}
	}

	security.ApplyOutboundForwarding(req, clientIP, origHost, preserveOriginalHost, "", security.TrustedInboundForwardedProto(c))
	sanitizeUpstreamHeaders(req.Header)
	return req, nil
}

func forwardableTEValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	for _, token := range strings.Split(raw, ",") {
		part := strings.TrimSpace(token)
		if part == "" {
			continue
		}
		name := part
		if semi := strings.IndexByte(part, ';'); semi >= 0 {
			name = strings.TrimSpace(part[:semi])
		}
		if strings.EqualFold(name, "trailers") {
			return "trailers"
		}
	}
	return ""
}

func hertzRequestTrailer(c *app.RequestContext) http.Header {
	ht := c.Request.Header.Trailer()
	if ht == nil {
		return nil
	}
	trailer := make(http.Header)
	ht.VisitAll(func(k, v []byte) {
		key := http.CanonicalHeaderKey(string(k))
		trailer[key] = append(trailer[key], string(v))
	})
	if len(trailer) == 0 {
		return nil
	}
	return trailer
}

type trailerSyncBody struct {
	inner   io.Reader
	hertz   *app.RequestContext
	trailer http.Header
	synced  bool
}

func (b *trailerSyncBody) Read(p []byte) (int, error) {
	n, err := b.inner.Read(p)
	if err == io.EOF && !b.synced {
		b.synced = true
		syncHertzTrailerToHTTP(b.hertz, b.trailer)
	}
	return n, err
}

func syncHertzTrailerToHTTP(c *app.RequestContext, dst http.Header) {
	ht := c.Request.Header.Trailer()
	if ht == nil {
		return
	}
	ht.VisitAll(func(k, v []byte) {
		key := http.CanonicalHeaderKey(string(k))
		dst[key] = []string{string(v)}
	})
}

func addUpstreamHeader(header http.Header, key, value []byte) {
	switch len(key) {
	case len("Accept"):
		if bytes.Equal(key, []byte("Accept")) {
			header.Add("Accept", string(value))
			return
		}
		if bytes.Equal(key, []byte("Origin")) {
			header.Add("Origin", string(value))
			return
		}
		if bytes.Equal(key, []byte("Pragma")) {
			header.Add("Pragma", string(value))
			return
		}
		if bytes.Equal(key, []byte("Cookie")) {
			header.Add("Cookie", string(value))
			return
		}
	case len("Referer"):
		if bytes.Equal(key, []byte("Referer")) {
			header.Add("Referer", string(value))
			return
		}
	case len("Sec-Ch-Ua"):
		if bytes.Equal(key, []byte("Sec-Ch-Ua")) {
			header.Add("Sec-Ch-Ua", string(value))
			return
		}
	case len("User-Agent"):
		if bytes.Equal(key, []byte("User-Agent")) {
			header.Add("User-Agent", string(value))
			return
		}
	case len("Content-Type"):
		if bytes.Equal(key, []byte("Content-Type")) {
			header.Add("Content-Type", string(value))
			return
		}
		if bytes.Equal(key, []byte("X-Tingyun-Id")) {
			header.Add("X-Tingyun-Id", string(value))
			return
		}
	case len("Cache-Control"):
		if bytes.Equal(key, []byte("Cache-Control")) {
			header.Add("Cache-Control", string(value))
			return
		}
		if bytes.Equal(key, []byte("X-Client-Data")) {
			header.Add("X-Client-Data", string(value))
			return
		}
	case len("Content-Length"):
		if bytes.Equal(key, []byte("Content-Length")) {
			header.Add("Content-Length", string(value))
			return
		}
		if bytes.Equal(key, []byte("Sec-Fetch-Site")) {
			header.Add("Sec-Fetch-Site", string(value))
			return
		}
		if bytes.Equal(key, []byte("Sec-Fetch-Mode")) {
			header.Add("Sec-Fetch-Mode", string(value))
			return
		}
		if bytes.Equal(key, []byte("Sec-Fetch-Dest")) {
			header.Add("Sec-Fetch-Dest", string(value))
			return
		}
	case len("Accept-Encoding"):
		if bytes.Equal(key, []byte("Accept-Encoding")) {
			header.Add("Accept-Encoding", string(value))
			return
		}
		if bytes.Equal(key, []byte("Accept-Language")) {
			header.Add("Accept-Language", string(value))
			return
		}
	case len("Sec-Ch-Ua-Mobile"):
		if bytes.Equal(key, []byte("Sec-Ch-Ua-Mobile")) {
			header.Add("Sec-Ch-Ua-Mobile", string(value))
			return
		}
		if bytes.Equal(key, []byte("X-Requested-With")) {
			header.Add("X-Requested-With", string(value))
			return
		}
	case len("If-Modified-Since"):
		if bytes.Equal(key, []byte("If-Modified-Since")) {
			header.Add("If-Modified-Since", string(value))
			return
		}
	case len("Sec-Ch-Ua-Platform"):
		if bytes.Equal(key, []byte("Sec-Ch-Ua-Platform")) {
			header.Add("Sec-Ch-Ua-Platform", string(value))
			return
		}
	case len("Upgrade-Insecure-Requests"):
		if bytes.Equal(key, []byte("Upgrade-Insecure-Requests")) {
			header.Add("Upgrade-Insecure-Requests", string(value))
			return
		}
	}
	header.Add(string(key), string(value))
}

func copyResponseHeaders(dst *app.RequestContext, src http.Header) {
	debugEnabled := slog.Default().Enabled(context.Background(), slog.LevelDebug)
	var removed []string
	connTokens := responseConnectionTokens(src)
	for k, vv := range src {
		if isHopByHop(k) || (connTokens != nil && connTokens[strings.ToLower(k)]) {
			if debugEnabled {
				removed = append(removed, k)
			}
			continue
		}
		if strings.EqualFold(k, "content-encoding") {
			dst.Response.Header.Set(k, strings.Join(vv, ", "))
			continue
		}
		for _, v := range vv {
			dst.Response.Header.Add(k, v)
		}
	}
	if src.Get("Server") == "" {
		dst.Response.Header.Del("Server")
	}
	if len(removed) > 0 {
		slog.Debug("upstream hop-by-hop response headers stripped", slog.Any("headers", removed))
	}
}

/**
 * AddResponseTrailerHeaders 重新写回被 copyResponseHeaders 剥掉的 Trailer 声明头。
 *
 * 该声明头用于告知下游 HTTP 客户端应当期待哪些 trailer 字段。
 *
 * @param dst Hertz 响应上下文。
 * @param trailers 上游响应 trailer 集合。
 */
func AddResponseTrailerHeaders(dst *app.RequestContext, trailers http.Header) {
	if len(trailers) == 0 {
		return
	}
	for k := range trailers {
		dst.Response.Header.Add("Trailer", k)
		_ = dst.Response.Header.Trailer().Set(k, "")
	}
}

func responseConnectionTokens(h http.Header) map[string]bool {
	if len(h) == 0 {
		return nil
	}
	var tokens map[string]bool
	for key, values := range h {
		if !strings.EqualFold(key, "Connection") {
			continue
		}
		for _, value := range values {
			for _, tok := range strings.Split(value, ",") {
				tok = strings.TrimSpace(tok)
				if tok != "" {
					if tokens == nil {
						tokens = make(map[string]bool)
					}
					tokens[strings.ToLower(tok)] = true
				}
			}
		}
	}
	return tokens
}

// FetchHTTP 执行上游请求并返回缓冲响应。
func fetchHTTPResponse(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string) (*http.Response, string, error) {
	res := proxytransport.ResolveUpstreamBase(rt, base)
	req, err := buildUpstreamRequest(ctx, c, res.Normalized, clientIP, origHost, rt.PreserveOriginalHost)
	if err != nil {
		return nil, "", err
	}

	debugEnabled := slog.Default().Enabled(ctx, slog.LevelDebug)
	var start time.Time
	if debugEnabled {
		start = time.Now()
	}

	if res.HertzH2C {
		hresp, hreq, requestDone, cancel, err := proxytransport.DoHertzUpstream(ctx, rt, base, req)
		if err != nil {
			logUpstreamRequestError(ctx, "buffered", req, origHost, err)
			return nil, "", err
		}
		if debugEnabled {
			slog.Debug("upstream buffered response received",
				slog.String("method", req.Method),
				slog.String("url", req.URL.String()),
				slog.String("host", origHost),
				slog.Int("status", hresp.StatusCode()),
				slog.Duration("latency", time.Since(start)),
			)
		}
		return proxytransport.HertzResponseToHTTPResponse(base, hresp, hreq, requestDone, cancel), req.Method, nil
	}

	hc := proxytransport.SharedPooledClient(res.Transport, 30*time.Second)
	resp, err := hc.Do(req)
	if err != nil {
		logUpstreamRequestError(ctx, "buffered", req, origHost, err)
		return nil, "", err
	}
	if debugEnabled {
		slog.Debug("upstream buffered response received",
			slog.String("method", req.Method),
			slog.String("url", req.URL.String()),
			slog.String("host", origHost),
			slog.Int("status", resp.StatusCode),
			slog.String("proto", resp.Proto),
			slog.Duration("latency", time.Since(start)),
		)
	}
	return resp, req.Method, nil
}

func FetchHTTP(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string) (*HTTPResponse, error) {
	return FetchHTTPLimited(ctx, c, rt, base, clientIP, origHost, 0)
}

/**
 * FetchHTTPForAppRouteCapture 缓冲上游响应供 AppRoute 响应体匹配使用，同时受动态变换体限约束。
 *
 * 超限的响应体仍可经 ForwardCapturedResponseForSite 流式转发。
 *
 * @param ctx 请求上下文。
 * @param c Hertz 请求上下文。
 * @param rt 站点运行时。
 * @param base 上游基础 URL。
 * @param clientIP 客户端 IP。
 * @param origHost 原始 Host。
 * @return 已缓冲（或保留未读余量）的上游响应。
 */
func FetchHTTPForAppRouteCapture(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string) (*HTTPResponse, error) {
	return FetchHTTPLimited(ctx, c, rt, base, clientIP, origHost, maxStreamTransformBufferBytes)
}

/**
 * FetchHTTPLimited 在 maxBodyBytes（解码后）上限内缓冲上游响应。
 *
 * maxBodyBytes > 0 且响应体超过上限时，返回的 HTTPResponse 保留未读余量，
 * 调用方可以流式转发完整响应 —— 既不截断，也不必把压缩炸弹完整展开到内存。
 *
 * @param ctx 请求上下文。
 * @param c Hertz 请求上下文。
 * @param rt 站点运行时。
 * @param base 上游基础 URL。
 * @param clientIP 客户端 IP。
 * @param origHost 原始 Host。
 * @param maxBodyBytes 缓冲上限（解码后字节数）；<= 0 表示不限。
 * @return 上游响应；超限时 Body 只含前缀，余量放入 remainingBody。
 */
func FetchHTTPLimited(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string, maxBodyBytes int64) (*HTTPResponse, error) {
	resp, method, err := fetchHTTPResponse(ctx, c, rt, base, clientIP, origHost)
	if err != nil {
		return nil, err
	}
	return bufferedHTTPResponseFromUpstream(resp, method, maxBodyBytes, false)
}

/**
 * FetchHTTPForCache 在回退到流式路径之前，先避免缓冲已知超限的响应。
 *
 * @param ctx 请求上下文。
 * @param c Hertz 请求上下文。
 * @param rt 站点运行时。
 * @param base 上游基础 URL。
 * @param clientIP 客户端 IP。
 * @param origHost 原始 Host。
 * @param maxBodyBytes 缓冲上限（解码后字节数）。
 * @return 上游响应，超限时保留未读余量。
 */
func FetchHTTPForCache(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string, maxBodyBytes int64) (*HTTPResponse, error) {
	resp, method, err := fetchHTTPResponse(ctx, c, rt, base, clientIP, origHost)
	if err != nil {
		return nil, err
	}
	return bufferedHTTPResponseFromUpstream(resp, method, maxBodyBytes, true)
}

func bufferedHTTPResponseFromUpstream(resp *http.Response, method string, maxBodyBytes int64, skipKnownOversize bool) (*HTTPResponse, error) {
	if resp == nil {
		return nil, nil
	}

	var body []byte
	var headers http.Header
	var remaining io.Reader
	var closeFn func() error
	var decoded bool
	var truncated bool
	if strings.EqualFold(method, http.MethodHead) || responseStatusDisallowsBody(resp.StatusCode) {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		headers = resp.Header.Clone()
	} else if maxBodyBytes > 0 {
		var err error
		if skipKnownOversize {
			body, headers, remaining, closeFn, decoded, truncated, err = readUpstreamResponseBodyLimited(resp, maxBodyBytes)
		} else {
			body, headers, remaining, closeFn, decoded, truncated, err = readUpstreamResponseBodyLimitedForCapture(resp, maxBodyBytes)
		}
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		body, headers, err = readUpstreamResponseBody(resp)
		if err != nil {
			return nil, err
		}
	}
	if headers == nil {
		headers = http.Header{}
	}
	if !truncated {
		for k, vv := range resp.Trailer {
			for _, v := range vv {
				headers.Add(k, v)
			}
		}
	}

	result := &HTTPResponse{
		StatusCode:           resp.StatusCode,
		ContentType:          headers.Get("Content-Type"),
		Body:                 body,
		Header:               headers,
		UpstreamHTTPProtocol: resp.Proto,
	}
	if truncated {
		result.remainingBody = remaining
		result.closeBody = closeFn
		result.upstreamResponse = resp
		result.decodedBody = decoded
	}
	return result, nil
}

func ForwardBufferedResponse(c *app.RequestContext, resp *HTTPResponse) {
	forwardBufferedResponseWithOptions(c, resp, DefaultResponseCompressionOptions(true), nil, nil)
}

func ForwardBufferedResponseForSiteWithClientIP(c *app.RequestContext, resp *HTTPResponse, rt snapshot.SiteRuntime, clientIP net.IP) {
	forwardBufferedResponseWithOptions(c, resp, streamCompressionOptions(rt), responseEntityTransformerForSiteAndClient(rt, c, clientIP), clientIP)
}

/**
 * ForwardCapturedResponseForSite 转发 FetchHTTPLimited 返回的响应。
 *
 * 已完整缓冲的响应仍走常规动态变换路径；超限响应则直接流式转发未读余量、
 * 不做变换，但保留完整响应体。
 *
 * @param ctx 请求上下文。
 * @param c Hertz 请求上下文。
 * @param resp 上游响应。
 * @param rt 站点运行时。
 * @return 写回下游过程中的错误。
 */
func ForwardCapturedResponseForSite(ctx context.Context, c *app.RequestContext, resp *HTTPResponse, rt snapshot.SiteRuntime) error {
	return ForwardCapturedResponseForSiteWithClientIP(ctx, c, resp, rt, nil)
}

func ForwardCapturedResponseForSiteWithClientIP(ctx context.Context, c *app.RequestContext, resp *HTTPResponse, rt snapshot.SiteRuntime, clientIP net.IP) error {
	if resp == nil || resp.remainingBody == nil {
		ForwardBufferedResponseForSiteWithClientIP(c, resp, rt, clientIP)
		return nil
	}

	proxytransport.SetUpstreamHTTPProtocol(c, resp.UpstreamHTTPProtocol)
	copyResponseHeaders(c, resp.Header)
	if resp.ContentType != "" && resp.Header.Get("Content-Type") == "" {
		c.SetContentType(resp.ContentType)
	}
	c.Status(resp.StatusCode)

	upstreamResp := resp.upstreamResponse
	if upstreamResp != nil && len(upstreamResp.Trailer) > 0 {
		AddResponseTrailerHeaders(c, upstreamResp.Trailer)
	}
	if responseStatusDisallowsBody(resp.StatusCode) || bytes.EqualFold(c.Method(), []byte(http.MethodHead)) {
		if resp.closeBody != nil {
			_ = resp.closeBody()
		}
		return nil
	}

	bodyReader := io.MultiReader(bytes.NewReader(resp.Body), resp.remainingBody)
	effectiveCE := contentEncodingHeaderValue(resp.Header)
	bodySize := -1
	if resp.decodedBody {
		c.Response.Header.Del("Content-Encoding")
		c.Response.Header.Del("Content-Length")
		effectiveCE = ""
	}

	compOpts := streamCompressionOptions(rt)
	encoding := responseEncodingIdentity
	if compOpts.Enabled && !requestCacheControlHasNoTransform(c.Request.Header.PeekAll("Cache-Control")) && shouldTransformStreamingResponseBody(
		resp.StatusCode,
		resp.Header.Get("Content-Type"),
		effectiveCE,
		resp.Header.Get("Cache-Control"),
		resp.Header.Get("Content-Range"),
		maxStreamTransformBufferBytes+1,
		compOpts.MinBytes,
	) {
		encoding = selectClientResponseEncodingBytes(c.GetHeader("Accept-Encoding"), compOpts.BrotliEnabled, compOpts.GzipEnabled, compOpts.DeflateEnabled, compOpts.ZstdEnabled)
	}
	if encoding != responseEncodingIdentity {
		c.Response.Header.Del("Content-Encoding")
		c.Response.Header.Del("Content-Length")
		return streamRecompressedResponse(ctx, c, bodyReader, resp.closeBody, upstreamResp, nil, encoding)
	}

	c.Response.ImmediateHeaderFlush = true
	if bodySize < 0 {
		c.Response.Header.Del("Content-Length")
		c.Response.Header.SetContentLength(-1)
	}
	stream := newProxyBodyStream(ctx, bodyReader, resp.closeBody, upstreamResp, c, nil)
	if StreamResponseViaHijack(ctx, c, stream, stream.cleanup) {
		return nil
	}
	c.Response.SetBodyStream(stream, bodySize)
	return nil
}

func forwardBufferedResponseWithOptions(c *app.RequestContext, resp *HTTPResponse, opts ResponseCompressionOptions, transformer identityResponseTransformer, clientIP net.IP) {
	if resp == nil {
		return
	}
	proxytransport.SetUpstreamHTTPProtocol(c, resp.UpstreamHTTPProtocol)
	if resp.Header != nil {
		copyResponseHeaders(c, resp.Header)
	}
	if resp.ContentType != "" && (resp.Header == nil || resp.Header.Get("Content-Type") == "") {
		c.SetContentType(resp.ContentType)
	}
	c.Status(resp.StatusCode)

	body, _, err := transformIdentityResponseBody(c, resp.StatusCode, resp.Body, transformer, clientIP)
	if err != nil {
		writeResponseTransformFailure(c)
		return
	}
	body = applyClientResponseCompressionWithOptions(c, resp.StatusCode, body, opts)

	if bytes.EqualFold(c.Request.Method(), []byte("HEAD")) {
		if len(body) > 0 {
			c.Response.Header.Set("Content-Length", strconv.Itoa(len(body)))
		}
		c.Response.SetBodyRaw(nil)
		return
	}
	c.Response.SetBodyRaw(body)
}

func ForwardBufferedResponseAsStreamForSiteWithClientIP(c *app.RequestContext, resp *HTTPResponse, rt snapshot.SiteRuntime, clientIP net.IP) {
	if resp == nil {
		return
	}
	proxytransport.SetUpstreamHTTPProtocol(c, resp.UpstreamHTTPProtocol)
	if resp.Header != nil {
		copyResponseHeaders(c, resp.Header)
	}
	if resp.ContentType != "" && (resp.Header == nil || resp.Header.Get("Content-Type") == "") {
		c.SetContentType(resp.ContentType)
	}
	c.Status(resp.StatusCode)

	body, changed, err := transformIdentityResponseBody(c, resp.StatusCode, resp.Body, responseEntityTransformerForSiteAndClient(rt, c, clientIP), clientIP)
	if err != nil {
		writeResponseTransformFailure(c)
		return
	}
	if changed {
		body = applyClientResponseCompressionWithOptions(c, resp.StatusCode, body, streamCompressionOptions(rt))
		c.Response.SetBodyRaw(body)
		return
	}
	c.Response.Header.Del("Content-Length")
	c.Response.SetBodyStream(bytes.NewReader(body), -1)
}

/**
 * SanitizeHeadersForEdgeCache 在随响应体一并持久化上游元数据之前剥离逐跳头与 Content-Length。
 *
 * 保留 Content-Encoding（如 br），缓存命中时才能正确解码。
 *
 * @param src 上游响应头。
 * @return 可安全存入共享缓存的头集合；无剩余字段时返回 nil。
 */
func SanitizeHeadersForEdgeCache(src http.Header) http.Header {
	if src == nil {
		return nil
	}
	connTokens := responseConnectionTokens(src)
	dst := src.Clone()
	for k := range dst {
		lk := strings.ToLower(k)
		if isHopByHop(lk) || connTokens[lk] {
			delete(dst, k)
		}
	}
	deleteHeaderValuesFold(dst, "Content-Length")
	// 防御历史调用方绕过 ShouldCacheHTTPResponse：共享缓存永远不应
	// 回放会建立会话的 Set-Cookie。
	deleteHeaderValuesFold(dst, "Set-Cookie")
	deleteHeaderValuesFold(dst, "Set-Cookie2")
	// Age 由本层回放时按 CachedAt 重新计算（RFC 9111 §5.1）；上游旧值
	// 若在 ShouldCacheHTTPResponse 之前进入存储，回放时会与本层 Age 重复。
	deleteHeaderValuesFold(dst, "Age")
	if len(dst) == 0 {
		return nil
	}
	return dst
}

func deleteHeaderValuesFold(header http.Header, name string) {
	for key := range header {
		if strings.EqualFold(key, name) {
			delete(header, key)
		}
	}
}

/**
 * WriteCachedResponse 回放一条 cache.ResponseEntry，条目带存储头时一并回放。
 *
 * @param c Hertz 请求上下文。
 * @param method 请求方法（HEAD 与 GET 共用同一条目）。
 * @param e 缓存条目。
 */
func WriteCachedResponse(c *app.RequestContext, method string, e *cache.ResponseEntry) {
	writeCachedResponseWithOptions(c, method, e, DefaultResponseCompressionOptions(false), nil, nil)
}

func WriteCachedResponseForSiteWithClientIP(c *app.RequestContext, method string, e *cache.ResponseEntry, rt snapshot.SiteRuntime, clientIP net.IP) {
	writeCachedResponseWithOptions(c, method, e, streamCompressionOptions(rt), responseEntityTransformerForSiteAndClient(rt, c, clientIP), clientIP)
}

func writeCachedResponseWithOptions(c *app.RequestContext, method string, e *cache.ResponseEntry, opts ResponseCompressionOptions, transformer identityResponseTransformer, clientIP net.IP) {
	if e == nil {
		return
	}
	isHead := strings.EqualFold(strings.TrimSpace(method), "HEAD")

	if e.Header != nil && len(e.Header) > 0 {
		// 缓存条目按不可信状态处理。更早写入的条目与测试构造的条目，可能
		// 早于存储闸门剥离 Set-Cookie 与逐跳头；这些头绝不能回放给共享缓存
		// 的客户端。
		copyResponseHeaders(c, SanitizeHeadersForEdgeCache(e.Header))
	}
	// RFC 9111 §5.1：Age 表示响应在本共享缓存中累计的年龄。上游自带的 Age
	// 已被 EffectiveCacheTTL 折算进条目 TTL，因此回放时必须换成本层的驻留
	// 时长，不能把陈旧或重复的旧值透给下游。
	c.Response.Header.Del("Age")
	if e.CachedAt > 0 {
		age := time.Now().Unix() - e.CachedAt
		if age < 0 {
			age = 0
		}
		c.Response.Header.Set("Age", strconv.FormatInt(age, 10))
	}
	if e.ContentType != "" {
		c.SetContentType(e.ContentType)
	}
	c.Status(e.StatusCode)

	body, _, err := transformIdentityResponseBody(c, e.StatusCode, e.Body, transformer, clientIP)
	if err != nil {
		writeResponseTransformFailure(c)
		return
	}
	body = applyClientResponseCompressionWithOptions(c, e.StatusCode, body, opts)

	if isHead {
		if len(body) > 0 {
			c.Response.Header.Set("Content-Length", strconv.Itoa(len(body)))
		}
		c.Response.SetBodyRaw(nil)
		return
	}
	c.Response.SetBodyRaw(body)
}

func ShouldCacheResponse(method string, statusCode int, body []byte) bool {
	return strings.EqualFold(method, "GET") && statusCode == 200 && len(body) > 0
}

/**
 * varyDisallowsCaching 判断任一 Vary 字段是否含有缓存未纳入身份表示的维度。
 *
 * @param values 各条 Vary 头的原值。
 * @return 存在未归一维度时返回 true，表示该响应不得进入共享缓存。
 */
func varyDisallowsCaching(values ...string) bool {
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			token := strings.ToLower(strings.TrimSpace(part))
			if token != "" && token != "accept-encoding" {
				return true
			}
		}
	}
	return false
}

func cacheControlDisallowsStorage(values []string) bool {
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			directive := strings.ToLower(strings.TrimSpace(part))
			directiveValue := ""
			if index := strings.IndexByte(directive, '='); index >= 0 {
				directiveValue = strings.Trim(strings.TrimSpace(directive[index+1:]), "\"")
				directive = strings.TrimSpace(directive[:index])
			}
			switch directive {
			case "private", "no-store", "no-cache", "must-revalidate", "proxy-revalidate", "no-transform":
				return true
			case "max-age", "s-maxage":
				// 零或负的新鲜期显式要求每次回源校验；站点 TTL 不得把它
				// 变成一次共享缓存命中。
				seconds, err := strconv.ParseInt(directiveValue, 10, 64)
				if err != nil || seconds <= 0 {
					return true
				}
			}
		}
	}
	return false
}

func expiresDisallowsStorage(values []string, now time.Time) bool {
	for _, value := range values {
		expiresAt, err := http.ParseTime(strings.TrimSpace(value))
		if err != nil {
			return true
		}
		if !expiresAt.After(now) {
			return true
		}
	}
	return false
}

func pragmaDisallowsStorage(values []string) bool {
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), "no-cache") {
				return true
			}
		}
	}
	return false
}

/**
 * responseHeaderValues 取某个头名的全部取值，包括挂非规范 map 键下的值。
 *
 * http.Header 正常会做键名规范化，但上游适配器与历史调用方可能直接构造该 map。
 * 安全判定不得依赖这一表示细节。
 *
 * @param header 待查头集合。
 * @param name 头名，大小写不敏感。
 * @return 所有匹配取值，按 map 遍历顺序拼接。
 */
func responseHeaderValues(header http.Header, name string) []string {
	if len(header) == 0 {
		return nil
	}
	var values []string
	for key, entries := range header {
		if strings.EqualFold(key, name) {
			values = append(values, entries...)
		}
	}
	return values
}

func contentEncodingDisallowsCaching(values []string) bool {
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			encoding := strings.ToLower(strings.TrimSpace(part))
			if encoding != "" && encoding != "identity" {
				return true
			}
		}
	}
	return false
}

/**
 * ShouldCacheHTTPResponse 判定上游响应是否可存入共享边缘缓存。
 *
 * 可选的历史参数被有意忽略：源站的隐私指令永远不能被站点路径规则覆盖。
 *
 * @param method 请求方法。
 * @param resp 已缓冲的上游响应。
 * @param _ 历史遗留参数，恒被忽略。
 * @return 允许入缓存时返回 true。
 */
func ShouldCacheHTTPResponse(method string, resp *HTTPResponse, _ ...bool) bool {
	if resp == nil || !ShouldCacheResponse(method, resp.StatusCode, resp.Body) {
		return false
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(resp.ContentType)), "application/grpc") {
		return false
	}
	if len(responseHeaderValues(resp.Header, "Set-Cookie")) > 0 ||
		len(responseHeaderValues(resp.Header, "Set-Cookie2")) > 0 {
		return false
	}
	if cacheControlDisallowsStorage(responseHeaderValues(resp.Header, "Cache-Control")) {
		return false
	}
	if expiresDisallowsStorage(responseHeaderValues(resp.Header, "Expires"), time.Now()) {
		return false
	}
	if pragmaDisallowsStorage(responseHeaderValues(resp.Header, "Pragma")) {
		return false
	}
	if varyDisallowsCaching(responseHeaderValues(resp.Header, "Vary")...) {
		return false
	}
	// 受支持的上游编码在本次判定之前就已被解码。仍有剩留编码说明编码未知，
	// 无法在 Accept-Encoding 变体之间共用同一个缓存键。
	if contentEncodingDisallowsCaching(responseHeaderValues(resp.Header, "Content-Encoding")) {
		return false
	}
	// Age 是单值响应字段。取值畸形或重复出现都会让新鲜期变得含糊，因此
	// 不得让它成为共享缓存命中。
	ages := responseHeaderValues(resp.Header, "Age")
	if len(ages) > 1 {
		return false
	}
	if len(ages) == 1 {
		age, err := strconv.ParseInt(strings.TrimSpace(ages[0]), 10, 64)
		if err != nil || age < 0 {
			return false
		}
	}
	return true
}

/**
 * EffectiveCacheTTL 用源站显式给出的新鲜期压住站点规则 TTL。
 *
 * 站点白名单可以把某条路径纳入缓存，但不能把源站更短的 max-age/s-maxage
 * 或 Expires 期限拉长。
 *
 * @param configured 站点规则配置的 TTL（秒）。
 * @param resp 已缓冲的上游响应。
 * @return 实际生效的 TTL（秒）；不可缓存时为 0。
 */
func EffectiveCacheTTL(configured int64, resp *HTTPResponse) int64 {
	if configured <= 0 || resp == nil {
		return 0
	}
	effective := configured
	for _, value := range responseHeaderValues(resp.Header, "Cache-Control") {
		for _, part := range strings.Split(value, ",") {
			directive := strings.TrimSpace(strings.ToLower(part))
			index := strings.IndexByte(directive, '=')
			if index < 0 {
				continue
			}
			name := strings.TrimSpace(directive[:index])
			if name != "max-age" && name != "s-maxage" {
				continue
			}
			seconds, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(directive[index+1:]), "\""), 10, 64)
			if err != nil || seconds <= 0 {
				return 0
			}
			if seconds < effective {
				effective = seconds
			}
		}
	}
	if values := responseHeaderValues(resp.Header, "Expires"); len(values) > 0 {
		for _, value := range values {
			expiresAt, err := http.ParseTime(strings.TrimSpace(value))
			if err != nil {
				return 0
			}
			remaining := int64(time.Until(expiresAt).Seconds())
			if remaining <= 0 {
				return 0
			}
			if remaining < effective {
				effective = remaining
			}
		}
	}
	if values := responseHeaderValues(resp.Header, "Age"); len(values) > 0 {
		age, err := strconv.ParseInt(strings.TrimSpace(values[0]), 10, 64)
		if err != nil || age < 0 {
			return 0
		}
		if age >= effective {
			return 0
		}
		effective -= age
	}
	if effective <= 0 {
		return 0
	}
	return effective
}

/**
 * siteCacheFirstMatch 返回首个命中缓存规则的 TTL、查询串建键策略与 stale-if-error 窗口。
 *
 * 大小写不敏感匹配不会改变存入缓存键的源站路径。
 *
 * @param rt 站点运行时。
 * @param matchKey 路径加可选原始查询串。
 * @return ttl 生效 TTL（秒）；stripQueryKey 是否从键中丢弃查询串；staleIfError
 *   stale-if-error 窗口秒数；matched 是否命中规则。
 */
func siteCacheFirstMatch(rt snapshot.SiteRuntime, matchKey string) (ttl int64, stripQueryKey bool, staleIfError int64, matched bool) {
	if !rt.CacheEnabled {
		return 0, false, 0, false
	}
	for _, rule := range rt.CacheRules {
		if rule.Disabled {
			continue
		}
		pat := cacheRulePattern(rule)
		if pat == "" {
			continue
		}
		ruleType := strings.ToLower(strings.TrimSpace(rule.Type))
		if ruleType == "" {
			ruleType = "prefix"
		}
		keyFor := matchKey
		if rule.IgnoreQuery {
			keyFor = pathOnlyFromRuleMatchKey(matchKey)
		}
		var matches bool
		switch ruleType {
		case "regex":
			if rule.Regex != nil {
				matches = rule.Regex.MatchString(keyFor)
			}
		default:
			keyCmp, patCmp := keyFor, pat
			if rule.CaseInsensitive {
				keyCmp = strings.ToLower(keyCmp)
				patCmp = strings.ToLower(patCmp)
			}
			switch ruleType {
			case "exact":
				matches = keyCmp == patCmp
			case "suffix":
				matches = cacheSuffixPatternMatch(keyCmp, patCmp)
			case "contains":
				matches = strings.Contains(keyCmp, patCmp)
			default:
				matches = strings.HasPrefix(keyCmp, patCmp)
			}
		}
		if !matches {
			continue
		}
		t := int64(rule.TTL)
		if t <= 0 {
			t = int64(rt.CacheDefaultTTL)
		}
		if t > 0 {
			return t, rule.IgnoreQuery, int64(rule.StaleIfError), true
		}
	}
	return 0, false, 0, false
}

/**
 * SiteCacheTTLDetails 返回 TTL，以及是否有 cache_rules 行命中（模式命中）。
 *
 * cache_default_ttl 只作为「已命中但自身 ttl <= 0」那条规则的 TTL 生效；
 * 它不会让未命中任何规则的路径获得缓存能力。
 *
 * @param rt 站点运行时。
 * @param matchKey 路径加可选原始查询串。
 * @return ttl 生效 TTL；matchedExplicitRule 是否命中显式规则。
 */
func SiteCacheTTLDetails(rt snapshot.SiteRuntime, matchKey string) (ttl int64, matchedExplicitRule bool) {
	t, _, _, ok := siteCacheFirstMatch(rt, matchKey)
	return t, ok
}

/**
 * RuleMatchKey 给出路径加可选原始查询串，用于评估缓存路径规则。
 *
 * @param c Hertz 请求上下文。
 * @return 规则匹配键。
 */
func RuleMatchKey(c *app.RequestContext) string {
	return ruleMatchKeyFromPathQuery(requestPath(c), c.URI().QueryString())
}

func ruleMatchKeyFromPathQuery(path string, query []byte) string {
	qs := strings.TrimSpace(string(query))
	if qs == "" {
		return path
	}
	return path + "?" + qs
}

func cacheRulePattern(r store.SiteCacheRule) string {
	v := strings.TrimSpace(r.Value)
	if v != "" {
		return v
	}
	return strings.TrimSpace(r.Path)
}

func pathOnlyFromRuleMatchKey(matchKey string) string {
	if i := strings.IndexByte(matchKey, '?'); i >= 0 {
		return matchKey[:i]
	}
	return matchKey
}

/**
 * cacheSuffixPatternMatch 做后缀规则匹配，但避免命中词中间位置造成的误判。
 *
 * 例：模式 "ig" 不得匹配 ".../config"。文件扩展名（".js"）与显式路径尾
 * （"a/b.js"）仍保持标准后缀语义。
 *
 * @param matchKey 路径加可选原始查询串。
 * @param pat 规则模式。
 * @return 命中时返回 true。
 */
func cacheSuffixPatternMatch(matchKey, pat string) bool {
	if pat == "" {
		return false
	}
	if strings.Contains(pat, "?") {
		return strings.HasSuffix(matchKey, pat)
	}
	pathOnly := pathOnlyFromRuleMatchKey(matchKey)
	if !strings.HasSuffix(pathOnly, pat) {
		return false
	}
	if strings.HasPrefix(pat, ".") || strings.Contains(pat, "/") {
		return true
	}
	idx := len(pathOnly) - len(pat)
	if idx < 0 {
		return false
	}
	if idx == 0 {
		return true
	}
	switch pathOnly[idx-1] {
	case '/', '.', '_', '-':
		return true
	default:
		return false
	}
}

/**
 * BuildSiteCacheStorageKey 构造进程内缓存键。
 *
 * stripQuery 为真时从键中丢弃查询串；lowerPath 为真（大小写不敏感规则命中）时
 * 只把路径段小写化，host 键不受影响。
 *
 * @param rt 站点运行时。
 * @param c Hertz 请求上下文。
 * @param stripQuery 是否丢弃查询串。
 * @param lowerPath 是否把路径段小写化。
 * @return 缓存键。
 */
func BuildSiteCacheStorageKey(rt snapshot.SiteRuntime, c *app.RequestContext, stripQuery, lowerPath bool) string {
	return buildSiteCacheStorageKeyFromParts(rt, c, requestPath(c), c.URI().QueryString(), stripQuery, lowerPath)
}

func buildSiteCacheStorageKeyFromParts(rt snapshot.SiteRuntime, c *app.RequestContext, path string, query []byte, stripQuery, lowerPath bool) string {
	method := string(c.Method())
	if strings.EqualFold(method, "HEAD") {
		method = "GET"
	}
	p := path
	if lowerPath {
		p = strings.ToLower(p)
	}
	q := string(query)
	if stripQuery {
		q = ""
	}
	hostKey := strings.TrimSpace(rt.Bind) + "|" + strconv.FormatUint(uint64(rt.Site.ID), 10) + "|" + snapshot.NormalizeMatchHost(string(c.Host()))
	return cache.CacheKey(method, hostKey, p, q)
}

/**
 * SiteCacheEligible 判定本次请求是否可以使用共享响应缓存。
 *
 * 第三个返回值保留了历史上的「规则命中」布尔语义。
 *
 * @param rt 站点运行时。
 * @param c Hertz 请求上下文。
 * @return key 缓存键（不可用为空串）；ttl 生效 TTL；matched 是否命中规则。
 */
func SiteCacheEligible(rt snapshot.SiteRuntime, c *app.RequestContext) (key string, ttl int64, matched bool) {
	key, ttl, _ = SiteCacheEligibleWithStale(rt, c)
	matched = key != ""
	return key, ttl, matched
}

/**
 * SiteCacheEligibleWithStale 是数据面使用的扩展缓存资格契约，额外返回配置的 stale-if-error 窗口。
 *
 * @param rt 站点运行时。
 * @param c Hertz 请求上下文。
 * @return key 缓存键（不可用为空串）；ttl 生效 TTL；staleIfError stale-if-error 窗口秒数。
 */
func SiteCacheEligibleWithStale(rt snapshot.SiteRuntime, c *app.RequestContext) (key string, ttl int64, staleIfError int64) {
	if !rt.CacheEnabled {
		return "", 0, 0
	}
	if !isCacheableRequestMethod(c.Method()) {
		return "", 0, 0
	}
	if requestHeaderHasValue(c.Request.Header.PeekAll("Authorization")) ||
		requestHeaderHasValue(c.Request.Header.PeekAll("Proxy-Authorization")) ||
		requestHeaderHasValue(c.Request.Header.PeekAll("Cookie")) {
		return "", 0, 0
	}
	if requestCacheControlDisallowsCaching(c.Request.Header.PeekAll("Cache-Control")) ||
		requestPragmaDisallowsCaching(c.Request.Header.PeekAll("Pragma")) {
		return "", 0, 0
	}
	path := requestPath(c)
	query := c.URI().QueryString()
	full := ruleMatchKeyFromPathQuery(path, query)
	ttlVal, stripQ, stale, ok := siteCacheFirstMatch(rt, full)
	if !ok || ttlVal <= 0 {
		return "", 0, 0
	}
	return buildSiteCacheStorageKeyFromParts(rt, c, path, query, stripQ, false), ttlVal, stale
}

func requestHeaderHasValue(values [][]byte) bool {
	for _, value := range values {
		if len(value) > 0 {
			return true
		}
	}
	return false
}

func requestCacheControlDisallowsCaching(values [][]byte) bool {
	for _, value := range values {
		for _, part := range strings.Split(string(value), ",") {
			directive := strings.ToLower(strings.TrimSpace(part))
			name := directive
			if index := strings.IndexByte(directive, '='); index >= 0 {
				name = strings.TrimSpace(directive[:index])
			}
			if name == "no-store" || name == "no-cache" || name == "no-transform" || name == "max-age" || name == "min-fresh" {
				return true
			}
		}
	}
	return false
}

func requestCacheControlHasNoTransform(values [][]byte) bool {
	for _, value := range values {
		for _, part := range strings.Split(string(value), ",") {
			directive := strings.ToLower(strings.TrimSpace(part))
			if index := strings.IndexByte(directive, '='); index >= 0 {
				directive = strings.TrimSpace(directive[:index])
			}
			if directive == "no-transform" {
				return true
			}
		}
	}
	return false
}

func requestPragmaDisallowsCaching(values [][]byte) bool {
	for _, value := range values {
		for _, part := range strings.Split(string(value), ",") {
			if strings.EqualFold(strings.TrimSpace(part), "no-cache") {
				return true
			}
		}
	}
	return false
}

func isCacheableRequestMethod(method []byte) bool {
	switch len(method) {
	case len("GET"):
		return asciiEqualFoldBytes(method, "get")
	case len("HEAD"):
		return asciiEqualFoldBytes(method, "head")
	}
	return false
}

/**
 * streamProbeSize 是对未知长度响应做单次 Read 探测所用的缓冲容量。
 *
 * 若整个响应体一次 Read 即可读完（返回 EOF），ForwardHTTP 走无压缩的缓冲
 * 路径，否则切换到流式压缩。32 KiB 在每请求内存占用与常见小响应体之间取平衡。
 */
const streamProbeSize = 32768
const completeUnknownLengthCompressMaxBytes = 5 * snapshot.DefaultResponseCompressionMinBytes

// streamCopyBufSize 是流式拷贝/压缩探测缓冲的标准容量。
const streamCopyBufSize = 32 * 1024

// streamCopyBufPool 复用流式转发的 32KiB 拷贝缓冲，削减每请求固定分配与 GC 压力。
// Put 时只接受恰好 streamCopyBufSize 容量的缓冲，避免探测路径偶发扩容后污染池。
var streamCopyBufPool = sync.Pool{New: func() any { b := make([]byte, streamCopyBufSize); return &b }}

func putStreamCopyBuf(bp *[]byte) {
	if bp == nil {
		return
	}
	if cap(*bp) != streamCopyBufSize {
		return
	}
	// 保持 len==cap，下次 Get 可直接按 32KiB 使用。
	*bp = (*bp)[:streamCopyBufSize]
	streamCopyBufPool.Put(bp)
}

/**
 * maxStreamTransformBufferBytes 是 forwardHTTP 为身份响应变换而缓冲进内存的响应体上限（解压后）。
 *
 * 超过该上限的响应不做变换，直接走常规流式路径。
 */
const maxStreamTransformBufferBytes = 8 * 1024 * 1024 // 8 MiB

/**
 * maxBufferedRawResponseBytes 是「已知长度响应整体缓冲为内存实体」的上限。
 *
 * 流式写出路径（SetBodyStream + WriteBodyFixedSize）会先把响应头 Flush 出去，
 * 再单独把响应体写一次，小响应因此固定多付一次 write syscall 和一整套
 * proxyBodyStream/Copy 机制；把上限内的定长响应体读进内存后改用 SetBodyRaw，
 * Hertz 就能把头部与响应体合并到同一次 Flush。64 KiB 与
 * server.WithMaxKeepBodySize 对齐，超过该值的响应继续流式转发，不改变大文件
 * 的 TTFB 与内存占用。
 */
const maxBufferedRawResponseBytes = 64 * 1024

// closeUpstreamResponse 释放上游响应占用的资源：先取消上下文，再执行关闭函数。
func closeUpstreamResponse(cancel context.CancelFunc, closeFn func() error, resp *http.Response) {
	if cancel != nil {
		cancel()
	}
	if closeFn != nil {
		_ = closeFn()
		return
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}

func ForwardHTTP(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string) error {
	return forwardHTTP(ctx, c, rt, base, clientIP, origHost, false)
}

func ForwardHTTPPreserveRequestBodyOnCancel(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string) error {
	return forwardHTTP(ctx, c, rt, base, clientIP, origHost, true)
}

func forwardHTTP(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string, preserveRequestBodyOnCancel bool) error {
	upstreamParentCtx := ctx
	if preserveRequestBodyOnCancel {
		upstreamParentCtx = context.WithoutCancel(ctx)
	}
	upstreamCtx, cancelUpstream := context.WithCancel(upstreamParentCtx)
	res := proxytransport.ResolveUpstreamBase(rt, base)
	req, err := buildUpstreamRequest(upstreamCtx, c, res.Normalized, clientIP, origHost, rt.PreserveOriginalHost)
	if err != nil {
		cancelUpstream()
		return err
	}
	if preserveRequestBodyOnCancel && req.Body != nil {
		req.Body = &proxytransport.FinishOnCanceledReadCloser{Body: req.Body, CancelCtx: ctx}
	}

	debugEnabled := slog.Default().Enabled(ctx, slog.LevelDebug)
	var start time.Time
	if debugEnabled {
		start = time.Now()
	}
	var resp *http.Response
	if res.HertzH2C {
		hresp, hreq, requestDone, cancelHertz, err := proxytransport.DoHertzUpstream(upstreamCtx, rt, base, req)
		if err != nil {
			cancelUpstream()
			logUpstreamRequestError(ctx, "streaming", req, origHost, err)
			return err
		}
		resp = proxytransport.HertzResponseToHTTPResponse(base, hresp, hreq, requestDone, cancelHertz)
	} else {
		hc := proxytransport.SharedPooledClient(res.Transport, 0)
		var err error
		resp, err = hc.Do(req)
		if err != nil {
			cancelUpstream()
			logUpstreamRequestError(ctx, "streaming", req, origHost, err)
			return err
		}
		if preserveRequestBodyOnCancel && ctx.Err() != nil {
			resp.Body.Close()
			cancelUpstream()
			return ctx.Err()
		}
	}
	proxytransport.SetUpstreamHTTPProtocol(c, resp.Proto)
	if debugEnabled {
		slog.Debug("upstream streaming response received",
			slog.String("method", req.Method),
			slog.String("url", req.URL.String()),
			slog.String("host", origHost),
			slog.Int("status", resp.StatusCode),
			slog.String("proto", resp.Proto),
			slog.Duration("latency", time.Since(start)),
		)
	}

	copyResponseHeaders(c, resp.Header)
	if len(resp.Trailer) > 0 {
		AddResponseTrailerHeaders(c, resp.Trailer)
	}

	c.Status(resp.StatusCode)

	if responseStatusDisallowsBody(resp.StatusCode) {
		resp.Body.Close()
		cancelUpstream()
		return nil
	}
	if bytes.EqualFold(c.Method(), []byte("HEAD")) {
		resp.Body.Close()
		cancelUpstream()
		return nil
	}

	// response 阶段 JS 变换器只作用于身份响应实体；与 dynamic/browser sign
	// 组合后的变换器非 nil 且满足 shouldTransform 条件时进入整体缓冲路径。
	// 显式传入请求 ctx：图像转换的墙钟预算从它派生，客户端断开或上游取消时
	// 转换会立即放弃，不再白跑 CPU。
	resolved := responseEntityTransformerForSiteAndClientWithContext(ctx, rt, c, clientIP)
	if resolved != nil && shouldTransformIdentityResponse(c, resp.StatusCode) {
		return forwardHTTPWithTransform(ctx, c, rt, resp, cancelUpstream, resolved, clientIP)
	}

	bodyReader, closeFn, decoded, decErr := upstreamResponseReader(resp)
	if decErr != nil {
		resp.Body.Close()
		cancelUpstream()
		return decErr
	}

	bodySize := int(resp.ContentLength)
	if decoded {
		bodySize = -1
		c.Response.Header.Del("Content-Encoding")
		c.Response.Header.Del("Content-Length")
	}
	streamBodySize := bodySize
	if len(resp.Trailer) > 0 {
		streamBodySize = -1
		c.Response.Header.Del("Content-Length")
		c.Response.Header.SetContentLength(-1)
	}

	compOpts := streamCompressionOptions(rt)
	effectiveCE := contentEncodingHeaderValue(resp.Header)
	if decoded {
		effectiveCE = ""
	}

	encoding := responseEncodingIdentity
	canCompress := false

	if bodySize >= 0 {
		canCompress = shouldTransformStreamingResponseBody(
			resp.StatusCode,
			resp.Header.Get("Content-Type"),
			effectiveCE,
			resp.Header.Get("Cache-Control"),
			resp.Header.Get("Content-Range"),
			bodySize,
			compOpts.MinBytes,
		)
	} else {
		canCompress = shouldTransformResponseMetadata(
			resp.StatusCode,
			resp.Header.Get("Content-Type"),
			effectiveCE,
			resp.Header.Get("Cache-Control"),
			resp.Header.Get("Content-Range"),
		)
	}
	if requestCacheControlHasNoTransform(c.Request.Header.PeekAll("Cache-Control")) {
		canCompress = false
	}

	if canCompress && compOpts.Enabled {
		encoding = selectClientResponseEncodingBytes(c.GetHeader("Accept-Encoding"), compOpts.BrotliEnabled, compOpts.GzipEnabled, compOpts.DeflateEnabled, compOpts.ZstdEnabled)
	}

	if decoded && encoding != responseEncodingIdentity {
		return streamRecompressedResponse(ctx, c, bodyReader, closeFn, resp, cancelUpstream, encoding)
	}

	if encoding != responseEncodingIdentity && bodySize >= 0 {
		return streamCompressedResponseFromReader(ctx, c, bodyReader, closeFn, resp, cancelUpstream, encoding, streamBodySize)
	}

	if encoding != responseEncodingIdentity && bodySize < 0 {
		// 复用 streamCopy 的 32KiB 池，避免未知长度压缩探测每次固定分配 32KiB。
		// 任何可能逃逸出本函数的 body 切片都必须 copy；池缓冲只在本函数内使用。
		probeBufp := streamCopyBufPool.Get().(*[]byte)
		probeBuf := *probeBufp
		if cap(probeBuf) < streamProbeSize {
			probeBuf = make([]byte, streamProbeSize)
			*probeBufp = probeBuf
		} else {
			probeBuf = probeBuf[:streamProbeSize]
		}
		defer putStreamCopyBuf(probeBufp)
		cloneProbe := func(n int) []byte {
			if n <= 0 {
				return []byte{}
			}
			return append([]byte(nil), probeBuf[:n]...)
		}
		n, readErr := bodyReader.Read(probeBuf)
		if readErr == io.EOF {
			if closeFn != nil {
				_ = closeFn()
			}
			cancelUpstream()
			copyResponseTrailers(c, resp)
			if shouldCompressCompleteUnknownLengthBody(n, compOpts, rt) {
				if len(resp.Trailer) > 0 || rt.ResponseCompressionConfigured {
					return streamRecompressedResponse(ctx, c, bytes.NewReader(cloneProbe(n)), nil, resp, nil, encoding)
				}
				encodedBody, encErr := compressResponseBody(probeBuf[:n], encoding)
				if encErr == nil {
					ensureVaryAcceptEncoding(c)
					c.Response.Header.Set("Content-Encoding", string(encoding))
					c.Response.Header.Del("Content-Length")
					c.Response.SetBodyRaw(encodedBody)
					return nil
				}
			}
			proxytransport.MarkResponseSizeUnknown(c)
			c.Response.SetBodyRaw(cloneProbe(n))
			return nil
		}
		if readErr != nil {
			if closeFn != nil {
				_ = closeFn()
			}
			resp.Body.Close()
			cancelUpstream()
			return readErr
		}
		if n < compOpts.MinBytes {
			n2, err2 := bodyReader.Read(probeBuf[n:])
			n += n2
			if err2 == io.EOF {
				if closeFn != nil {
					_ = closeFn()
				}
				cancelUpstream()
				copyResponseTrailers(c, resp)
				if shouldCompressCompleteUnknownLengthBody(n, compOpts, rt) {
					encodedBody, encErr := compressResponseBody(probeBuf[:n], encoding)
					if encErr == nil {
						ensureVaryAcceptEncoding(c)
						c.Response.Header.Set("Content-Encoding", string(encoding))
						c.Response.Header.Del("Content-Length")
						c.Response.SetBodyRaw(encodedBody)
						return nil
					}
				}
				c.Response.SetBodyRaw(cloneProbe(n))
				return nil
			}
			if err2 != nil {
				if closeFn != nil {
					_ = closeFn()
				}
				resp.Body.Close()
				cancelUpstream()
				return err2
			}
		}
		probedReader, isComplete, probeErr := probeStreamEOF(bodyReader)
		if probeErr != nil {
			if closeFn != nil {
				_ = closeFn()
			}
			resp.Body.Close()
			cancelUpstream()
			return probeErr
		}
		if isComplete {
			if closeFn != nil {
				_ = closeFn()
			}
			cancelUpstream()
			copyResponseTrailers(c, resp)
			if shouldCompressCompleteUnknownLengthBody(n, compOpts, rt) {
				if len(resp.Trailer) > 0 || rt.ResponseCompressionConfigured {
					return streamRecompressedResponse(ctx, c, bytes.NewReader(cloneProbe(n)), nil, resp, nil, encoding)
				}
				encodedBody, encErr := compressResponseBody(probeBuf[:n], encoding)
				if encErr == nil {
					ensureVaryAcceptEncoding(c)
					c.Response.Header.Set("Content-Encoding", string(encoding))
					c.Response.Header.Del("Content-Length")
					c.Response.SetBodyRaw(encodedBody)
					return nil
				}
			}
			proxytransport.MarkResponseSizeUnknown(c)
			c.Response.SetBodyRaw(cloneProbe(n))
			return nil
		}
		bodyReader = probedReader
		// MultiReader 可能在 return 后异步消费，必须 copy 前缀。
		combined := io.MultiReader(bytes.NewReader(cloneProbe(n)), bodyReader)
		return streamRecompressedResponse(ctx, c, combined, closeFn, resp, cancelUpstream, encoding)
	}
	if !decoded && encoding == responseEncodingIdentity && bodySize >= 0 &&
		bodySize <= maxBufferedRawResponseBytes && resp.Trailer == nil &&
		!isStreamingResponseContentType(resp.Header) {
		if bodySize == 0 {
			if closeFn != nil {
				_ = closeFn()
			}
			cancelUpstream()
			copyResponseTrailers(c, resp)
			c.Response.Header.Set("Content-Length", "0")
			c.Response.SetBodyRaw(nil)
			return nil
		}
		probe := make([]byte, bodySize)
		n, readErr := bodyReader.Read(probe)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			if closeFn != nil {
				_ = closeFn()
			}
			resp.Body.Close()
			cancelUpstream()
			return readErr
		}
		if n == bodySize && resp.Trailer == nil {
			if closeFn != nil {
				_ = closeFn()
			}
			cancelUpstream()
			copyResponseTrailers(c, resp)
			c.Response.Header.Set("Content-Length", strconv.Itoa(n))
			c.Response.SetBodyRaw(probe[:n])
			return nil
		}
		// 未一次读完（上游仍在发送）或读取过程中出现了 trailer：前缀必须独立
		// 拷贝后再与剩余流拼接，MultiReader 会在本次函数返回后异步消费。
		prefix := append([]byte(nil), probe[:n]...)
		bodyReader = io.MultiReader(bytes.NewReader(prefix), bodyReader)
	}
	if !decoded && bodySize < 0 && len(resp.Trailer) == 0 && !isStreamingResponseContentType(resp.Header) {
		buffered, rest, complete, probeErr := probeCompleteResponseBody(bodyReader)
		if probeErr != nil {
			if closeFn != nil {
				_ = closeFn()
			}
			resp.Body.Close()
			cancelUpstream()
			return probeErr
		}
		if complete {
			if closeFn != nil {
				_ = closeFn()
			}
			cancelUpstream()
			copyResponseTrailers(c, resp)
			c.Response.Header.Set("Content-Length", strconv.Itoa(len(buffered)))
			c.Response.SetBodyRaw(buffered)
			return nil
		}
		bodyReader = io.MultiReader(bytes.NewReader(buffered), rest)
	}
	c.Response.ImmediateHeaderFlush = streamBodySize < 0
	if bodySize < 0 {
		c.Response.Header.Del("Content-Length")
		c.Response.Header.SetContentLength(-1)
	}
	stream := newProxyBodyStream(ctx, bodyReader, closeFn, resp, c, cancelUpstream)
	if StreamResponseViaHijack(ctx, c, stream, stream.cleanup) {
		return nil
	}
	c.Response.SetBodyStream(stream, streamBodySize)
	return nil
}

// isStreamingResponseContentType 判断响应是否声明了不可缓冲的流式语义。
//
// text/event-stream（SSE）、application/x-ndjson（行式日志流）与
// multipart/x-mixed-replace（MJPEG）依赖逐块即时下发，缓冲会破坏其实时性，
// 因此这类响应保持原有流式转发路径。SSE 另有 ForwardSSE 独立入口，这里
// 再排除一次是为了覆盖「客户端未带 Accept 但上游仍返回 SSE」的情形。
//
// @param h 上游响应头。
// @return 是否属于不可缓冲的流式类型。
func isStreamingResponseContentType(h http.Header) bool {
	ct := strings.ToLower(strings.TrimSpace(h.Get("Content-Type")))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "text/event-stream", "application/x-ndjson", "multipart/x-mixed-replace":
		return true
	}
	return false
}

/**
 * probeCompleteResponseBody 尝试把未知长度响应体的前缀读入内存，并判断
 * 响应是否已经结束。
 *
 * 判定策略与压缩探测路径一致：先读满 streamProbeSize；未读满且仍未见到
 * 结束时，再用 probeStreamEOF 做 5ms EOF 探测。只有确认 EOF 才返回
 * complete=true，此时 buffered 就是完整响应体；否则 buffered 是已读前缀
 * 的独立拷贝，rest 是可继续读取的剩余流，两者需由调用方拼接后转发，
 * 不会丢失任何字节。
 *
 * @param bodyReader 上游响应体读取器。
 * @return buffered 已读前缀（独立于池缓冲）；rest 剩余流；complete 是否已读完；
 *   err 读取错误。
 */
func probeCompleteResponseBody(bodyReader io.Reader) ([]byte, io.Reader, bool, error) {
	bufp := streamCopyBufPool.Get().(*[]byte)
	buf := *bufp
	if cap(buf) < streamProbeSize {
		buf = make([]byte, streamProbeSize)
		*bufp = buf
	} else {
		buf = buf[:streamProbeSize]
	}
	defer putStreamCopyBuf(bufp)

	n, err := bodyReader.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, false, err
	}
	if errors.Is(err, io.EOF) {
		return append([]byte(nil), buf[:n]...), bytes.NewReader(nil), true, nil
	}
	if n < streamProbeSize {
		n2, err2 := bodyReader.Read(buf[n:])
		n += n2
		if errors.Is(err2, io.EOF) {
			return append([]byte(nil), buf[:n]...), bytes.NewReader(nil), true, nil
		}
		if err2 != nil {
			return nil, nil, false, err2
		}
		rest, complete, probeErr := probeStreamEOF(bodyReader)
		if probeErr != nil {
			return nil, nil, false, probeErr
		}
		return append([]byte(nil), buf[:n]...), rest, complete, nil
	}
	return append([]byte(nil), buf[:n]...), bodyReader, false, nil
}

/**
 * forwardHTTPWithTransform 缓冲上游响应（上限 maxStreamTransformBufferBytes），施加身份响应变换后写回。
 *
 * 响应体超过缓冲上限时，回退为不做变换的流式转发。
 *
 * @param ctx 请求上下文。
 * @param c Hertz 请求上下文。
 * @param rt 站点运行时。
 * @param resp 上游响应。
 * @param cancelUpstream 取消上游请求的函数。
 * @param transformer 身份响应变换器。
 * @param clientIP 客户端 IP。
 * @return 写回下游过程中的错误。
 */
func forwardHTTPWithTransform(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, resp *http.Response, cancelUpstream context.CancelFunc, transformer identityResponseTransformer, clientIP net.IP) error {
	body, _, remaining, closeFn, decoded, truncated, readErr := readUpstreamResponseBodyLimited(resp, maxStreamTransformBufferBytes)
	if readErr != nil {
		cancelUpstream()
		return readErr
	}

	if truncated {
		bodyReader := io.MultiReader(bytes.NewReader(body), remaining)
		c.Response.Header.Del("Content-Encoding")
		c.Response.Header.Del("Content-Length")
		c.Response.Header.SetContentLength(-1)

		compOpts := streamCompressionOptions(rt)
		encoding := responseEncodingIdentity
		if compOpts.Enabled && shouldTransformStreamingResponseBody(
			resp.StatusCode,
			resp.Header.Get("Content-Type"),
			"",
			resp.Header.Get("Cache-Control"),
			resp.Header.Get("Content-Range"),
			maxStreamTransformBufferBytes+1,
			compOpts.MinBytes,
		) {
			encoding = selectClientResponseEncodingBytes(c.GetHeader("Accept-Encoding"), compOpts.BrotliEnabled, compOpts.GzipEnabled, compOpts.DeflateEnabled, compOpts.ZstdEnabled)
		}
		if encoding != responseEncodingIdentity {
			return streamRecompressedResponse(ctx, c, bodyReader, closeFn, resp, cancelUpstream, encoding)
		}

		c.Response.ImmediateHeaderFlush = true
		stream := newProxyBodyStream(ctx, bodyReader, closeFn, resp, c, cancelUpstream)
		if StreamResponseViaHijack(ctx, c, stream, stream.cleanup) {
			return nil
		}
		c.Response.SetBodyStream(stream, -1)
		return nil
	}

	cancelUpstream()
	c.Response.Header.Del("Content-Encoding")
	if decoded {
		c.Response.Header.Del("Content-Length")
	}
	transformed, changed, err := transformIdentityResponseBody(c, resp.StatusCode, body, transformer, clientIP)
	if err != nil {
		writeResponseTransformFailure(c)
		return nil
	}
	if changed {
		transformed = applyClientResponseCompressionWithOptions(c, resp.StatusCode, transformed, streamCompressionOptions(rt))
	} else {
		transformed = applyClientResponseCompressionWithOptions(c, resp.StatusCode, body, streamCompressionOptions(rt))
	}
	c.Response.SetBodyRaw(transformed)
	return nil
}

func defaultStreamCompressionOptions() ResponseCompressionOptions {
	return ResponseCompressionOptions{
		Enabled:        true,
		BrotliEnabled:  true,
		GzipEnabled:    true,
		DeflateEnabled: true,
		ZstdEnabled:    true,
		MinBytes:       snapshot.DefaultResponseCompressionMinBytes,
	}
}

func streamCompressionOptions(rt snapshot.SiteRuntime) ResponseCompressionOptions {
	if !rt.ResponseCompressionConfigured {
		return defaultStreamCompressionOptions()
	}
	return normalizeResponseCompressionOptions(ResponseCompressionOptions{
		Enabled:        rt.ResponseCompressionEnabled,
		BrotliEnabled:  rt.BrotliEnabled,
		GzipEnabled:    rt.ResponseCompressionGzipEnabled,
		DeflateEnabled: rt.ResponseCompressionDeflateEnabled,
		ZstdEnabled:    rt.ResponseCompressionZstdEnabled,
		MinBytes:       rt.ResponseCompressionMinBytes,
	})
}

func shouldCompressCompleteUnknownLengthBody(bodySize int, opts ResponseCompressionOptions, rt snapshot.SiteRuntime) bool {
	if bodySize < opts.MinBytes {
		return false
	}
	if rt.ResponseCompressionConfigured {
		return true
	}
	return bodySize <= completeUnknownLengthCompressMaxBytes
}

type recompressedResponseBody struct {
	reader *io.PipeReader
	stop   func(error)
	done   <-chan struct{}
}

func (b *recompressedResponseBody) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

func (b *recompressedResponseBody) Close() error {
	b.stop(context.Canceled)
	<-b.done
	return nil
}

/**
 * streamRecompressedResponse 搭建非阻塞的流式压缩管线。
 *
 * 由一个 goroutine 从 src 读取、压缩并写入管道，管道读端经 SetBodyStream
 * 交给 Hertz，ForwardHTTP 因此可以立即返回。
 *
 * @param ctx 请求上下文。
 * @param c Hertz 请求上下文。
 * @param src 上游响应体读取器。
 * @param closeFn 上游资源关闭函数。
 * @param resp 上游响应，用于读取状态码与头。
 * @param cancel 取消上游请求的函数。
 * @param encoding 目标压缩编码。
 * @return 建立管线过程中的错误。
 */
func streamRecompressedResponse(ctx context.Context, c *app.RequestContext, src io.Reader, closeFn func() error, resp *http.Response, cancel context.CancelFunc, encoding responseEncoding) error {
	ensureVaryAcceptEncoding(c)
	c.Response.Header.Set("Content-Encoding", string(encoding))
	c.Response.Header.Del("Content-Length")
	c.Response.Header.SetContentLength(-1)

	pr, pw := io.Pipe()
	streamDone := make(chan struct{})
	var stopOnce sync.Once
	stop := func(err error) {
		stopOnce.Do(func() {
			if cancel != nil {
				cancel()
			}
			_ = pr.CloseWithError(err)
		})
	}
	go func() {
		defer close(streamDone)
		defer closeUpstreamResponse(cancel, closeFn, resp)
		defer copyResponseTrailers(c, resp)

		compWriter, closeComp := newStreamCompressWriter(pw, encoding)
		bufp := streamCopyBufPool.Get().(*[]byte)
		defer putStreamCopyBuf(bufp)
		buf := *bufp
		for {
			n, readErr := src.Read(buf)
			if n > 0 {
				if _, writeErr := compWriter.Write(buf[:n]); writeErr != nil {
					closeComp()
					_ = pw.CloseWithError(writeErr)
					return
				}
				if flushWriter, ok := compWriter.(interface{ Flush() error }); ok {
					_ = flushWriter.Flush()
				}
			}
			if readErr != nil {
				closeComp()
				if readErr != io.EOF {
					_ = pw.CloseWithError(readErr)
				} else {
					_ = pw.Close()
				}
				return
			}
		}
	}()

	go func() {
		select {
		case <-ctx.Done():
			stop(ctx.Err())
		case <-streamDone:
		}
	}()

	c.Response.ImmediateHeaderFlush = true
	body := &recompressedResponseBody{reader: pr, stop: stop, done: streamDone}
	if StreamResponseViaHijack(ctx, c, body, func() { _ = body.Close() }) {
		return nil
	}
	c.Response.SetBodyStream(body, -1)
	return nil
}

/**
 * streamCompressedResponseFromReader 为已知长度的响应体搭建流式压缩。
 *
 * @param ctx 请求上下文。
 * @param c Hertz 请求上下文。
 * @param src 上游响应体读取器。
 * @param closeFn 上游资源关闭函数。
 * @param resp 上游响应。
 * @param cancel 取消上游请求的函数。
 * @param encoding 目标压缩编码。
 * @param bodySize 响应体长度。
 * @return 建立管线过程中的错误。
 */
func streamCompressedResponseFromReader(ctx context.Context, c *app.RequestContext, src io.Reader, closeFn func() error, resp *http.Response, cancel context.CancelFunc, encoding responseEncoding, bodySize int) error {
	return streamRecompressedResponse(ctx, c, src, closeFn, resp, cancel, encoding)
}

func StreamResponseViaHijack(ctx context.Context, c *app.RequestContext, src io.Reader, cleanup func()) bool {
	if c.Response.StatusCode() != http.StatusOK {
		return false
	}
	writer, err := http2.NewResponseWriter(c.GetConn())
	if err != nil {
		return false
	}
	wrapped := &finalizeOnceWriter{inner: writer}
	c.Response.HijackWriter(wrapped)
	if cleanup != nil {
		defer cleanup()
	}
	bufp := streamCopyBufPool.Get().(*[]byte)
	defer putStreamCopyBuf(bufp)
	buf := *bufp

	// 立即发送响应头，避免在 src.Read 阻塞时客户端无法收到 headers
	_, _ = c.Write(nil)
	if flushErr := c.Flush(); flushErr != nil {
		return true
	}

	for {
		select {
		case <-ctx.Done():
			return true
		default:
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			if _, writeErr := c.Write(buf[:n]); writeErr != nil {
				return true
			}
			if flushErr := c.Flush(); flushErr != nil {
				return true
			}
		}
		if readErr != nil {
			return true
		}
	}
}

/**
 * proxyBodyStream 包装上游响应体读取器供 SetBodyStream 使用。
 *
 * 它在 EOF 或 Close 时释放底层资源并搬运 trailer，同时监视请求上下文的取消。
 */
type proxyBodyStream struct {
	reader        io.Reader
	closeFn       func() error
	resp          *http.Response
	hertzCtx      *app.RequestContext
	cancel        context.CancelFunc
	done          chan struct{}
	mu            sync.Mutex
	cond          *sync.Cond
	activeReaders int
	closing       bool
	closed        bool
}

type finalizeOnceWriter struct {
	inner network.ExtWriter
	once  sync.Once
	err   error
}

func (w *finalizeOnceWriter) Write(p []byte) (int, error) {
	return w.inner.Write(p)
}

func (w *finalizeOnceWriter) Flush() error {
	return w.inner.Flush()
}

func (w *finalizeOnceWriter) Finalize() error {
	w.once.Do(func() {
		w.err = w.inner.Finalize()
	})
	return w.err
}

func newProxyBodyStream(ctx context.Context, reader io.Reader, closeFn func() error, resp *http.Response, hertzCtx *app.RequestContext, cancel context.CancelFunc) *proxyBodyStream {
	s := &proxyBodyStream{
		reader:   reader,
		closeFn:  closeFn,
		resp:     resp,
		hertzCtx: hertzCtx,
		cancel:   cancel,
		done:     make(chan struct{}),
	}
	go func() {
		select {
		case <-ctx.Done():
			s.cleanup()
		case <-s.done:
		}
	}()
	return s
}

func (s *proxyBodyStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	if s.closing || s.closed {
		s.mu.Unlock()
		return 0, io.EOF
	}
	s.activeReaders++
	s.mu.Unlock()

	n, err := s.reader.Read(p)

	s.mu.Lock()
	s.activeReaders--
	if s.activeReaders == 0 && s.cond != nil {
		s.cond.Broadcast()
	}
	s.mu.Unlock()
	if err != nil {
		s.cleanup()
	}
	return n, err
}

func (s *proxyBodyStream) Close() error {
	s.cleanup()
	return nil
}

func (s *proxyBodyStream) cleanup() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if s.closing {
		s.initCondLocked()
		for !s.closed {
			s.cond.Wait()
		}
		s.mu.Unlock()
		return
	}
	s.closing = true
	close(s.done)
	cancel := s.cancel
	s.cancel = nil
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	s.mu.Lock()
	s.initCondLocked()
	for s.activeReaders > 0 {
		s.cond.Wait()
	}
	s.mu.Unlock()

	copyResponseTrailers(s.hertzCtx, s.resp)
	closeUpstreamResponse(nil, s.closeFn, s.resp)

	s.mu.Lock()
	s.closed = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *proxyBodyStream) initCondLocked() {
	if s.cond == nil {
		s.cond = sync.NewCond(&s.mu)
	}
}

const probeEOFTimeout = 5 * time.Millisecond

/**
 * probeStreamEOF 用一次短时非阻塞读取探测上游响应体是否已经完整。
 *
 * 对 chunked 响应而言，首次 Read 可能返回全部数据字节却不带 EOF —— 零长度
 * 结束块尚未到达。本函数因此另起一个短命 goroutine 读取：若 EOF 在
 * probeEOFTimeout 内到达即判定响应体已全部缓冲，否则 bodyReader 仍可用于流式读取。
 *
 * @param bodyReader 上游响应体读取器。
 * @return reader 可继续读的读取器（探测到 EOF 时可能并入探测到的字节）；
 *   complete 是否已完整；err 读取错误。
 */
func probeStreamEOF(bodyReader io.Reader) (io.Reader, bool, error) {
	type probeResult struct {
		data []byte
		err  error
	}
	ch := make(chan probeResult, 1)
	go func() {
		var one [1]byte
		n, err := bodyReader.Read(one[:])
		res := probeResult{err: err}
		if n > 0 {
			res.data = append(res.data, one[:n]...)
		}
		ch <- res
	}()

	timer := time.NewTimer(probeEOFTimeout)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()

	select {
	case r := <-ch:
		if r.err == io.EOF && len(r.data) == 0 {
			return bytes.NewReader(nil), true, nil
		}
		if r.err != nil && r.err != io.EOF {
			return nil, false, r.err
		}
		if len(r.data) == 0 {
			return bodyReader, false, nil
		}
		if r.err == io.EOF {
			return bytes.NewReader(r.data), false, nil
		}
		return io.MultiReader(bytes.NewReader(r.data), bodyReader), false, nil
	case <-timer.C:
		pr, pw := io.Pipe()
		go func() {
			r := <-ch
			if len(r.data) > 0 {
				if _, err := pw.Write(r.data); err != nil {
					_ = pw.CloseWithError(err)
					return
				}
			}
			if r.err != nil && r.err != io.EOF {
				_ = pw.CloseWithError(r.err)
				return
			}
			_ = pw.Close()
		}()
		return io.MultiReader(pr, bodyReader), false, nil
	}
}

func copyResponseTrailers(c *app.RequestContext, resp *http.Response) {
	for k, vv := range resp.Trailer {
		lk := strings.ToLower(k)
		if isHopByHop(lk) {
			continue
		}
		for _, v := range vv {
			c.Response.Header.Trailer().Set(k, v)
		}
	}
}

func forwardedProtoFromHeader(raw []byte) string {
	start := 0
	end := len(raw)
	for start < end && isASCIISpace(raw[start]) {
		start++
	}
	for end > start && isASCIISpace(raw[end-1]) {
		end--
	}
	if start == end {
		return ""
	}
	trimmed := raw[start:end]
	switch len(trimmed) {
	case len("h3"):
		if asciiEqualFoldBytes(trimmed, "h3") {
			return "h3"
		}
	case len("http"):
		if asciiEqualFoldBytes(trimmed, "http") {
			return "http"
		}
	case len("https"):
		if asciiEqualFoldBytes(trimmed, "https") {
			return "https"
		}
	}
	return strings.ToLower(string(trimmed))
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

func isHopByHopBytes(name []byte) bool {
	switch len(name) {
	case len("te"):
		return asciiEqualFoldBytes(name, "te")
	case len("trailer"):
		return asciiEqualFoldBytes(name, "trailer") || asciiEqualFoldBytes(name, "upgrade")
	case len("connection"):
		return asciiEqualFoldBytes(name, "connection") || asciiEqualFoldBytes(name, "keep-alive")
	case len("proxy-connection"):
		return asciiEqualFoldBytes(name, "proxy-connection")
	case len("transfer-encoding"):
		return asciiEqualFoldBytes(name, "transfer-encoding")
	case len("proxy-authenticate"):
		return asciiEqualFoldBytes(name, "proxy-authenticate")
	case len("proxy-authorization"):
		return asciiEqualFoldBytes(name, "proxy-authorization")
	}
	return false
}

func asciiEqualFoldBytes(got []byte, want string) bool {
	if len(got) != len(want) {
		return false
	}
	for i, b := range got {
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if b != want[i] {
			return false
		}
	}
	return true
}

/**
 * isHopByHop 判断给定头名是否为逐跳头（大小写无关）。
 *
 * 与 isHopByHopBytes 共用同一份长度分派判据：直接复用字节版本即可，编译器对
 * 「只读且不逃逸」的 string→[]byte 转换不做拷贝，因此这里不会产生分配。
 * 旧的 map + strings.ToLower 实现每个头名都要分配一次小写串，是响应热路径的
 * 固定开销。
 *
 * @param name 头名。
 * @return 是逐跳头时返回 true。
 */
func isHopByHop(name string) bool {
	return isHopByHopBytes([]byte(name))
}

/**
 * IsHopByHop 判断给定头名是否为转发响应时应当剥离的逐跳头。
 *
 * @param name 头名。
 * @return 是逐跳头时返回 true。
 */
func IsHopByHop(name string) bool { return isHopByHop(name) }

/**
 * RequestConnectionHeaderStripper 按 Connection 头列出的令牌执行剥离。
 */
type RequestConnectionHeaderStripper struct {
	tokens map[string]struct{}
}

/**
 * NewRequestConnectionHeaderStripper 依据请求的 Connection 头构造剥离器。
 *
 * @param c Hertz 请求上下文。
 * @return 剥离器；Connection 未列出任何令牌时返回 nil。
 */
func NewRequestConnectionHeaderStripper(c *app.RequestContext) *RequestConnectionHeaderStripper {
	s := &RequestConnectionHeaderStripper{tokens: make(map[string]struct{})}
	for _, val := range c.Request.Header.PeekAll("Connection") {
		parseConnectionTokensInto(val, s.tokens)
	}
	parseRawHeaderConnectionTokens(c.Request.Header.RawHeaders(), s.tokens)
	if len(s.tokens) == 0 {
		return nil
	}
	return s
}

func parseConnectionTokensInto(val []byte, tokens map[string]struct{}) {
	for len(val) > 0 {
		part := val
		if comma := bytes.IndexByte(val, ','); comma >= 0 {
			part = val[:comma]
			val = val[comma+1:]
		} else {
			val = nil
		}
		part = bytes.TrimSpace(part)
		if len(part) > 0 {
			tokens[lowerConnectionToken(part)] = struct{}{}
		}
	}
}

func parseRawHeaderConnectionTokens(raw []byte, tokens map[string]struct{}) {
	for len(raw) > 0 {
		var line []byte
		if idx := bytes.Index(raw, []byte("\r\n")); idx >= 0 {
			line = raw[:idx]
			raw = raw[idx+2:]
		} else {
			line = raw
			raw = nil
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := bytes.TrimSpace(line[:colon])
		if asciiEqualFoldBytes(key, "connection") {
			parseConnectionTokensInto(bytes.TrimSpace(line[colon+1:]), tokens)
		}
	}
}

/**
 * ShouldStrip 判断给定头键是否应当剥离。
 *
 * 令牌在插入时就已折叠为小写，因此成员判定用零分配的 ASCII 折叠比较，
 * 而不是对每个键调用 ToLower。
 *
 * @param key 待判定的头键。
 * @return 应剥离时返回 true。
 */
func (s *RequestConnectionHeaderStripper) ShouldStrip(key []byte) bool {
	if s == nil || len(s.tokens) == 0 {
		return false
	}
	for tok := range s.tokens {
		if asciiEqualFoldBytes(key, tok) {
			return true
		}
	}
	return false
}

/**
 * lowerConnectionToken 返回 Connection 头令牌的 ASCII 小写形式，除返回的副本外不额外分配。
 *
 * 令牌字节来自请求缓冲，会在 handler 返回后被复用，因此小写结果不得与其
 * 别名 —— 除非本来就没有字符发生变化。
 *
 * @param raw 原始令牌字节。
 * @return 小写令牌；无变化时直接复用原字节。
 */
func lowerConnectionToken(raw []byte) string {
	lower := make([]byte, len(raw))
	changed := false
	for i, b := range raw {
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
			changed = true
		}
		lower[i] = b
	}
	if !changed {
		return string(raw)
	}
	return string(lower)
}

/**
 * trimASCIIHeaderSpaceBytes 去除字节切片两端的 ASCII 空格。
 *
 * @param raw 原始字节。
 * @return 去空白后的子切片。
 */
func trimASCIIHeaderSpaceBytes(raw []byte) []byte {
	start := 0
	end := len(raw)
	for start < end && isASCIISpace(raw[start]) {
		start++
	}
	for end > start && isASCIISpace(raw[end-1]) {
		end--
	}
	return raw[start:end]
}
