package dataplane

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	pathpkg "path"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/adminweb"
	"My-OpenWaf/internal/dataplane/logredact"
	dpreqid "My-OpenWaf/internal/dataplane/reqid"
	"My-OpenWaf/internal/security"
	"My-OpenWaf/internal/waf/challenge"
	challengepow "My-OpenWaf/internal/waf/challenge/pow"
	dynamicpkg "My-OpenWaf/internal/waf/dynamic"
	"My-OpenWaf/internal/waf/owasp"
)

/**
 * isScriptCreatedOWAFPath 判断被 JavaScript 改写过的路径是否指向内部 OWAF 命名空间。
 * 额外做一次 URL 路径解码，可一并封堵那些上游路由器可能在路由匹配前自行解码的编码形式。
 */
func isScriptCreatedOWAFPath(rawPath string) bool {
	isInternal := func(value string) bool {
		lowerValue := strings.ToLower(value)
		if lowerValue == "/__owaf" || strings.HasPrefix(lowerValue, "/__owaf/") {
			return true
		}
		cleanValue := strings.ToLower(pathpkg.Clean(value))
		return cleanValue == "/__owaf" || strings.HasPrefix(cleanValue, "/__owaf/")
	}
	if isInternal(rawPath) {
		return true
	}
	decodedPath, err := url.PathUnescape(rawPath)
	return err == nil && decodedPath != rawPath && isInternal(decodedPath)
}

/**
 * matchInlineOWASPGuards 检查那些必须在通用管道之前执行、且在请求阶段的路径或请求体
 * 改写之后还要再执行一次的请求级快捷判定。
 */
func matchInlineOWASPGuards(path, query string, body []byte, contentType, host, ciscoASAMode string) (action.Result, bool) {
	lowerPath := logredact.ToLowerASCII(path)
	if strings.Contains(lowerPath, "/translation-table") {
		if owasp.CheckCiscoASAInlineGuard(path, query, ciscoASAMode) {
			return action.Result{
				Type:      action.Intercept,
				Phase:     "owasp_default",
				RuleIDStr: "owasp:path:015",
				MatchDesc: "Cisco translation-table path traversal pattern",
				Matched:   true,
				Category:  string(owasp.CatPathTrav),
			}, true
		}
	}
	if strings.EqualFold(path, "/uc/feedback/api/v1/pc/feedback/add") && contentType == "" && len(body) > 0 {
		rawBody := strings.TrimSpace(string(body))
		if len(rawBody) > 48*1024 {
			rawBody = rawBody[:48*1024]
		}
		normalized := owasp.NormalizeForDebug(rawBody)
		if owasp.IsOpaqueEncodedAttackBodyForDebug(rawBody, normalized, map[string]string{"Host": host}, 3) {
			return action.Result{
				Type:      action.Intercept,
				Phase:     "owasp_default",
				RuleIDStr: "owasp:proto:010",
				MatchDesc: "opaque encoded body without content-type",
				Matched:   true,
				Category:  string(owasp.CatProtoViol),
			}, true
		}
	}
	return action.Pass(), false
}

func serveOWAFStatic(c *app.RequestContext, webFS fs.FS) bool {
	if webFS == nil {
		return false
	}

	path := string(c.Path())
	if path != "/__owaf" && path != "/__owaf/" && !strings.HasPrefix(path, "/__owaf/") {
		return false
	}

	assetPath := strings.TrimPrefix(path, "/__owaf")
	if assetPath == "" {
		assetPath = "/"
	}

	data, resolvedPath, err := adminweb.ReadRouteFile(webFS, assetPath)
	if err != nil {
		c.String(404, "not found")
		return true
	}

	c.Data(200, adminweb.ContentType(resolvedPath), data)
	return true
}

func handleACMEChallenge(c *app.RequestContext, lookup func(token string) (string, bool)) bool {
	const prefix = "/.well-known/acme-challenge/"
	if lookup == nil {
		return false
	}
	path := string(c.Path())
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	token := strings.TrimPrefix(path, prefix)
	if token == "" || strings.Contains(token, "/") {
		c.String(404, "not found")
		return true
	}
	response, ok := lookup(token)
	if !ok {
		c.String(404, "not found")
		return true
	}
	c.Response.Header.Set("Content-Type", "text/plain")
	c.String(200, response)
	return true
}

// handleWASMAssets 提供 PoW WASM 二进制与 JS 胶水文件。
func handleWASMAssets(c *app.RequestContext) bool {
	path := string(c.Path())
	switch path {
	case "/__owaf/pow.wasm":
		challengepow.ServePoWWASM(c)
		return true
	case "/__owaf/pow_glue.js":
		challengepow.ServePowGlueJS(c)
		return true
	}
	return false
}

type dynamicProtectionKeyRequest struct {
	Ticket string `json:"ticket"`
	Key    string `json:"key"`
}

/**
 * parseDynamicProtectionKeyRequest 仅解析服务端签发票据所需的字段。
 * 浏览器环境信号可由客户端任意构造，不能作为 KEK 兑换授权条件。
 */
func parseDynamicProtectionKeyRequest(body []byte) (dynamicProtectionKeyRequest, bool) {
	if len(body) == 0 {
		return dynamicProtectionKeyRequest{}, false
	}
	var req dynamicProtectionKeyRequest
	dec := json.NewDecoder(strings.NewReader(string(body)))
	if err := dec.Decode(&req); err != nil {
		return dynamicProtectionKeyRequest{}, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return dynamicProtectionKeyRequest{}, false
	}
	if req.Ticket == "" || req.Key == "" {
		return dynamicProtectionKeyRequest{}, false
	}
	return req, true
}

func handleDynamicProtectionKey(c *app.RequestContext, opts Options) bool {
	if string(c.Path()) != logredact.GroupKeyPath {
		return false
	}
	statusCode := http.StatusOK
	wafAction := "dynamic_key"
	requestID := dpreqid.FastRequestID()
	c.Response.Header.Set("X-Request-ID", requestID)
	c.Response.Header.Set("Cache-Control", "no-store")
	c.Response.Header.Set("Pragma", "no-cache")
	if opts.Metrics != nil {
		opts.Metrics.RecordRequest()
	}
	host := string(c.Host())
	bind := listenerBind(c)
	if bind == "" {
		bind = opts.Bind
	}
	var siteID uint
	var logClientIP net.IP
	defer func() {
		if opts.Metrics != nil {
			opts.Metrics.RecordStatus(statusCode)
		}
		if logClientIP == nil {
			logClientIP = security.ResolveClientIP(c, "", "", nil)
		}
		recordAccessLog(c, opts, accessLogInfo{SiteID: siteID, RequestID: requestID, ClientIP: clientIPStr(logClientIP), Host: host, Path: string(c.Path()), QueryString: string(c.URI().QueryString()), Method: string(c.Method()), UserAgent: string(c.UserAgent()), StatusCode: statusCode, WAFAction: wafAction, CacheState: "bypass"})
	}()
	if string(c.Method()) != http.MethodPost {
		statusCode = http.StatusMethodNotAllowed
		wafAction = "dynamic_key_error"
		c.JSON(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return true
	}
	body := c.Request.Body()
	if len(body) > dynamicProtectionKeyRequestBodyMax {
		statusCode = http.StatusRequestEntityTooLarge
		wafAction = "dynamic_key_error"
		c.JSON(http.StatusRequestEntityTooLarge, map[string]string{"error": "dynamic key request body too large"})
		return true
	}
	req, ok := parseDynamicProtectionKeyRequest(body)
	if !ok {
		statusCode = http.StatusBadRequest
		wafAction = "dynamic_key_error"
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid dynamic key request"})
		return true
	}
	sn := opts.Holder.Load()
	if sn == nil {
		statusCode = http.StatusServiceUnavailable
		wafAction = "dynamic_key_error"
		c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "configuration snapshot not loaded"})
		return true
	}
	rt, ok := sn.MatchSite(bind, host)
	if !ok {
		statusCode = http.StatusNotFound
		wafAction = "dynamic_key_error"
		c.JSON(http.StatusNotFound, map[string]string{"error": "site not found"})
		return true
	}
	siteID = rt.Site.ID
	clientIP := security.ResolveClientIP(c, rt.XFFMode, rt.TrustedCIDR, rt.ClientIPHeaderOrder)
	logClientIP = clientIP
	ttl := dynamicpkg.NormalizeDecryptCacheTTLSeconds(rt.DynamicProtection.DecryptCacheTTLSeconds)
	claims := challenge.DynamicProtectionClaims{Host: host, ClientIP: clientIP, UserAgent: string(c.UserAgent()), SiteID: rt.Site.ID, Bind: bind}
	kek, ok := challenge.VerifyDynamicProtectionKeyTicket(req.Ticket, challenge.DynamicProtectionKeyClaims{DynamicProtectionClaims: claims, Key: req.Key}, time.Now())
	if !ok {
		statusCode = http.StatusForbidden
		wafAction = "dynamic_key_error"
		c.JSON(http.StatusForbidden, map[string]string{"error": "invalid dynamic key ticket"})
		return true
	}
	cookie := challenge.BuildDynamicProtectionSessionCookieWithClaims(claims, rt.Site.TLSEnabled, time.Now(), time.Duration(ttl)*time.Second)
	c.Response.Header.Add("Set-Cookie", cookie)
	c.JSON(http.StatusOK, map[string]any{"kek": kek, "ttl": ttl})
	return true
}

// validateBasicAuth 校验 HTTP Basic Auth 凭据，使用常量时间比较防止时序攻击。
func validateBasicAuth(authHeader, expectedUser, expectedPass string) bool {
	if authHeader == "" || !strings.HasPrefix(authHeader, "Basic ") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(authHeader[6:])
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}
	userMatch := subtle.ConstantTimeCompare([]byte(parts[0]), []byte(expectedUser)) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expectedPass)) == 1
	return userMatch && passMatch
}
