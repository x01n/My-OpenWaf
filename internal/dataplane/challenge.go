package dataplane

import (
	"encoding/json"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/dataplane/logredact"
	"My-OpenWaf/internal/security"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/iprep"
	"My-OpenWaf/internal/waf/pages"
)

/**
 * cookieRenewJSONBody 是脚本上下文下返回的机器可读续期标记。
 *
 * 这是给**脚本**看的，不是给人看的：`fetch`/XHR 拿到 HTML 续期页会让
 * `response.json()` 抛 SyntaxError，调用方只能看到「请求失败」，无法区分
 * 「需要续期」与「真的出错」。
 *
 * 处理口径（必须让调用方知道，否则会误以为「返 JSON 就等于问题解决了」）：
 *   - 收到 {"renew":"required"} 的脚本**不能自行完成续期** —— 续期页需要在
 *     顶层导航里跑 WASM 才能落位 C2。脚本应把控制权交回页面路由层，由路由
 *     层导航一次当前 URL（GET）触发续期流程。
 *   - **若页面代码不做这个处理，本请求就是失败状态**：不是静默成功，也不会
 *     被服务端自动重试。服务端不提供「重试即通过」的语义。
 */
type cookieRenewJSONBody struct {
	Renew string `json:"renew"`
	URL   string `json:"url"`
	Hint  string `json:"hint"`
}

// renewJSONHint 是给人读的兜底说明（脚本不应解析它，只用于排查）。
const renewJSONHint = "navigate to this URL in the top-level context to complete the session renewal"

/**
 * requestWantsRenewJSON 判定「本请求是脚本发起的，应返回 JSON 而非 HTML 续期页」。
 *
 * 判据来自实测（真实 Chromium 抓头，非规范推断）：
 *
 * 	fetch/XHR            -> Sec-Fetch-Dest: empty,  Sec-Fetch-Mode: cors
 * 	表单 POST / reload   -> Sec-Fetch-Dest: document, Sec-Fetch-Mode: navigate
 *
 * 因此**只有 `Dest: empty` 或 `Mode: cors|same-origin` 才算脚本**；顶层导航
 * （`Mode: navigate`）一律走 HTML 页。注意不能只按 `Mode: navigate` 反推——POST
 * 表单提交与 `location.reload()` 重提交同样是 navigate，按 navigate 反推会让
 * POST 表单提交拿到 HTML，而页面 reload 又是 POST，形成循环。
 *
 * **缺失回退**：`Sec-Fetch-*` 是 Chromium/Firefox 系特有头，Safari 与部分
 * 爬虫不带。头缺失时一律返回 false（走现状的 HTML 页面），既不返 JSON 也不
 * 拒服务——否则老客户端会拿到它读不懂的 JSON。
 */
func requestWantsRenewJSON(c *app.RequestContext) bool {
	if c == nil {
		return false
	}
	dest := logredact.ToLowerASCII(strings.TrimSpace(string(c.GetHeader("Sec-Fetch-Dest"))))
	mode := logredact.ToLowerASCII(strings.TrimSpace(string(c.GetHeader("Sec-Fetch-Mode"))))
	switch dest {
	case "empty":
		return true
	case "document":
		// 顶层导航：明确不是脚本，直接判定，避免被下面的 mode 分支误判。
		return false
	}
	switch mode {
	case "cors", "same-origin":
		return true
	}
	// 含 mode 缺失、navigate、no-cors（如 <img>/<script> 子资源）等一律走 HTML。
	return false
}

/**
 * writeRenewJSON 输出 412 + 机器可读标记 + Retry-After。
 *
 * Retry-After 取 1 秒：它表达的是「稍后重试」而非「多久之后一定会好」——
 * 真正的完成条件由页面导航触发，与等待时长无关。
 */
func writeRenewJSON(c *app.RequestContext, reqID string, requestURL string) {
	if reqID != "" {
		c.Response.Header.Set("X-Request-ID", reqID)
	}
	c.Response.Header.Del("Server")
	c.Response.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	c.Response.Header.Set("X-OWAF-Probe", "renew-json")
	c.Response.Header.Set("Retry-After", "1")
	body, err := json.Marshal(cookieRenewJSONBody{
		Renew: "required",
		URL:   requestURL,
		Hint:  renewJSONHint,
	})
	if err != nil {
		c.Data(http.StatusPreconditionFailed, "application/json", []byte(`{"renew":"required"}`))
		return
	}
	c.Data(http.StatusPreconditionFailed, "application/json; charset=utf-8", body)
}

// isStaticAsset 对常见的静态资产路径返回 true，这些路径应跳过 nonce 校验。
func isStaticAsset(lowerPath string) bool {
	staticExts := []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".map"}
	for _, ext := range staticExts {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	staticPrefixes := []string{"/static/", "/assets/", "/public/", "/favicon"}
	for _, prefix := range staticPrefixes {
		if strings.HasPrefix(lowerPath, prefix) {
			return true
		}
	}
	return false
}

// setNonceCookie 在响应上设置反重放 nonce cookie。
func setNonceCookie(c *app.RequestContext, nonce string, secure bool) {
	cookie := challenge.NonceKey + "=" + nonce + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" + strconv.Itoa(snapshot.OneDaySeconds)
	if secure {
		cookie += "; Secure"
	}
	c.Response.Header.Add("Set-Cookie", cookie)
}

// challengeSubmission 是 JS 挑战页回传的表单内容。
type challengeSubmission struct {
	TS        string
	Token     string
	RequestID string
	EnvFP     string
	// Proof/Counter 为工作量证明：SHA-256(Token+Counter) 需满足前导零难度。
	Proof   string
	Counter string
	// WASM 附带的环境评分及其签名。sig 用编译期盐计算，只能证明这些值未被
	// WASM 之外的脚本改写，不能证明 WASM 本身未被替换，故仅作附加信号。
	EnvScore   string
	EnvMarkers string
	PoWSig     string
}

func challengeSubmissionValues(body []byte, contentType string) (challengeSubmission, bool) {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "application/x-www-form-urlencoded") {
		return challengeSubmission{}, false
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return challengeSubmission{}, false
	}

	sub := challengeSubmission{
		TS:         values.Get("__waf_challenge_ts"),
		Token:      values.Get("__waf_challenge_token"),
		RequestID:  values.Get("__waf_challenge_rid"),
		EnvFP:      values.Get("__waf_env_fp"),
		Proof:      values.Get("__waf_challenge_proof"),
		Counter:    values.Get("__waf_challenge_counter"),
		EnvScore:   values.Get("__waf_env_score"),
		EnvMarkers: values.Get("__waf_env_markers"),
		PoWSig:     values.Get("__waf_pow_sig"),
	}
	return sub, sub.TS != "" && sub.Token != "" && sub.RequestID != ""
}

/**
 * antiReplayCookieSkipPath 判断 Cookie AntiReplay 内建跳过路径。
 *
 * @param requestPath 请求路径。
 * @return 静态资源或内部 OWAF 资源返回 true。
 */
func antiReplayCookieSkipPath(requestPath string) bool {
	lowerPath := logredact.ToLowerASCII(requestPath)
	return strings.HasPrefix(lowerPath, "/__owaf/") || isStaticAsset(lowerPath)
}

/**
 * clientAcceptsHTML 判断请求是否来自能渲染并执行 HTML/JS 的客户端。
 *
 * 判据是 Accept 显式包含 text/html：浏览器导航请求一律发送
 * "text/html,application/xhtml+xml,..."；curl、blazehttp、gotestwaf 与一般
 * API 客户端默认发送通配符 Accept 或不发送 Accept 头。通配符只表示
 * 「任何类型都接受」，不代表客户端会解析并执行页面内联脚本，因此不计入。
 *
 * @param c Hertz 请求上下文。
 * @return 显式接受 text/html 时返回 true。
 */
func clientAcceptsHTML(c *app.RequestContext) bool {
	if c == nil {
		return false
	}
	return strings.Contains(logredact.ToLowerASCII(string(c.GetHeader("Accept"))), "text/html")
}

/**
 * handleAntiReplayCookie 执行 Cookie nonce 的签发、校验和轮换。
 *
 * @param c Hertz 请求上下文。
 * @param opts 数据面处理器配置。
 * @param sn 当前配置快照。
 * @param rt 当前站点运行时。
 * @return handled 表示响应已完成；consumedNonce 表示本请求已消费的 Cookie nonce。
 */
func handleAntiReplayCookie(
	c *app.RequestContext,
	opts Options,
	sn *snapshot.Snapshot,
	rt *snapshot.SiteRuntime,
	reqID string,
	clientIP string,
	host string,
	requestPath string,
	method string,
	userAgent string,
	rawQuery string,
	accessLog *slog.Logger,
) (handled bool, consumedNonce string) {
	if c == nil || rt == nil || opts.Engine == nil || antiReplayCookieSkipPath(requestPath) {
		return false, ""
	}
	manager := opts.Engine.AntiReplay()
	if manager == nil {
		return false, ""
	}

	nonceCookie := string(c.Cookie(challenge.NonceKey))
	// 站点/全局合并后的 Cookie 校验模式；非 "dual"（含空串脏值）一律回落 standard。
	mode := snapshot.NormalizeAntiReplayCookieMode(rt.AntiReplayCookieMode)
	// dual 的续期页依赖浏览器执行内联 JS 落位 C2，非浏览器客户端（无 JS
	// 运行时）会在每一步都停留在 412，站点对它完全不可用。因此 dual 的
	// 页面续期只对显式接受 text/html 的客户端生效；其余客户端按 Cookie
	// 自身状态照常校验，续期页不参与：缺 Cookie 时降级为 standard 的首访
	// 语义（签发 C1 后放行，不渲染续期页），携带无效 C1 时仍按站点配置的
	// 反重放动作处置，重放仍拦截 —— 防护强度不因客户端类型而降低。
	//
	// 续期页的本质是「让浏览器把同一请求再发一次」，这个机制**只对幂等方法
	// 成立**：页面结束时执行 location.reload()，而实测确认 reload 会重提交
	// POST（连同请求体与 Content-Type）。若对非幂等方法也回 412 续期页，
	// 序列会是「POST -> 412 续期页 -> reload 重提交同一 POST -> 仍无有效 C1
	// -> 412 ...」的循环，请求永远无法自动恢复。因此非幂等方法不进续期页，
	// 照常走下面的 Cookie 状态判定（缺 Cookie 时仍签发 C1 并放行，携带无效
	// C1 时仍按站点反重放动作处置）—— 重放拦截语义不变。
	renewRequired := mode == "dual" && clientAcceptsHTML(c) && !isUnsafeRequestMethod(method)
	if nonceCookie == "" {
		// 首访：standard 沿用原语义——签发 C1 后直接放行（fail-open）。
		// dual 则在签发 C1 的同一响应上渲染 412 续期页，由浏览器落位 C2 后重试。
		fresh := manager.GenerateNonce(clientIP)
		setNonceCookie(c, fresh, rt.Site.TLSEnabled)
		if renewRequired {
			recordAntiReplayRenewEvent(c, opts, sn, accessLog, reqID, host, clientIP, requestPath, method, userAgent, rawQuery, rt)
			return true, ""
		}
		return false, ""
	}

	ttl := time.Duration(0)
	if rt.Site.AntiReplayTTL > 0 {
		ttl = time.Duration(rt.Site.AntiReplayTTL) * time.Second
	}
	valid, isReplay, newNonce := manager.ValidateAndRotate(nonceCookie, clientIP, ttl)
	switch {
	case valid:
		if renewRequired && string(c.Cookie(challenge.NoncePairKey)) == "" {
			// dual 下 C1 合法但 C2 缺失：轮换 C1 并渲染续期页，不触上游。
			setNonceCookie(c, newNonce, rt.Site.TLSEnabled)
			recordAntiReplayRenewEvent(c, opts, sn, accessLog, reqID, host, clientIP, requestPath, method, userAgent, rawQuery, rt)
			return true, ""
		}
		if renewRequired {
			// dual 下 C1 合法且 C2 存在：校验 C2 的服务端 MAC。
			// MAC 绑定 (clientIP, exp) 而非 C1——C1 每请求都被轮换成新值，
			// 若绑定 C1 则「用下一枚 C1 校验绑定上一枚 C1 的 MAC」永不匹配，
			// dual 站点会陷入无限 412。不可伪造由 k_mac 不下发保证。
			if challenge.VerifyC2Cookie(string(c.Cookie(challenge.NoncePairKey)), clientIP) {
				// C2 有效：轮换 C1 后放行本轮请求。
				setNonceCookie(c, newNonce, rt.Site.TLSEnabled)
				return false, nonceCookie
			}
			// C2 无效：轮换 C1、重新签发种子并回 412 续期页，不触上游。
			setNonceCookie(c, newNonce, rt.Site.TLSEnabled)
			recordAntiReplayRenewEvent(c, opts, sn, accessLog, reqID, host, clientIP, requestPath, method, userAgent, rawQuery, rt)
			return true, ""
		}
		setNonceCookie(c, newNonce, rt.Site.TLSEnabled)
		return false, nonceCookie
	case isReplay:
		blockAction := action.Result{
			Type:      action.Intercept,
			Phase:     "anti_replay",
			RuleIDStr: "antireplay:nonce_reuse",
			MatchDesc: "replayed nonce detected",
			Matched:   true,
			Category:  "replay",
		}
		revoked, warnMsg := revokeAccessSessionIfPresent(c, rt)
		if warnMsg != "" && opts.Log != nil {
			opts.Log.Warn("revoke access session on replay failed",
				slog.String("request_id", reqID),
				slog.Uint64("site_id", uint64(rt.Site.ID)),
				slog.String("err", warnMsg),
			)
		} else if revoked && opts.Log != nil {
			opts.Log.Warn("access session revoked on replay",
				slog.String("request_id", reqID),
				slog.Uint64("site_id", uint64(rt.Site.ID)),
			)
		}
		clearChallengePassCookie(c, rt.Site.TLSEnabled)
		if opts.Metrics != nil {
			opts.Metrics.RecordWAFBlock()
		}
		if opts.Writer != nil {
			recordSecurityEvent(c, opts, store.SecurityEvent{
				SiteID:     rt.Site.ID,
				RequestID:  reqID,
				ClientIP:   clientIP,
				Host:       host,
				Path:       requestPath,
				Method:     method,
				UserAgent:  userAgent,
				RuleIDStr:  blockAction.RuleIDStr,
				Phase:      blockAction.Phase,
				Action:     string(action.Intercept),
				Category:   blockAction.Category,
				MatchDesc:  blockAction.MatchDesc,
				StatusCode: http.StatusForbidden,
			})
		}
		pages.WriteBlockResponse(c, reqID, rt, sn, blockAction)
		logAccess(accessLog, reqID, method, requestPath, host, http.StatusForbidden, string(action.Intercept))
		recordAccessLog(c, opts, accessLogInfo{
			SiteID: rt.Site.ID, RequestID: reqID, ClientIP: clientIP, Host: host,
			Path: requestPath, QueryString: rawQuery, Method: method, UserAgent: userAgent,
			StatusCode: http.StatusForbidden, WAFAction: string(action.Intercept), CacheState: "bypass",
		})
		return true, ""
	default:
		fresh := manager.GenerateNonce(clientIP)
		setNonceCookie(c, fresh, rt.Site.TLSEnabled)
		if renewRequired {
			// dual 下 C1 无效：重建 C1 并渲染续期页（profile_renew 事件），不触上游。
			recordAntiReplayRenewEvent(c, opts, sn, accessLog, reqID, host, clientIP, requestPath, method, userAgent, rawQuery, rt)
			return true, ""
		}
		antiReplayAct := normalizeAntiReplayAction(rt.AntiReplayAction)
		challengeResult := action.Result{
			Type:      action.Type(antiReplayAct),
			Phase:     "anti_replay",
			RuleIDStr: "antireplay:invalid_nonce",
			MatchDesc: "expired or invalid nonce",
			Matched:   true,
			Category:  "replay",
		}
		if opts.Metrics != nil {
			opts.Metrics.RecordWAFBlock()
		}
		if opts.Writer != nil {
			recordSecurityEvent(c, opts, store.SecurityEvent{
				SiteID:     rt.Site.ID,
				RequestID:  reqID,
				ClientIP:   clientIP,
				Host:       host,
				Path:       requestPath,
				Method:     method,
				UserAgent:  userAgent,
				RuleIDStr:  challengeResult.RuleIDStr,
				Phase:      challengeResult.Phase,
				Action:     antiReplayAct,
				Category:   challengeResult.Category,
				MatchDesc:  challengeResult.MatchDesc,
				StatusCode: http.StatusForbidden,
			})
		}
		writeAntiReplayActionResponse(c, opts, sn, rt, reqID, antiReplayAct, challengeResult, http.StatusForbidden)
		statusCode := accessStatusCode(c, antiReplayAct)
		logAccess(accessLog, reqID, method, requestPath, host, statusCode, antiReplayAct)
		recordAccessLog(c, opts, accessLogInfo{
			SiteID: rt.Site.ID, RequestID: reqID, ClientIP: clientIP, Host: host,
			Path: requestPath, QueryString: rawQuery, Method: method, UserAgent: userAgent,
			StatusCode: statusCode, WAFAction: antiReplayAct, CacheState: "bypass",
		})
		return true, ""
	}
}

func normalizeAntiReplayAction(raw string) string {
	switch action.Normalize(action.Type(raw)) {
	case action.CaptchaChallenge:
		return string(action.CaptchaChallenge)
	case action.ShieldChallenge:
		return string(action.ShieldChallenge)
	case action.ChainChallenge:
		return string(action.ChainChallenge)
	case action.Intercept:
		return string(action.Intercept)
	case action.Challenge:
		return string(action.Challenge)
	default:
		return string(action.Challenge)
	}
}

/**
 * recordAntiReplayRenewEvent 记录 dual 模式下的一次 Cookie 续期（profile_renew）：
 * 渲染 412 续期页、写安全事件（RuleIDStr "antireplay:profile_renew",
 * Action "challenge", Category "replay"）与访问日志。
 *
 * @param c Hertz 请求上下文
 * @param opts 数据面处理器配置
 * @param sn 当前快照，供续期页品牌渲染（nil 时回落默认品牌）
 * @param accessLog 结构化访问日志器，nil 时跳过
 * @param reqID 请求 ID
 * @param host 请求 Host 头
 * @param clientIP 已解析的客户端 IP
 * @param requestPath 请求路径
 * @param method 请求方法
 * @param userAgent 请求 User-Agent
 * @param rawQuery 原始查询串
 * @param rt 当前站点运行时
 */
func recordAntiReplayRenewEvent(
	c *app.RequestContext,
	opts Options,
	sn *snapshot.Snapshot,
	accessLog *slog.Logger,
	reqID string,
	host string,
	clientIP string,
	requestPath string,
	method string,
	userAgent string,
	rawQuery string,
	rt *snapshot.SiteRuntime,
) {
	// 脚本上下文（fetch/XHR）拿到 HTML 续期页会让 response.json() 抛
	// SyntaxError，调用方无法区分「需要续期」与「真的出错」。这类请求改发
	// 机器可读标记；顶层导航与不带 Sec-Fetch-* 的客户端仍走完整页面。
	if requestWantsRenewJSON(c) {
		writeRenewJSON(c, reqID, string(c.Request.URI().RequestURI()))
	} else {
		// dual 续期页需要把「服务端算出的 C2 种子」交给浏览器：种子以单片分片
		// 信封形态经 GM 信封（域 0x06）下发，客户端用现成的
		// wasm_bindgen.vm_assemble_shards 在 WASM 内存内解出，再把信封里的 cookie
		// 字段原样落位（客户端不拼接、不计算）。签发失败（密钥未装载等）时种子
		// 为空，页面回退到「重新加载、由服务端再次签发」，不会硬失败也不会放行。
		seedEnvelope, seedKeyHex, _ := challenge.IssueC2Seed(clientIP)
		pages.WriteCookieRenewPage(c, reqID, rt, sn, http.StatusPreconditionFailed, pages.CookieRenewSeed{Envelope: seedEnvelope, KeyHex: seedKeyHex})
	}
	if opts.Writer != nil {
		recordSecurityEvent(c, opts, store.SecurityEvent{
			SiteID:     rt.Site.ID,
			RequestID:  reqID,
			ClientIP:   clientIP,
			Host:       host,
			Path:       requestPath,
			Method:     method,
			UserAgent:  userAgent,
			RuleIDStr:  "antireplay:profile_renew",
			Phase:      "anti_replay",
			Action:     "challenge",
			Category:   "replay",
			MatchDesc:  "dual-cookie profile missing pair cookie",
			StatusCode: http.StatusPreconditionFailed,
		})
	}
	logAccess(accessLog, reqID, method, requestPath, host, http.StatusPreconditionFailed, "challenge")
	recordAccessLog(c, opts, accessLogInfo{
		SiteID: rt.Site.ID, RequestID: reqID, ClientIP: clientIP, Host: host,
		Path: requestPath, QueryString: rawQuery, Method: method, UserAgent: userAgent,
		StatusCode: http.StatusPreconditionFailed, WAFAction: "challenge", CacheState: "bypass",
	})
}

/**
 * siteChallengeAction 按「站点 → 全局」顺序解析质询动作覆盖：
 * 站点 rt.ChallengeAction 非空则优先；否则全局 ProtectionConfig.ChallengeAction
 * 非空且合法时使用；两者都不可用时返回空串，由调用方按原 result.Action.Type 分发。
 */
func siteChallengeAction(rt *snapshot.SiteRuntime, sn *snapshot.Snapshot) string {
	if rt != nil && rt.ChallengeAction != "" {
		act := action.Normalize(action.Type(rt.ChallengeAction))
		if act == action.Challenge || act == action.CaptchaChallenge || act == action.ShieldChallenge || act == action.ChainChallenge {
			return string(act)
		}
	}
	if sn != nil {
		global := sn.Protection.ChallengeAction
		if global != "" {
			act := action.Normalize(action.Type(global))
			if act == action.Challenge || act == action.CaptchaChallenge || act == action.ShieldChallenge || act == action.ChainChallenge {
				return string(act)
			}
		}
	}
	return ""
}

/**
 * effectiveCaptchaType 计算验证码渲染分支使用的验证码类型：
 * 规则级 result.Action.CaptchaType 合法则优先；否则站点 rt.ChallengeCaptchaType；
 * 再否则全局 sn.Protection.CaptchaType。
 */
func effectiveCaptchaType(result action.Result, rt *snapshot.SiteRuntime, sn *snapshot.Snapshot) challenge.CaptchaType {
	if challenge.IsValidCaptchaType(challenge.CaptchaType(result.CaptchaType)) {
		return challenge.CaptchaType(result.CaptchaType)
	}
	if rt != nil {
		if t := challenge.CaptchaType(rt.ChallengeCaptchaType); challenge.IsValidCaptchaType(t) {
			return t
		}
	}
	if sn != nil {
		if t := challenge.CaptchaType(sn.Protection.CaptchaType); challenge.IsValidCaptchaType(t) {
			return t
		}
	}
	return "math"
}

/**
 * challengeTokenClaims 组装 JS 挑战 token 的客户端绑定信息。
 * 客户端 IP 按站点的 XFF 策略解析，与通行 cookie 使用同一套身份字段，
 * 保证挑战页与其换取的通行凭证绑定到同一个客户端。
 */
func challengeSessionBinding(c *app.RequestContext, opts Options) (challenge.ChallengeSessionBinding, bool) {
	if opts.Holder == nil {
		return challenge.ChallengeSessionBinding{}, false
	}
	sn := opts.Holder.Load()
	if sn == nil {
		return challenge.ChallengeSessionBinding{}, false
	}
	host := string(c.Host())
	bind := listenerBind(c)
	if bind == "" {
		bind = opts.Bind
	}
	rt, ok := sn.MatchSite(bind, host)
	if !ok {
		return challenge.ChallengeSessionBinding{}, false
	}
	return challengeSessionBindingForSite(rt.Site.ID, host, bind), true
}

func challengeSessionBindingForSite(siteID uint, host, bind string) challenge.ChallengeSessionBinding {
	return challenge.ChallengeSessionBinding{SiteID: siteID, Host: snapshot.NormalizeMatchHost(host), Bind: bind}
}

func challengeTokenClaims(c *app.RequestContext, rt *snapshot.SiteRuntime) challenge.ChallengeTokenClaims {
	claims := challenge.ChallengeTokenClaims{
		UserAgent: string(c.UserAgent()),
		Host:      string(c.Host()),
	}
	if rt != nil {
		claims.ClientIP = clientIPStr(security.ResolveClientIP(c, rt.XFFMode, rt.TrustedCIDR, rt.ClientIPHeaderOrder))
		claims.SiteID = rt.Site.ID
	}
	return claims
}

func writeAntiReplayActionResponse(c *app.RequestContext, opts Options, sn *snapshot.Snapshot, rt *snapshot.SiteRuntime, reqID, antiReplayAct string, result action.Result, statusCode int) {
	bind := listenerBind(c)
	if bind == "" {
		bind = opts.Bind
	}
	binding := challengeSessionBindingForSite(rt.Site.ID, string(c.Host()), bind)
	switch action.Type(antiReplayAct) {
	case action.CaptchaChallenge:
		if sn != nil && opts.CaptchaManager != nil {
			captchaType := effectiveCaptchaType(action.Result{}, rt, sn)
			challenge.WriteCaptchaChallengeResponse(c, reqID, opts.CaptchaManager, captchaType, sn.Protection.ShieldEnableEnvCheck, binding, statusCode, sn.CaptchaPage)
			return
		}
	case action.ShieldChallenge:
		if sn != nil && opts.ShieldManager != nil {
			origURL := string(c.Request.URI().RequestURI())
			opts.ShieldManager.WriteShieldChallengeResponse(c, reqID, origURL, requestProtocol(c), binding, statusCode)
			return
		}
	case action.ChainChallenge:
		if sn != nil && opts.ChainManager != nil {
			challenge.WriteChainChallengeResponse(c, reqID, opts.ChainManager, binding, statusCode)
			return
		}
	case action.Challenge:
		envCheck := sn != nil && sn.Protection.ShieldEnableEnvCheck
		pages.WriteChallengeResponse(c, reqID, rt, envCheck, statusCode, sn.ChallengePage, challengeTokenClaims(c, rt))
		return
	}
	pages.WriteBlockResponse(c, reqID, rt, sn, result)
}

/**
 * recordChallengeFailure 在服务端记录一次挑战验证失败。
 *
 * 三个 verify 端点原先失败即裸 redirect，服务端不留任何计数，客户端可无限重试。
 * ShieldMaxRetries 只在挑战页 JS 内判断，脚本化客户端重新 POST 即可绕过，
 * 因此必须由服务端把失败计入 IP 信誉。
 *
 * 复用既有的 iprep 违规计数（含滑动窗口、阈值与自动封禁 TTL），而不是新造一套
 * 计数器——避免对同一事实产生第二数据源，也让运维只需调一处阈值。
 *
 * 已匹配站点时，客户端 IP 按站点 XFF 配置解析；命中站点白名单时，只跳过自动封禁
 * 的违规计数，不影响 challenge verify 原有的成功、失败或重定向语义。快照缺失或站点
 * 不匹配时回退 strip 模式，避免伪造 XFF 影响信誉计数。
 *
 * @param c    请求上下文。
 * @param opts 数据面选项，用于取 IP 信誉运行时与指标。
 */
func recordChallengeFailure(c *app.RequestContext, opts Options) {
	if opts.Engine == nil {
		return
	}
	ipRep := opts.Engine.IPReputation()
	if ipRep == nil {
		return
	}
	clientIP := security.ResolveClientIP(c, store.XFFModeStrip, "", nil)
	if opts.Holder != nil {
		sn := opts.Holder.Load()
		if sn != nil {
			host := string(c.Host())
			bind := listenerBind(c)
			if bind == "" {
				bind = opts.Bind
			}
			if rt, ok := sn.MatchSite(bind, host); ok {
				clientIP = security.ResolveClientIP(c, rt.XFFMode, rt.TrustedCIDR, rt.ClientIPHeaderOrder)
				if siteIPWhitelistContains(rt.SiteIPWhitelist, clientIP) {
					return
				}
			}
		}
	}
	if clientIP == nil {
		return
	}
	if ipRep.RecordViolation(clientIP) && opts.Metrics != nil {
		opts.Metrics.RecordWAFBlock()
	}
}

// siteIPWhitelistContains 采用与 IP 声誉相位相同的带过期时间条目语义。
func siteIPWhitelistContains(entries []iprep.IPListEntry, clientIP net.IP) bool {
	if clientIP == nil {
		return false
	}
	now := time.Now().Unix()
	for _, entry := range entries {
		if entry.ExpireAt > 0 && now > entry.ExpireAt {
			continue
		}
		if entry.CIDR != nil && entry.CIDR.Contains(clientIP) || entry.Single != nil && entry.Single.Equal(clientIP) {
			return true
		}
	}
	return false
}

func setChallengeCookie(c *app.RequestContext, opts Options) {
	sn := opts.Holder.Load()
	if sn == nil {
		return
	}
	host := string(c.Host())
	bind := listenerBind(c)
	if bind == "" {
		bind = opts.Bind
	}
	rt, ok := sn.MatchSite(bind, host)
	if !ok {
		return
	}
	clientIP := security.ResolveClientIP(c, rt.XFFMode, rt.TrustedCIDR, rt.ClientIPHeaderOrder)
	cookie := challenge.BuildChallengePassCookieWithClaims(challenge.ChallengePassClaims{Host: host, ClientIP: clientIP, UserAgent: string(c.UserAgent()), SiteID: rt.Site.ID, Bind: bind}, rt.Site.TLSEnabled, time.Now(), challengePassTTL(sn.Protection))
	c.Response.Header.Add("Set-Cookie", cookie)
}

/**
 * clearChallengePassCookie 在防重放命中等安全场景下吊销挑战免验态。
 * __waf_passed 是无状态签名（服务端无存储），吊销语义即响应追加该 cookie
 * 的清除头。属性必须与签发侧 BuildChallengePassCookieWithClaims 一致
 * （Path=/、HttpOnly、SameSite=Strict、Secure 随站点 TLS），否则浏览器会
 * 视作不同 cookie 而清不掉。
 */
func clearChallengePassCookie(c *app.RequestContext, secure bool) {
	cookie := challenge.ChallengePassCookieName + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
	if secure {
		cookie += "; Secure"
	}
	c.Response.Header.Add("Set-Cookie", cookie)
}

func challengePassTTL(prot store.ProtectionConfig) time.Duration {
	if prot.CaptchaPassTTL > 0 {
		return time.Duration(prot.CaptchaPassTTL) * time.Second
	}
	if prot.CaptchaTimeout > 0 {
		return time.Duration(prot.CaptchaTimeout) * time.Second
	}
	return time.Hour
}

/**
 * handleChallengeVerify 处理发往质询验证端点的 POST 请求。
 * 返回 true 表示请求已被处理（调用方应提前返回）。
 */
func handleChallengeVerify(c *app.RequestContext, opts Options) bool {
	if string(c.Method()) != "POST" {
		return false
	}

	path := string(c.Path())
	switch path {
	case "/__owaf/captcha/verify":
		return handleCaptchaVerify(c, opts)
	case "/__owaf/shield/verify":
		return handleShieldVerify(c, opts)
	case "/__owaf/chain/verify":
		return handleChainVerify(c, opts)
	}
	return false
}

func handleCaptchaVerify(c *app.RequestContext, opts Options) bool {
	if opts.CaptchaManager == nil {
		c.String(503, "captcha not configured")
		return true
	}
	binding, ok := challengeSessionBinding(c, opts)
	if !ok {
		recordChallengeFailure(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
		return true
	}

	sessionID := string(c.FormValue("__waf_captcha_session"))
	answer := string(c.FormValue("__waf_captcha_answer"))
	envFP := string(c.FormValue("__waf_env_fp"))

	if sessionID == "" || answer == "" {
		recordChallengeFailure(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
		return true
	}
	ok, session := opts.CaptchaManager.VerifyAdvancedSessionWithBinding(sessionID, answer, binding)
	if ok && !challenge.VerifyCaptchaEnvEnvelope(envFP, session) {
		ok = false
	}

	if ok {
		setChallengeCookie(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
	} else {
		recordChallengeFailure(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
	}
	return true
}

func handleShieldVerify(c *app.RequestContext, opts Options) bool {
	if opts.ShieldManager == nil {
		c.String(503, "shield not configured")
		return true
	}
	binding, ok := challengeSessionBinding(c, opts)
	if !ok {
		recordChallengeFailure(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
		return true
	}

	sessionID := string(c.FormValue("__waf_shield_session"))
	captchaAnswer := string(c.FormValue("__waf_captcha_answer"))
	counterStr := string(c.FormValue("__waf_pow_counter"))
	hash := string(c.FormValue("__waf_pow_hash"))
	envFP := string(c.FormValue("__waf_env_fp"))
	// 客户端只采集上报，判定全在服务端：
	// probe 的 dt/auto 由服务端加分为软信号并入盾 verify 的硬门槛。
	probeJSON := string(c.FormValue("__waf_shield_probe"))

	counterText := strings.TrimSpace(counterStr)
	if counterText == "" {
		recordChallengeFailure(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
		return true
	}
	counter, err := strconv.ParseInt(counterText, 10, 64)
	if err != nil || counter < 0 {
		recordChallengeFailure(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
		return true
	}

	passed, originalURL := opts.ShieldManager.VerifyChallengeWithBinding(sessionID, captchaAnswer, counter, hash, envFP, probeJSON, requestProtocol(c), binding)
	if passed {
		setChallengeCookie(c, opts)
		if originalURL == "" {
			originalURL = "/"
		}
		c.Redirect(302, []byte(originalURL))
	} else {
		// Re-challenge。失败计入 IP 信誉：ShieldMaxRetries 只在页面 JS 内生效，
		// 脚本化客户端重新 POST 即可绕过，必须由服务端侧限制重试。
		recordChallengeFailure(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
	}
	return true
}

func handleChainVerify(c *app.RequestContext, opts Options) bool {
	if opts.ChainManager == nil {
		c.String(503, "chain challenge not configured")
		return true
	}
	binding, ok := challengeSessionBinding(c, opts)
	if !ok {
		recordChallengeFailure(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
		return true
	}

	sessionID := string(c.FormValue("__waf_chain_session"))
	stepType := string(c.FormValue("__waf_chain_step"))

	formData := map[string]string{
		"env_fp":         string(c.FormValue("__waf_env_fp")),
		"pow_counter":    string(c.FormValue("__waf_pow_counter")),
		"pow_hash":       string(c.FormValue("__waf_pow_hash")),
		"captcha_answer": string(c.FormValue("__waf_captcha_answer")),
		"step_type":      stepType,
	}

	// 用 Detailed 版本：链内「正常推进到下一步」与「步内校验失败重渲染当前步」
	// 的三元返回值完全相同，只有 Failed 能区分，否则会把正常访客计为失败。
	outcome := opts.ChainManager.ProcessStepDetailedWithBinding(sessionID, formData, binding)
	if outcome.Failed {
		recordChallengeFailure(c, opts)
	}
	switch {
	case outcome.Passed:
		setChallengeCookie(c, opts)
		redirectURL := outcome.RedirectURL
		if redirectURL == "" {
			redirectURL = "/"
		}
		c.Redirect(302, []byte(redirectURL))
	case outcome.NextHTML != "":
		c.Data(403, "text/html; charset=utf-8", []byte(outcome.NextHTML))
	default:
		c.Redirect(302, []byte("/"))
	}
	return true
}
