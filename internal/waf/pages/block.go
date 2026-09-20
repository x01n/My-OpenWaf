package pages

import (
	"bytes"
	"html/template"
	"io/fs"
	"strconv"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/adminweb"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/pageconfig"
)

// WriteBlockResponse renders the intercept block page.
func WriteBlockResponse(c *app.RequestContext, reqID string, rt *snapshot.SiteRuntime, sn *snapshot.Snapshot, res action.Result) {
	c.Response.Header.Set("X-Request-ID", reqID)
	c.Response.Header.Del("Server")

	statusCode := res.ResponseStatusCode()
	html := ""
	if sn != nil {
		html = sn.DefaultBlockHTML
	}

	if rt != nil {
		if rt.BlockHTML != "" {
			html = rt.BlockHTML
		}
		if statusCode == 403 && rt.BlockStatus > 0 {
			statusCode = rt.BlockStatus
		}
	}

	if html != "" {
		renderTemplatePage(c, html, reqID, res, statusCode, false)
		return
	}

	if sn != nil {
		data := configuredPageConfig(sn.BlockPage, action.Normalize(res.Type) == action.RateLimit)
		data.RequestID = reqID
		data.StatusLabel = strconv.Itoa(statusCode)
		if statusCode == 429 {
			data.StatusLabel += " Too Many Requests"
		} else {
			data.StatusLabel += " Forbidden"
		}
		c.Data(statusCode, "text/html; charset=utf-8", renderConfiguredBlockPage(data))
		return
	}

	renderEmbeddedPage(c, "block/index.html", statusCode, reqID, res.RuleIDStr)
}

// WriteMaintenanceResponse renders the maintenance page.
func WriteMaintenanceResponse(c *app.RequestContext, reqID string, rt *snapshot.SiteRuntime, sn *snapshot.Snapshot) {
	c.Response.Header.Set("X-Request-ID", reqID)
	c.Response.Header.Del("Server")

	html := ""
	statusCode := 503

	if rt != nil && rt.MaintenanceHTML != "" {
		html = rt.MaintenanceHTML
		if rt.MaintenanceStatus > 0 {
			statusCode = rt.MaintenanceStatus
		}
	} else if sn.Protection.MaintenanceGlobalHTML != "" {
		html = sn.Protection.MaintenanceGlobalHTML
		if sn.Protection.MaintenanceGlobalStatus > 0 {
			statusCode = sn.Protection.MaintenanceGlobalStatus
		}
	}

	if html != "" {
		renderTemplatePage(c, html, reqID, action.Result{}, statusCode, true)
		return
	}

	renderEmbeddedPage(c, "maintenance/index.html", statusCode, reqID, "")
}

// WriteChallengeResponse renders a JS challenge page that the client must solve.
// envCheck 为 true 时在挑战页注入浏览器/环境采集 JS，提交时携带 v1 AES-256-GCM
// 加密的 __waf_env_fp；服务端使用挑战令牌的原始 32 字节值校验该密文。
//
// tokenClaims 把挑战 token 绑定到发起请求的客户端（IP/UA/Host/站点），
// 其他客户端拿到页面里的 rid/ts/token 三元组也无法换取通行凭证。
func WriteChallengeResponse(c *app.RequestContext, reqID string, rt *snapshot.SiteRuntime, envCheck bool, statusCode int, cfg pageconfig.ChallengePageConfig, tokenClaims challenge.ChallengeTokenClaims) {
	c.Response.Header.Set("X-Request-ID", reqID)
	c.Response.Header.Del("Server")
	c.Response.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate")

	ts, token := challenge.GenerateChallengeTokenPairWithClaims(reqID, tokenClaims)

	envJS := ""
	envKeyHex := ""
	if envCheck {
		envKeyHex = challenge.EnvSessionKeyHex(challenge.EnvSessionKeyFromChallengeToken(token))
		if envKeyHex == "" {
			c.String(500, "environment challenge key generation failed")
			return
		}
		aad := challenge.EnvFingerprintAAD("challenge", reqID, challenge.ChallengeSessionBinding{
			SiteID: tokenClaims.SiteID,
			Host:   tokenClaims.Host,
		})
		envJS = challenge.EnvCheckJSEncrypted(envKeyHex, aad)
	}
	// 工作量证明一律由 Rust WASM 模块在 Web Worker 中求解，无 JS 降级路径：
	// WASM 加载失败即抛错、挑战不通过，避免纯 JS 实现被轻易改写或跳过。
	// 以 token 作为 nonce，使工作量与本次挑战绑定，无法预算或跨挑战复用。
	powScript := challenge.GeneratePoWWASMScript(challenge.ChallengeProofDifficulty, token)
	html := buildChallengeHTML(reqID, ts, token, envJS, powScript, cfg)
	c.Data(statusCode, "text/html; charset=utf-8", []byte(html))
}

// WriteUpstreamErrorResponse renders an error page for upstream failures.
func WriteUpstreamErrorResponse(c *app.RequestContext, reqID string, statusCode int) {
	c.Response.Header.Set("X-Request-ID", reqID)
	c.Response.Header.Del("Server")

	page, err := loadEmbeddedPage("error/index.html")
	if err != nil {
		c.Data(statusCode, "text/html; charset=utf-8", []byte(buildErrorFallbackHTML(reqID, statusCode)))
		return
	}
	page = bytes.ReplaceAll(page, []byte("__WAF_REQUEST_ID__"), []byte(reqID))
	page = bytes.ReplaceAll(page, []byte("__WAF_STATUS_CODE__"), []byte(strconv.Itoa(statusCode)))
	page = bytes.ReplaceAll(page, []byte(`"/_next/`), []byte(`"/__owaf/_next/`))
	page = bytes.ReplaceAll(page, []byte(`'/_next/`), []byte(`'/__owaf/_next/`))
	c.Data(statusCode, "text/html; charset=utf-8", page)
}

func renderTemplatePage(c *app.RequestContext, html, reqID string, res action.Result, statusCode int, maintenance bool) {
	tpl, err := template.New("page").Parse(html)
	if err != nil {
		c.Data(statusCode, "text/html; charset=utf-8", []byte(defaultFallbackHTML(reqID, res, maintenance, action.Intercept)))
		return
	}
	// 防止信息泄露：仅填充 RequestID 和 StatusCode，
	// 其余字段保留空字符串以兼容自定义模板引用但不暴露 WAF 内部信息。
	var buf bytes.Buffer
	_ = tpl.Execute(&buf, struct {
		RequestID  string
		RuleID     string
		RuleIDStr  string
		Phase      string
		Action     string
		Category   string
		MatchDesc  string
		StatusCode int
	}{
		RequestID:  reqID,
		RuleID:     "",
		RuleIDStr:  "",
		Phase:      "",
		Action:     "",
		Category:   "",
		MatchDesc:  "",
		StatusCode: statusCode,
	})
	c.Data(statusCode, "text/html; charset=utf-8", buf.Bytes())
}

func renderEmbeddedPage(c *app.RequestContext, assetPath string, statusCode int, reqID, ruleID string) {
	page, err := loadEmbeddedPage(assetPath)
	if err != nil {
		c.Data(statusCode, "text/html; charset=utf-8", []byte(defaultFallbackHTML(reqID, action.Result{RuleIDStr: ruleID}, assetPath == "maintenance/index.html", action.Intercept)))
		return
	}

	page = bytes.ReplaceAll(page, []byte("__WAF_STATUS_CODE__"), []byte(strconv.Itoa(statusCode)))
	page = bytes.ReplaceAll(page, []byte("__WAF_REQUEST_ID__"), []byte(reqID))
	if assetPath == "block/index.html" {
		ruleID = ""
	}
	page = bytes.ReplaceAll(page, []byte("__WAF_RULE_ID__"), []byte(ruleID))
	page = bytes.ReplaceAll(page, []byte(`"/_next/`), []byte(`"/__owaf/_next/`))
	page = bytes.ReplaceAll(page, []byte(`'/_next/`), []byte(`'/__owaf/_next/`))
	c.Data(statusCode, "text/html; charset=utf-8", page)
}

func loadEmbeddedPage(assetPath string) ([]byte, error) {
	webFS, err := adminweb.SubFS()
	if err != nil {
		return nil, err
	}
	return fs.ReadFile(webFS, assetPath)
}

func defaultFallbackHTML(reqID string, _ action.Result, maintenance bool, actionType action.Type) string {
	data := fallbackPageData{
		Maintenance: maintenance,
		RequestID:   reqID,
	}
	if maintenance {
		data.Title = "服务维护中"
		data.Message = "服务正在进行维护，请稍后再试。The service is under maintenance, please try again later."
		data.Label = "503 Service Unavailable"
	} else {
		data.Title = "访问被拒绝"
		data.Message = "您的请求已被 Web 应用防火墙拦截。Your request was blocked by the web application firewall."
		data.Label = "403 Forbidden"
		if action.Normalize(actionType) == action.RateLimit {
			data.Title = "请求过于频繁"
			data.Message = "当前访问频率过高，请稍后重试。Too many requests, please retry later."
			data.Label = "429 Too Many Requests"
		}
	}
	return renderFallbackPage(data)
}

func valueOrFallback(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func buildErrorFallbackHTML(reqID string, statusCode int) string {
	data := upstreamErrorPageData{
		StatusCode: statusCode,
		Title:      "Error",
		TitleZh:    "错误",
		Message:    "An error occurred while processing your request.",
		MessageZh:  "处理您的请求时发生错误。",
		RequestID:  reqID,
		Icon:       template.HTML("&#9888;"),
	}
	switch statusCode {
	case 502:
		data.Title = "Bad Gateway"
		data.TitleZh = "网关错误"
		data.Message = "The upstream server returned an invalid response."
		data.MessageZh = "上游服务器返回了无效的响应。"
		data.Icon = template.HTML("&#9889;")
	case 503:
		data.Title = "Service Unavailable"
		data.TitleZh = "服务不可用"
		data.Message = "The service is temporarily unavailable."
		data.MessageZh = "服务暂时不可用，请稍后再试。"
		data.Icon = template.HTML("&#128736;")
	case 504:
		data.Title = "Gateway Timeout"
		data.TitleZh = "网关超时"
		data.Message = "The upstream server did not respond in time."
		data.MessageZh = "上游服务器未能及时响应。"
		data.Icon = template.HTML("&#9203;")
	}
	return renderUpstreamErrorPage(data)
}

func buildChallengeHTML(reqID, ts, token, envJS, powScript string, cfg pageconfig.ChallengePageConfig) string {
	defaults := pageconfig.DefaultChallengePageConfig()
	if cfg.BrandName == "" {
		cfg = defaults
	}
	data := challengePageData{
		RequestID:      reqID,
		EnvJS:          template.JS(envJS),
		PowScript:      template.JS(powScript),
		TimestampJS:    javascriptString(ts),
		TokenJS:        javascriptString(token),
		RequestIDJS:    javascriptString(reqID),
		PageTitle:      valueOrFallback(cfg.Title, defaults.Title),
		BrandName:      valueOrFallback(cfg.BrandName, defaults.BrandName),
		CheckingText:   valueOrFallback(cfg.CheckingText, defaults.CheckingText),
		CheckingTextZh: valueOrFallback(cfg.CheckingTextZh, defaults.CheckingTextZh),
		WaitText:       valueOrFallback(cfg.WaitText, defaults.WaitText),
		WaitTextZh:     valueOrFallback(cfg.WaitTextZh, defaults.WaitTextZh),
		FooterText:     valueOrFallback(cfg.FooterText, defaults.FooterText),
		PrimaryColor:   template.CSS(pageconfig.SafePrimaryColor(cfg.PrimaryColor, defaults.PrimaryColor)),
		Background:     template.CSS(pageconfig.SafeBackground(cfg.BgGradient, defaults.BgGradient)),
		LogoURL:        pageconfig.SafeLogoURL(cfg.LogoURL),
		CustomCSS:      template.CSS(pageconfig.SanitizeCSS(cfg.CustomCSS)),
	}
	page, err := executePageTemplate("challenge.html", data)
	if err != nil {
		return "<!DOCTYPE html><html><head><title>Security Check</title></head><body><h1>Security Check</h1></body></html>"
	}
	return string(page)
}
