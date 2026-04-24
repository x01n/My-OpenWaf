package waf

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"strconv"
	"text/template"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/adminweb"
	"My-OpenWaf/internal/snapshot"
)

// WriteBlockResponse renders the intercept block page.
func WriteBlockResponse(c *app.RequestContext, reqID string, rt *snapshot.SiteRuntime, sn *snapshot.Snapshot, res action.Result) {
	c.Response.Header.Set("X-Request-ID", reqID)
	c.Response.Header.Set("X-WAF-Action", string(action.Normalize(res.Type)))
	c.Response.Header.Del("Server")

	statusCode := res.EffectiveStatusCode(403)
	html := sn.DefaultBlockHTML

	if rt != nil {
		if rt.BlockHTML != "" {
			html = rt.BlockHTML
		}
		if statusCode == 403 && rt.BlockStatus > 0 {
			statusCode = rt.BlockStatus
		}
	}

	if html != "" {
		renderTemplatePage(c, html, reqID, res.RuleID, statusCode, false)
		return
	}

	renderEmbeddedPage(c, "blocked/index.html", statusCode, reqID, strconv.FormatUint(uint64(res.RuleID), 10))
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
		renderTemplatePage(c, html, reqID, 0, statusCode, true)
		return
	}

	renderEmbeddedPage(c, "maintenance/index.html", statusCode, reqID, "")
}

// challengeSecret is a fixed key used to sign JS challenge tokens.
// In production this should be configurable, but for now derive from a constant.
var challengeSecret = []byte("owaf-challenge-v1-secret-key-2026")

// WriteChallengeResponse renders a JS challenge page that the client must solve.
func WriteChallengeResponse(c *app.RequestContext, reqID string, rt *snapshot.SiteRuntime, statusCode int) {
	c.Response.Header.Set("X-Request-ID", reqID)
	c.Response.Header.Set("X-WAF-Action", "challenge")
	c.Response.Header.Del("Server")
	c.Response.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate")

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, challengeSecret)
	mac.Write([]byte(reqID + ":" + ts))
	token := hex.EncodeToString(mac.Sum(nil))

	html := buildChallengeHTML(reqID, ts, token)
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

// VerifyChallengeToken checks if a JS challenge response token is valid.
func VerifyChallengeToken(reqID, ts, token string, maxAge time.Duration) bool {
	mac := hmac.New(sha256.New, challengeSecret)
	mac.Write([]byte(reqID + ":" + ts))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(token), []byte(expected)) {
		return false
	}
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	return time.Since(time.Unix(tsInt, 0)) < maxAge
}

func renderTemplatePage(c *app.RequestContext, html, reqID string, ruleID uint, statusCode int, maintenance bool) {
	tpl, err := template.New("page").Parse(html)
	if err != nil {
		c.Data(statusCode, "text/html; charset=utf-8", []byte(defaultFallbackHTML(reqID, strconv.FormatUint(uint64(ruleID), 10), maintenance)))
		return
	}
	var buf bytes.Buffer
	_ = tpl.Execute(&buf, struct {
		RequestID  string
		RuleID     string
		StatusCode int
	}{RequestID: reqID, RuleID: strconv.FormatUint(uint64(ruleID), 10), StatusCode: statusCode})
	c.Data(statusCode, "text/html; charset=utf-8", buf.Bytes())
}

func renderEmbeddedPage(c *app.RequestContext, assetPath string, statusCode int, reqID, ruleID string) {
	page, err := loadEmbeddedPage(assetPath)
	if err != nil {
		c.Data(statusCode, "text/html; charset=utf-8", []byte(defaultFallbackHTML(reqID, ruleID, assetPath == "maintenance/index.html")))
		return
	}

	page = bytes.ReplaceAll(page, []byte("__WAF_REQUEST_ID__"), []byte(reqID))
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

func defaultFallbackHTML(reqID, ruleID string, maintenance bool) string {
	if maintenance {
		return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Maintenance</title></head><body><h1>Service under maintenance</h1><p>Request ID: ` + reqID + `</p></body></html>`
	}
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Blocked</title></head><body><h1>Request blocked</h1><p>Request ID: ` + reqID + `</p><p>Rule ID: ` + ruleID + `</p></body></html>`
}

func buildErrorFallbackHTML(reqID string, statusCode int) string {
	title := "Error"
	msg := "An error occurred while processing your request."
	switch statusCode {
	case 502:
		title = "Bad Gateway"
		msg = "The upstream server returned an invalid response."
	case 503:
		title = "Service Unavailable"
		msg = "The service is temporarily unavailable."
	case 504:
		title = "Gateway Timeout"
		msg = "The upstream server did not respond in time."
	}
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>` + title + `</title>` +
		`<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f8fafc;color:#1e293b}.c{text-align:center;max-width:480px;padding:2rem}h1{font-size:4rem;font-weight:800;color:#ef4444;margin-bottom:.5rem}h2{font-size:1.25rem;margin-bottom:1rem;color:#475569}p{color:#64748b;font-size:.875rem;margin-top:1.5rem}</style>` +
		`</head><body><div class="c"><h1>` + strconv.Itoa(statusCode) + `</h1><h2>` + title + `</h2><p>` + msg + `</p><p style="margin-top:2rem;font-size:.75rem">Request ID: ` + reqID + `</p></div></body></html>`
}

func buildChallengeHTML(reqID, ts, token string) string {
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Security Check</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f8fafc;color:#1e293b}.c{text-align:center;max-width:480px;padding:2rem}.spinner{width:48px;height:48px;border:4px solid #e2e8f0;border-top-color:#3b82f6;border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 1.5rem}@keyframes spin{to{transform:rotate(360deg)}}h2{font-size:1.25rem;margin-bottom:.5rem}p{color:#64748b;font-size:.875rem}#msg{margin-top:1rem;color:#ef4444;display:none}.rid{margin-top:2rem;font-size:.75rem;color:#94a3b8}</style>
</head><body><div class="c"><div class="spinner"></div><h2>正在验证您的浏览器</h2><p>此过程是自动的，请稍候...</p><p id="msg"></p><p class="rid">Request ID: ` + reqID + `</p></div>
<script>
(function(){
var ts="` + ts + `",tk="` + token + `",rid="` + reqID + `";
function solve(){
var start=Date.now(),sum=0;
for(var i=0;i<1e6;i++) sum=(sum+i*7)%1e9;
var elapsed=Date.now()-start;
var d=document.createElement("form");d.method="POST";d.style.display="none";
function af(n,v){var i=document.createElement("input");i.type="hidden";i.name=n;i.value=v;d.appendChild(i)}
af("__waf_challenge_ts",ts);af("__waf_challenge_token",tk);af("__waf_challenge_rid",rid);
af("__waf_challenge_proof",sum.toString());af("__waf_challenge_elapsed",elapsed.toString());
document.body.appendChild(d);d.submit();
}
setTimeout(solve,800+Math.random()*400);
})();
</script></body></html>`
}
