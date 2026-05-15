package waf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
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

// challengeSecret is used to sign JS challenge tokens and pass cookies.
// Generated at startup so it cannot be extracted from the binary.
// This means cookies are invalidated on restart, which is acceptable for security.
var challengeSecret = generateChallengeSecret()

func generateChallengeSecret() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}

// SetChallengeSecret allows overriding the secret (e.g. from JWT secret for consistency across restarts).
func SetChallengeSecret(secret []byte) {
	if len(secret) >= 16 {
		challengeSecret = secret
	}
}

const ChallengePassCookieName = "__waf_passed"

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

func BuildChallengePassCookie(host string, clientIP net.IP, tlsEnabled bool, now time.Time, ttl time.Duration) string {
	value := SignChallengePassValue(host, clientIP, now, ttl)
	cookie := &http.Cookie{
		Name:     ChallengePassCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   tlsEnabled,
	}
	return cookie.String()
}

func SignChallengePassValue(host string, clientIP net.IP, now time.Time, ttl time.Duration) string {
	if ttl <= 0 {
		ttl = time.Hour
	}
	expires := now.Add(ttl).Unix()
	// Random nonce per cookie to prevent replay and make each cookie unique.
	sessionNonce := make([]byte, 8)
	_, _ = rand.Read(sessionNonce)
	// Versioned format: v2|host|ip|expiry|nonce_hex|challenge_type
	payload := fmt.Sprintf("v2|%s|%s|%d|%x|shield",
		strings.ToLower(host),
		challengeIPString(clientIP),
		expires,
		sessionNonce,
	)
	encrypted, err := challengeEncrypt([]byte(payload))
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(encrypted)
}

func VerifyChallengePassCookie(cookieHeader, host string, clientIP net.IP, now time.Time) bool {
	if cookieHeader == "" {
		return false
	}
	for _, raw := range strings.Split(cookieHeader, ";") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		name, value, ok := strings.Cut(raw, "=")
		if !ok || name != ChallengePassCookieName {
			continue
		}
		return VerifyChallengePassValue(value, host, clientIP, now)
	}
	return false
}

func VerifyChallengePassValue(value, host string, clientIP net.IP, now time.Time) bool {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 {
		return false
	}
	plaintext, err := challengeDecrypt(raw)
	if err != nil {
		return false
	}
	parts := strings.Split(string(plaintext), "|")
	// v2 format: v2|host|ip|expiry|nonce|type (6 parts)
	if len(parts) >= 6 && parts[0] == "v2" {
		expires, err := strconv.ParseInt(parts[3], 10, 64)
		if err != nil || now.Unix() > expires {
			return false
		}
		return parts[1] == strings.ToLower(host) && parts[2] == challengeIPString(clientIP)
	}
	// v1 legacy format: host|ip|expiry (3 parts)
	if len(parts) == 3 {
		expires, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil || now.Unix() > expires {
			return false
		}
		return parts[0] == strings.ToLower(host) && parts[1] == challengeIPString(clientIP)
	}
	return false
}

func challengeEncrypt(plaintext []byte) ([]byte, error) {
	key := challengeDeriveAESKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func challengeDecrypt(ciphertext []byte) ([]byte, error) {
	key := challengeDeriveAESKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize+1 {
		return nil, fmt.Errorf("too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

func challengeDeriveAESKey() []byte {
	h := sha256.Sum256(append([]byte("owaf-challenge-aes256:"), challengeSecret...))
	return h[:]
}

func challengeIPString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
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
	baseStyle := `*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(160deg,#f0fdfa 0%,#f8fafc 40%,#f1f5f9 100%);color:#1e293b}.card{background:#fff;border-radius:16px;box-shadow:0 4px 32px rgba(0,0,0,.08);max-width:480px;width:92%;padding:48px 40px;text-align:center}.icon{font-size:48px;margin-bottom:12px}h1{font-size:1.2rem;font-weight:600;color:#334155;margin-bottom:12px}.msg{font-size:.85rem;color:#64748b;line-height:1.5}.meta{font-size:.7rem;color:#94a3b8;margin-top:16px}.footer{margin-top:20px;padding-top:14px;border-top:1px solid #f1f5f9;font-size:.7rem;color:#94a3b8}`
	if maintenance {
		return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Maintenance</title><style>` + baseStyle + `</style></head><body><div class="card"><div class="icon">&#128736;</div><h1>Service Under Maintenance / 服务维护中</h1><p class="msg">We are currently performing scheduled maintenance. Please try again later.</p><p class="msg">我们正在进行计划维护，请稍后再试。</p><p class="meta">Request ID: ` + reqID + `</p><div class="footer">Protected by My-OpenWAF</div></div></body></html>`
	}
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Blocked</title><style>` + baseStyle + `</style></head><body><div class="card"><div class="icon">&#128737;</div><h1>Access Denied / 访问被拒绝</h1><p class="msg">Your request has been blocked by the web application firewall.</p><p class="msg">您的请求已被Web应用防火墙拦截。</p><p class="meta">Request ID: ` + reqID + ` | Rule: ` + ruleID + `</p><div class="footer">Protected by My-OpenWAF</div></div></body></html>`
}

func buildErrorFallbackHTML(reqID string, statusCode int) string {
	title := "Error"
	titleZh := "错误"
	msg := "An error occurred while processing your request."
	msgZh := "处理您的请求时发生错误。"
	icon := "&#9888;"
	switch statusCode {
	case 502:
		title = "Bad Gateway"
		titleZh = "网关错误"
		msg = "The upstream server returned an invalid response."
		msgZh = "上游服务器返回了无效的响应。"
		icon = "&#9889;"
	case 503:
		title = "Service Unavailable"
		titleZh = "服务不可用"
		msg = "The service is temporarily unavailable."
		msgZh = "服务暂时不可用，请稍后再试。"
		icon = "&#128736;"
	case 504:
		title = "Gateway Timeout"
		titleZh = "网关超时"
		msg = "The upstream server did not respond in time."
		msgZh = "上游服务器未能及时响应。"
		icon = "&#9203;"
	}
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` + title + `</title>` +
		`<style>` +
		`*{margin:0;padding:0;box-sizing:border-box}` +
		`body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(160deg,#f0fdfa 0%,#f8fafc 40%,#f1f5f9 100%);color:#1e293b}` +
		`.card{background:#fff;border-radius:16px;box-shadow:0 4px 32px rgba(0,0,0,.08),0 1px 4px rgba(0,0,0,.04);max-width:480px;width:92%;padding:48px 40px;text-align:center}` +
		`.icon{font-size:52px;margin-bottom:8px;line-height:1.2}` +
		`.code{font-size:4rem;font-weight:800;color:#14b8a6;margin-bottom:4px}` +
		`h2{font-size:1.2rem;font-weight:600;color:#334155;margin-bottom:6px}` +
		`.msg{font-size:.9rem;color:#64748b;line-height:1.6;margin-bottom:4px}` +
		`.divider{width:48px;height:3px;background:#14b8a6;border-radius:2px;margin:20px auto}` +
		`.rid{font-size:.75rem;color:#94a3b8;margin-top:8px}` +
		`.footer{margin-top:24px;padding-top:16px;border-top:1px solid #f1f5f9;font-size:.7rem;color:#94a3b8}` +
		`</style></head><body><div class="card">` +
		`<div class="icon">` + icon + `</div>` +
		`<div class="code">` + strconv.Itoa(statusCode) + `</div>` +
		`<h2>` + title + ` / ` + titleZh + `</h2>` +
		`<div class="divider"></div>` +
		`<p class="msg">` + msg + `</p>` +
		`<p class="msg">` + msgZh + `</p>` +
		`<p class="rid">Request ID: ` + reqID + `</p>` +
		`<div class="footer">Protected by My-OpenWAF</div>` +
		`</div></body></html>`
}

func buildChallengeHTML(reqID, ts, token string) string {
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Security Check</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(160deg,#f0fdfa 0%,#f8fafc 40%,#f1f5f9 100%);color:#1e293b}
.card{background:#fff;border-radius:16px;box-shadow:0 4px 32px rgba(0,0,0,.08),0 1px 4px rgba(0,0,0,.04);max-width:460px;width:92%;padding:48px 40px;text-align:center}
.icon{font-size:48px;margin-bottom:16px;line-height:1.2}
.spinner{width:40px;height:40px;border:3px solid #e2e8f0;border-top-color:#14b8a6;border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 20px}
@keyframes spin{to{transform:rotate(360deg)}}
h2{font-size:1.15rem;font-weight:600;color:#334155;margin-bottom:6px}
.sub{font-size:.875rem;color:#64748b;margin-bottom:4px}
.bar{width:100%;height:4px;background:#e2e8f0;border-radius:2px;margin:20px 0;overflow:hidden}
.bar-fill{height:100%;width:30%;background:linear-gradient(90deg,#14b8a6,#0d9488);border-radius:2px;animation:loading 2s ease-in-out infinite}
@keyframes loading{0%{width:10%}50%{width:70%}100%{width:95%}}
#msg{margin-top:12px;color:#ef4444;font-size:.8rem;display:none}
.rid{font-size:.7rem;color:#94a3b8;margin-top:20px}
.footer{margin-top:20px;padding-top:14px;border-top:1px solid #f1f5f9;font-size:.7rem;color:#94a3b8}
</style>
</head><body><div class="card">
<div class="icon">&#128737;</div>
<div class="spinner"></div>
<h2>Checking your browser / 正在验证您的浏览器</h2>
<p class="sub">This process is automatic, please wait...</p>
<p class="sub">此过程是自动的，请稍候...</p>
<div class="bar"><div class="bar-fill"></div></div>
<p id="msg"></p>
<p class="rid">Request ID: ` + reqID + `</p>
<div class="footer">Protected by My-OpenWAF</div>
</div>
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
