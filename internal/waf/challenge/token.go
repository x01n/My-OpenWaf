package challenge

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/snapshot"
)

// NonceKey is the cookie name used for anti-replay nonces.
const NonceKey = "__waf_nonce"

// ChallengePassCookieName is the cookie name for challenge pass cookies.
const ChallengePassCookieName = "__waf_passed"

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

// GenerateChallengeTokenPair creates a timestamp and HMAC token for JS challenge pages.
// This is used by the pages subpackage to render challenge HTML without direct access to challengeSecret.
func GenerateChallengeTokenPair(reqID string) (ts, token string) {
	ts = strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, challengeSecret)
	mac.Write([]byte(reqID + ":" + ts))
	token = hex.EncodeToString(mac.Sum(nil))
	return
}

// WriteChallengeResponse renders a JS challenge page that the client must solve.
func WriteChallengeResponse(c *app.RequestContext, reqID string, rt *snapshot.SiteRuntime, statusCode int) {
	c.Response.Header.Set("X-Request-ID", reqID)
	c.Response.Header.Del("Server")
	c.Response.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate")

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, challengeSecret)
	mac.Write([]byte(reqID + ":" + ts))
	token := hex.EncodeToString(mac.Sum(nil))

	html := buildChallengeHTML(reqID, ts, token)
	c.Data(statusCode, "text/html; charset=utf-8", []byte(html))
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
