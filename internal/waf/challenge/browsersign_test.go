package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestIssueAndVerifyBrowserSignHeaders(t *testing.T) {
	SetChallengeSecret([]byte("test-browser-sign-secret"))
	ticket := IssueBrowserSignTicket(7, "example.com", 120, true)
	if ticket.Nonce == "" || ticket.TicketMAC == "" || ticket.SignKey == "" {
		t.Fatalf("ticket incomplete: %+v", ticket)
	}
	if ticket.EnvKeyHex == "" {
		t.Fatal("envCheck should mark EnvKeyHex")
	}

	now := time.Now()
	ts := now.Unix()
	method := "POST"
	path := "/api/v1/items"
	reqMAC := browserSignRequestMAC(ticket.Nonce, method, path, ts)
	headers := map[string]string{
		strings.ToLower(BrowserSignHeaderNonce): ticket.Nonce,
		strings.ToLower(BrowserSignHeaderExp):   strconv.FormatInt(ticket.ExpiresAt, 10),
		strings.ToLower(BrowserSignHeaderMAC):   ticket.TicketMAC,
		strings.ToLower(BrowserSignHeaderTS):    strconv.FormatInt(ts, 10),
		strings.ToLower(BrowserSignHeaderSig):   reqMAC,
		strings.ToLower(BrowserSignHeaderEnv):   `{"webdriver":false,"chrome_present":true,"plugins_count":3,"languages":"zh-CN","canvas_hash":"1","webgl_renderer":"NVIDIA","screen_width":1920,"screen_height":1080,"hardware_concurrency":8,"session_storage":true,"indexed_db":true,"cookie_enabled":true,"platform":"Linux","web_assembly":true,"screen_consistency":true,"timezone_consistency":true,"language_consistency":true,"math_consistency":true}`,
	}
	ok, reason := VerifyBrowserSignHeaders(headers, method, path, "example.com", 7, now, true)
	if !ok {
		t.Fatalf("expected pass, got reason=%q", reason)
	}

	// wrong site should fail ticket mac
	ok, reason = VerifyBrowserSignHeaders(headers, method, path, "example.com", 8, now, true)
	if ok || reason == "" {
		t.Fatalf("expected site mismatch fail, ok=%v reason=%q", ok, reason)
	}
}

func TestVerifyBrowserSignHeadersRejectsHardEnv(t *testing.T) {
	SetChallengeSecret([]byte("test-browser-sign-secret-2"))
	ticket := IssueBrowserSignTicket(1, "a.test", 60, true)
	now := time.Now()
	ts := now.Unix()
	method := "GET"
	path := "/api/data"
	headers := map[string]string{
		BrowserSignHeaderNonce: ticket.Nonce,
		BrowserSignHeaderExp:   strconv.FormatInt(ticket.ExpiresAt, 10),
		BrowserSignHeaderMAC:   ticket.TicketMAC,
		BrowserSignHeaderTS:    strconv.FormatInt(ts, 10),
		BrowserSignHeaderSig:   browserSignRequestMAC(ticket.Nonce, method, path, ts),
		BrowserSignHeaderEnv:   `{"webdriver":true}`,
	}
	ok, reason := VerifyBrowserSignHeaders(headers, method, path, "a.test", 1, now, true)
	if ok || !strings.Contains(reason, "env hard-fail") {
		t.Fatalf("expected env hard-fail, ok=%v reason=%q", ok, reason)
	}
}

func TestIsLikelyAPIRequest(t *testing.T) {
	if !IsLikelyAPIRequest("POST", "/api/v1/login", map[string]string{
		"content-type": "application/json",
	}) {
		t.Fatal("json post should be api")
	}
	if IsLikelyAPIRequest("GET", "/index.html", map[string]string{
		"accept":         "text/html",
		"sec-fetch-mode": "navigate",
		"sec-fetch-dest": "document",
	}) {
		t.Fatal("html navigate should not be api")
	}
	if IsLikelyAPIRequest("GET", "/static/app.js", nil) {
		t.Fatal("static js should not be api")
	}
	if !IsLikelyAPIRequest("GET", "/graphql", map[string]string{
		"accept": "application/json",
	}) {
		t.Fatal("graphql json accept should be api")
	}
}

func TestInjectBrowserSignIntoHTML(t *testing.T) {
	SetChallengeSecret([]byte("test-browser-sign-secret-3"))
	ticket := IssueBrowserSignTicket(2, "b.test", 60, true)
	html := []byte("<html><body><h1>ok</h1></body></html>")
	out := InjectBrowserSignIntoHTML(html, ticket)
	s := string(out)
	if !strings.Contains(s, BrowserSignHeaderNonce) && !strings.Contains(s, "X-OWAF") {
		// 变量名会被混淆，至少应包含 script 与 nonce 值
	}
	if !strings.Contains(s, ticket.Nonce) {
		t.Fatal("expected ticket nonce in injected html")
	}
	if !strings.Contains(s, "</body>") {
		t.Fatal("expected body close tag retained")
	}
	if !strings.Contains(s, "<script>") {
		t.Fatal("expected script tag")
	}
}

func TestBrowserSignRequestMACDeterministic(t *testing.T) {
	SetChallengeSecret([]byte("fixed-secret"))
	nonce := "abc"
	ts := int64(1700000000)
	a := browserSignRequestMAC(nonce, "get", "/api/x?q=1", ts)
	b := browserSignRequestMAC(nonce, "GET", "/api/x", ts)
	if a != b {
		t.Fatalf("mac should ignore query and method case: %s vs %s", a, b)
	}
	key := browserSignRequestKey(nonce)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("GET|/api/x|1700000000|abc"))
	want := hex.EncodeToString(mac.Sum(nil))
	if a != want {
		t.Fatalf("mac mismatch got=%s want=%s", a, want)
	}
}
