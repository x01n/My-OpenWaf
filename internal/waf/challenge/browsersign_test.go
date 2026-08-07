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
	rawQuery := "filter=active&sort=created%2Bdesc"
	reqMAC := browserSignRequestMAC(ticket.Nonce, method, path, rawQuery, ts)
	headers := map[string]string{
		strings.ToLower(BrowserSignHeaderNonce): ticket.Nonce,
		strings.ToLower(BrowserSignHeaderExp):   strconv.FormatInt(ticket.ExpiresAt, 10),
		strings.ToLower(BrowserSignHeaderMAC):   ticket.TicketMAC,
		strings.ToLower(BrowserSignHeaderTS):    strconv.FormatInt(ts, 10),
		strings.ToLower(BrowserSignHeaderSig):   reqMAC,
		strings.ToLower(BrowserSignHeaderEnv):   `{"webdriver":false,"chrome_present":true,"plugins_count":3,"languages":"zh-CN","canvas_hash":"1","webgl_renderer":"NVIDIA","screen_width":1920,"screen_height":1080,"hardware_concurrency":8,"session_storage":true,"indexed_db":true,"cookie_enabled":true,"platform":"Linux","web_assembly":true,"screen_consistency":true,"timezone_consistency":true,"language_consistency":true,"math_consistency":true}`,
	}
	ok, reason := VerifyBrowserSignHeaders(headers, method, path, rawQuery, "example.com", 7, now, true)
	if !ok {
		t.Fatalf("expected pass, got reason=%q", reason)
	}

	ok, reason = VerifyBrowserSignHeaders(headers, method, path, rawQuery+"&page=2", "example.com", 7, now, true)
	if ok || reason != "browser sign request mac mismatch" {
		t.Fatalf("expected query mismatch failure, ok=%v reason=%q", ok, reason)
	}

	// wrong site should fail ticket mac
	ok, reason = VerifyBrowserSignHeaders(headers, method, path, rawQuery, "example.com", 8, now, true)
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
	rawQuery := "page=1"
	headers := map[string]string{
		BrowserSignHeaderNonce: ticket.Nonce,
		BrowserSignHeaderExp:   strconv.FormatInt(ticket.ExpiresAt, 10),
		BrowserSignHeaderMAC:   ticket.TicketMAC,
		BrowserSignHeaderTS:    strconv.FormatInt(ts, 10),
		BrowserSignHeaderSig:   browserSignRequestMAC(ticket.Nonce, method, path, rawQuery, ts),
		BrowserSignHeaderEnv:   `{"webdriver":true}`,
	}
	ok, reason := VerifyBrowserSignHeaders(headers, method, path, rawQuery, "a.test", 1, now, true)
	if ok || !strings.Contains(reason, "env hard-fail") {
		t.Fatalf("expected env hard-fail, ok=%v reason=%q", ok, reason)
	}

	delete(headers, BrowserSignHeaderEnv)
	ok, reason = VerifyBrowserSignHeaders(headers, method, path, rawQuery, "a.test", 1, now, true)
	if ok || reason != "missing browser env fingerprint" {
		t.Fatalf("expected missing environment fingerprint failure, ok=%v reason=%q", ok, reason)
	}

	headers[BrowserSignHeaderEnv] = "not-json"
	ok, reason = VerifyBrowserSignHeaders(headers, method, path, rawQuery, "a.test", 1, now, true)
	if ok || reason != "invalid browser env fingerprint" {
		t.Fatalf("expected invalid environment fingerprint failure, ok=%v reason=%q", ok, reason)
	}
}

func TestVerifyBrowserSignHeadersEnvHardFailRequiresValidEnv(t *testing.T) {
	SetChallengeSecret([]byte("test-browser-sign-secret-3"))
	ticket := IssueBrowserSignTicket(3, "env.test", 60, true)
	now := time.Now()
	ts := now.Unix()
	method := "POST"
	path := "/api/resource"
	baseHeaders := map[string]string{
		BrowserSignHeaderNonce: ticket.Nonce,
		BrowserSignHeaderExp:   strconv.FormatInt(ticket.ExpiresAt, 10),
		BrowserSignHeaderMAC:   ticket.TicketMAC,
		BrowserSignHeaderTS:    strconv.FormatInt(ts, 10),
		BrowserSignHeaderSig:   browserSignRequestMAC(ticket.Nonce, method, path, "", ts),
	}

	tests := []struct {
		name        string
		envHardFail bool
		env         string
		includeEnv  bool
		wantOK      bool
		wantReason  string
	}{
		{name: "hard fail missing env", envHardFail: true, wantReason: "missing browser env fingerprint"},
		{name: "hard fail invalid env", envHardFail: true, env: "not-json", includeEnv: true, wantReason: "invalid browser env fingerprint"},
		{name: "soft fail missing env", wantOK: true},
		{name: "soft fail invalid env", env: "not-json", includeEnv: true, wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(map[string]string, len(baseHeaders)+1)
			for name, value := range baseHeaders {
				headers[name] = value
			}
			if tt.includeEnv {
				headers[BrowserSignHeaderEnv] = tt.env
			}

			ok, reason := VerifyBrowserSignHeaders(headers, method, path, "", "env.test", 3, now, tt.envHardFail)
			if ok != tt.wantOK || reason != tt.wantReason {
				t.Fatalf("VerifyBrowserSignHeaders() = (%v, %q), want (%v, %q)", ok, reason, tt.wantOK, tt.wantReason)
			}
		})
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
	if !strings.Contains(s, ticket.Nonce) {
		t.Fatal("expected ticket nonce in injected html")
	}
	if !strings.Contains(s, "</body>") {
		t.Fatal("expected body close tag retained")
	}
	if ticket.CSPNonce == "" {
		t.Fatal("expected CSP nonce in ticket")
	}
	if !strings.Contains(s, `<script nonce="`+ticket.CSPNonce+`" data-owaf-bs="1">`) {
		t.Fatal("expected CSP nonce script tag")
	}
	if !strings.Contains(s, "function queryOnly") {
		t.Fatal("expected injected browser signer to extract raw query")
	}
	if !strings.Contains(s, `var payload=m+"|"+path+"|"+query+"|"+String(ts)+"|"+`) {
		t.Fatal("expected injected browser signer to bind raw query")
	}
}

func TestBrowserSignRequestMACDeterministic(t *testing.T) {
	SetChallengeSecret([]byte("fixed-secret"))
	nonce := "abc"
	ts := int64(1700000000)
	a := browserSignRequestMAC(nonce, "get", "/api/x", "q=1", ts)
	b := browserSignRequestMAC(nonce, "GET", "/api/x", "q=1", ts)
	if a != b {
		t.Fatalf("mac should normalize method case: %s vs %s", a, b)
	}
	if a == browserSignRequestMAC(nonce, "GET", "/api/x", "q=2", ts) {
		t.Fatal("mac should bind raw query")
	}
	if got := browserSignRequestMAC(nonce, "GET", "/api/x?q=1", "", ts); got != a {
		t.Fatalf("path query compatibility mismatch got=%s want=%s", got, a)
	}
	if got := browserSignRequestMAC(nonce, "GET", "/api/x", "?q=1", ts); got != a {
		t.Fatalf("query prefix normalization mismatch got=%s want=%s", got, a)
	}
	key := browserSignRequestKey(nonce)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("GET|/api/x|q=1|1700000000|abc"))
	want := hex.EncodeToString(mac.Sum(nil))
	if a != want {
		t.Fatalf("mac mismatch got=%s want=%s", a, want)
	}
	if a != "0d821ab5ed8aadc8eac57487a7ad0baee2e9d8d73a722451913d507b027279d8" {
		t.Fatalf("golden mac mismatch got=%s", a)
	}
}
