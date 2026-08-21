package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

const browserSignTestEnv = `{"webdriver":false,"chrome_present":true,"plugins_count":3,"languages":"zh-CN","canvas_hash":"1","webgl_renderer":"NVIDIA","screen_width":1920,"screen_height":1080,"hardware_concurrency":8,"session_storage":true,"indexed_db":true,"cookie_enabled":true,"platform":"Linux","web_assembly":true,"screen_consistency":true,"timezone_consistency":true,"language_consistency":true,"math_consistency":true}`

func browserSignTestHeaders(t *testing.T, ticket BrowserSignTicket, method, path, rawQuery, env string, ts int64) map[string]string {
	t.Helper()
	return map[string]string{
		BrowserSignHeaderNonce: ticket.Nonce,
		BrowserSignHeaderExp:   strconv.FormatInt(ticket.ExpiresAt, 10),
		BrowserSignHeaderMAC:   ticket.TicketMAC,
		BrowserSignHeaderTS:    strconv.FormatInt(ts, 10),
		BrowserSignHeaderSig:   browserSignRequestMAC(ticket.Nonce, method, path, rawQuery, ts, env),
		BrowserSignHeaderEnv:   env,
	}
}

func encryptBrowserSignTestEnv(t *testing.T, ticket BrowserSignTicket, siteID uint, plaintext string) string {
	t.Helper()
	key := browserSignEnvKey(ticket.Nonce, siteID)
	return encryptVersionedEnvFingerprint(t, []byte(plaintext), key, browserSignEnvAAD(ticket.Nonce, siteID))
}

func TestIssueAndVerifyBrowserSignHeaders(t *testing.T) {
	SetChallengeSecret([]byte("test-browser-sign-secret"))
	ticket := IssueBrowserSignTicket(7, 120)
	if ticket.Nonce == "" || ticket.TicketMAC == "" || ticket.SignKey == "" {
		t.Fatalf("ticket incomplete: %+v", ticket)
	}
	if len(ticket.EnvKeyHex) != 64 || ticket.EnvAAD == "" || ticket.EnvKeyHex == "1" {
		t.Fatalf("invalid environment ticket material: %+v", ticket)
	}
	if key, err := hex.DecodeString(ticket.EnvKeyHex); err != nil || len(key) != 32 {
		t.Fatalf("environment key must be 32-byte hex: key=%x err=%v", key, err)
	}

	now := time.Now()
	ts := now.Unix()
	method := "POST"
	path := "/api/v1/items"
	rawQuery := "filter=active&sort=created%2Bdesc"
	env := encryptBrowserSignTestEnv(t, ticket, 7, browserSignTestEnv)
	headers := browserSignTestHeaders(t, ticket, method, path, rawQuery, env, ts)

	ok, reason := VerifyBrowserSignHeaders(headers, method, path, rawQuery, 7, now)
	if !ok {
		t.Fatalf("expected pass, got reason=%q", reason)
	}

	ok, reason = VerifyBrowserSignHeaders(headers, method, path, rawQuery+"&page=2", 7, now)
	if ok || reason != "浏览器签名请求 MAC 校验失败" {
		t.Fatalf("expected query mismatch failure, ok=%v reason=%q", ok, reason)
	}

	ok, reason = VerifyBrowserSignHeaders(headers, method, path, rawQuery, 8, now)
	if ok || reason != "浏览器签名票据 MAC 校验失败" {
		t.Fatalf("expected site mismatch failure, ok=%v reason=%q", ok, reason)
	}
}

func TestVerifyBrowserSignHeadersRejectsInvalidOrHardFailEnv(t *testing.T) {
	SetChallengeSecret([]byte("test-browser-sign-secret-2"))
	ticket := IssueBrowserSignTicket(1, 60)
	now := time.Now()
	ts := now.Unix()
	method := "GET"
	path := "/api/data"
	rawQuery := "page=1"

	hardFailEnv := encryptBrowserSignTestEnv(t, ticket, 1, `{"webdriver":true}`)
	headers := browserSignTestHeaders(t, ticket, method, path, rawQuery, hardFailEnv, ts)
	ok, reason := VerifyBrowserSignHeaders(headers, method, path, rawQuery, 1, now)
	if ok || reason != "browser env hard-fail" {
		t.Fatalf("expected env hard-fail, ok=%v reason=%q", ok, reason)
	}

	delete(headers, BrowserSignHeaderEnv)
	ok, reason = VerifyBrowserSignHeaders(headers, method, path, rawQuery, 1, now)
	if ok || reason != "缺少浏览器环境指纹" {
		t.Fatalf("expected missing environment fingerprint failure, ok=%v reason=%q", ok, reason)
	}

	headers = browserSignTestHeaders(t, ticket, method, path, rawQuery, "not-json", ts)
	ok, reason = VerifyBrowserSignHeaders(headers, method, path, rawQuery, 1, now)
	if ok || reason != "invalid browser env fingerprint" {
		t.Fatalf("expected invalid environment fingerprint failure, ok=%v reason=%q", ok, reason)
	}

	headers = browserSignTestHeaders(t, ticket, method, path, rawQuery, browserSignTestEnv, ts)
	ok, reason = VerifyBrowserSignHeaders(headers, method, path, rawQuery, 1, now)
	if ok || reason != "invalid browser env fingerprint" {
		t.Fatalf("plaintext environment must be rejected, ok=%v reason=%q", ok, reason)
	}
}

func TestVerifyBrowserSignHeadersRejectsMismatchedEnvironmentScope(t *testing.T) {
	SetChallengeSecret([]byte("test-browser-sign-secret-3"))
	ticket := IssueBrowserSignTicket(3, 60)
	now := time.Now()
	ts := now.Unix()
	method := "POST"
	path := "/api/resource"
	env := encryptVersionedEnvFingerprint(t, []byte(browserSignTestEnv), browserSignEnvKey(ticket.Nonce, 3), browserSignEnvAAD(ticket.Nonce, 3)+"-other")
	headers := browserSignTestHeaders(t, ticket, method, path, "", env, ts)

	ok, reason := VerifyBrowserSignHeaders(headers, method, path, "", 3, now)
	if ok || reason != "invalid browser env fingerprint" {
		t.Fatalf("wrong AAD must fail, ok=%v reason=%q", ok, reason)
	}

	env = encryptBrowserSignTestEnv(t, ticket, 3, browserSignTestEnv)
	headers = browserSignTestHeaders(t, ticket, method, path, "", env, ts)
	headers[BrowserSignHeaderEnv] = env + "x"
	ok, reason = VerifyBrowserSignHeaders(headers, method, path, "", 3, now)
	if ok || reason != "浏览器签名请求 MAC 校验失败" {
		t.Fatalf("tampered environment header must invalidate request mac, ok=%v reason=%q", ok, reason)
	}
}

func TestIsLikelyAPIRequest(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
		want    bool
	}{
		{name: "json post", method: "POST", path: "/api/v1/login", headers: map[string]string{"content-type": "application/json"}, want: true},
		{name: "html navigation", method: "GET", path: "/index.html", headers: map[string]string{"accept": "text/html", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document"}},
		{name: "urlencoded form", method: "POST", path: "/login", headers: map[string]string{"content-type": "application/x-www-form-urlencoded", "accept": "text/html"}},
		{name: "multipart form", method: "POST", path: "/upload", headers: map[string]string{"content-type": "multipart/form-data; boundary=x", "accept": "text/html"}},
		{name: "xhr form", method: "POST", path: "/login", headers: map[string]string{"content-type": "application/x-www-form-urlencoded", "x-requested-with": "XMLHttpRequest"}, want: true},
		{name: "cors form", method: "POST", path: "/login", headers: map[string]string{"content-type": "application/x-www-form-urlencoded", "sec-fetch-mode": "cors"}, want: true},
		{name: "explicit api form", method: "POST", path: "/api/login", headers: map[string]string{"content-type": "application/x-www-form-urlencoded"}, want: true},
		{name: "static js", method: "GET", path: "/static/app.js"},
		{name: "graphql", method: "GET", path: "/graphql", headers: map[string]string{"accept": "application/json"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLikelyAPIRequest(tt.method, tt.path, tt.headers); got != tt.want {
				t.Fatalf("IsLikelyAPIRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInjectBrowserSignIntoHTML(t *testing.T) {
	SetChallengeSecret([]byte("test-browser-sign-secret-4"))
	ticket := IssueBrowserSignTicket(2, 60)
	html := []byte("<html><body><h1>ok</h1></body></html>")
	out := InjectBrowserSignIntoHTML(html, ticket)
	s := string(out)
	if !strings.Contains(s, ticket.Nonce) || !strings.Contains(s, ticket.EnvKeyHex) || !strings.Contains(s, ticket.EnvAAD) {
		t.Fatal("expected ticket material in injected html")
	}
	if !strings.Contains(s, "</body>") {
		t.Fatal("expected body close tag retained")
	}
	if ticket.CSPNonce == "" || !strings.Contains(s, `<script nonce="`+ticket.CSPNonce+`" data-owaf-bs="1">`) {
		t.Fatal("expected CSP nonce script tag")
	}
	if !strings.Contains(s, "function queryOnly") || !strings.Contains(s, `var payload=m+"|"+path+"|"+query+"|"+String(ts)+"|"+`) {
		t.Fatal("expected injected browser signer to bind raw query")
	}
	if !strings.Contains(s, "wasm_bindgen.collect_and_encrypt_fingerprint") || !strings.Contains(s, "window.__owaf_env_encrypted=encrypted") {
		t.Fatal("expected encrypted WASM environment fingerprint collection")
	}
	if strings.Contains(s, "wasm_bindgen.collect_fingerprint()") || strings.Contains(s, "window.__owaf_env=") {
		t.Fatal("browser signer must not use plain environment collection")
	}
	if !strings.Contains(s, "window.__owaf_env_ready") || !strings.Contains(s, `env.indexOf("v1.")`) {
		t.Fatal("expected browser signer to await a versioned environment envelope")
	}
	for _, marker := range []string{
		"document.currentScript&&document.currentScript.nonce",
		"script.nonce=cspNonce",
		"sc.nonce=__owaf_bs_csp_nonce",
		"function requestURL(input)",
		"input instanceof URL",
		"function isChallengeHTML",
		"function showChallengeResponse",
		"function signedFetchResponse",
		`/__owaf/captcha/verify`,
		`/__owaf/shield/verify`,
		`/__owaf/chain/verify`,
		`__waf_challenge_token`,
		"},function(){return ofetch.apply(fetchThis,fetchArgs)}).then(signedFetchResponse)",
	} {
		if !strings.Contains(s, marker) {
			t.Fatalf("expected browser signer marker %q", marker)
		}
	}
	if strings.Count(s, `addEventListener("load"`) != 1 || !strings.Contains(s, "showChallengeXHR(xhr)") {
		t.Fatal("expected browser signer to inspect completed XHR challenge responses exactly once")
	}
	// xhr.responseText 在 responseType 为 json/arraybuffer/document 时抛 InvalidStateError，
	// 外层 try-catch 会把异常吞掉，导致 403 challenge HTML 静默失败、页面不被接管。
	// 因此读取正文必须先按 responseType 分派，不能直接访问 responseText。
	if !strings.Contains(s, "function xhrBodyText(xhr)") {
		t.Fatal("expected browser signer to read XHR bodies through a responseType-aware helper")
	}
	for _, marker := range []string{
		`if(rt===""||rt==="text")`,
		`if(rt==="json")`,
		"raw instanceof ArrayBuffer",
		"raw instanceof Document",
	} {
		if !strings.Contains(s, marker) {
			t.Fatalf("expected XHR body reader to handle responseType %q", marker)
		}
	}
	if strings.Contains(s, "},xhr.responseText||\"\")") {
		t.Fatal("browser signer must not pass xhr.responseText directly to isChallengeHTML")
	}
}

func TestBrowserSignXHRTemplateSupportsBlobChallengeAndStaticConstants(t *testing.T) {
	SetChallengeSecret([]byte("test-browser-sign-secret-5"))
	ticket := IssueBrowserSignTicket(2, 60)
	injected := string(InjectBrowserSignIntoHTML([]byte("<html><body></body></html>"), ticket))

	for _, marker := range []string{
		"Object.setPrototypeOf(P,XO);",
		"function showChallengeXHRHTML(xhr,html)",
		`if(rt==="blob")`,
		"raw instanceof Blob",
		`raw.text().then(function(html){showChallengeXHRHTML(xhr,html)})`,
		"new FileReader()",
		"reader.readAsText(raw)",
	} {
		if !strings.Contains(injected, marker) {
			t.Fatalf("expected XHR compatibility marker %q", marker)
		}
	}
}

func TestBrowserSignFetchDoesNotRetrySignedNetworkFailure(t *testing.T) {
	runtime, err := exec.LookPath("node")
	if err != nil {
		runtime, err = exec.LookPath("bun")
	}
	if err != nil {
		t.Skip("node or bun is required for the BrowserSign fetch behavior test")
	}

	SetChallengeSecret([]byte("browser-sign-fetch-behavior-secret"))
	script := BrowserSignInjectScript(IssueBrowserSignTicket(1, 60))
	start := strings.IndexByte(script, '>')
	end := strings.LastIndex(script, "</script>")
	if start < 0 || end <= start {
		t.Fatal("injected BrowserSign script has no executable body")
	}

	harness := fmt.Sprintf(`
var injected=%s;
global.window=global;
global.location={href:"https://example.test/page",origin:"https://example.test"};
global.document={currentScript:{nonce:""},createElement:function(){return {};},head:{appendChild:function(){}},documentElement:{appendChild:function(){}},open:function(){},write:function(){},close:function(){}};
global.WebAssembly={};
var signFails=false;
function wasm_bindgen(){return Promise.resolve();}
wasm_bindgen.collect_and_encrypt_fingerprint=function(){return "v1.test";};
wasm_bindgen.hmac_sha256=function(){if(signFails)throw new Error("sign failed");return "signed";};
global.wasm_bindgen=wasm_bindgen;
var mode="network-fail";
var calls=[];
window.fetch=function(input,init){
  calls.push({input:String(input),headers:init&&init.headers});
  if(mode==="network-fail")return Promise.reject(new Error("network rejected"));
  return Promise.resolve({status:200,headers:{get:function(){return "";}},clone:function(){return {text:function(){return Promise.resolve("");}};}});
};
eval(injected);
(async function(){
  await window.__owaf_env_ready;
  var rejected=false;
  try{await window.fetch("/api/network");}catch(e){rejected=true;}
  if(!rejected)throw new Error("signed network failure must reject");
  if(calls.length!==1)throw new Error("signed network failure retried the request");
  if(!calls[0].headers||!calls[0].headers["X-OWAF-BS-S"])throw new Error("signed request lost its signature");
  signFails=true;
  mode="sign-fail";
  var response=await window.fetch("/api/sign-fail");
  if(response.status!==200)throw new Error("sign failure fallback did not return the response");
  if(calls.length!==2)throw new Error("sign failure fallback did not issue exactly one request");
  if(calls[1].headers&&calls[1].headers["X-OWAF-BS-S"])throw new Error("sign failure fallback sent a signed request");
})().then(function(){process.stdout.write("ok");}).catch(function(err){console.error(err&&err.stack||err);process.exitCode=1;});
`, strconv.Quote(script[start+1:end]))

	output, err := exec.Command(runtime, "-e", harness).CombinedOutput()
	if err != nil {
		t.Fatalf("BrowserSign fetch behavior test failed: %v\n%s", err, output)
	}
	if strings.TrimSpace(string(output)) != "ok" {
		t.Fatalf("unexpected BrowserSign fetch behavior output: %q", output)
	}
}

func TestBrowserSignRequestMACDeterministic(t *testing.T) {
	SetChallengeSecret([]byte("fixed-secret"))
	nonce := "abc"
	ts := int64(1700000000)
	env := "v1.envelope"
	a := browserSignRequestMAC(nonce, "get", "/api/x", "q=1", ts, env)
	b := browserSignRequestMAC(nonce, "GET", "/api/x", "q=1", ts, env)
	if a != b {
		t.Fatalf("mac should normalize method case: %s vs %s", a, b)
	}
	if a == browserSignRequestMAC(nonce, "GET", "/api/x", "q=2", ts, env) {
		t.Fatal("mac should bind raw query")
	}
	if a == browserSignRequestMAC(nonce, "GET", "/api/x", "q=1", ts, "v1.other") {
		t.Fatal("mac should bind environment envelope")
	}
	if got := browserSignRequestMAC(nonce, "GET", "/api/x?q=1", "", ts, env); got != a {
		t.Fatalf("path query compatibility mismatch got=%s want=%s", got, a)
	}
	if got := browserSignRequestMAC(nonce, "GET", "/api/x", "?q=1", ts, env); got != a {
		t.Fatalf("query prefix normalization mismatch got=%s want=%s", got, a)
	}
	key := browserSignRequestKey(nonce)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("GET|/api/x|q=1|1700000000|abc|v1.envelope"))
	want := hex.EncodeToString(mac.Sum(nil))
	if a != want {
		t.Fatalf("mac mismatch got=%s want=%s", a, want)
	}
}
