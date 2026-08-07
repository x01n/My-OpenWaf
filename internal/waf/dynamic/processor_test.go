package dynamic

import (
	"bytes"
	"encoding/base64"
	"html"
	"strings"
	"testing"
)

func TestProcessHTMLEncryptsBody(t *testing.T) {
	cfg := ProtectionConfig{
		HTMLObfuscationEnabled: true,
		SiteID:                 1,
	}
	p := NewProcessor(cfg)

	html := []byte(`<!DOCTYPE html><html><head></head><body><p>Hello World</p></body></html>`)
	result, err := p.ProcessHTML(html)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(result, html) {
		t.Fatal("expected HTML to be transformed")
	}
	if !bytes.Contains(result, []byte(`data-owaf-dp="2"`)) {
		t.Fatal("expected owaf data attribute")
	}
	if bytes.Contains(result, []byte(`nonce=\"`)) || bytes.Contains(result, []byte(`data-owaf-dp=\"2\"`)) || bytes.Contains(result, []byte(`charset=\"utf-8\"`)) {
		t.Fatal("HTML protection shell attributes must use real quotes, not escaped quotes")
	}
	if !bytes.Contains(result, []byte(`data-owaf-data="`)) {
		t.Fatal("expected encrypted data attribute")
	}
	if !bytes.Contains(result, []byte(`data-owaf-iv="`)) {
		t.Fatal("expected iv attribute")
	}
	if !bytes.Contains(result, []byte(`data-owaf-wrap="`)) {
		t.Fatal("expected wrapped key attribute")
	}
	if bytes.Contains(result, []byte(`Hello World`)) {
		t.Fatal("original body content should not appear in encrypted output")
	}
}

func TestProcessHTMLEscapesSignedTicketAttributes(t *testing.T) {
	payload := `"><script>window.__owafInjected=true</script>`
	cfg := ProtectionConfig{HTMLObfuscationEnabled: true, SiteID: 1}
	p := NewProcessorWithKeyTicketSigner(cfg, func(string, int, string) string {
		return payload
	})

	result, err := p.ProcessHTML([]byte(`<html><body>secret</body></html>`))
	if err != nil {
		t.Fatal(err)
	}
	output := string(result)
	if strings.Contains(output, `<script>window.__owafInjected=true</script>`) {
		t.Fatal("signed ticket escaped its attribute context")
	}
	if !strings.Contains(output, `data-owaf-ticket="&#34;&gt;&lt;script&gt;`) {
		t.Fatal("signed ticket was not HTML-escaped")
	}
	if strings.Contains(output, `data-owaf-kek=`) {
		t.Fatal("ticket envelope must not expose KEK")
	}
}

func TestProcessHTMLSkipsWhenDisabled(t *testing.T) {
	cfg := ProtectionConfig{
		HTMLObfuscationEnabled: false,
		SiteID:                 1,
	}
	p := NewProcessor(cfg)

	html := []byte(`<html><body><p>Hello</p></body></html>`)
	result, err := p.ProcessHTML(html)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, html) {
		t.Fatal("expected no transformation when disabled")
	}
}

func TestProcessJSEncrypts(t *testing.T) {
	cfg := ProtectionConfig{
		JSObfuscationEnabled: true,
		JSProtectionMode:     "all",
		SiteID:               1,
	}
	p := NewProcessor(cfg)

	js := []byte(`console.log("hello");`)
	result, err := p.ProcessJS("/app.js", js)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(result, js) {
		t.Fatal("expected JS to be encrypted")
	}
	if !bytes.Contains(result, []byte("decrypt_dynamic_with_cek")) {
		t.Fatal("expected self-decrypt wrapper with WASM decrypt")
	}
	if bytes.Contains(result, []byte(`console.log("hello")`)) {
		t.Fatal("original JS should not appear in encrypted output")
	}
}

func TestProcessJSRespectsPathMode(t *testing.T) {
	cfg := ProtectionConfig{
		JSObfuscationEnabled: true,
		JSProtectionMode:     "paths",
		JSObfuscationPaths:   []string{"/static/*"},
		SiteID:               1,
	}
	p := NewProcessor(cfg)

	// 匹配路径应加密
	result1, _ := p.ProcessJS("/static/app.js", []byte(`var x=1;`))
	if !bytes.Contains(result1, []byte("decrypt_dynamic_with_cek")) {
		t.Fatal("expected encryption for matching path")
	}

	// 不匹配路径不加密
	result2, _ := p.ProcessJS("/api/data.js", []byte(`var x=1;`))
	if bytes.Contains(result2, []byte("decrypt_dynamic_with_cek")) {
		t.Fatal("expected no encryption for non-matching path")
	}
}

func TestProcessRoutesCorrectly(t *testing.T) {
	cfg := ProtectionConfig{
		HTMLObfuscationEnabled: true,
		JSObfuscationEnabled:   true,
		JSProtectionMode:       "all",
		SiteID:                 1,
	}
	p := NewProcessor(cfg)

	// HTML
	html, _ := p.Process("/", "text/html; charset=utf-8", []byte(`<html><body>hi</body></html>`))
	if !bytes.Contains(html, []byte("owaf")) {
		t.Fatal("HTML should be processed")
	}

	// JS
	js, _ := p.Process("/app.js", "application/javascript", []byte(`var x=1;`))
	if !bytes.Contains(js, []byte("decrypt_dynamic_with_cek")) {
		t.Fatal("JS should be processed")
	}

	// Other (not processed)
	css, _ := p.Process("/style.css", "text/css", []byte(`body{color:red}`))
	if !bytes.Equal(css, []byte(`body{color:red}`)) {
		t.Fatal("CSS should not be processed")
	}
}

func TestEncryptionNonceUniqueness(t *testing.T) {
	cfg := ProtectionConfig{
		HTMLObfuscationEnabled: true,
		SiteID:                 1,
	}
	p := NewProcessor(cfg)

	html := []byte(`<html><body><p>test</p></body></html>`)
	result1, _ := p.ProcessHTML(html)
	result2, _ := p.ProcessHTML(html)

	if bytes.Equal(result1, result2) {
		t.Fatal("two encryptions of same content should produce different output (unique nonce)")
	}
}

func TestAESKeyWrapRoundTrip(t *testing.T) {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i)
	}
	plaintext := make([]byte, 32)
	for i := range plaintext {
		plaintext[i] = byte(i + 32)
	}

	wrapped, err := aesKeyWrap(kek, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if len(wrapped) != len(plaintext)+8 {
		t.Fatalf("wrapped length should be plaintext+8, got %d", len(wrapped))
	}
}

func TestAESGCMEncryptProducesValidOutput(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("test data for encryption")

	iv, ct, err := aesGCMEncrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if len(iv) != 12 {
		t.Fatalf("expected 12-byte IV, got %d", len(iv))
	}
	if len(ct) != len(plaintext)+16 {
		t.Fatalf("expected ciphertext length %d, got %d", len(plaintext)+16, len(ct))
	}
}

func TestShouldProcessContentType(t *testing.T) {
	tests := []struct {
		ct   string
		want string
	}{
		{"text/html", "html"},
		{"text/html; charset=utf-8", "html"},
		{"application/javascript", "js"},
		{"text/javascript", "js"},
		{"image/png", "image"},
		{"image/jpeg", "image"},
		{"text/css", ""},
		{"application/json", ""},
	}
	for _, tt := range tests {
		got := ShouldProcessContentType(tt.ct)
		if got != tt.want {
			t.Errorf("ShouldProcessContentType(%q) = %q, want %q", tt.ct, got, tt.want)
		}
	}
}

func TestEnvelopeContainsValidBase64(t *testing.T) {
	cfg := ProtectionConfig{
		HTMLObfuscationEnabled: true,
		SiteID:                 1,
	}
	p := NewProcessor(cfg)

	env, err := p.makeEnvelope([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	for _, field := range []string{env.data, env.iv, env.wrap, env.kek, env.key} {
		if _, err := base64.StdEncoding.DecodeString(field); err != nil {
			t.Fatalf("envelope field is not valid base64: %v", err)
		}
	}
	if env.key == "" {
		t.Fatal("expected envelope cache key")
	}
}

func TestMatchPathPatterns(t *testing.T) {
	if !matchPathPatterns("/any/path", nil) {
		t.Fatal("nil patterns should match all")
	}
	if !matchPathPatterns("/static/app.js", []string{"/static/*"}) {
		t.Fatal("should match wildcard suffix")
	}
	if matchPathPatterns("/other/path", []string{"/static/*"}) {
		t.Fatal("should not match non-matching pattern")
	}
}

func TestHTMLEncryptedOutputContainsBootstrapScript(t *testing.T) {
	cfg := ProtectionConfig{
		HTMLObfuscationEnabled: true,
		SiteID:                 42,
	}
	p := NewProcessor(cfg)

	result, err := p.ProcessHTML([]byte(`<html><body><p>secret</p></body></html>`))
	if err != nil {
		t.Fatal(err)
	}

	// 验证引导脚本使用 WASM 接管 AES-KW 与 AES-GCM 解密。
	s := string(result)
	if strings.Contains(s, "crypto.subtle.importKey") || strings.Contains(s, "crypto.subtle.decrypt") || strings.Contains(s, "unwrapKey") {
		t.Fatal("bootstrap script must not use Web Crypto for dynamic decrypt")
	}
	if !strings.Contains(s, "wasm_bindgen") {
		t.Fatal("expected WASM loader in bootstrap script")
	}
	if !strings.Contains(s, "decrypt_dynamic_with_cek") {
		t.Fatal("expected WASM dynamic decrypt call in bootstrap script")
	}
	if !strings.Contains(s, "unwrap_dynamic_cek") {
		t.Fatal("expected WASM AES-KW unwrap call in bootstrap script")
	}
}

func TestProcessHTMLWithScriptNonceReturnsBootstrapNonce(t *testing.T) {
	p := NewProcessor(ProtectionConfig{HTMLObfuscationEnabled: true, SiteID: 42})
	result, nonce, err := p.ProcessHTMLWithScriptNonce([]byte(`<html><body>secret</body></html>`))
	if err != nil {
		t.Fatal(err)
	}
	if nonce == "" {
		t.Fatal("expected bootstrap script nonce")
	}
	if !strings.Contains(html.UnescapeString(string(result)), `nonce="`+nonce+`"`) {
		t.Fatalf("bootstrap output does not contain returned nonce %q", nonce)
	}
}

func TestDynamicBootstrapIncludesEnvironmentGateAndLoadingState(t *testing.T) {
	cfg := ProtectionConfig{HTMLObfuscationEnabled: true, SiteID: 42}
	result, err := NewProcessor(cfg).ProcessHTML([]byte(`<html><body>secret</body></html>`))
	if err != nil {
		t.Fatal(err)
	}
	s := string(result)
	for _, marker := range []string{
		"正在解密页面内容",
		"owafCheckEnvironment",
		"navigator.webdriver",
		"HeadlessChrome",
		"__owaf_dp_blocked",
		"document.open();document.write(html);document.close();",
		"script[data-owaf-dp='2']",
		"data-owaf-key",
		"g.cekKey===key",
		"g.cekCached",
		"decryptWithRetry",
		"try{k=await cek(false)",
		"softScore>=100",
		"markSoft(\"devtools window gap\"",
		"OpenWAF 安全网关",
		"OpenWAF 内容保护调试",
		"owafMaybeStatus",
		"owafHasRecentSuccess",
		"owafMarkRecentSuccess",
		"__owaf_dp_recent",
		"document.write(html)",
		"调试输出",
		"owafDebugPayload",
		"owafEnvelopeInfo",
		"owafExchangeDynamicKey",
		"html-decrypt",
		"missing-envelope",
	} {
		if !strings.Contains(s, marker) {
			t.Fatalf("expected dynamic bootstrap marker %q", marker)
		}
	}
}

func TestDynamicJSBootstrapIncludesEnvironmentGate(t *testing.T) {
	cfg := ProtectionConfig{JSObfuscationEnabled: true, SiteID: 42}
	result, err := NewProcessor(cfg).ProcessJS("/app.js", []byte(`window.__appReady=true`))
	if err != nil {
		t.Fatal(err)
	}
	s := string(result)
	for _, marker := range []string{
		"owafCheckEnvironment",
		"navigator.webdriver",
		"脚本解密失败",
		"(0,eval)",
		"g.cekKey===key",
		"decryptWithRetry",
		"try{k=await cek(false)",
		"OpenWAF 内容保护调试",
		"owafDebugPayload",
		"owafExchangeDynamicKey",
		"js-decrypt",
		"js-environment-blocked",
		"owafRemoveStatus();owafStatus(\"检测到自动化或调试浏览器",
	} {
		if !strings.Contains(s, marker) {
			t.Fatalf("expected dynamic JS bootstrap marker %q", marker)
		}
	}
}

func TestProcessJSSkipsEmptyPathsMode(t *testing.T) {
	p := NewProcessor(ProtectionConfig{
		JSObfuscationEnabled: true,
		JSProtectionMode:     "paths",
		SiteID:               1,
	})
	js := []byte(`console.log("plain");`)
	result, err := p.ProcessJS("/app.js", js)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, js) {
		t.Fatal("paths mode with no configured paths must not encrypt JS")
	}
}

func TestNormalizeDecryptCacheTTLSeconds(t *testing.T) {
	tests := []struct {
		value int
		want  int
	}{
		{value: -1, want: DefaultDecryptCacheTTLSeconds},
		{value: 0, want: DefaultDecryptCacheTTLSeconds},
		{value: 45, want: 45},
		{value: MaxDecryptCacheTTLSeconds, want: MaxDecryptCacheTTLSeconds},
		{value: MaxDecryptCacheTTLSeconds + 1, want: MaxDecryptCacheTTLSeconds},
	}
	for _, tt := range tests {
		if got := NormalizeDecryptCacheTTLSeconds(tt.value); got != tt.want {
			t.Fatalf("NormalizeDecryptCacheTTLSeconds(%d) = %d, want %d", tt.value, got, tt.want)
		}
	}
}
