package waf

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
func hasCategory(hits []OWASPHit, cat OWASPCategory) bool {
	for _, h := range hits {
		if h.Category == cat {
			return true
		}
	}
	return false
}
