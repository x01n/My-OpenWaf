package waf

import (
	"testing"
)

func TestCheckOWASP_SSRF_Metadata(t *testing.T) {
	hits := CheckOWASP("mid", "/fetch", "url=http://169.254.169.254/latest/meta-data/", nil)
	if !hasCategory(hits, CatSSRF) {
		t.Fatal("expected SSRF hit for cloud metadata endpoint")
	}
}

func TestCheckOWASP_SSRF_FileScheme(t *testing.T) {
	hits := CheckOWASP("mid", "/", "u=file:///etc/passwd", nil)
	if !hasCategory(hits, CatSSRF) && !hasCategory(hits, CatPathTrav) {
		t.Fatal("expected SSRF or path traversal hit")
	}
}

func TestCheckOWASP_CmdInjection(t *testing.T) {
	hits := CheckOWASP("mid", "/ping", "host=8.8.8.8;cat /etc/passwd", nil)
	if !hasCategory(hits, CatCmdInject) && !hasCategory(hits, CatPathTrav) {
		t.Fatal("expected command injection hit")
	}
}

func TestCheckOWASP_CmdInjection_Backtick(t *testing.T) {
	hits := CheckOWASP("high", "/", "q=`whoami`", nil)
	if !hasCategory(hits, CatCmdInject) {
		t.Fatal("expected command injection for backtick")
	}
}

func TestCheckOWASP_XXE(t *testing.T) {
	payload := `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
	hits := CheckOWASP("mid", "/", "xml="+payload, nil)
	if !hasCategory(hits, CatXXE) && !hasCategory(hits, CatSSRF) {
		t.Fatal("expected XXE hit")
	}
}

func TestCheckOWASP_LDAP(t *testing.T) {
	hits := CheckOWASP("mid", "/login", "user=*)(objectclass=*", nil)
	if !hasCategory(hits, CatLDAPI) {
		t.Fatal("expected LDAP injection hit")
	}
}

func TestCheckOWASP_NoSQLi(t *testing.T) {
	hits := CheckOWASP("mid", "/api/users", `filter={"$where": "this.password == 'a'"}`, nil)
	if !hasCategory(hits, CatNoSQLi) {
		t.Fatal("expected NoSQL injection hit")
	}
}

func TestCheckOWASP_TemplateInjection(t *testing.T) {
	hits := CheckOWASP("mid", "/", "name={{7*7}}", nil)
	if !hasCategory(hits, CatTmplInject) {
		t.Fatal("expected template injection hit")
	}
}

func TestCheckOWASP_TemplateInjection_Jinja(t *testing.T) {
	hits := CheckOWASP("mid", "/", "n={{''.__class__.__mro__}}", nil)
	if !hasCategory(hits, CatTmplInject) {
		t.Fatal("expected SSTI hit for jinja mro")
	}
}

func TestCheckOWASP_ProtocolViolation_Smuggling(t *testing.T) {
	headers := map[string]string{
		"Content-Length":    "10",
		"Transfer-Encoding": "chunked",
	}
	hits := CheckOWASP("mid", "/", "", headers)
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
	hits := CheckOWASP("mid", "/", "id=1 or 1=1", nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for boolean tautology")
	}
}

func TestCheckOWASP_SQLi_ErrorBased(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 and extractvalue(1,concat(0x7e,version()))", nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for extractvalue error-based")
	}
}

// Enhanced XSS patterns
func TestCheckOWASP_XSS_SVG(t *testing.T) {
	hits := CheckOWASP("mid", "/", "q=<svg onload=alert(1)>", nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit for SVG vector")
	}
}

func TestCheckOWASP_XSS_DataURL(t *testing.T) {
	hits := CheckOWASP("mid", "/", "url=data:text/html,<script>alert(1)</script>", nil)
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
	hits := CheckOWASP("high", "/abcdefg/hijklmn/a.html", "", headers)
	if hasCategory(hits, CatSSRF) {
		t.Fatal("Host header 127.0.0.1 should not trigger SSRF — it is a standard request attribute")
	}
}

// Ensure SSRF still detects localhost in actual payloads (query string).
func TestCheckOWASP_SSRF_LocalhostInPayload(t *testing.T) {
	hits := CheckOWASP("high", "/", "url=http://127.0.0.1/admin", nil)
	if !hasCategory(hits, CatSSRF) {
		t.Fatal("expected SSRF hit for localhost in query payload")
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
