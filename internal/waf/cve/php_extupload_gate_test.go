package cve

import (
	"testing"
)

// buildUploadExtCases 返回 测试名 -> CVERequest 构造参数。
//
// 所有用例均通过 BuildCVERequestInto 走真实归一化路径,
// ComputeSubDetectorHits 后调用 PHP 检测器,避免手拼 CVERequest
// 与线上字段语义漂移。
func TestPHPCVEDetectorWebshellExtUploadGate(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		rawQuery    string
		headers     map[string]string
		body        string
		contentType string
		// wantExtHit 断言是否应命中 CVE-2016-WEBSHELL-EXT。
		wantExtHit bool
	}{
		{
			name:        "无上传语境的普通 GET 路径命中 php 扩展名 -> 放行(上下文收窄)",
			path:        "/plugin.php",
			rawQuery:    "act=get&idsite=1",
			headers:     map[string]string{"Host": "example.com"},
			body:        "",
			contentType: "",
			wantExtHit:  false,
		},
		{
			name:     "multipart 上传 filename=x.php -> 命中",
			path:     "/index.php",
			rawQuery: "",
			headers:  map[string]string{"Host": "example.com"},
			body: "--X-BOUNDARY\r\n" +
				"Content-Disposition: form-data; name=\"file\"; filename=\"x.php\"\r\n" +
				"Content-Type: application/octet-stream\r\n\r\n" +
				"plain upload body\r\n" +
				"--X-BOUNDARY--\r\n",
			contentType: "multipart/form-data; boundary=X-BOUNDARY",
			wantExtHit:  true,
		},
		{
			name:        "urlencoded 表单携带 filename=shell.php -> 命中",
			path:        "/upload.php",
			rawQuery:    "",
			headers:     map[string]string{"Host": "example.com"},
			body:        "filename=shell.php&action=save",
			contentType: "application/x-www-form-urlencoded",
			wantExtHit:  true,
		},
		{
			name:        "Content-Disposition 请求头(附件上传痕迹),路径无 php -> 命中",
			path:        "/upload",
			rawQuery:    "",
			headers:     map[string]string{"Host": "example.com", "Content-Disposition": "form-data; name=\"file\"; filename=\"a.php\""},
			body:        "",
			contentType: "",
			wantExtHit:  true,
		},
		{
			name:        "纯 body 含 .php 但无任何上传痕迹 -> 放行(交由 webshell 具体规则兜底)",
			path:        "/api/notes",
			rawQuery:    "",
			headers:     map[string]string{"Host": "example.com"},
			body:        `{"page":"index.php"}`,
			contentType: "application/json",
			wantExtHit:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var req CVERequest
			BuildCVERequestInto(&req, tc.path, tc.rawQuery, tc.headers, []byte(tc.body), tc.contentType)
			hits := computeSubDetectorHits(&req)
			d := NewPHPCVEDetector()
			got, ok := d.DetectFirst(&req, &hits)
			gotExtHit := ok && got.CVEID == "CVE-2016-WEBSHELL-EXT"
			if gotExtHit != tc.wantExtHit {
				t.Fatalf("WEBSHELL-EXT 命中=%v, want=%v (match=%+v ok=%v)", gotExtHit, tc.wantExtHit, got, ok)
			}
		})
	}
}

// TestPHPCVEDetectorWebshellExtStillFires 锁死「multipart body filename=x.php 必须命中」。
//
// 该用例与上面 multipart 用例语义重复,但以显式 Detect 全量模式断言,
// 防止后续有人把规则误删导致漏报而未被 DetectFirst 用例覆盖。
func TestPHPCVEDetectorWebshellExtStillFires(t *testing.T) {
	var req CVERequest
	body := "--B\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\n" +
		"payload\r\n" +
		"--B--\r\n"
	BuildCVERequestInto(&req, "/upload", "", map[string]string{"Host": "example.com"},
		[]byte(body), "multipart/form-data; boundary=B")
	hits := computeSubDetectorHits(&req)
	matches := NewPHPCVEDetector().Detect(&req, &hits)
	for _, m := range matches {
		if m.CVEID == "CVE-2016-WEBSHELL-EXT" {
			return
		}
	}
	t.Fatalf("未找到 CVE-2016-WEBSHELL-EXT 命中, matches=%+v", matches)
}
