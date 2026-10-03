package cve

import (
	"testing"
)

// TestRequestTargetContainsCRLFGate 锁死 CRLF 门的两个语义点:
//   - 解码后的目标含有 %0d%0a / \r\n 任意形态时,规则继续走(命中真实 CRLF 载荷);
//   - 目标完全不含 CRLF 字符或编码形态时,门直接关闭(不放跑任何误报路径)。
//
// GeneralDetector.DetectFirst 全量返回,逐 CVEID 判定,避免只测门函数漏掉规则表挂接。
func TestGeneralDetectorCRLFGate(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		rawQ    string
		body    string
		ctype   string
		wantHit bool
	}{
		{
			name:    "query 编码 %0d%0aLocation: -> 命中",
			path:    "/redirect",
			rawQ:    "url=http://x/%0d%0aLocation:%20http://evil",
			body:    "",
			ctype:   "",
			wantHit: true,
		},
		{
			name:    "query 单编码 %250d%250a 解码出 %0d%0a -> 命中",
			path:    "/redirect",
			rawQ:    "url=http://x/%250d%250aLocation:%20http://evil",
			body:    "",
			ctype:   "",
			wantHit: true,
		},
		{
			name:    "合法查询无任何 CRLF 字符/编码 -> 放行",
			path:    "/plugin.php",
			rawQ:    "act=get&idsite=1",
			body:    "",
			ctype:   "",
			wantHit: false,
		},
		{
			name:    "JSON body 带真实 \\r\\n 字面 -> 命中",
			path:    "/api",
			rawQ:    "",
			body:    "{\"v\":\"a\r\nb\"}",
			ctype:   "application/json",
			wantHit: true,
		},
		{
			name:    "urlencoded body 带 %0d%0a -> 命中",
			path:    "/api",
			rawQ:    "",
			body:    "url=http://x/%0d%0aLocation:%20http://evil",
			ctype:   "application/x-www-form-urlencoded",
			wantHit: true,
		},
		{
			name:    "header 值带 %0d%0a 但 query/body 干净 -> 命中",
			path:    "/ok",
			rawQ:    "a=b",
			body:    "",
			ctype:   "",
			wantHit: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{"Host": "example.com"}
			if tc.wantHit && tc.path == "/ok" {
				headers["X-Evil"] = "v%0d%0aLocation: http://evil"
			}
			req := BuildCVERequest(tc.path, tc.rawQ, headers, []byte(tc.body), tc.ctype)
			hits := computeSubDetectorHits(req)
			matches := NewGeneralCVEDetector().Detect(req, &hits)
			got := false
			for _, m := range matches {
				if m.CVEID == "CVE-2019-CRLF" {
					got = true
				}
			}
			if got != tc.wantHit {
				t.Fatalf("CVE-2019-CRLF 命中=%v, want=%v (matches=%+v)", got, tc.wantHit, matches)
			}
		})
	}
}
