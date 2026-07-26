package owasp

import (
	"encoding/base64"
	"strings"
	"testing"
)

// normalizeBenchCase 描述一条归一化基准输入。
// queryPlusAsSpace 与生产调用点保持一致（query/form 源为 true，path 源为 false）。
type normalizeBenchCase struct {
	name             string
	raw              string
	queryPlusAsSpace bool
}

var benchB64SQLi = base64.StdEncoding.EncodeToString([]byte("id=1' UNION SELECT username,password FROM users-- "))
var benchB64XSS = base64.StdEncoding.EncodeToString([]byte("<script>alert(document.cookie)</script>"))

// normalizeBenchCases 覆盖 normalizeWithDecodeTarget 的各条分支：
// 早退、有候选但解不出、真实 base64 解出、JS 转义链、以及 raw/s/urlDecoded 高度重叠的多源扫描。
var normalizeBenchCases = []normalizeBenchCase{
	{
		name:             "CleanQueryNoToken",
		raw:              "page=2&sort=created_at&order=desc&per_page=20",
		queryPlusAsSpace: true,
	},
	{
		name:             "SessionTokenNoDecode",
		raw:              "sid=a7Kd93LmQpZx01Rt5YbN2VcW8sHgJfEu&ref=dashboard&ts=1721990400",
		queryPlusAsSpace: true,
	},
	{
		name:             "Base64SQLiDecoded",
		raw:              "data=" + benchB64SQLi,
		queryPlusAsSpace: true,
	},
	{
		name:             "Base64XSSDecoded",
		raw:              "payload=" + benchB64XSS,
		queryPlusAsSpace: true,
	},
	{
		name:             "URLEncodedOverlapMultiSource",
		raw:              "q=%73%65%61%72%63%68&token=" + benchB64XSS + "&next=%2Fadmin%2Fdashboard",
		queryPlusAsSpace: true,
	},
	{
		name:             "JSEscapeChain",
		raw:              `v=\x77\x69\x6e\x64\x6f\x77\x5b\x27\x61\x6c\x65\x72\x74\x27\x5d&b=` + benchB64XSS,
		queryPlusAsSpace: true,
	},
	{
		name:             "LongJSONBodyWithTokens",
		raw:              buildBenchJSONBody(),
		queryPlusAsSpace: false,
	},
}

// buildBenchJSONBody 构造一个体量接近真实 API 请求体的 JSON，
// 内含多个长 base64 形态 token（解不出可疑内容），用于放大源串重复扫描成本。
func buildBenchJSONBody() string {
	var b strings.Builder
	b.WriteString(`{"user":{"id":10234,"name":"alice","avatar":"aHR0cHM6Ly9jZG4uZXhhbXBsZS5jb20vYS9hdmF0YXIucG5n"},`)
	b.WriteString(`"session":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDIzNCIsImV4cCI6MTc1MzQ1NjAwMH0",`)
	b.WriteString(`"items":[`)
	for i := 0; i < 12; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"sku":"SKU00`)
		b.WriteByte(byte('0' + i%10))
		b.WriteString(`","hash":"9f8c2b1aD4e7F0a3B6c9D2e5F8a1B4c7","qty":3}`)
	}
	b.WriteString(`],"note":"regular checkout request with no attack payload"}`)
	return b.String()
}

func BenchmarkNormalizeWithDecodeTarget(b *testing.B) {
	for _, tc := range normalizeBenchCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = normalizeWithDecodeTarget(tc.raw, tc.queryPlusAsSpace)
			}
		})
	}
}

// BenchmarkDecodeJSEscapes 单独测量 JS 转义解码，覆盖无转义短路与密集转义两种输入。
func BenchmarkDecodeJSEscapes(b *testing.B) {
	inputs := []struct {
		name string
		s    string
	}{
		{"NoBackslash", "page=2&sort=created_at&order=desc&per_page=20"},
		{"HexDense", `\x77\x69\x6e\x64\x6f\x77\x5b\x27\x61\x6c\x65\x72\x74\x27\x5d\x28\x31\x29`},
		{"UnicodeDense", `\u0077\u0069\u006e\u0064\u006f\u0077\u005b\u0027\u0061\u006c\u0065\u0072\u0074\u0027\u005d`},
		{"MixedSparse", `prefix text without escapes then \x41 and more plain text tail content here`},
	}
	for _, in := range inputs {
		b.Run(in.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = decodeJSEscapesPooled(in.s)
			}
		})
	}
}
