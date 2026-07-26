package owasp

import (
	"encoding/base64"
	"strings"
	"testing"
)

// 以下两段是 blazehttp 基准中被误判为攻击的真实正常样本（.white）请求体，
// base64 内嵌以便脱离 testcases 目录运行。
//
// sample1: POST /v3/projects/9daf8dfdc099c207/collect（gio.pingcode.com 埋点上报，
// 无 Content-Type，body 为压缩二进制），曾被 owasp:cmd:002 判定为命令注入并返回 403。
const falsePositiveSample1BodyB64 = `
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
0gAAAA==`

// sample2: PUT /v1.0/me/drive/root:/<中文文件名>.pdf:/content（Microsoft Graph 文件上传，
// Content-Type 声明 application/json 但 body 实为 PDF），曾被 owasp:sqli:006 判定为
// SQL 注入并返回 403。此处内嵌触发该规则的真实 4KiB 切片。
const falsePositiveSample2SliceB64 = `
jE9000N/sT1rJV95H2v541frUyd559seX2QS1tKceraVmT3NPD8x36DbfcvQRvfzzky2H6rbkOyvOP756f8B2XYVwwplbmRz
dHJlYW0KZW5kb2JqCjEyIDAgb2JqCjw8L0FJUyBmYWxzZS9CTS9Ob3JtYWwvQ0EgMS9UeXBlL0V4dEdTdGF0ZS9jYSAwLjY5
OD4+CmVuZG9iagoxMyAwIG9iago8PC9BSVMgZmFsc2UvQk0vTm9ybWFsL0NBIDEvVHlwZS9FeHRHU3RhdGUvY2EgMT4+CmVu
ZG9iagoxNCAwIG9iago8PC9CYXNlRm9udC9TSFpSVVArV2VuUXVhbllpTWljcm9IZWkvRGVzY2VuZGFudEZvbnRzWzE3IDAg
Ul0vRW5jb2RpbmcvSWRlbnRpdHktSC9TdWJ0eXBlL1R5cGUwL1RvVW5pY29kZSAxOCAwIFIvVHlwZS9Gb250Pj4KZW5kb2Jq
CjE1IDAgb2JqCjw8L0xlbmd0aCA0MDI5L0ZpbHRlci9GbGF0ZURlY29kZT4+c3RyZWFtCnic7V1Zi+W4FX4P3P/g54F4dKQj
S4Ih4HVIYB6SFOQHhMzA0J3Qk4f8/cjLdVk6X7lct1WdDjMUXV3X19Zy9lX+dKNKxZ/fz/95pjpUf/94+3Sbr9lga7Nd/OUf
t799U/3zpmo2oVJ142z8Tb765ad497ff/9VXP/37Zppa2co01cebsbWtvOLa2urD/MXxk9tu+/D8xIfbj7c/x2n/c9PVD/Hf
n+K/n5dlqOov3+8zfKqcrdmva2auueLAdcOVU6EOel78t3/8gVw1/KuKw9VaxXtrQ/NvHde8LDdOZ3x89OONtKnvnz7cyOja
xxFd7eYFbV9aV2telnr8c3vkx2/iqv98ArBP697j7aEKVJOtyNX+GZ7Zhqmaf+KGP926p+1TXPO301OotArV0487KHT19Mu8
w+C9i6OoGZALWJa/2FaWap4f+Xj7jlzgPzz9XGmKS/Az+J6G71RQ3XJR+doFt1103SDutFp7cadRQd5pvBvlmIOx8eLvxqcF
WGfgegFjcc/E86Yp3k0hbq+pmxAiBm1jaj2jTMWPH+4f/fZxvX1BaXO4sD+/Ut0r+PNxHRH3If7nKmtoJmI2XM+LewGNamaR
mU8CP2MzufgCUtWK1ASVVsWpQqTwOgJ0xqZSNMOzIrIHbCoy6CKjiz26SPNFm15zO96ubyFdvdc1c7p49fmD2khdD4Pk+p0r
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`

// decodeFPSample 解码内嵌的 base64 样本体。
func decodeFPSample(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded), ""))
	if err != nil {
		t.Fatalf("decode embedded sample: %v", err)
	}
	return string(raw)
}

// normalizeBodyTarget 复现数据面对请求体目标的归一化（body target 的
// queryPlusAsSpace 为 true，见 forEachOWASPTarget）。
func normalizeBodyTarget(raw string) string {
	n := normalizeWithDecodeTarget(raw, true)
	if len(n) > maxTargetLen {
		n = truncateTarget(n)
	}
	return n
}

// TestBinaryBodyFalsePositivesNotFlagged 固化两个真实误报样本：
// 站点实测灵敏度 strict（阈值 1）下，二进制请求体不得被判定为攻击。
func TestBinaryBodyFalsePositivesNotFlagged(t *testing.T) {
	th := CompileThresholds("strict")
	cases := []struct {
		name    string
		encoded string
		path    string
		query   string
		headers map[string]string
	}{
		{
			name:    "pingcode_collect_compressed_body",
			encoded: falsePositiveSample1BodyB64,
			path:    "/v3/projects/9daf8dfdc099c207/collect",
			query:   "stm=1688382556459&compress=1",
			headers: map[string]string{"host": "gio.pingcode.com"},
		},
		{
			name:    "msgraph_pdf_upload_slice",
			encoded: falsePositiveSample2SliceB64,
			path:    "/v1.0/me/drive/root:/report.pdf:/content",
			query:   "@microsoft.graph.conflictBehavior=rename&select=webDavUrl,*",
			headers: map[string]string{"host": "graph.microsoft.com", "content-type": "application/json"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := decodeFPSample(t, tc.encoded)
			if !isBinaryScanTarget(normalizeBodyTarget(body)) {
				t.Fatalf("sample body should be classified as binary scan target")
			}
			hit, ok := FirstOWASPHitWithThresholds(th, tc.path, tc.query, tc.headers, []string{body})
			if ok {
				t.Errorf("false positive: rule=%s category=%s score=%d desc=%s",
					hit.RuleID, hit.Category, hit.Score, hit.Desc)
			}
		})
	}
}

// TestBinaryBodySuppressorIsTheOnlyDefence 证明这两条规则的正则在真实样本上确实匹配，
// 即二进制目标判定是唯一防线；若判定被误改，本测试与上面的用例会同时暴露问题。
func TestBinaryBodySuppressorIsTheOnlyDefence(t *testing.T) {
	sample1 := normalizeBodyTarget(decodeFPSample(t, falsePositiveSample1BodyB64))
	sample2 := normalizeBodyTarget(decodeFPSample(t, falsePositiveSample2SliceB64))

	var cmd002, sqli006 *owaspPattern
	for i := range cmdInjectPatterns {
		if cmdInjectPatterns[i].id == "owasp:cmd:002" {
			cmd002 = &cmdInjectPatterns[i]
		}
	}
	for i := range sqliPatterns {
		if sqliPatterns[i].id == "owasp:sqli:006" {
			sqli006 = &sqliPatterns[i]
		}
	}
	if cmd002 == nil || sqli006 == nil {
		t.Fatal("expected owasp:cmd:002 and owasp:sqli:006 to exist")
	}
	if !cmd002.re.MatchString(sample1) {
		t.Error("owasp:cmd:002 regex no longer matches sample1; test lost its meaning")
	}
	if !sqli006.re.MatchString(sample2) {
		t.Error("owasp:sqli:006 regex no longer matches sample2; test lost its meaning")
	}
}

// TestBinaryBodyStillDetectsRealAttacks 确认二进制包裹不能成为绕过手段：
// 高置信度规则在同样被判定为二进制的目标上仍然拦截。
func TestBinaryBodyStillDetectsRealAttacks(t *testing.T) {
	th := CompileThresholds("strict")
	binaryPrefix := decodeFPSample(t, falsePositiveSample1BodyB64)

	attacks := []struct {
		name    string
		payload string
	}{
		{"tautology", "id=1 or 1=1--"},
		{"backtick_command", "file=`whoami`"},
		{"command_chain", "host=127.0.0.1; cat /etc/passwd"},
		{"php_webshell", "<?php system($_GET['cmd']); ?>"},
		{"path_traversal", "file=../../../../etc/passwd"},
	}

	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			body := binaryPrefix + a.payload
			if !isBinaryScanTarget(normalizeBodyTarget(body)) {
				t.Fatalf("test setup: payload should still sit in a binary target")
			}
			if _, ok := FirstOWASPHitWithThresholds(th, "/upload", "", map[string]string{"host": "example.com"}, []string{body}); !ok {
				t.Errorf("attack payload %q hidden in binary body was not detected", a.payload)
			}
		})
	}
}

// TestUnionSelectSuppressionIsPreexisting 记录一个既有检测缺口的归属：
// 二进制体中拼接的 `union select` 不被检出，抑制点是 isSQLiFalsePositive 对
// owasp:sqli:001 的既有判定，而非本次新增的二进制目标判定——后者只作用于
// owasp:sqli:006 与 owasp:cmd:002。若该抑制日后被调整，本测试会失败并提示重新评估。
func TestUnionSelectSuppressionIsPreexisting(t *testing.T) {
	binaryPrefix := decodeFPSample(t, falsePositiveSample1BodyB64)
	normalized := normalizeBodyTarget(binaryPrefix + "id=1 union select username,password from users--")

	var sqli001 *owaspPattern
	for i := range sqliPatterns {
		if sqliPatterns[i].id == "owasp:sqli:001" {
			sqli001 = &sqliPatterns[i]
		}
	}
	if sqli001 == nil {
		t.Fatal("expected owasp:sqli:001 to exist")
	}
	if !sqli001.re.MatchString(normalized) {
		t.Fatal("test setup: owasp:sqli:001 regex should match the payload")
	}
	if !isSQLiFalsePositive(normalized, "owasp:sqli:001") {
		t.Error("owasp:sqli:001 suppression changed; re-evaluate the union-select detection gap")
	}
}

// TestIsBinaryScanTargetTextInputs 确认正常文本（含中文 UTF-8）不会被判定为二进制。
func TestIsBinaryScanTargetTextInputs(t *testing.T) {
	texts := []struct {
		name string
		body string
	}{
		{"chinese_utf8", strings.Repeat("这是一段正常的中文内容，包含标点符号。", 40)},
		{"english_prose", strings.Repeat("The quick brown fox jumps over the lazy dog. ", 40)},
		{"json_payload", strings.Repeat(`{"user":"alice","note":"it's fine; ok"},`, 40)},
		{"base64_blob", strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5", 40)},
		{"html_fragment", strings.Repeat("<div class=\"row\"><span>value</span></div>", 40)},
	}
	for _, tc := range texts {
		t.Run(tc.name, func(t *testing.T) {
			if isBinaryScanTarget(tc.body) {
				t.Errorf("text input misclassified as binary scan target")
			}
		})
	}
}

// TestIsBinaryScanTargetShortInput 确认短目标（路径、查询值）不进入二进制判定。
func TestIsBinaryScanTargetShortInput(t *testing.T) {
	short := string([]byte{0xff, 0xfe, 0x00, 0x01, 0x02})
	if isBinaryScanTarget(short) {
		t.Error("short input should not be classified as binary scan target")
	}
}
