package owasp

import (
	"encoding/base64"
	"math/rand"
	"strings"
	"testing"
)

// 本文件对拍 decodeBase64IfSuspicious 的结构预检与可打印性预判：参照实现
// legacyDecodeBase64Ref 静态复制剪枝前逻辑（四种变体依次解码 + 可打印比例
// 判定 + 剥首字符递归），任何预检引入的漏判都会被随机对拍拦截。

// legacyDecodeBase64Ref 是 decodeBase64IfSuspicious 剪枝前的静态黄金参照。
func legacyDecodeBase64Ref(s string) string {
	if len(s) < 8 {
		return ""
	}
	if s[0] == '/' && len(s) > 9 {
		if dec := legacyDecodeBase64Ref(s[1:]); dec != "" {
			return dec
		}
		return ""
	}
	var decoded []byte
	var err error
	if len(s) <= 256 {
		var buf [192]byte
		decoded, err = decodeBase64WithBuffer(s, buf[:])
	} else {
		decoded, err = decodeBase64String(s)
	}
	if err != nil {
		return ""
	}
	if len(decoded) == 0 {
		return ""
	}
	printable := 0
	for _, b := range decoded {
		if (b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\n' || b == '\r' {
			printable++
		}
	}
	ratio := float64(printable) / float64(len(decoded))
	minRatio := 0.70
	if len(s) >= 20 {
		minRatio = 0.50
	}
	if ratio < minRatio {
		if len(s) > 8 && !isBase64AlphaNum(s[0]) {
			return legacyDecodeBase64Ref(s[1:])
		}
		return ""
	}
	return string(decoded)
}

func checkBase64DecodePair(t *testing.T, s string) {
	t.Helper()
	got := decodeBase64IfSuspicious(s)
	want := legacyDecodeBase64Ref(s)
	if got != want {
		t.Fatalf("输入 %q 与黄金参照不一致：\n现=%q\n参=%q", s, got, want)
	}
}

// TestDecodeBase64IfSuspiciousFixed 固定样例：真实载荷、变体、填充与边界。
func TestDecodeBase64IfSuspiciousFixed(t *testing.T) {
	payloads := []string{
		"SELECT username,password FROM users",
		"<script>alert(document.cookie)</script>",
		"' OR 1=1-- ",
		"../../etc/passwd",
		"",
		"a",
		"short",
		strings.Repeat("A", 300),
	}
	var samples []string
	for _, p := range payloads {
		samples = append(samples,
			base64.StdEncoding.EncodeToString([]byte(p)),
			base64.RawStdEncoding.EncodeToString([]byte(p)),
			base64.URLEncoding.EncodeToString([]byte(p)),
			base64.RawURLEncoding.EncodeToString([]byte(p)),
		)
	}
	samples = append(samples,
		"YWJjZGVm",       // 无填充
		"YWJjZGVmZw==",   // 单层填充
		"YWJjZGVmZg=",    // 另一填充
		"YWJjZGVmZg===",  // 非法填充
		"YWJjZGVmZ",      // len%4==1
		"ABCDEFG",        // 短 token
		"ABCDEFGH",       // 短 token
		"ABCDEFGHI",      // len%4==1
		"+YWJjZGVm",      // 前导非 alnum
		"/YWJjZGVm",      // 前导斜杠
		"//YWJjZGVm",     // 双斜杠
		"-_YWJjZGVm",     // URL 安全前导
		"YWJj-GVm",       // 混合字母表
		"YWJj+GVm",       // 混合字母表
		"abcdEFGH1234+/", // 随机字母数字
		"abcdefghijklmnop",
		"0123456789abcdef",
		"deadbeefcafebabe",
	)
	for _, s := range samples {
		checkBase64DecodePair(t, s)
	}
}

// TestDecodeBase64IfSuspiciousRandomCharset 随机字符集串对拍。
func TestDecodeBase64IfSuspiciousRandomCharset(t *testing.T) {
	r := rand.New(rand.NewSource(20261106))
	alpha := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_="
	for i := 0; i < 40000; i++ {
		n := 1 + r.Intn(72)
		var b strings.Builder
		for j := 0; j < n; j++ {
			b.WriteByte(alpha[r.Intn(len(alpha))])
		}
		checkBase64DecodePair(t, b.String())
	}
}

// TestDecodeBase64IfSuspiciousRandomPayload 随机明文载荷（可打印与二进制混合）
// 经四种变体编码后对拍，覆盖可打印比例边界。
func TestDecodeBase64IfSuspiciousRandomPayload(t *testing.T) {
	r := rand.New(rand.NewSource(20261106))
	encs := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for i := 0; i < 20000; i++ {
		n := 1 + r.Intn(64)
		raw := make([]byte, n)
		switch i % 4 {
		case 0: // 全可打印
			for j := range raw {
				raw[j] = byte(0x20 + r.Intn(0x5F))
			}
		case 1: // 高比例可打印
			for j := range raw {
				if r.Intn(8) == 0 {
					raw[j] = byte(r.Intn(256))
				} else {
					raw[j] = byte(0x20 + r.Intn(0x5F))
				}
			}
		case 2: // 低比例可打印
			for j := range raw {
				raw[j] = byte(r.Intn(256))
			}
		case 3: // 纯二进制
			for j := range raw {
				raw[j] = byte(0x80 + r.Intn(0x80))
			}
		}
		enc := encs[r.Intn(len(encs))]
		checkBase64DecodePair(t, enc.EncodeToString(raw))
	}
}

// TestDecodeBase64IfSuspiciousLeadingNoise 前导噪声 + 真实载荷：覆盖剥字符
// 递归与结构预检的交互。
func TestDecodeBase64IfSuspiciousLeadingNoise(t *testing.T) {
	r := rand.New(rand.NewSource(20261106))
	payload := base64.StdEncoding.EncodeToString([]byte("' OR 1=1-- <script>alert(1)</script>"))
	lead := []string{"+", "/", "-", "_", "++", "//", "+/", "-_"}
	for _, p := range lead {
		for _, tail := range []string{"", "=", "==", "==="} {
			checkBase64DecodePair(t, p+payload+tail)
		}
	}
	for i := 0; i < 4000; i++ {
		var b strings.Builder
		for j := 0; j < 1+r.Intn(4); j++ {
			b.WriteByte("+/-_"[r.Intn(4)])
		}
		checkBase64DecodePair(t, b.String()+payload)
	}
}
