package owasp

import (
	"encoding/base64"
	"math/rand"
	"net/url"
	"strings"
	"testing"
)

// 本文件是 base64 token 扫描剪枝的对拍测试（等价性为主，判定恒等是唯一边界）：
// 1) 表驱动 isBase64TokenByte 对拍：256 字节全部语义与旧多分支判定一致，
//    并验证与 reBase64Token / hasBase64Candidate 的字节域同界。
// 2) normalizeWithDecodeTarget 与「去剪枝黄金参照」legacyNormalizeWithDecodeRef
//    的对拍：目标 + 恶意 + 白样本 + 大字符串 + 高字节随机，返回串逐字节一致。
//    参照复制自剪枝前的 R2 解码环，随本测试文件静态冻结；未来任何对 R2 的
//    剪枝（前置筛选、词法版本改写）只要改变返回值，即被同输入对拍拦截。

// TestIsBase64TokenByteTableEquiv 逐字节核对查表实现与旧多分支判定。
func TestIsBase64TokenByteTableEquiv(t *testing.T) {
	for b := 0; b < 256; b++ {
		old := (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
			b == '+' || b == '/' || b == '-' || b == '_'
		if got := isBase64TokenByte(byte(b)); got != old {
			t.Fatalf("字节 0x%02x：查表=%v 旧判定=%v", b, got, old)
		}
		inCandidate := (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
			b == '+' || b == '/' || b == '-' || b == '_'
		if inCandidate != old {
			t.Fatalf("字节 0x%02x：hasBase64Candidate 域与旧判定不一致", b)
		}
	}
}

// TestForEachBase64TokenIndexTableEquiv 对拍查表重构前后的收集器：用冻结的
// 旧谓词副本重放同一扫描循环，与当前 forEachBase64TokenIndex 收集结果逐条一致。
// 注意 reBase64Token 的字符类不含 -/_，与扫描器对含 -/_ 的 run 有既有差异
// （旧测试只喂标准字母表输入，从未触及）；本测试用旧谓词语义做参照，另在
// 无 -/_ 的输入上维持原有「扫描器 == 正则」见证关系。
func TestForEachBase64TokenIndexTableEquiv(t *testing.T) {
	legacyPred := func(b byte) bool {
		return isBase64AlphaNum(b) || b == '+' || b == '/' || b == '-' || b == '_'
	}
	legacyCollect := func(src string) []string {
		var out []string
		i := 0
		for i < len(src) {
			for i < len(src) && !legacyPred(src[i]) {
				i++
			}
			start := i
			for i < len(src) && legacyPred(src[i]) {
				i++
			}
			if i-start < 8 {
				continue
			}
			end := i
			for end < len(src) && end-i < 2 && src[end] == '=' {
				end++
			}
			out = append(out, src[start:end])
			i = end
		}
		return out
	}
	collect := func(src string) []string {
		var out []string
		forEachBase64TokenIndex(src, -1, func(start, end int) bool {
			out = append(out, src[start:end])
			return true
		})
		return out
	}

	fixed := []string{
		"plain text without base64 tokens here",
		"U0VMRUNUIFVOSU9OIFBBU1NXT1JE",
		"token=QUJDREVGR0g=&next=abcdefgh",
		"Zm9vIGJhcuKAmQ==", // 内含 UTF-8 右单引号（多字节）
		"retain=e3sgMzMzMSozMzMwIH19==&x=TlM4cUlH",
		"8q8q8q8q8q8q8q8q",
		"a\"e3sgMzMzMSozMzMwIH19\"+plain/ABCDEF12==!",
		"abc ABCDEFG normal",
		"----____++++....12345678",
		"lKCl_/Rjq2dfF", // 含 -/_ 的 run：扫描器视作单 token
		"01%xXoPrA\xa9b<8p1ZhKtMeMG/8Bx/lKCl",
	}
	r := rand.New(rand.NewSource(20260929))
	alpha := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-= %?&<>.\\x\u00e9\u4e2d"
	inputs := append([]string{}, fixed...)
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		n := 1 + r.Intn(80)
		for j := 0; j < n; j++ {
			b.WriteByte(alpha[r.Intn(len(alpha))])
		}
		inputs = append(inputs, b.String())
	}
	for _, s := range inputs {
		got := collect(s)
		want := legacyCollect(s)
		if len(got) != len(want) {
			t.Fatalf("输入 %q：当前收集 %d 个 token，旧谓词收集 %d 个", s, len(got), len(want))
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("输入 %q：token %d 当前 %q，旧谓词 %q", s, i, got[i], want[i])
			}
		}
	}

	// 无 -/_ 输入上维持「扫描器 == reBase64Token」的传统见证。
	regexInputs := []string{
		"plain text without base64 tokens here",
		"U0VMRUNUIFVOSU9OIFBBU1NXT1JE",
		"token=QUJDREVGR0g=&next=abcdefgh",
		"retain=e3sgMzMzMSozMzMwIH19==&x=TlM4cUlH",
		"a\"e3sgMzMzMSozMzMw IH19\"+plain/ABCDEF12==!",
		"abc ABCDEFG normal",
	}
	for _, s := range regexInputs {
		want := reBase64Token.FindAllString(s, -1)
		got := collect(s)
		if len(got) != len(want) {
			t.Fatalf("输入 %q：收集 %d 个 token，reBase64Token 收集 %d 个", s, len(got), len(want))
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("输入 %q：token %d 收集 %q，正则收集 %q", s, i, got[i], want[i])
			}
		}
	}
}

// legacyNormalizeWithDecodeRef 是 normalizeWithDecodeTarget 剪枝前的静态黄金
// 参照：完整复制其 R2 解码环（schema 依次扫描 raw/s/urlDecoded/jsDecoded 的
// base64 token 并递归解码）。它只在本测试文件中冻结，不随生产代码演化。
func legacyNormalizeWithDecodeRef(raw string, queryPlusAsSpace bool) string {
	if needsDecoding(raw) {
		if strings.Contains(raw, "\\x") {
			hexDecoded := decodeHexEscapes(raw)
			if hexDecoded != raw {
				raw = hexDecoded
			}
		}
	}

	s := normalizeTarget(raw, queryPlusAsSpace)
	if len(s) < 8 || !hasLikelyBase64Candidate(s) && (raw == s || !hasLikelyBase64Candidate(raw)) {
		return s
	}
	urlDecoded := raw
	if strings.Contains(raw, "%") {
		for i := range 3 {
			var d string
			var err error
			if i == 0 {
				d, err = unescapeURLComponent(urlDecoded, queryPlusAsSpace)
			} else {
				d, err = url.PathUnescape(urlDecoded)
			}
			if err != nil || d == urlDecoded {
				break
			}
			urlDecoded = d
		}
	}
	jsDecoded := ""
	if strings.Contains(urlDecoded, "\\") {
		jsDecoded = decodeJSEscapesPooled(urlDecoded)
		if jsDecoded == urlDecoded || jsDecoded == raw || jsDecoded == s {
			jsDecoded = ""
		}
	}

	const maxTotalBytes = 32768
	const maxDepth = 3

	var accPtr *[]byte
	var acc []byte
	seen := make(map[string]bool, 8)
	found := false
	totalBytes := 0
	attemptsRemaining := 2 * ((len(raw) + len(s) + len(urlDecoded) + len(jsDecoded) + maxTotalBytes + 7) / 8)

	var decodeSource func(src string, depth int) bool
	decodeSource = func(src string, depth int) bool {
		if depth > maxDepth || totalBytes >= maxTotalBytes || attemptsRemaining <= 0 {
			return false
		}
		stop := false
		forEachBase64TokenIndex(src, -1, func(start, end int) bool {
			tok := src[start:end]
			if seen[tok] {
				return true
			}
			seen[tok] = true
			if attemptsRemaining <= 0 {
				stop = true
				return false
			}
			attemptsRemaining--
			decoded := decodeBase64IfSuspicious(tok)
			if decoded == "" && start > 0 && isURLSafeBase64LeadByte(src[start-1]) {
				if attemptsRemaining <= 0 {
					stop = true
					return false
				}
				attemptsRemaining--
				decoded = decodeBase64IfSuspicious(src[start-1 : end])
			}
			if decoded == "" {
				return true
			}
			remaining := maxTotalBytes - totalBytes
			if len(decoded) > remaining {
				decoded = decoded[:remaining]
			}
			totalBytes += len(decoded)
			if !found {
				accPtr = getNormBuf()
				acc = *accPtr
				if cap(acc) < len(s)+256 {
					acc = make([]byte, 0, len(s)+256)
				}
				acc = append(acc[:0], s...)
				found = true
			}
			normalizedDecoded := normalize(decoded)
			acc = append(acc, ' ')
			acc = append(acc, normalizedDecoded...)

			nextJS := ""
			nextNormalizedJS := ""
			if strings.Contains(decoded, "\\") {
				nextJS = decodeJSEscapesPooled(decoded)
				if nextJS != decoded {
					nextNormalizedJS = normalize(nextJS)
					acc = append(acc, ' ')
					acc = append(acc, nextNormalizedJS...)
				} else {
					nextJS = ""
				}
			}
			if nextJS != "" {
				stop = decodeSource(nextJS, depth+1)
			}
			if !stop && nextNormalizedJS != "" {
				stop = decodeSource(nextNormalizedJS, depth+1)
			}
			if !stop {
				stop = decodeSource(decoded, depth+1)
			}
			if stop || totalBytes >= maxTotalBytes {
				stop = true
				return false
			}
			return true
		})
		return stop
	}

	stopped := decodeSource(raw, 1)
	if !stopped && s != raw {
		stopped = decodeSource(s, 1)
	}
	if !stopped && urlDecoded != raw && urlDecoded != s {
		stopped = decodeSource(urlDecoded, 1)
	}
	if !stopped && jsDecoded != "" {
		decodeSource(jsDecoded, 1)
	}

	if found {
		result := string(acc)
		*accPtr = acc
		putNormBuf(accPtr)
		return result
	}
	return s
}

func checkLegacyRefPair(t *testing.T, s string, q bool) {
	t.Helper()
	got := normalizeWithDecodeTarget(s, q)
	want := legacyNormalizeWithDecodeRef(s, q)
	if got != want {
		t.Fatalf("样例 %q qPlus=%v 与黄金参照不一致：\n现=%q\n参=%q", s, q, got, want)
	}
}

// TestNormalizeWithDecodeLegacyRefFixed 固定样例（目标 + 恶意 + 白样本）对拍。
func TestNormalizeWithDecodeLegacyRefFixed(t *testing.T) {
	payloads := []string{
		// 恶意样本：base64 编码的 SQLi/XSS、直写 SQL。
		"id=" + base64.StdEncoding.EncodeToString([]byte("1' UNION SELECT username,password FROM users-- ")),
		"data=" + base64.RawURLEncoding.EncodeToString([]byte("<script>alert(document.cookie)</script>")),
		"SELECT * FROM users WHERE id = 1 OR 1=1",
		"Q0xBU1NFUyBQT1dFUg", // 去除填充后仍为 token
		"YjIwY2hhbGxlbmdl",
		"//etc/passwd%00",
		"%40abcdefgh", // %40 引线（纯 ASCII 边缘输入）
		"v=%40%41%42%43%44%45%46%47",
		"x=%3c%73%63%72%69%70%74%3e",
		// 白样本：干净查询、会话 token、JWT 形态。
		"page=2&sort=created_at&order=desc&per_page=20",
		"sid=a7Kd93LmQpZx01Rt5YbN2VcW8sHgJfEu&ref=dashboard&ts=1721990400",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDIzNCJ9",
		"user=alice&action=view",
	}
	for _, s := range payloads {
		for _, q := range []bool{false, true} {
			checkLegacyRefPair(t, s, q)
		}
	}
}

// TestNormalizeWithDecodeLegacyRefRandom 随机生成器对拍：可打印 ASCII 混合串，
// 长度 1..96，均匀覆盖 token 集聚与稀疏分布。
func TestNormalizeWithDecodeLegacyRefRandom(t *testing.T) {
	r := rand.New(rand.NewSource(20260929))
	alpha := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-= %?&<>.\\\"':;,#@!()[]{}"
	for i := 0; i < 12000; i++ {
		n := 1 + r.Intn(96)
		var b strings.Builder
		for j := 0; j < n; j++ {
			b.WriteByte(alpha[r.Intn(len(alpha))])
		}
		checkLegacyRefPair(t, b.String(), i%2 == 0)
	}
}

// TestNormalizeWithDecodeLegacyRefLongTarget 大字符串对拍：4KiB..48KiB 的
// token 密集串与高字节随机串，覆盖 maxTargetLen(16384) 约束下的遍历与截断。
func TestNormalizeWithDecodeLegacyRefLongTarget(t *testing.T) {
	r := rand.New(rand.NewSource(20260929))
	longASCII := strings.Repeat("LoremIpsumDolorSitAmet1234567890+/", 800) // ~34400
	longASCII += ".tail" + strings.Repeat("a", 100)                        // > 2*16384 截断阈值
	sampled := []string{
		longASCII,
		strings.Repeat("QUJDREVGR0hJSktM", 3000), // token 边界清晰的大样本 ~42000
	}
	const longAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-= %?&"
	for len(sampled) < 14 {
		n := 4096 + r.Intn(45000)
		run := make([]byte, 0, n)
		for len(run) < n {
			if r.Intn(8) == 0 {
				run = append(run, byte(0x20+r.Intn(0x5F)))
			} else {
				run = append(run, longAlpha[r.Intn(len(longAlpha))])
			}
		}
		sampled = append(sampled, string(run))
	}
	for _, s := range sampled {
		for _, q := range []bool{false, true} {
			checkLegacyRefPair(t, s, q)
		}
	}
}

// TestNormalizeWithDecodeLegacyRefHighByte 高字节样例：UTF-8/latin-1 与随机
// 非法 UTF-8 字节，对拍与参照逐字节一致。
func TestNormalizeWithDecodeLegacyRefHighByte(t *testing.T) {
	r := rand.New(rand.NewSource(20260929))
	hb := []string{
		"café" + "U0VMRUNUIFVOSU9O",
		"中文payload" + base64.StdEncoding.EncodeToString([]byte("' OR 1=1--")),
		strings.Repeat("£", 20) + "ABCDEFGH",
		"%C3%A9ABCDEFGH",
		"Zm9vIGJhcuKAmQ==",
	}
	for i := 0; i < 4000; i++ {
		n := 1 + r.Intn(64)
		var b strings.Builder
		for j := 0; j < n; j++ {
			if r.Intn(2) == 0 {
				b.WriteByte(byte(0x80 + r.Intn(0x80)))
			} else {
				b.WriteByte("abcdefgh ABCDEFGH1234+/=-_%?&"[r.Intn(28)])
			}
		}
		hb = append(hb, b.String())
	}
	for _, s := range hb {
		for _, q := range []bool{false, true} {
			checkLegacyRefPair(t, s, q)
		}
	}
}

// TestNormalizeWithDecodeLegacyRefPrimers 攻击引物对拍：以 base64、
// %3c 型、%40 型三种编码的攻击载荷嵌入随机上下文，保证攻击面命中。
func TestNormalizeWithDecodeLegacyRefPrimers(t *testing.T) {
	r := rand.New(rand.NewSource(20260929))
	alpha := "abcdefgh ABCDEFGH1234%\\"
	payload := "<script>alert(1)</script>"
	primers := []string{
		base64.StdEncoding.EncodeToString([]byte(payload)),
		"%3c%73%63%72%69%70%74%3e",
		"%40ab" + base64.StdEncoding.EncodeToString([]byte(payload)),
		base64.StdEncoding.EncodeToString([]byte("' OR 1=1--")),
	}
	for i := 0; i < 12000; i++ {
		n := 1 + r.Intn(48)
		var b strings.Builder
		for j := 0; j < n; j++ {
			b.WriteByte(alpha[r.Intn(len(alpha))])
		}
		base := b.String()
		s := base + primers[i%len(primers)] + base
		checkLegacyRefPair(t, s, i%2 == 0)
	}
}
