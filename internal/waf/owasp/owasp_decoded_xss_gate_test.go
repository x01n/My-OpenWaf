package owasp

import (
	"math/rand"
	"strings"
	"testing"
)

// collectBase64Tokens 是 forEachBase64TokenIndex 的收集封装，返回源串上
// 所有被扫描到的 [start:end) 区间（含 token 跨度超过 8 前导字节的情况）。
func collectBase64Tokens(src string, limit int) []string {
	var out []string
	forEachBase64TokenIndex(src, limit, func(start, end int) bool {
		out = append(out, src[start:end])
		return true
	})
	return out
}

// TestBase64CandidateTokenSubsumption 验证 hasBase64Candidate 的字节域
// [A-Za-z0-9+/_-] 全部被 isBase64TokenByte 收录：候选快检不依赖任何
// token 扫描不认识的字节。这是「Base64 门不漏任何 token」的前提。
func TestBase64CandidateTokenSubsumption(t *testing.T) {
	for b := 0; b < 256; b++ {
		inCandidate := (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '+' || b == '/' || b == '-' || b == '_'
		inToken := isBase64TokenByte(byte(b))
		if inCandidate && !inToken {
			t.Fatalf("字节 0x%02x：hasBase64Candidate 收录而 isBase64TokenByte 未收录", b)
		}
	}
}

// gatedNextDecodedXSSHit 模拟「Likely 之后补 Base64 门」而门内语义原样。
func gatedNextDecodedXSSHit(raw string, qPlus bool, thr int) (OWASPHit, string, bool) {
	if len(raw) < 8 || !hasLikelyBase64Candidate(raw) {
		return OWASPHit{}, "", false
	}
	if !hasBase64Candidate(raw) {
		return OWASPHit{}, "", false
	}
	return nextDecodedXSSHit(raw, qPlus, thr)
}

// TestBase64GateNoTokenEquiv 定向样例：无连续 8 base64 字符的串在门内直接
// 返回无命中，与「Likely 门内但 token 列表为空」的原路径判定同一。
func TestBase64GateNoTokenEquiv(t *testing.T) {
	candidates := []string{
		"select * from dual",            // 字距散开无 8 连
		"abcdefg",                       // 7 连（len<8 双门均关）
		"a-b-c-d-e-f-g",                 // 短连字符交替
		strings.Repeat(" ", 32),         // 纯空白
		"\x41\x41\x41\x41\x41\x41\x41 ", // 7 个大写 + 空格
		"(((((((())))))))",              // 括号
		"a1b2c3d4e5f6g7",                // 数字间隔
		"!@#$%^&*()_+|\":{}<>?",         // 符号串
	}
	for _, s := range candidates {
		gotHit, gotTarget, gotOK := gatedNextDecodedXSSHit(s, false, 4)
		wantHit, wantTarget, wantOK := nextDecodedXSSHit(s, false, 4)
		if gotHit != wantHit || gotTarget != wantTarget || gotOK != wantOK {
			t.Fatalf("无 token 样例 %q 判定偏差", s)
		}
		if hasBase64Candidate(s) {
			t.Logf("注意 %q 实际上被 hasBase64Candidate 记录为候选，跳过门无法细化", s)
		}
	}
}

// TestBase64GateEquivFixed 构造样例：门开启路径输入（8+ 连 base64 字符）的判定
// 与未加门原函数完全一致。
func TestBase64GateEquivFixed(t *testing.T) {
	fixed := []string{
		"ABCDEFGH",
		"abcdefgh",
		"12345678",
		"U0VMRUNUIFVOSU9O",
		"aaaaaaaabbbbbbbb",
		"../etc/passwd",
		"<script>alert(1)</script>",
		"javascript:alert(1)",
		"\" onmouseover=alert(1) x=\"",
		"AAAA%2527AAAA",
		"YjIwY2hhbGxlbmdl",
		"////////////",
		"----____++++",
		"8q8q8q8q8q8q8q8q",
		"QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
		"d2FmOnNjcmlwdA==",
	}
	for _, s := range fixed {
		for _, q := range []bool{false, true} {
			for _, thr := range []int{4, 9} {
				gotHit, gotTarget, gotOK := gatedNextDecodedXSSHit(s, q, thr)
				wantHit, wantTarget, wantOK := nextDecodedXSSHit(s, q, thr)
				if gotHit != wantHit || gotTarget != wantTarget || gotOK != wantOK {
					t.Fatalf("固定样例 %q q=%v thr=%d 判定偏差: gated=(%v,%q,%v) orig=(%v,%q,%v)",
						s, q, thr, gotHit, gotTarget, gotOK, wantHit, wantTarget, wantOK)
				}
			}
		}
	}
}

// TestBase64GateEquivRandom 随机对拍：全部阈值取 4/7/9，覆盖高阈值无命中路径。
func TestBase64GateEquivRandom(t *testing.T) {
	r := rand.New(rand.NewSource(20260928))
	randBase64 := func(r *rand.Rand, n int) string {
		const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-="
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteByte(alpha[r.Intn(len(alpha))])
		}
		return b.String()
	}
	randMix := func(r *rand.Rand, n int) string {
		var b strings.Builder
		for b.Len() < n {
			switch r.Intn(4) {
			case 0:
				b.WriteString(randBase64(r, 6+r.Intn(24)))
			case 1:
				sep := " %?x=.. "
				b.WriteByte(sep[r.Intn(len(sep))])
			case 2:
				b.WriteString("<script>alert(1)</script>")
			default:
				b.WriteByte(byte(r.Intn(128)))
			}
		}
		return b.String()
	}
	for i := 0; i < 20000; i++ {
		s := randMix(r, 1+r.Intn(96))
		q := i%2 == 0
		thr := []int{4, 7, 9}[i%3]
		gotHit, gotTarget, gotOK := gatedNextDecodedXSSHit(s, q, thr)
		wantHit, wantTarget, wantOK := nextDecodedXSSHit(s, q, thr)
		if gotHit != wantHit || gotTarget != wantTarget || gotOK != wantOK {
			t.Fatalf("随机样例 %q q=%v thr=%d 判定偏差: gated=(%v,%q,%v) orig=(%v,%q,%v)",
				s, q, thr, gotHit, gotTarget, gotOK, wantHit, wantTarget, wantOK)
		}
	}
}

// TestLemmaLikelyImpliesBase64 元性质对拍：hasLikelyBase64Candidate 为真的
// 一切混串，hasBase64Candidate 同为真；出现反例立即失败。
func TestLemmaLikelyImpliesBase64(t *testing.T) {
	r := rand.New(rand.NewSource(20260928))
	gen := func(r *rand.Rand, n int) string {
		var b strings.Builder
		for b.Len() < n {
			switch r.Intn(12) {
			case 0, 1, 2, 3:
				l := 4 + r.Intn(20)
				for i := 0; i < l && b.Len() < n; i++ {
					b.WriteByte('a' + byte(r.Intn(26)))
				}
			case 4, 5:
				l := 3 + r.Intn(12)
				for i := 0; i < l && b.Len() < n; i++ {
					b.WriteByte('A' + byte(r.Intn(26)))
				}
			case 6:
				l := 3 + r.Intn(10)
				for i := 0; i < l && b.Len() < n; i++ {
					b.WriteByte('0' + byte(r.Intn(10)))
				}
			case 7:
				b.WriteByte('%')
			case 8:
				b.WriteByte("+-/_"[r.Intn(4)])
			default:
				b.WriteByte(" =?&<.\n"[r.Intn(6)])
			}
		}
		return b.String()
	}
	for i := 0; i < 100000; i++ {
		s := gen(r, 1+r.Intn(80))
		lik := hasLikelyBase64Candidate(s)
		b64 := hasBase64Candidate(s)
		if lik && !b64 {
			t.Fatalf("反例（Likely=true 且 Base64=false）：%q", s)
		}
	}
}

// TestLemmaNoTokenEquivForTokenFunction 验证「hasBase64Candidate=false ⇒ token 列表为空」
// 的要点：所有无 8 连 base64 字节的串，其 token 扫描结果不得包含任何非空 token。
func TestLemmaNoTokenEquivForTokenFunction(t *testing.T) {
	r := rand.New(rand.NewSource(20260929))
	alpha := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for i := 0; i < 100000; i++ {
		n := 1 + r.Intn(40)
		var b strings.Builder
		for j := 0; j < n; j++ {
			if r.Intn(3) == 0 {
				b.WriteByte(" !@#%^&*()[]{};',.:?~`<>\"\n\t"[r.Intn(27)])
			} else {
				b.WriteByte(alpha[r.Intn(len(alpha))])
			}
			// 每 7 个字符强制插入一位非 base64 字节，确保无 8 连 base64。
			if j%7 == 6 {
				b.WriteByte(' ')
			}
		}
		s := b.String()
		if hasBase64Candidate(s) {
			continue
		}
		toks := collectBase64Tokens(s, -1)
		for _, tok := range toks {
			dec := decodeBase64IfSuspicious(tok)
			if dec != "" {
				t.Fatalf("hasBase64Candidate=false 却产出可解 token %q → 解码 %q，输入 %q", tok, dec, s)
			}
		}
	}
}

// TestLemmaThresholdsCrossValidate 随机场下补充阈值 7/9 的交叉矩阵，保证门在各阈值都等价。
func TestLemmaThresholdsCrossValidate(t *testing.T) {
	r := rand.New(rand.NewSource(20260930))
	alpha := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-% =?&<>!'\""
	for i := 0; i < 5000; i++ {
		n := 1 + r.Intn(64)
		var b strings.Builder
		for j := 0; j < n; j++ {
			b.WriteByte(alpha[r.Intn(len(alpha))])
		}
		s := b.String()
		for _, thr := range []int{4, 7, 9} {
			gotHit, gotTarget, gotOK := gatedNextDecodedXSSHit(s, i%2 == 0, thr)
			wantHit, wantTarget, wantOK := nextDecodedXSSHit(s, i%2 == 0, thr)
			if gotHit != wantHit || gotTarget != wantTarget || gotOK != wantOK {
				t.Fatalf("阈值对拍 %q thr=%d 判定偏差", s, thr)
			}
		}
	}
}
