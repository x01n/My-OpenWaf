package owasp

import "testing"

// TestJavascriptLettersScanEquivalence 验证 hasJavascriptLettersScan 与
// reJSProtocolObfuscated 的漏斗等价性：
//   - 某个组成字母（集语义：全部出现）被替换为 'x' 时预检为假，且原正则可证不命中；
//   - 字母集完好但顺序/分隔被打乱时预检为真，且原正则命中；
//   - 与若干混淆正例逐一对照。
func TestJavascriptLettersScanEquivalence(t *testing.T) {
	obfBase := "j a v a s c r i p t:"
	seen := map[byte]bool{}
	for i := 0; i < len(obfBase); i++ {
		c := obfBase[i]
		if c == ' ' || seen[c] {
			continue
		}
		seen[c] = true
		// 把该字符的全部出现替换为 'x'：字母集必然缺位。
		mutated := make([]byte, len(obfBase))
		for j := 0; j < len(obfBase); j++ {
			if obfBase[j] == c {
				mutated[j] = 'x'
			} else {
				mutated[j] = obfBase[j]
			}
		}
		muts := string(mutated)
		if hasJavascriptLettersScan(muts) {
			t.Fatalf("letters scan must be false when %q is fully removed: %q", string(c), muts)
		}
		if reJSProtocolObfuscated.MatchString(muts) {
			t.Fatalf("obfuscated javascript regex must not match after %q removal: %q", string(c), muts)
		}
	}

	// 集语义是行序敏感的：字母集全在场的行序样例预检与正则同时命中；
	// 行序被破坏（'j' 与 'a' 交换）时预检仍为真（开放漏斗），但正则必然不命中——
	// 这正是预检作为 FP 判定漏斗的安全方向：多放行、不漏杀。
	if !hasJavascriptLettersScan("j ava script:") || !reJSProtocolObfuscated.MatchString("j ava script:") {
		t.Error("letters scan and regex must both accept in-order sample \"j ava script:\"")
	}
	if hasJavascriptLettersScan("a jva script:") && !reJSProtocolObfuscated.MatchString("a jva script:") {
		// 预检开放而正则不命中：允许且是本预检的既定行为（超集漏斗）。
	} else if !hasJavascriptLettersScan("a jva script:") {
		t.Error("letters scan should stay open for reordered letters")
	}

	// 正例：预检为真，且正则命中。
	// 注意 reJSProtocolObfuscated 的第 4 个分隔符是 \s+（a 与 s 之间至少一个空白），
	// 因此紧凑的 "javascript:" 不命中该正则（由 hasXSSIndicator 与 xss:003 兜底）。
	positives := []string{
		obfBase,
		"j\tav\na\tscript:",
		"j ava script:" + `alert(1)`,
	}
	for _, pos := range positives {
		if !hasJavascriptLettersScan(pos) {
			t.Errorf("expected letters scan true for %q", pos)
		}
		if !reJSProtocolObfuscated.MatchString(pos) {
			t.Errorf("expected obfuscated javascript regex hit for %q", pos)
		}
	}
}
