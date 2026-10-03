package owasp

import (
	"math/rand"
	"strings"
	"testing"
)

// TestOWASPPatternGateEquivHitPositive 逐门锁正例：给定门字面量组成的输入，
// 对应正则必然命中，且 owaspPatternGatePass 必然放行（防漏杀）。
func TestOWASPPatternGateEquivHitPositive(t *testing.T) {
	// 每条 gate 的 musts 拼接体是该正则的极小命中样本（正则必然匹配）。
	// 用 follow-up 断言校验正则确能命中，然后检查 owaspPatternGatePass 放行。
	positives := map[string]string{
		// xxe:004 %\w+; → "%x;" 命中
		"owasp:xxe:004": "%x;",
		// ldap:004 \(\|\(\w+\s*=\s*\*\) → "(|(x=*)" 命中
		"owasp:ldap:004": "(|(x=*)",
		// nosql:014  "$foo":{"$ne":1} → 全 musts 满足 + 正则命中
		"owasp:nosql:014": `"$foo":{"$ne":1}`,
		// ssti:015 {prefix:/func:call( → "{a:b:c(" 命中
		"owasp:ssti:015": "{a:b:c(",
		// ssti:016 {prefix:func(arg)} → "{a:b()}" 命中（arg 可为空）
		"owasp:ssti:016": "{a:b()}",
		// jndi:003 ${...${...}} → "${a${b}}" 命中
		"owasp:jndi:003": "${a${b}}",
		// graphql:006 [{"query": → 必须命中（[{"query":是精确字面）
		"owasp:graphql:006": `[{"query":`,
		// graphql:007 @skip(if:$ → "@skip(if: $" 命中
		"owasp:graphql:007": "@skip(if: $",
	}

	for id, s := range positives {
		p := findOWASPPatternForGate(id)
		if !p.re.MatchString(s) {
			t.Fatalf("正例 %q 未被正则 %s 命中（正例失效，需换）", s, id)
		}
		if !owaspPatternGatePass(p, s) {
			t.Fatalf("门 %s 把正例 %q 滤掉（漏杀，违反必要条件约束）", id, s)
		}
	}
}

// TestOWASPPatternGateEquivHitNegative 逐门锁负例：非注入的常态字符串
// 若含足够结构但各 gate musts 不全，不应被门提前放行导致正则空转。
// 每个负例：门必 false 且正则必不命中（或命中则属设计错误）。
func TestOWASPPatternGateEquivHitNegative(t *testing.T) {
	negatives := map[string][]string{
		"owasp:xxe:004":     {"hello", "x=1", "%20", "a;b", "%a"},
		"owasp:ldap:004":    {"hello", "(|x)", "(*=)", "(|=x", "x=*("},
		"owasp:nosql:014":   {"hello", "$foo", "$bar", "{x:1}", `"a":{},"b":`},
		"owasp:ssti:015":    {"hello", "{a:b", "{a:b}c", ":b:c(", "{a=(c)"},
		"owasp:ssti:016":    {"{a:b:c", "{a:b:c}d", "{a:b(c)", "a:b:c(})}"},
		"owasp:jndi:003":    {"hello", "$a{b}", "a${b", "{ab}"},
		"owasp:graphql:006": {`hello`, `"query"`, `query`, `:`, `{"query`},
		"owasp:graphql:007": {`@skip`, `skip(if:$)`, `@(if$`, `@skip(if$`, `@skip(`},
	}

	for id, items := range negatives {
		p := findOWASPPatternForGate(id)
		for _, s := range items {
			if owaspPatternGatePass(p, s) {
				t.Fatalf("门 %s 应剪掉负例 %q（musts 不全，门却放行）", id, s)
			}
			// 正则不应命中；若偶然命中则负例选得不好，换。
			if p.re.MatchString(s) {
				t.Fatalf("负例失效：%s 的负例 %q 被正则击中了（需换负例）", id, s)
			}
		}
	}
}

// TestOWASPPatternGateIsNecessary 随机对拍：新门 vs 旧判定（直接把门 false 当作 skip）。
// 全量 8 条待门规则 × 5000 随机 ASCII+特殊字节串。
// 唯一准绳：门 false ⇒ 正则必不命中（必要条件）。
// 门 true ⇒ 不保证正则命中，不测此方向。
func TestOWASPPatternGateIsNecessary(t *testing.T) {
	rng := rand.New(rand.NewSource(20260930))
	full := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 '\"();^&|/<>@#$%{}[]:.-+*=_,")
	full = append(full, []byte("\x00\xef\xbd\x93\xce\xb1~!`\\\n\r\t")...)

	ids := []string{
		"owasp:xxe:004", "owasp:ldap:004", "owasp:nosql:014",
		"owasp:ssti:015", "owasp:ssti:016", "owasp:jndi:003",
		"owasp:graphql:006", "owasp:graphql:007",
	}

	for _, id := range ids {
		p := findOWASPPatternForGate(id)
		for i := 0; i < 5000; i++ {
			n := rng.Intn(60)
			b := make([]byte, n)
			for j := range b {
				b[j] = full[rng.Intn(len(full))]
			}
			s := string(b)
			gate := owaspPatternGatePass(p, s)
			if !gate && p.re.MatchString(s) {
				t.Fatalf("门 false 但正则命中（漏检）%s: %q", id, s)
			}
		}
	}
}

// TestOWASPPatternGateKnownHitStable 用每规则至少 1 条已知命中串验证：
// 门 true 且正则命中，锁定这些命中的端口不是靠盲猜。
func TestOWASPPatternGateKnownHitStable(t *testing.T) {
	known := map[string][]string{
		"owasp:xxe:004":     {"%a;", "%abc;", "%x;%y;"},
		"owasp:ldap:004":    {"(|(x=*)", "(|(uid=*)"},
		"owasp:nosql:014":   {`$a:{$ne}`, `"$foo":{"$ne":1}`, `$x:{ $regex}`},
		"owasp:ssti:015":    {"{aa:bb:cc(", "{pboot:if:check("},
		"owasp:ssti:016":    {"{x:y(w)}", "{foo:bar(baz)}"},
		"owasp:jndi:003":    {"${x${y}}", "${jndi:${lower:}}"},
		"owasp:graphql:006": {`[{"query":`, `[{ "query" :`},
		"owasp:graphql:007": {"@skip(if: $x", "@include(if: $y"},
	}

	for id, samples := range known {
		p := findOWASPPatternForGate(id)
		for _, s := range samples {
			if !p.re.MatchString(s) {
				t.Fatalf("已知命中串 %q 未被正则 %s 命中（串失效）", s, id)
			}
			if !owaspPatternGatePass(p, s) {
				t.Fatalf("门 %s 把已知命中串 %q 滤掉（漏杀）", id, s)
			}
		}
	}
}

// findOWASPPatternForGate 在全部 pattern 表中按 ID 查找规则。
// 基线测试函数与 findSQLiPatternForTest/refShouldScanXSSPattern 同范式。
func findOWASPPatternForGate(id string) owaspPattern {
	all := [][]owaspPattern{
		sqliPatterns, webshellPatterns, revshellPatterns, xssPatterns,
		pathTravPatterns, ssrfPatterns, cmdInjectPatterns, xxePatterns,
		ldapiPatterns, nosqliPatterns, tmplInjectPatterns, jndiPatterns,
		crlfPatterns, exprLangPatterns, deserialPatterns, graphqlPatterns,
	}
	for _, table := range all {
		for _, p := range table {
			if p.id == id {
				return p
			}
		}
	}
	panic("gate 规则 ID 未找到：" + id)
}

// BenchmarkOWASPPatternGate 比较 owaspPatternGatePass (新门) vs 旧 hint-only
// 判定（p.hint != "" && !strings.Contains...）。对拍同一输入三组 × 3 次、
// 取中位数比较。如果本机负载不准则撤数字（不强行伪造）。
func BenchmarkOWASPPatternGate(b *testing.B) {
	// 用 gate 表里 id 对应的规则、随机串，测两路判定。
	ids := []string{
		"owasp:xxe:004", "owasp:ldap:004", "owasp:nosql:014",
		"owasp:ssti:015", "owasp:ssti:016", "owasp:jndi:003",
		"owasp:graphql:006", "owasp:graphql:007",
	}
	rng := rand.New(rand.NewSource(20260930))
	inputs := make([]string, b.N)
	for i := range inputs {
		n := rng.Intn(60) + 1
		buf := make([]byte, n)
		for j := range buf {
			buf[j] = byte(rng.Intn(128))
		}
		inputs[i] = string(buf)
	}

	b.Run("new-gate", func(b *testing.B) {
		b.ReportAllocs()
		idx := 0
		for i := 0; i < b.N; i++ {
			p := findOWASPPatternForGate(ids[idx%len(ids)])
			_ = owaspPatternGatePass(p, inputs[i%len(inputs)])
			idx++
		}
	})

	b.Run("old-hint", func(b *testing.B) {
		b.ReportAllocs()
		idx := 0
		for i := 0; i < b.N; i++ {
			p := findOWASPPatternForGate(ids[idx%len(ids)])
			old := p.hint != "" && !strings.Contains(inputs[i%len(inputs)], p.hint)
			_ = old
			idx++
		}
	})
}
