package owasp

import (
	"math/rand"
	"strings"
	"testing"
)

// refShouldScanSQLiGate 以「逐条字面量 Contains」的线式实现重建 shouldScanSQLiPatternWithSignals
// 的桥接判定（hint 门 + 各规则前置链），用作 current 版本（两级 mask 门 + 必需品桥接）的对拍参照。
// 注意：本参照不含任何掩码/位门，是任务描述中「改造前」的字面形态。
func refShouldScanSQLiGate(normalized string, p owaspPattern, signals sqliPatternSignals) bool {
	if p.hint != "" && !strings.Contains(normalized, p.hint) {
		return false
	}
	switch p.id {
	case "owasp:sqli:002":
		return (signals.containsOr || signals.containsAnd) && strings.Contains(normalized, "'")
	case "owasp:sqli:003":
		return (signals.containsSleep || signals.containsBenchmark || signals.containsWaitfor || signals.containsPGSleep) && strings.Contains(normalized, "(")
	case "owasp:sqli:004":
		return signals.containsSemicolon && (strings.Contains(normalized, "select") || strings.Contains(normalized, "drop") || strings.Contains(normalized, "alter") || strings.Contains(normalized, "create") || strings.Contains(normalized, "truncate") || strings.Contains(normalized, "delete") || strings.Contains(normalized, "update") || strings.Contains(normalized, "insert"))
	case "owasp:sqli:005":
		return signals.containsComment && strings.ContainsAny(normalized, "'\"0123456789")
	case "owasp:sqli:006":
		return signals.containsSemicolon && strings.Contains(normalized, "'")
	case "owasp:sqli:007":
		return hasSQLiFunctionCallPattern(normalized, "chr") ||
			hasSQLiFunctionCallPattern(normalized, "unhex") ||
			hasSQLiFunctionCallPattern(normalized, "conv")
	case "owasp:sqli:008":
		return hasSQLiHexLiteralPattern(normalized)
	case "owasp:sqli:009":
		return signals.containsInformation || signals.containsSysobjects || signals.containsSysDot
	case "owasp:sqli:010":
		return hasSQLBooleanNumericComparison(normalized)
	case "owasp:sqli:011":
		if !strings.ContainsAny(normalized, "'\"") {
			return false
		}
		return hasSQLBooleanQuotedComparison(normalized)
	case "owasp:sqli:036":
		if !strings.ContainsAny(normalized, "'\"") {
			return false
		}
		return hasSQLBooleanEmptyQuotedComparison(normalized)
	case "owasp:sqli:039":
		return (signals.containsOr || signals.containsAnd) && signals.containsSelect && strings.Contains(normalized, "(")
	case "owasp:sqli:012":
		return signals.containsSemicolon && strings.Contains(normalized, "--")
	case "owasp:sqli:013", "owasp:sqli:017":
		return signals.containsOutfile || signals.containsDumpfile || signals.containsLoadFile || signals.containsInto
	case "owasp:sqli:014":
		return signals.containsAtAt
	case "owasp:sqli:015":
		return (signals.containsExtractvalue || signals.containsUpdatexml) && strings.Contains(normalized, "(")
	case "owasp:sqli:018", "owasp:sqli:040":
		return signals.containsCase && signals.containsWhen
	case "owasp:sqli:019":
		return signals.containsOrder
	case "owasp:sqli:021":
		return (signals.containsSubstr || signals.containsSubstring || signals.containsMid) && strings.Contains(normalized, "(")
	case "owasp:sqli:022":
		if !strings.Contains(normalized, "if") || !strings.Contains(normalized, "(") {
			return false
		}
		return hasSQLiIfFunctionPattern(normalized)
	case "owasp:sqli:023":
		return strings.Contains(normalized, "'") && (strings.ContainsAny(normalized, "^&") || strings.Contains(normalized, "<<") || strings.Contains(normalized, ">>"))
	case "owasp:sqli:024", "owasp:sqli:045":
		return signals.containsXP
	case "owasp:sqli:025":
		return signals.containsProcedure
	case "owasp:sqli:026":
		return signals.containsUTL || signals.containsDBMS
	case "owasp:sqli:027":
		return signals.containsHaving
	case "owasp:sqli:028", "owasp:sqli:031", "owasp:sqli:038", "owasp:sqli:041", "owasp:sqli:046", "owasp:sqli:047":
		return signals.containsSelect
	case "owasp:sqli:029":
		return signals.containsLike && strings.Contains(normalized, "'")
	case "owasp:sqli:030", "owasp:sqli:033":
		return signals.containsLimit || signals.containsOffset
	case "owasp:sqli:032":
		return signals.containsGroup && strings.Contains(normalized, "by")
	case "owasp:sqli:034":
		return signals.containsSemicolon && strings.Contains(normalized, "exec")
	case "owasp:sqli:035":
		return signals.containsWaitfor
	case "owasp:sqli:037":
		return signals.containsCopy || signals.containsProgram
	case "owasp:sqli:043":
		return signals.containsChr && strings.Count(normalized, "chr") >= 2 && (strings.Contains(normalized, "+") || strings.Contains(normalized, "||"))
	case "owasp:sqli:044":
		return signals.containsUTLInaddr
	case "owasp:sqli:048":
		return signals.containsMaster
	case "owasp:sqli:049", "owasp:sqli:053":
		if !hasHighByte(normalized) {
			return false
		}
		return signals.containsFullwidthS
	case "owasp:sqli:050", "owasp:sqli:051", "owasp:sqli:052":
		return signals.containsComment
	case "owasp:sqli:054":
		return signals.containsDoubleURLEncode
	default:
		return true
	}
}

// sqliGateMaliciousFamilies 是恶意样本族：每条 payload 都推进其 ruleID 对应规则的位门，
// 且参照线式桥接必须返回 true。这些样本是「规则真命中」的位门前端形态。
var sqliGateMaliciousFamilies = []struct {
	ruleID  string
	payload string
}{
	{"owasp:sqli:002", `id=1 or 'a'='a'`},
	{"owasp:sqli:002", `id=1 and '1'='1'`},
	{"owasp:sqli:003", `id=1;select sleep(5)`},
	{"owasp:sqli:003", `id=1;select benchmark(1000000,md5(1))`},
	{"owasp:sqli:003", `x'||pg_sleep(10)--`},
	{"owasp:sqli:004", `id=1; drop table users`},
	{"owasp:sqli:005", `admin'--`},
	{"owasp:sqli:006", `id='; show tables`},
	{"owasp:sqli:007", `id=chr(65)`},
	{"owasp:sqli:014", `id=1 union select @@version`},
	{"owasp:sqli:011", `name=admin" or "a"="a"`},
	{"owasp:sqli:036", `id=1' or ''='`},
	{"owasp:sqli:022", `id=if(select 123)`},
	{"owasp:sqli:043", `id=p';chr(65)+chr(66)`},
}

// sqliGateBenignFamilies 是常见良性字符串族，确保位门在无推进形状时不误放行。
var sqliGateBenignFamilies = []string{
	"hello world this is a normal request parameter",
	"filename=report-2026.pdf",
	"https://example.com/docs/page?id=42",
	"https://my.site/app/index.html?tab=home",
	"search=how to grow tomatoes",
}

func TestSQLiGateBucketEquivalence(t *testing.T) {
	// 恶意族：每条 payload 必须让参照桥接 true（正向形状保留），且两版判定一致。
	for _, fam := range sqliGateMaliciousFamilies {
		p := findSQLiPatternForTest(fam.ruleID)
		ref := refCollectSQLiPatternSignals(fam.payload)
		cur := collectSQLiPatternSignals(fam.payload)
		if !refShouldScanSQLiGate(fam.payload, p, ref) {
			t.Fatalf("恶意样本 %q 未推进规则 %s 的参照位门", fam.payload, fam.ruleID)
		}
		if refShouldScanSQLiGate(fam.payload, p, ref) != shouldScanSQLiPatternWithSignals(fam.payload, p, cur) {
			t.Fatalf("sqliGate 等价破坏（恶意）%s: %q", fam.ruleID, fam.payload)
		}
	}
	// 良性族：每族 × 全 54 id。
	for _, text := range sqliGateBenignFamilies {
		ref := refCollectSQLiPatternSignals(text)
		cur := collectSQLiPatternSignals(text)
		for _, id := range sqliSignalsEquivIDs {
			p := findSQLiPatternForTest(id)
			if refShouldScanSQLiGate(text, p, ref) != shouldScanSQLiPatternWithSignals(text, p, cur) {
				t.Fatalf("sqliGate 等价破坏（良性）%s: %q", id, text)
			}
		}
	}
}

// TestSQLiGateBucketRandomEquivalence 是随机对拍：位门判定必须逐输入一致。
// 对「新门 false、参照 true」的输入再覆核反向必要条件：位门 false ⇒ 正则不可能命中
// （即若正则命中则位门必须 true，防漏检）。
func TestSQLiGateBucketRandomEquivalence(t *testing.T) {
	rng := rand.New(rand.NewSource(20260929))
	alph := []byte("abcdefghijklmnopqrstuvwxyz0123456789 '\"();^&|/<>@#$.-+*=_,")
	full := make([]byte, 0, len(alph)+10)
	full = append(full, alph...)
	full = append(full, []byte("\xef\xbd\x93\xef\xbc\xb3\xef\xbd\xc3\xa5\xc2\xa7\x00\xff")...)

	for i := 0; i < 50000; i++ {
		n := rng.Intn(80)
		b := make([]byte, n)
		for j := range b {
			b[j] = full[rng.Intn(len(full))]
		}
		in := string(b)
		ref := refCollectSQLiPatternSignals(in)
		cur := collectSQLiPatternSignals(in)
		for _, id := range sqliSignalsEquivIDs {
			p := findSQLiPatternForTest(id)
			refGate := refShouldScanSQLiGate(in, p, ref)
			curGate := shouldScanSQLiPatternWithSignals(in, p, cur)
			if refGate != curGate {
				t.Fatalf("sqliGate 随机等价破坏 %s: %q (ref=%v cur=%v)", id, in, refGate, curGate)
			}
			// 必要条件方向：gated=false ⇒ 正则不可能匹配（防漏检）。
			if !curGate && p.re.MatchString(in) {
				t.Fatalf("位门 false 但正则命中（漏检）%s: %q", id, in)
			}
		}
	}
}

// TestSQLiGateBucketNoScanIsNoMatch 对「位门 false」的输入跑正则禁则：false ⇒ 正则必不匹配。
// 这是每条规则位门作为必要条件（bucket 允许 false negative，禁止 false positive）的写入测试。
// 注意反方向（true ⇒ 匹配）不是性质，不在此断言。
func TestSQLiGateBucketNoScanIsNoMatch(t *testing.T) {
	rng := rand.New(rand.NewSource(20260929))
	// 只取全集 ASCII + 少量高位字节；位门 false 的输入大多没有推进字节。
	alph := []byte("abcdefghijklmnopqrstuvwxyz0123456789 '\"();^&|/<>@#$.-+*=_,")
	for i := 0; i < 20000; i++ {
		n := rng.Intn(70)
		b := make([]byte, n)
		for j := range b {
			b[j] = alph[rng.Intn(len(alph))]
		}
		in := string(b)
		cur := collectSQLiPatternSignals(in)
		if strings.ContainsAny(in, "'\"()%") {
			continue
		}
		for _, id := range sqliSignalsEquivIDs {
			p := findSQLiPatternForTest(id)
			if shouldScanSQLiPatternWithSignals(in, p, cur) {
				continue
			}
			if p.re.MatchString(in) {
				t.Fatalf("位门 false 但正则命中 %s: %q", id, in)
			}
		}
	}
}
