package owasp

import (
	"math/rand"
	"strings"
	"testing"
)

// refCollectSQLiPatternSignals 重建 collectSQLiPatternSignals 掩码化前的逐字段 Contains 链。
func refCollectSQLiPatternSignals(normalized string) sqliPatternSignals {
	return sqliPatternSignals{
		containsSelect:          strings.Contains(normalized, "select"),
		containsSemicolon:       strings.Contains(normalized, ";"),
		containsComment:         strings.Contains(normalized, "--") || strings.Contains(normalized, "/*") || strings.Contains(normalized, "/*!"),
		containsOr:              strings.Contains(normalized, "or"),
		containsAnd:             strings.Contains(normalized, "and"),
		containsSleep:           strings.Contains(normalized, "sleep"),
		containsBenchmark:       strings.Contains(normalized, "benchmark"),
		containsWaitfor:         strings.Contains(normalized, "waitfor"),
		containsPGSleep:         strings.Contains(normalized, "pg_sleep"),
		containsChr:             strings.Contains(normalized, "chr"),
		containsInformation:     strings.Contains(normalized, "information_schema"),
		containsSysobjects:      strings.Contains(normalized, "sysobjects"),
		containsSysDot:          strings.Contains(normalized, "sys."),
		containsOutfile:         strings.Contains(normalized, "outfile"),
		containsDumpfile:        strings.Contains(normalized, "dumpfile"),
		containsLoadFile:        strings.Contains(normalized, "load_file"),
		containsInto:            strings.Contains(normalized, "into"),
		containsAtAt:            strings.Contains(normalized, "@@"),
		containsExtractvalue:    strings.Contains(normalized, "extractvalue"),
		containsUpdatexml:       strings.Contains(normalized, "updatexml"),
		containsCase:            strings.Contains(normalized, "case"),
		containsWhen:            strings.Contains(normalized, "when"),
		containsOrder:           strings.Contains(normalized, "order"),
		containsSubstr:          strings.Contains(normalized, "substr"),
		containsSubstring:       strings.Contains(normalized, "substring"),
		containsMid:             strings.Contains(normalized, "mid"),
		containsXP:              strings.Contains(normalized, "xp_"),
		containsProcedure:       strings.Contains(normalized, "procedure"),
		containsUTL:             strings.Contains(normalized, "utl_"),
		containsDBMS:            strings.Contains(normalized, "dbms_"),
		containsHaving:          strings.Contains(normalized, "having"),
		containsLike:            strings.Contains(normalized, "like"),
		containsLimit:           strings.Contains(normalized, "limit"),
		containsOffset:          strings.Contains(normalized, "offset"),
		containsGroup:           strings.Contains(normalized, "group"),
		containsCopy:            strings.Contains(normalized, "copy"),
		containsProgram:         strings.Contains(normalized, "program"),
		containsUTLInaddr:       strings.Contains(normalized, "utl_inaddr"),
		containsMaster:          strings.Contains(normalized, "master"),
		containsFullwidthS:      strings.Contains(normalized, "\xef\xbd\x93") || strings.Contains(normalized, "\xef\xbc\xb3"),
		containsDoubleURLEncode: strings.Contains(normalized, "%25"),
	}
}

func refShouldScanSQLiPatternWithSignals(normalized string, p owaspPattern, signals sqliPatternSignals) bool {
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
		return hasSQLBooleanQuotedComparison(normalized)
	case "owasp:sqli:036":
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
		return signals.containsFullwidthS
	case "owasp:sqli:050", "owasp:sqli:051", "owasp:sqli:052":
		return signals.containsComment
	case "owasp:sqli:054":
		return signals.containsDoubleURLEncode
	default:
		return true
	}
}

// sqliSignalsEquivLiterals 覆盖全部 43 条信号字面量（含全角两字面量与 /*!）。
var sqliSignalsEquivLiterals = []string{
	"select", ";", "--", "/*", "/*!", "or", "and", "sleep", "benchmark", "waitfor",
	"pg_sleep", "chr", "information_schema", "sysobjects", "sys.", "outfile", "dumpfile",
	"load_file", "into", "@@", "extractvalue", "updatexml", "case", "when", "order",
	"substr", "substring", "mid", "xp_", "procedure", "utl_", "dbms_", "having",
	"like", "limit", "offset", "group", "copy", "program", "utl_inaddr", "master",
	"\xef\xbd\x93", "\xef\xbc\xb3", "%25",
}

// sqliSignalsEquivIDs 覆盖 shouldScan 位门改造涉及的全部模式 id（51 个），
// 取值与 sqliPatterns 表中一一对应（含 011/022/036/007 位门 case）。
var sqliSignalsEquivIDs = []string{
	"owasp:sqli:002", "owasp:sqli:003", "owasp:sqli:004", "owasp:sqli:005",
	"owasp:sqli:006", "owasp:sqli:007", "owasp:sqli:008", "owasp:sqli:009",
	"owasp:sqli:010", "owasp:sqli:011", "owasp:sqli:012", "owasp:sqli:013",
	"owasp:sqli:014", "owasp:sqli:015", "owasp:sqli:016", "owasp:sqli:017",
	"owasp:sqli:018", "owasp:sqli:019", "owasp:sqli:020", "owasp:sqli:021",
	"owasp:sqli:022", "owasp:sqli:023", "owasp:sqli:024", "owasp:sqli:025",
	"owasp:sqli:026", "owasp:sqli:027", "owasp:sqli:028", "owasp:sqli:029",
	"owasp:sqli:030", "owasp:sqli:031", "owasp:sqli:032", "owasp:sqli:033",
	"owasp:sqli:034", "owasp:sqli:035", "owasp:sqli:036", "owasp:sqli:037",
	"owasp:sqli:038", "owasp:sqli:039", "owasp:sqli:040", "owasp:sqli:041",
	"owasp:sqli:043", "owasp:sqli:044", "owasp:sqli:045", "owasp:sqli:046",
	"owasp:sqli:047", "owasp:sqli:048", "owasp:sqli:049", "owasp:sqli:050",
	"owasp:sqli:051", "owasp:sqli:052", "owasp:sqli:053", "owasp:sqli:054",
}

func sqliSignalsDiff(a, b sqliPatternSignals) string {
	check := func(x, y bool, name string) string {
		if x != y {
			return name
		}
		return ""
	}
	for _, c := range []struct {
		x, y bool
		n    string
	}{
		{a.containsSelect, b.containsSelect, "containsSelect"},
		{a.containsSemicolon, b.containsSemicolon, "containsSemicolon"},
		{a.containsComment, b.containsComment, "containsComment"},
		{a.containsOr, b.containsOr, "containsOr"},
		{a.containsAnd, b.containsAnd, "containsAnd"},
		{a.containsSleep, b.containsSleep, "containsSleep"},
		{a.containsBenchmark, b.containsBenchmark, "containsBenchmark"},
		{a.containsWaitfor, b.containsWaitfor, "containsWaitfor"},
		{a.containsPGSleep, b.containsPGSleep, "containsPGSleep"},
		{a.containsChr, b.containsChr, "containsChr"},
		{a.containsInformation, b.containsInformation, "containsInformation"},
		{a.containsSysobjects, b.containsSysobjects, "containsSysobjects"},
		{a.containsSysDot, b.containsSysDot, "containsSysDot"},
		{a.containsOutfile, b.containsOutfile, "containsOutfile"},
		{a.containsDumpfile, b.containsDumpfile, "containsDumpfile"},
		{a.containsLoadFile, b.containsLoadFile, "containsLoadFile"},
		{a.containsInto, b.containsInto, "containsInto"},
		{a.containsAtAt, b.containsAtAt, "containsAtAt"},
		{a.containsExtractvalue, b.containsExtractvalue, "containsExtractvalue"},
		{a.containsUpdatexml, b.containsUpdatexml, "containsUpdatexml"},
		{a.containsCase, b.containsCase, "containsCase"},
		{a.containsWhen, b.containsWhen, "containsWhen"},
		{a.containsOrder, b.containsOrder, "containsOrder"},
		{a.containsSubstr, b.containsSubstr, "containsSubstr"},
		{a.containsSubstring, b.containsSubstring, "containsSubstring"},
		{a.containsMid, b.containsMid, "containsMid"},
		{a.containsXP, b.containsXP, "containsXP"},
		{a.containsProcedure, b.containsProcedure, "containsProcedure"},
		{a.containsUTL, b.containsUTL, "containsUTL"},
		{a.containsDBMS, b.containsDBMS, "containsDBMS"},
		{a.containsHaving, b.containsHaving, "containsHaving"},
		{a.containsLike, b.containsLike, "containsLike"},
		{a.containsLimit, b.containsLimit, "containsLimit"},
		{a.containsOffset, b.containsOffset, "containsOffset"},
		{a.containsGroup, b.containsGroup, "containsGroup"},
		{a.containsCopy, b.containsCopy, "containsCopy"},
		{a.containsProgram, b.containsProgram, "containsProgram"},
		{a.containsUTLInaddr, b.containsUTLInaddr, "containsUTLInaddr"},
		{a.containsMaster, b.containsMaster, "containsMaster"},
		{a.containsFullwidthS, b.containsFullwidthS, "containsFullwidthS"},
		{a.containsDoubleURLEncode, b.containsDoubleURLEncode, "containsDoubleURLEncode"},
	} {
		if r := check(c.x, c.y, c.n); r != "" {
			return r
		}
	}
	return ""
}

// TestSQLiPatternSignalsMaskEquivalence 逐字面量（原样/大写/前后缀包裹/删字节）
// 与随机壳输入逐字段对拍 collectSQLiPatternSignals。
func TestSQLiPatternSignalsMaskEquivalence(t *testing.T) {
	for _, lit := range sqliSignalsEquivLiterals {
		for _, wrap := range []string{"", "x", " ", "(", "-", "'", "/", "%"} {
			in := wrap + lit + wrap
			if d := sqliSignalsDiff(refCollectSQLiPatternSignals(in), collectSQLiPatternSignals(in)); d != "" {
				t.Errorf("信号等价破坏(%s): %q", d, in)
			}
			up := strings.ToUpper(lit)
			if d := sqliSignalsDiff(refCollectSQLiPatternSignals(up), collectSQLiPatternSignals(up)); d != "" {
				t.Errorf("大写信号等价破坏(%s): %q", d, up)
			}
		}
		// 删字节变体：截断可能命中表内更短子串（如 updatexml->update），
		// 不能假设"必不命中"，一律逐输入对拍。
		for k := 0; k < len(lit); k++ {
			trunc := lit[:k] + lit[k+1:]
			if d := sqliSignalsDiff(refCollectSQLiPatternSignals(trunc), collectSQLiPatternSignals(trunc)); d != "" {
				t.Errorf("删字节信号等价破坏(%s): %q -> %q", d, lit, trunc)
			}
		}
	}
}

// TestSQLiPatternSignalsMaskRandomEquivalence 随机壳 10 万对拍。
func TestSQLiPatternSignalsMaskRandomEquivalence(t *testing.T) {
	rng := rand.New(rand.NewSource(2026))
	chars := []byte("abcdefghijklmnopqrstuvwxyz0123456789 ^&|%;,'\"/\\()<>@#$.-+*=_:")
	full := append(append([]byte{}, chars...), []byte("\xef\xbd\x93\xef\xbc\xb3\xef\xbd")...)
	for i := 0; i < 100000; i++ {
		n := rng.Intn(90)
		b := make([]byte, n)
		for j := range b {
			b[j] = full[rng.Intn(len(full))]
		}
		in := string(b)
		if d := sqliSignalsDiff(refCollectSQLiPatternSignals(in), collectSQLiPatternSignals(in)); d != "" {
			t.Fatalf("随机信号等价破坏(%s): %q", d, in)
		}
	}
}

// TestSQLiShouldScanSignalsEquivalence 在全部 51 个 sqli 模式 id 上对拍
// shouldScanSQLiPatternWithSignals（含 007/011/022/036 位门 case），输入含
// 位门相关边界：函数家族字面量、"chr(65)+chr(66)"、"if(select 1)"、引号对等。
func TestSQLiShouldScanSignalsEquivalence(t *testing.T) {
	inputs := []string{
		// 位门正例
		"id=chr(65)", "id=unhex (414243)", "id=conv (10,10,16)",
		"chr(65)+chr(66)", "chr(65)||chr(66)", "chrchr",
		"if(select 1)", "if ( ascii(1) )", "if(ord(1))", "if( substr(1) )",
		"or 'a'='a'", "or ''='", `or "x"="y"`, "'a' = 'b'", `"x" = "y"`,
		// 位门负例（函数名不完整 / 无括号 / 无引号）
		"chrx", "chr", "convX", "ifx(1)", "if(select)", "if()", "if(",
		"unhexagonal layout", "conversation notes", "chromium browser setting",
		// 信号边界
		"select", "selectcase", "orand", "ord", "and or", "s elect", "- -",
		"\xef\xbd\x93", "\xef\xbc\xb3", "%25", "%%25", "'", "\"", "--", "/*",
		// 随机方向补充
		"1' or '1'='1", "admin'--", "union select 1", "group by 1 --", "limit 1,2",
		"0x41414141", "x' AND 1=1", "';exec xp_", "utl_inaddr.get_host",
	}
	for _, in := range inputs {
		ref := refCollectSQLiPatternSignals(in)
		got := collectSQLiPatternSignals(in)
		if d := sqliSignalsDiff(ref, got); d != "" {
			t.Fatalf("信号等价破坏(%s): %q", d, in)
		}
		for _, id := range sqliSignalsEquivIDs {
			p := findSQLiPatternForTest(id)
			if refShouldScanSQLiPatternWithSignals(in, p, ref) != shouldScanSQLiPatternWithSignals(in, p, got) {
				t.Fatalf("shouldScan 等价破坏 %s: %q", id, in)
			}
		}
	}
}

// TestSQLiShouldScanSignalsRandomEquivalence 随机壳 10 万 × 10 个代表性 id 对拍
// shouldScanSQLiPatternWithSignals（覆盖全部三个位门判定族与信号桶族）。
func TestSQLiShouldScanSignalsRandomEquivalence(t *testing.T) {
	ids := []string{
		"owasp:sqli:007", "owasp:sqli:011", "owasp:sqli:022", "owasp:sqli:036",
		"owasp:sqli:002", "owasp:sqli:010", "owasp:sqli:013", "owasp:sqli:028",
		"owasp:sqli:035", "owasp:sqli:049",
	}
	rng := rand.New(rand.NewSource(4242))
	chars := []byte("abcdefghijklmnopqrstuvwxyz0123456789 ^&|%;,'\"/\\()<>@#$.-+*=_:")
	funcBytes := []byte("chrconvunhexif'\"orandselect")
	full := append(append([]byte{}, chars...), []byte("\xef\xbd\x93\xef\xbc\xb3\xef\xbd")...)
	for i := 0; i < 100000; i++ {
		n := rng.Intn(70)
		b := make([]byte, n)
		for j := range b {
			switch rng.Intn(3) {
			case 0:
				b[j] = funcBytes[rng.Intn(len(funcBytes))]
			case 1:
				b[j] = full[rng.Intn(len(full))]
			default:
				b[j] = byte(rng.Intn(256))
			}
		}
		in := string(b)
		ref := refCollectSQLiPatternSignals(in)
		got := collectSQLiPatternSignals(in)
		for _, id := range ids {
			p := findSQLiPatternForTest(id)
			if refShouldScanSQLiPatternWithSignals(in, p, ref) != shouldScanSQLiPatternWithSignals(in, p, got) {
				t.Fatalf("随机 shouldScan 等价破坏 %s: %q", id, in)
			}
		}
	}
}
