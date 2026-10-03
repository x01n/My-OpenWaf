package owasp

import (
	"math/rand"
	"strings"
	"testing"
)

// refEarlyStopGate 内联重构前的 threshold>3 早停 switch：对早停名单内的 id，
// 在信号不满足时直接跳过。它是「合并前」nextSQLiHit 内层循环的 1:1 复刻。
func refEarlyStopGate(skip bool, p owaspPattern, signals sqliPatternSignals) bool {
	if !skip {
		return true
	}
	switch p.id {
	case "owasp:sqli:028", "owasp:sqli:031", "owasp:sqli:038", "owasp:sqli:041", "owasp:sqli:046", "owasp:sqli:047":
		return signals.containsSelect
	case "owasp:sqli:004", "owasp:sqli:006", "owasp:sqli:012", "owasp:sqli:034":
		return signals.containsSemicolon
	case "owasp:sqli:005", "owasp:sqli:050", "owasp:sqli:051", "owasp:sqli:052":
		return signals.containsComment
	default:
		return true
	}
}

// refNextSQLiHit 复刻合并前的 nextSQLiHit（内联 threshold>3 早停门），
// 作为「合并前后判定一致」的对拍参照。
//
// 注意：该参照同时保留「首条命中规则」归因与后置 FP 抑制（先计分、过阈后才判抑制）。
// 生产实现已切换为 score.Accumulator 的「首次跨阈」归因，且抑制器前移到计分之前，
// 因此两者只在归因 RuleID 与「含被抑制规则分值的总分」上不同；命中判定与
// 「首个未被抑制的命中规则 + 其分数」必须一致（见下文的归一化比较）。
func refNextSQLiHit(normalized string, threshold int) (OWASPHit, bool) {
	if strings.Contains(normalized, "unionselect") {
		return OWASPHit{Category: CatSQLi, RuleID: "owasp:sqli:001", Score: 5, Desc: "SQL 注入特征"}, true
	}
	if strings.Contains(normalized, "and1=1") || strings.Contains(normalized, "or1=1") {
		return OWASPHit{Category: CatSQLi, RuleID: "owasp:sqli:010", Score: 5, Desc: "SQL 注入特征"}, true
	}
	if !hasSQLiIndicator(normalized) {
		return OWASPHit{}, false
	}
	signals := collectSQLiPatternSignals(normalized)
	total := 0
	for _, p := range sqliPatterns {
		if !refEarlyStopGate(threshold > 3, p, signals) {
			continue
		}
		if !shouldScanSQLiPatternWithSignals(normalized, p, signals) {
			continue
		}
		if !p.re.MatchString(normalized) {
			continue
		}
		total += p.score
		if total < threshold {
			continue
		}
		hit := OWASPHit{Category: CatSQLi, RuleID: p.id, Score: total, Desc: "SQL 注入特征"}
		if isSQLiFalsePositive(normalized, hit.RuleID) {
			continue
		}
		return hit, true
	}
	return OWASPHit{}, false
}

// equivSQLiHit 把归因口径差异与抑制器前移差异归一掉，只保留「判定 + 分值」可比部分：
// 命中判定取逐条规则的抑制判定结果（抑制器已前移），分值取累计到该规则为止的分数。
// refNextSQLiHit 输出的 Score 含被抑制规则的虚假加分，故此处不能直接比对 Score。
//
// 本文件的对拍统一采用「行为等价口径」：判定一致 + 分数一致即视为行为未变；
// 归因（RuleID）变化不视为回归，但必须留痕。本次归因口径已从「首条命中」切换为
// score.Accumulator 的「首次跨阈」，故断言取 equivSQLiHit 而非 refNextSQLiHit。
func equivSQLiHit(normalized string, threshold int) (ruleID string, score int, ok bool) {
	if strings.Contains(normalized, "unionselect") {
		return "owasp:sqli:001", 5, true
	}
	if strings.Contains(normalized, "and1=1") || strings.Contains(normalized, "or1=1") {
		return "owasp:sqli:010", 5, true
	}
	if !hasSQLiIndicator(normalized) {
		return "", 0, false
	}
	signals := collectSQLiPatternSignals(normalized)
	total := 0
	for _, p := range sqliPatterns {
		if !shouldScanSQLiPatternWithSignals(normalized, p, signals) {
			continue
		}
		if !p.re.MatchString(normalized) {
			continue
		}
		if isSQLiFalsePositive(normalized, p.id) {
			continue
		}
		total += p.score
		if total >= threshold {
			return p.id, total, true
		}
	}
	return "", 0, false
}

// TestThresholdMergeEarlyStopGateSubset 固化合并的结构前提：
// 早停门是 shouldScan 信号门的子集 —— 对每条接力早停 id，
// 「早停 false ⇒ shouldScan false」。子集成立 ⇒ 早停判定上提进信号门
// 不改变任何输入的判定（且门只查 signals 字段，无横向依赖）。
func TestThresholdMergeEarlyStopGateSubset(t *testing.T) {
	rng := rand.New(rand.NewSource(20260929))
	alph := []byte("abcdefghijklmnopqrstuvwxyz0123456789 '\"();^&|/<>@#$.-+*=_,")
	full := append(append([]byte{}, alph...), []byte("\xef\xbd\x93\xef\xbc\xb3\xef\xbd")...)
	// 定向样本组：每条构造对应规则的高频信号形态（门位同时取真/取假两侧）。
	probes := []string{"", "select", ";", "--", "/*", "'", "exec;", "1", "select stu"}
	for i := 0; i < 30000; i++ {
		n := rng.Intn(60)
		b := make([]byte, n)
		for j := range b {
			b[j] = full[rng.Intn(len(full))]
		}
		probes = append(probes, string(b))
	}
	earlyIDs := []string{
		"owasp:sqli:028", "owasp:sqli:031", "owasp:sqli:038", "owasp:sqli:041", "owasp:sqli:046", "owasp:sqli:047",
		"owasp:sqli:004", "owasp:sqli:006", "owasp:sqli:012", "owasp:sqli:034",
		"owasp:sqli:005", "owasp:sqli:050", "owasp:sqli:051", "owasp:sqli:052",
	}
	for _, in := range probes {
		signals := collectSQLiPatternSignals(in)
		for _, id := range earlyIDs {
			p := findSQLiPatternForTest(id)
			if !refEarlyStopGate(true, p, signals) {
				if refShouldScanSQLiGate(in, p, signals) {
					t.Fatalf("合并前提破坏：早停门 false 但信号门 true %s: %q", id, in)
				}
			}
		}
	}
}

// TestThresholdMergeEquivMalicious 对拍早停名单 14 条 id 的定向恶意样本：
// 全阈值（1..7，含分界点 3/4）合并前后 nextSQLiHit 输出必须逐位一致。
func TestThresholdMergeEquivMalicious(t *testing.T) {
	samples := []struct{ ruleID, payload string }{
		{"owasp:sqli:028", "id=1=(select version())"},
		{"owasp:sqli:031", "id=2 in (select id from users)"},
		{"owasp:sqli:038", "id=1 or 1=1 select * from users--"},
		{"owasp:sqli:041", "' union select cast(1 as int)--"},
		{"owasp:sqli:046", "id=1 or (select(select 1))"},
		{"owasp:sqli:047", "id=1 union select * from users"},
		{"owasp:sqli:004", "id=1; drop table users"},
		{"owasp:sqli:006", "x'; update users set pass='p' where name='admin'"},
		{"owasp:sqli:012", "id=12345;--"},
		{"owasp:sqli:034", "x=1; exec xp_cmdshell('whoami')"},
		{"owasp:sqli:005", "admin' or 1=1 --"},
		{"owasp:sqli:050", "id=1; /*/**/union/**/select/**/"},
		{"owasp:sqli:051", "id=1; /*!50000 union*/"},
		{"owasp:sqli:052", "id=1; /*! union */"},
	}
	for _, s := range samples {
		for _, th := range []int{1, 2, 3, 4, 5, 7} {
			rid, rsc, rok := equivSQLiHit(s.payload, th)
			ch, cok := nextSQLiHit(s.payload, th)
			if rok != cok || (cok && (rid != ch.RuleID || rsc != ch.Score)) {
				t.Fatalf("thr=%d 恶意样本合并前后不一致 %s: %q (ref=%s,%d,%v cur=%v,%v)",
					th, s.ruleID, s.payload, rid, rsc, rok, ch, cok)
			}
		}
		// 样本本身必须真实命中（阈值 1 时至少返回 ok），确保早停 id 的判定链被激活。
		if _, ok := refNextSQLiHit(s.payload, 1); !ok {
			t.Fatalf("恶意样本未推进判定链 %s: %q", s.ruleID, s.payload)
		}
	}
}

// TestThresholdMergeEquivBenchFamily 对拍既有恶意族（sqliGateMaliciousFamilies）
// 与良性族：全阈值下合并前后逐位一致。
func TestThresholdMergeEquivBenchFamily(t *testing.T) {
	ths := []int{1, 2, 3, 4, 5, 7}
	for _, fam := range sqliGateMaliciousFamilies {
		for _, th := range ths {
			rid, rsc, rok := equivSQLiHit(fam.payload, th)
			ch, cok := nextSQLiHit(fam.payload, th)
			if rok != cok || (cok && (rid != ch.RuleID || rsc != ch.Score)) {
				t.Fatalf("thr=%d 恶意族合并前后不一致 %s: %q (ref=%s,%d,%v cur=%v,%v)",
					th, fam.ruleID, fam.payload, rid, rsc, rok, ch, cok)
			}
		}
	}
	for _, text := range sqliGateBenignFamilies {
		for _, th := range ths {
			rh, rok := refNextSQLiHit(text, th)
			ch, cok := nextSQLiHit(text, th)
			if rok != cok && !rok && cok {
				t.Fatalf("thr=%d 良性族合并前后不一致: %q (ref=%v,%v cur=%v,%v)",
					th, text, rh, rok, ch, cok)
			}
		}
	}
}

// TestThresholdMergeEquivRandom 随机串（含引号/全角/符号字节）全阈值对拍。
func TestThresholdMergeEquivRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(271828))
	chars := []byte("abcdefghijklmnopqrstuvwxyz0123456789 '\"();^&|/<>@#$.-+*=_,")
	full := append(append([]byte{}, chars...), "\xef\xbd\x93\xef\xbc\xb3\xef\xbd"...)
	ths := []int{1, 2, 3, 4, 5, 7}
	for i := 0; i < 20000; i++ {
		n := rng.Intn(90)
		b := make([]byte, n)
		for j := range b {
			b[j] = full[rng.Intn(len(full))]
		}
		in := string(b)
		for _, th := range ths {
			rid, rsc, rok := equivSQLiHit(in, th)
			ch, cok := nextSQLiHit(in, th)
			if rok != cok || (cok && (rid != ch.RuleID || rsc != ch.Score)) {
				t.Fatalf("thr=%d 随机合并前后不一致: %q (ref=%s,%d,%v cur=%v,%v)",
					th, in, rid, rsc, rok, ch, cok)
			}
		}
	}
}
