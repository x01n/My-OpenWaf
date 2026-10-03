package score

import (
	"fmt"
	"sync"
	"testing"
)

// TestThresholdBoundary 覆盖阈值闭区间的三个边界：threshold-1 未过阈，
// threshold 与 threshold+1 均过阈。
func TestThresholdBoundary(t *testing.T) {
	cases := []struct {
		name      string
		weights   []int
		threshold int
		wantTotal int
		wantHit   bool
	}{
		{name: "below_by_one", weights: []int{3, 3}, threshold: 7, wantTotal: 6, wantHit: false},
		{name: "equal", weights: []int{3, 4}, threshold: 7, wantTotal: 7, wantHit: true},
		{name: "above_by_one", weights: []int{4, 4}, threshold: 7, wantTotal: 8, wantHit: true},
		{name: "single_rule_exact", weights: []int{5}, threshold: 5, wantTotal: 5, wantHit: true},
		{name: "no_rules", weights: nil, threshold: 1, wantTotal: 0, wantHit: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAccumulator(tc.threshold)
			for i, w := range tc.weights {
				a.Add(fmt.Sprintf("rule:%d", i), w)
			}
			if got := a.Total(); got != tc.wantTotal {
				t.Fatalf("Total() = %d, want %d", got, tc.wantTotal)
			}
			if got := a.Exceeded(); got != tc.wantHit {
				t.Fatalf("Exceeded() = %v, want %v (total=%d threshold=%d)", got, tc.wantHit, tc.wantTotal, tc.threshold)
			}
			if got := a.Threshold(); got != tc.threshold {
				t.Fatalf("Threshold() = %d, want %d", got, tc.threshold)
			}
		})
	}
}

// TestDuplicateIDCountedOnce 断言同一 ID 重复计入只算一次，且不覆盖首次明细。
func TestDuplicateIDCountedOnce(t *testing.T) {
	a := NewAccumulator(10)
	a.Add("owasp:sqli:001", 3)
	a.Add("owasp:sqli:001", 3)
	a.Add("owasp:sqli:001", 5)

	if got := a.Total(); got != 3 {
		t.Fatalf("Total() = %d, want 3 (duplicate ID must count once)", got)
	}
	if got := len(a.Hits()); got != 1 {
		t.Fatalf("len(Hits()) = %d, want 1", got)
	}
	if got := a.Hits()[0].Weight; got != 3 {
		t.Fatalf("Hits()[0].Weight = %d, want 3", got)
	}

	// 明细以首次为准，后续重复调用不得覆盖。
	b := NewAccumulator(10)
	b.AddDetail("owasp:xss:001", 4, "first")
	b.AddDetail("owasp:xss:001", 4, "second")
	if got := b.Hits()[0].Detail; got != "first" {
		t.Fatalf("Detail = %q, want %q", got, "first")
	}
	if got := b.Total(); got != 4 {
		t.Fatalf("Total() = %d, want 4", got)
	}
}

// TestDuplicateAfterManyHits 覆盖「重复 ID 出现在多个正常命中之后」的查重路径：
// 惰性 seen 索引回填后，历史命中不得被二次计分。
//
// 期望值推导（逐项手算，不在断言里重演被测逻辑）：全部权重字面量为 2。
//
//	rule:00..rule:09 —— 10 条各计一次 → 10 次计分
//	rule:03（第 2 次）—— 重复，不计分 → 0
//	rule:11 —— 新 ID，计一次 → 1 次计分
//	rule:03（第 3 次）—— 重复，不计分 → 0
//
// 故计分次数 11，总分 11 × 2 = 22。
func TestDuplicateAfterManyHits(t *testing.T) {
	a := NewAccumulator(100)
	for _, id := range []string{
		"rule:00", "rule:01", "rule:02", "rule:03", "rule:04",
		"rule:05", "rule:06", "rule:07", "rule:08", "rule:09",
	} {
		a.Add(id, 2) // 10 条各计一次 = 20 分
	}
	a.Add("rule:03", 2) // 重复 ID：此时 seen 尚未建立，线性查重后建索引，不计分
	a.Add("rule:11", 2) // 新 ID：+2 分，累计 22
	a.Add("rule:03", 2) // 再次重复：走 O(1) 索引查重，不计分

	if got := a.Total(); got != 22 { // 推导：10×2 + rule:11 的 2；两次重复的 rule:03 不计
		t.Fatalf("Total() = %d, want 22", got)
	}
	if got := len(a.Hits()); got != 11 { // 推导：rule:00..rule:09 共 10 条 + rule:11
		t.Fatalf("len(Hits()) = %d, want 11", got)
	}
	ids := map[string]int{}
	for _, h := range a.Hits() {
		ids[h.ID]++
	}
	if len(ids) != 11 {
		t.Fatalf("distinct hit IDs = %d, want 11", len(ids))
	}
	for id, n := range ids {
		if n != 1 {
			t.Fatalf("hit %q recorded %d times, want 1", id, n)
		}
	}
}

// TestNonPositiveWeightIgnored 断言 weight<=0 的命中被忽略：不计分、不写入
// hits。若此类命中被记录，归因会指向一条零贡献规则而误导排查；负分则会
// 抵消后续真命中的分数。
func TestNonPositiveWeightIgnored(t *testing.T) {
	a := NewAccumulator(5)
	a.Add("zero", 0)
	a.Add("negative", -4)
	a.AddDetail("zero_detail", 0, "should not appear")

	if got := a.Total(); got != 0 {
		t.Fatalf("Total() = %d, want 0", got)
	}
	if got := len(a.Hits()); got != 0 {
		t.Fatalf("len(Hits()) = %d, want 0", got)
	}
	if a.Exceeded() {
		t.Fatalf("Exceeded() = true, want false")
	}
	if id, sc := a.Attribution(); id != "" || sc != 0 {
		t.Fatalf("Attribution() = (%q, %d), want (\"\", 0)", id, sc)
	}

	// 负权重不得抵消真命中：先记一条真命中，再喂负权重。
	a.Add("real", 6)
	if got := a.Total(); got != 6 {
		t.Fatalf("Total() = %d, want 6", got)
	}
	if id, sc := a.Attribution(); id != "real" || sc != 6 {
		t.Fatalf("Attribution() = (%q, %d), want (real, 6)", id, sc)
	}
}

// TestAttributionIgnoresSuppressedFirstRule 构造 checkNoSQLi 的等价场景。
//
// 现有 OWASP 实现以「首个命中的规则」归因（best），而 FP 抑制器按归因规则 ID
// 判定是否丢弃整类结果。于是当首条命中规则恒被抑制时，后面本该贡献分数的
// 规则连分数一起被吞掉。等价形态：
//
//	owasp:nosql:001 (权重 5) —— 恒被 isNoSQLiFalsePositive 抑制
//	owasp:nosql:022 (权重 5) —— 真实攻击特征
//	阈值 7：total=10 应过阈，归因必须是 022（真正把总分推过阈值的那条）。
//
// 同时对照受抑制规则本身不参与计分（接入方在 FP 抑制后不调用 Add）的形态。
func TestAttributionIgnoresSuppressedFirstRule(t *testing.T) {
	const threshold = 7

	// 形态一：两条规则都进入累加器（旧实现归因到 001，整类被丢弃）。
	a := NewAccumulator(threshold)
	a.Add("owasp:nosql:001", 5)
	if a.Exceeded() {
		t.Fatalf("Exceeded() = true after first rule, want false (total=5 < 7)")
	}
	if id, sc := a.Attribution(); id != "" || sc != 0 {
		t.Fatalf("pre-lock Attribution() = (%q, %d), want (\"\", 0)", id, sc)
	}
	a.Add("owasp:nosql:022", 5)

	if !a.Exceeded() {
		t.Fatalf("Exceeded() = false, want true (total=10)")
	}
	id, sc := a.Attribution()
	if id != "owasp:nosql:022" {
		t.Fatalf("Attribution() id = %q, want %q (last rule to cross threshold)", id, "owasp:nosql:022")
	}
	if sc != 10 {
		t.Fatalf("Attribution() score = %d, want 10", sc)
	}

	// 形态二：被抑制规则不参与计分时，归因同样落在 022。
	b := NewAccumulator(threshold)
	b.Add("owasp:nosql:022", 5)
	if b.Exceeded() {
		t.Fatalf("Exceeded() = true with 5 < 7, want false")
	}
	b.Add("owasp:nosql:023", 4)
	if id, sc := b.Attribution(); id != "owasp:nosql:023" || sc != 9 {
		t.Fatalf("Attribution() = (%q, %d), want (owasp:nosql:023, 9)", id, sc)
	}
}

// TestAttributionLocksOnFirstCrossing 断言归因锁定在「首次跨过阈值」的那一刻，
// 跨阈之后继续计分不得改写归因。
func TestAttributionLocksOnFirstCrossing(t *testing.T) {
	a := NewAccumulator(6)
	a.Add("early", 2)
	a.Add("crosser", 5) // total=7 首次跨阈
	id, sc := a.Attribution()
	if id != "crosser" || sc != 7 {
		t.Fatalf("Attribution() = (%q, %d), want (crosser, 7)", id, sc)
	}

	a.Add("later", 9) // total=16，不得改写归因
	id, sc = a.Attribution()
	if id != "crosser" || sc != 7 {
		t.Fatalf("Attribution() after later hits = (%q, %d), want (crosser, 7)", id, sc)
	}
	if got := a.Total(); got != 16 {
		t.Fatalf("Total() = %d, want 16", got)
	}
}

// TestAttributionBelowThreshold 断言未过阈时不产生归因。
func TestAttributionBelowThreshold(t *testing.T) {
	a := NewAccumulator(10)
	a.Add("a", 4)
	a.Add("b", 4)
	if a.Exceeded() {
		t.Fatalf("Exceeded() = true, want false")
	}
	if id, sc := a.Attribution(); id != "" || sc != 0 {
		t.Fatalf("Attribution() = (%q, %d), want (\"\", 0)", id, sc)
	}
}

// TestSetThreshold 覆盖阈值热调整：提高阈值使既有归因锁定失效（该跨阈点在
// 新阈值下不再成立），降低阈值使未锁定归因的累加器重新锁定到末条已计分规则。
func TestSetThreshold(t *testing.T) {
	a := NewAccumulator(5)
	a.Add("a", 3)
	a.Add("b", 3) // total=6 >= 5，锁定 b
	if id, sc := a.Attribution(); id != "b" || sc != 6 {
		t.Fatalf("Attribution() = (%q, %d), want (b, 6)", id, sc)
	}

	a.SetThreshold(8)
	if a.Exceeded() {
		t.Fatalf("Exceeded() = true with total=6 threshold=8, want false")
	}
	if id, sc := a.Attribution(); id != "" || sc != 0 {
		t.Fatalf("Attribution() after raise = (%q, %d), want (\"\", 0)", id, sc)
	}
	if got := a.Total(); got != 6 {
		t.Fatalf("Total() = %d, want 6 (threshold change must not alter score)", got)
	}

	// 阈值回落后总分重新达标：归因锁到最后一条已计分规则。
	a.SetThreshold(6)
	if id, sc := a.Attribution(); id != "b" || sc != 6 {
		t.Fatalf("Attribution() after lower = (%q, %d), want (b, 6)", id, sc)
	}

	// 已过阈但未锁定（提高阈值再降回低于总分）：同样重新锁定。
	// 降低阈值落到「已锁定且仍达标」区间时，原归因保持不被改写。
	a.SetThreshold(4)
	if id, sc := a.Attribution(); id != "b" || sc != 6 {
		t.Fatalf("Attribution() after further lower = (%q, %d), want (b, 6)", id, sc)
	}

	// 空累加器降阈值：无规则可归因，保持未锁定。
	empty := NewAccumulator(10)
	empty.SetThreshold(0)
	if !empty.Exceeded() {
		t.Fatalf("Exceeded() = false with total=0 threshold=0, want true")
	}
	if id, sc := empty.Attribution(); id != "" || sc != 0 {
		t.Fatalf("Attribution() on empty = (%q, %d), want (\"\", 0)", id, sc)
	}
}

// TestSetThresholdReattributionAfterRaise 断言提高阈值清除旧锁定后，后续
// 规则再次跨阈时归因指向新的跨阈规则，而不是残留的旧归因。
func TestSetThresholdReattributionAfterRaise(t *testing.T) {
	a := NewAccumulator(5)
	a.Add("old_crosser", 6) // total=6 >= 5
	if id, sc := a.Attribution(); id != "old_crosser" || sc != 6 {
		t.Fatalf("Attribution() = (%q, %d), want (old_crosser, 6)", id, sc)
	}

	a.SetThreshold(10) // 总分不足，旧锁定失效
	a.Add("new_crosser", 7)
	if id, sc := a.Attribution(); id != "new_crosser" || sc != 13 {
		t.Fatalf("Attribution() = (%q, %d), want (new_crosser, 13)", id, sc)
	}
}

// TestResetClearsState 断言 Reset 清除全部分数与锁定状态。
func TestResetClearsState(t *testing.T) {
	a := NewAccumulator(5)
	a.AddDetail("x", 6, "detail")
	a.Reset()

	if got := a.Total(); got != 0 {
		t.Fatalf("Total() = %d, want 0", got)
	}
	if got := len(a.Hits()); got != 0 {
		t.Fatalf("len(Hits()) = %d, want 0", got)
	}
	if a.Exceeded() {
		t.Fatalf("Exceeded() = true, want false")
	}
	if id, sc := a.Attribution(); id != "" || sc != 0 {
		t.Fatalf("Attribution() = (%q, %d), want (\"\", 0)", id, sc)
	}
	if a.Threshold() != 5 {
		t.Fatalf("Threshold() = %d, want 5 (Reset must keep threshold)", a.Threshold())
	}

	// Reset 后查重索引不得残留：同一 ID 应可再次计分。
	a.Add("x", 6)
	if got := a.Total(); got != 6 {
		t.Fatalf("Total() after reset+add = %d, want 6", got)
	}
}

// TestReuseDoesNotLeakAcrossRounds 复用 1000 轮后状态与首轮一致，
// 且每轮热路径零分配（重复 ID 首次触发的惰性索引只建一次）。
func TestReuseDoesNotLeakAcrossRounds(t *testing.T) {
	a := NewAccumulator(7)
	allocs := testing.AllocsPerRun(1000, func() {
		a.Reset()
		a.AddDetail("owasp:sqli:001", 3, "union select")
		a.AddDetail("owasp:sqli:002", 4, "or 1=1")
		a.AddDetail("owasp:sqli:001", 3, "dup") // 触发惰性查重索引
	})
	if allocs != 0 {
		t.Fatalf("AllocsPerRun = %v, want 0 on steady-state hot path", allocs)
	}

	a.Reset()
	for i := 0; i < 1000; i++ {
		a.AddDetail("owasp:sqli:001", 3, "union select")
		a.AddDetail("owasp:sqli:002", 4, "or 1=1")
		a.AddDetail("owasp:sqli:001", 3, "dup")
		if got := a.Total(); got != 7 {
			t.Fatalf("round %d: Total() = %d, want 7", i, got)
		}
		if got := len(a.Hits()); got != 2 {
			t.Fatalf("round %d: len(Hits()) = %d, want 2", i, got)
		}
		if id, sc := a.Attribution(); id != "owasp:sqli:002" || sc != 7 {
			t.Fatalf("round %d: Attribution() = (%q, %d), want (owasp:sqli:002, 7)", i, id, sc)
		}
	}
}

// TestAddZeroAllocNoDuplicate 断言无重复 ID 且容量足够时 Add 完全不分配。
func TestAddZeroAllocNoDuplicate(t *testing.T) {
	a := NewAccumulator(7)
	allocs := testing.AllocsPerRun(1000, func() {
		a.Reset()
		a.Add("owasp:sqli:001", 3)
		a.Add("owasp:sqli:002", 2)
		a.Add("owasp:sqli:003", 1)
	})
	if allocs != 0 {
		t.Fatalf("AllocsPerRun = %v, want 0", allocs)
	}
}

// TestCount 覆盖 Count 的边界与组合：min<=0 恒成立、min>len 恒不成立、
// 全 true / 全 false / 部分 true。
func TestCount(t *testing.T) {
	cases := []struct {
		name    string
		min     int
		results []bool
		want    bool
	}{
		{name: "min_zero", min: 0, results: []bool{false, false}, want: true},
		{name: "min_negative", min: -3, results: nil, want: true},
		{name: "min_gt_len", min: 3, results: []bool{true, true}, want: false},
		{name: "min_gt_len_zero_results", min: 1, results: nil, want: false},
		{name: "all_true", min: 3, results: []bool{true, true, true}, want: true},
		{name: "all_false", min: 1, results: []bool{false, false, false}, want: false},
		{name: "partial_met", min: 2, results: []bool{true, false, true}, want: true},
		{name: "partial_unmet", min: 3, results: []bool{true, false, true}, want: false},
		{name: "exact_len", min: 2, results: []bool{true, true}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Count(tc.min, tc.results); got != tc.want {
				t.Fatalf("Count(%d, %v) = %v, want %v", tc.min, tc.results, got, tc.want)
			}
		})
	}
}

// TestIndependentAccumulators 验证并发契约：Accumulator 本身不保证并发安全，
// 但每个 goroutine 各持一份时互不干扰。
func TestIndependentAccumulators(t *testing.T) {
	const (
		workers = 8
		rounds  = 200
	)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			a := NewAccumulator(5)
			id := fmt.Sprintf("rule:%d", w)
			for i := 0; i < rounds; i++ {
				a.Reset()
				a.AddDetail(id, 5, "own")
				a.Add("shared-name", 1)
				if got := a.Total(); got != 6 {
					t.Errorf("worker %d round %d: Total() = %d, want 6", w, i, got)
					return
				}
				if got, sc := a.Attribution(); got != id || sc != 5 {
					t.Errorf("worker %d round %d: Attribution() = (%q, %d), want (%q, 5)", w, i, got, sc, id)
					return
				}
			}
		}(w)
	}
	wg.Wait()
}

// TestDangerIsOrthogonalToScore 覆盖核心语义：分数决定档位，危险标记决定
// 是否终止。低权重模块累加出来的低总分绝不允许把一个已判定的危险稀释成放行。
func TestDangerIsOrthogonalToScore(t *testing.T) {
	a := NewAccumulator(80) // 高分档阈值：低分模块不可能把分数推上去
	a.MarkDanger("owasp:rce:001")
	for i := 0; i < 20; i++ {
		a.Add(fmt.Sprintf("weak:module:%02d", i), 1) // 20 个互不相同的低权重模块
	}

	if !a.Dangerous() {
		t.Fatalf("Dangerous() = false, want true（危险不得被低分稀释）")
	}
	if got := a.Total(); got != 20 { // 推导：20 个模块 × 权重 1 = 20
		t.Fatalf("Total() = %d, want 20", got)
	}
	if a.Exceeded() {
		t.Fatalf("Exceeded() = true (total=20 threshold=80), want false——档位仍由分数决定")
	}
	if ids := a.DangerIDs(); len(ids) != 1 || ids[0] != "owasp:rce:001" {
		t.Fatalf("DangerIDs() = %v, want [owasp:rce:001]", ids)
	}
}

// TestDangerUnaffectedByScoreState 断言危险标记不参与任何分数语义：
// 不改变 Total、不触达阈值、不产生归因锁定。
func TestDangerUnaffectedByScoreState(t *testing.T) {
	a := NewAccumulator(3)
	a.MarkDanger("owasp:rce:001")

	if got := a.Total(); got != 0 {
		t.Fatalf("Total() = %d, want 0（危险标记不计分）", got)
	}
	if a.Exceeded() {
		t.Fatalf("Exceeded() = true, want false")
	}
	if id, sc := a.Attribution(); id != "" || sc != 0 {
		t.Fatalf("Attribution() = (%q, %d), want (\"\", 0)", id, sc)
	}
	if got := len(a.Hits()); got != 0 {
		t.Fatalf("len(Hits()) = %d, want 0（危险标记不写入 hits）", got)
	}

	// 与计分通道的归因锁定互不干扰：先标记危险，再让规则跨阈。
	a.Add("owasp:sqli:001", 5)
	if id, sc := a.Attribution(); id != "owasp:sqli:001" || sc != 5 {
		t.Fatalf("Attribution() = (%q, %d), want (owasp:sqli:001, 5)", id, sc)
	}
}

// TestMarkDangerDeduplicates 断言重复 MarkDanger 同一 ID 只记一次。
func TestMarkDangerDeduplicates(t *testing.T) {
	a := NewAccumulator(80)
	for i := 0; i < 5; i++ {
		a.MarkDanger("owasp:rce:001")
	}
	a.MarkDanger("owasp:rce:002")
	a.MarkDanger("owasp:rce:001")

	if ids := a.DangerIDs(); len(ids) != 2 {
		t.Fatalf("DangerIDs() = %v, want 2 entries", ids)
	}
	if ids := a.DangerIDs(); ids[0] != "owasp:rce:001" || ids[1] != "owasp:rce:002" {
		t.Fatalf("DangerIDs() = %v, want [owasp:rce:001 owasp:rce:002]（按标记顺序）", ids)
	}
}

// TestDangerAndScoreDedupeIndependently 断言两条通道各自去重、互不吞并：
// 同一 ID 可以在分数通道与危险通道上各占用一次。
func TestDangerAndScoreDedupeIndependently(t *testing.T) {
	a := NewAccumulator(80)
	a.Add("shared:id", 4)
	a.MarkDanger("shared:id") // 分数通道已占用，危险通道仍须记录
	a.Add("shared:id", 4)     // 重复计分：忽略
	a.MarkDanger("shared:id") // 重复标记：忽略

	if got := a.Total(); got != 4 {
		t.Fatalf("Total() = %d, want 4", got)
	}
	if got := len(a.Hits()); got != 1 {
		t.Fatalf("len(Hits()) = %d, want 1", got)
	}
	if !a.Dangerous() {
		t.Fatalf("Dangerous() = false, want true（同 ID 的计分不得吞掉危险标记）")
	}
	if ids := a.DangerIDs(); len(ids) != 1 || ids[0] != "shared:id" {
		t.Fatalf("DangerIDs() = %v, want [shared:id]", ids)
	}

	// 反向顺序：先标记危险，再以同一 ID 计分。
	b := NewAccumulator(80)
	b.MarkDanger("shared:id")
	b.Add("shared:id", 4)
	if got := b.Total(); got != 4 {
		t.Fatalf("Total() = %d, want 4（危险标记不得吞掉同 ID 的计分）", got)
	}
	if got := len(b.Hits()); got != 1 {
		t.Fatalf("len(Hits()) = %d, want 1", got)
	}
}

// TestMarkDangerIgnoredWeightRuleDoesNotApply 断言危险标记不受 weight<=0
// 忽略规则约束：标记本身没有权重概念，不应存在「零权重危险」这种被丢弃的形态。
func TestMarkDangerIgnoredWeightRuleDoesNotApply(t *testing.T) {
	a := NewAccumulator(80)
	// 消费方可能先 Add 一条零权重判据再标记同一 ID；零权重被计分通道忽略，
	// 但它不得连带把危险标记一并吞掉。
	a.Add("owasp:rce:001", 0)
	a.MarkDanger("owasp:rce:001")

	if !a.Dangerous() {
		t.Fatalf("Dangerous() = false, want true")
	}
	if got := a.Total(); got != 0 {
		t.Fatalf("Total() = %d, want 0", got)
	}
}

// TestResetClearsDanger 断言 Reset 同时清空危险标记，且清空后可重新标记。
func TestResetClearsDanger(t *testing.T) {
	a := NewAccumulator(80)
	a.MarkDanger("owasp:rce:001")
	a.Add("owasp:sqli:001", 5)
	a.Reset()

	if a.Dangerous() {
		t.Fatalf("Dangerous() = true after Reset, want false")
	}
	if ids := a.DangerIDs(); len(ids) != 0 {
		t.Fatalf("DangerIDs() = %v after Reset, want empty", ids)
	}

	// Reset 后去重索引不得残留：同一 ID 可再次标记。
	a.MarkDanger("owasp:rce:001")
	if ids := a.DangerIDs(); len(ids) != 1 {
		t.Fatalf("DangerIDs() = %v after reset+mark, want 1 entry", ids)
	}
}

// TestDangerIndependentAccumulators 并发契约在危险通道上同样成立：各 goroutine
// 各持一份时危险标记互不串扰。
func TestDangerIndependentAccumulators(t *testing.T) {
	const (
		workers = 8
		rounds  = 200
	)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			a := NewAccumulator(80)
			id := fmt.Sprintf("danger:%d", w)
			for i := 0; i < rounds; i++ {
				a.Reset()
				a.MarkDanger(id)
				if ids := a.DangerIDs(); len(ids) != 1 || ids[0] != id {
					t.Errorf("worker %d round %d: DangerIDs() = %v, want [%s]", w, i, ids, id)
					return
				}
			}
		}(w)
	}
	wg.Wait()
}

// dangerSliceCap 是危险标记切片的预留容量，用于验证池化复用时的零分配契约。
const dangerSliceCap = 4

// TestDangerousFalseWhenNeverMarked 断言从未标记时 Dangerous() 为 false、
// DangerIDs() 为空，且 Dangerous() 是零分配读取（它是每请求都会走的判定点）。
func TestDangerousFalseWhenNeverMarked(t *testing.T) {
	a := NewAccumulator(80)
	if a.Dangerous() {
		t.Fatalf("Dangerous() = true on a fresh accumulator, want false")
	}
	if ids := a.DangerIDs(); len(ids) != 0 {
		t.Fatalf("DangerIDs() = %v on a fresh accumulator, want empty", ids)
	}

	// 只计分不标记时同样为 false。
	a.Add("owasp:sqli:001", 3)
	if a.Dangerous() {
		t.Fatalf("Dangerous() = true after scoring only, want false")
	}

	allocs := testing.AllocsPerRun(1000, func() { _ = a.Dangerous() })
	if allocs != 0 {
		t.Fatalf("AllocsPerRun = %v, want 0", allocs)
	}
}

// TestMarkDangerEstablishesSeenIndex 覆盖「MarkDanger 先于 Add 成为首个建立
// 惰性 seen 索引的调用」这条路径：索引由危险通道建立后，两条通道的去重
// 必须同时生效。
func TestMarkDangerEstablishesSeenIndex(t *testing.T) {
	a := NewAccumulator(80)
	a.MarkDanger("owasp:rce:001")
	a.MarkDanger("owasp:rce:002")
	a.MarkDanger("owasp:rce:001") // 重复标记：首次出现重复 ID，由危险通道建立 seen
	if a.seen == nil {
		t.Fatalf("seen index was not established by a duplicate MarkDanger")
	}

	// 索引建立后，两条通道各自去重仍然成立。
	a.Add("owasp:rce:001", 5)
	a.Add("owasp:rce:002", 5)
	a.Add("owasp:rce:001", 5) // 重复计分：忽略

	if got := a.Total(); got != 10 { // 推导：5 + 5；重复计分不计
		t.Fatalf("Total() = %d, want 10", got)
	}
	if got := len(a.Hits()); got != 2 {
		t.Fatalf("len(Hits()) = %d, want 2", got)
	}
	if ids := a.DangerIDs(); len(ids) != 2 || ids[0] != "owasp:rce:001" || ids[1] != "owasp:rce:002" {
		t.Fatalf("DangerIDs() = %v, want [owasp:rce:001 owasp:rce:002]", ids)
	}
}

// TestMarkDangerZeroAllocAfterReserve 断言危险通道在容量已预留时零分配。
//
// 注意 precondition：dangerIDs 不经预分配（危险标记只出现在攻击流量上，
// 不应让常规路径垫付容量），因此池化复用方必须按自己的危险标记上界预留
// cap，否则首次标记会发生一次切片成长分配。这里是该契约的固定测试。
func TestMarkDangerZeroAllocAfterReserve(t *testing.T) {
	a := NewAccumulator(80)
	a.dangerIDs = make([]string, 0, dangerSliceCap)
	allocs := testing.AllocsPerRun(1000, func() {
		a.Reset()
		a.MarkDanger("owasp:rce:001")
		a.MarkDanger("owasp:rce:002")
	})
	if allocs != 0 {
		t.Fatalf("AllocsPerRun = %v, want 0（容量已预留）", allocs)
	}
	if cap(a.dangerIDs) < dangerSliceCap {
		t.Fatalf("cap(dangerIDs) = %d, want >= %d", cap(a.dangerIDs), dangerSliceCap)
	}
}

// BenchmarkAccumulatorAddNoDuplicate 测量无重复 ID 的热路径：Reset + 3 条命中。
func BenchmarkAccumulatorAddNoDuplicate(b *testing.B) {
	a := NewAccumulator(7)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Reset()
		a.Add("owasp:sqli:001", 3)
		a.Add("owasp:sqli:002", 2)
		a.Add("owasp:sqli:003", 1)
	}
}

// BenchmarkAccumulatorAddWithDuplicate 测量含重复 ID 的路径（查重索引已建立）。
func BenchmarkAccumulatorAddWithDuplicate(b *testing.B) {
	a := NewAccumulator(7)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Reset()
		a.Add("owasp:sqli:001", 3)
		a.Add("owasp:sqli:002", 2)
		a.Add("owasp:sqli:001", 3)
		a.Add("owasp:sqli:003", 1)
	}
}

// BenchmarkAccumulatorAddDetail 测量带明文的命中路径。
func BenchmarkAccumulatorAddDetail(b *testing.B) {
	a := NewAccumulator(7)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Reset()
		a.AddDetail("owasp:xss:001", 3, "<script>alert(1)</script>")
		a.AddDetail("owasp:xss:002", 4, "javascript:")
	}
}

// BenchmarkAccumulatorDangerPath 测量危险通道形态：Reset + 2 条计分 + 1 条
// 危险标记（dangerIDs 容量已预留，见 TestMarkDangerZeroAllocAfterReserve）。
func BenchmarkAccumulatorDangerPath(b *testing.B) {
	a := NewAccumulator(7)
	a.dangerIDs = make([]string, 0, dangerSliceCap)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Reset()
		a.Add("owasp:sqli:001", 3)
		a.Add("owasp:sqli:002", 2)
		a.MarkDanger("owasp:rce:001")
	}
}

// BenchmarkAccumulatorReuse 测量池化复用形态：单实例 1000 轮 Reset+Add，
// 与上面的每次新建形成对照，确认复用路径没有隐藏分配。
func BenchmarkAccumulatorReuse(b *testing.B) {
	a := NewAccumulator(7)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Reset()
		a.AddDetail("owasp:sqli:001", 3, "union select")
		a.AddDetail("owasp:sqli:002", 4, "or 1=1")
		a.AddDetail("owasp:sqli:001", 3, "dup")
	}
}
