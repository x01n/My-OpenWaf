package rules

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"My-OpenWaf/internal/store"
)

/**
 * ccRateStateEntryCount 统计全局 cc_rate 状态注册表的当前条目数。
 *
 * sync.Map 没有 Len()，只能 Range 计数；仅测试使用。
 *
 * @return 当前注册的 cc_rate 状态条目数
 */
func ccRateStateEntryCount() int {
	n := 0
	ccRateStates.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

/**
 * ccRateStateGrowPerCompile 是每轮编译新增的唯一 cc_rate 条件数，也是
 * 「一个批量的未持久化 pattern 最多能塞进多少个条件」的经验上界。
 */
const ccRateStateGrowPerCompile = 500

/**
 * buildUniqueCCRateCompound 构造含 count 个互不相同 cc_rate 叶子的复合条件。
 *
 * 叶子挂在 and 之下：buildCompound 会遍历全部子节点，`and` 不短路构图，
 * 因此每个唯一叶子各注册一条全局状态。整串形状与 /api/v1/rules/test
 * 传入的未持久化 pattern 一致。
 *
 * @param prefix 叶子参数前缀，用于跨用例区分唯一取值
 * @param count  叶子数量
 * @return 可直接交给 Compile 的 compound pattern
 */
func buildUniqueCCRateCompound(prefix string, count int) string {
	leaves := make([]string, 0, count)
	for i := 0; i < count; i++ {
		leaves = append(leaves, fmt.Sprintf(
			`{"op":"cc_rate","window":60,"threshold":5,"children":[{"kind":"host","arg":"%s-%d"}]}`,
			prefix, i))
	}
	return `{"op":"and","children":[` + strings.Join(leaves, ",") + `]}`
}

// compileCompoundPattern 把 pattern 走一遍与 /rules/test 相同的编译路径。
func compileCompoundPattern(t *testing.T, pattern string) {
	t.Helper()
	if _, _, errs := ValidatePattern(pattern); len(errs) != 0 {
		t.Fatalf("固件非法：%v", errs)
	}
	Compile([]store.Rule{{Phase: store.PhaseCustom, Pattern: pattern, Action: store.ActionObserve, Priority: 1, Enabled: true}})
}

/**
 * TestCCRateStateGrowthIsUnboundedOnTarget 记录注册表在**当前实现**下的增长曲线。
 *
 * 这是本目录下唯一直接量出「注册表条目数有没有被封顶」的地方，同时给出
 * 单条常驻成本，为上限取值提供依据。它的通过条件只要求「确实观察到了
 * 常驻条目」，不要求数值单调——上限生效后曲线会周期性回落，那是预期行为，
 * 回落的幅度正好是每轮注入的条数。
 */
func TestCCRateStateGrowthIsUnboundedOnTarget(t *testing.T) {
	const rounds = 24

	base := ccRateStateEntryCount()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	peak := 0
	for r := 0; r < rounds; r++ {
		pattern := buildUniqueCCRateCompound(fmt.Sprintf("ccrate-growth-%d", r), ccRateStateGrowPerCompile)
		compileCompoundPattern(t, pattern)
		grown := ccRateStateEntryCount() - base
		if grown > peak {
			peak = grown
		}
		t.Logf("第 %2d 次编译：pattern=%d 字节，相对基线条目=%d", r+1, len(pattern), grown)
	}

	runtime.GC()
	runtime.ReadMemStats(&after)
	if peak == 0 {
		t.Fatal("未观察到任何新增条目")
	}
	t.Logf("峰值相对基线条目=%d（上限 %d），累计编译条目=%d，堆分配增量=%d B，折合每条约 %d B",
		peak, ccRateStateMaxEntries, rounds*ccRateStateGrowPerCompile,
		int64(after.HeapAlloc)-int64(before.HeapAlloc),
		(int64(after.HeapAlloc)-int64(before.HeapAlloc))/int64(peak))
}

/**
 * TestCCRateStatesStayWithinMaxEntries 是上限的锁测试。
 *
 * 未持久化的 pattern 会经 /api/v1/rules/test 进入 Compile → buildCompound，
 * 每个唯一 cc_rate 叶子注册一条全局状态且全仓没有删除点。上限的作用是把
 * 这条无界增长路径封住：单批注入的条目数必须始终不超过 ccRateStateMaxEntries。
 *
 * 同时守住不变量「上限不影响功能」：触顶后新注册的条件仍能正常计数
 * （阈值 2 的规则第二次命中必须仍超限）。
 *
 * 方案把「编译一批」当作增长单元——真实触达路径（/rules/test、快照重建）
 * 都是一次请求编译一整个规则集，因此这里以单批为判据，不做跨批次累计断言：
 * 跨批累计会随上一批残留条目而波动 0～上限，断言会变成对测试顺序的依赖。
 */
func TestCCRateStatesStayWithinMaxEntries(t *testing.T) {
	// 每批都超过上限，且不小于残留量的两倍，保证「触顶换表」必然发生。
	const batches = 3

	if base := ccRateStateEntryCount(); base > ccRateStateMaxEntries {
		t.Fatalf("测试开始时条目数 %d 已超过上限 %d", base, ccRateStateMaxEntries)
	}

	injected := ccRateStateMaxEntries + ccRateStateGrowPerCompile
	for b := 0; b < batches; b++ {
		pattern := buildUniqueCCRateCompound(fmt.Sprintf("ccrate-bound-%d", b), injected)
		compileCompoundPattern(t, pattern)
		if got := ccRateStateEntryCount(); got > ccRateStateMaxEntries {
			t.Fatalf("第 %d 批后注册表条目数 %d 超过上限 %d（本批注入 %d 条）", b+1, got, ccRateStateMaxEntries, injected)
		}
		t.Logf("第 %d 批后条目数=%d（上限 %d，本批注入 %d 条）", b+1, ccRateStateEntryCount(), ccRateStateMaxEntries, injected)
	}

	// 上限不得破坏功能：触顶之后注册的条件仍按窗口/阈值计数。
	functional := `{"op":"cc_rate","window":3600,"threshold":2,"children":[{"kind":"path_contains","arg":"/ccrate-bound-functional"}]}`
	matcher := buildMatcher("compound", functional)
	mc := matchCtxForCCRateBound("203.0.113.77", "/ccrate-bound-functional")
	if matcher.Match(mc) {
		t.Fatal("窗口内首次命中不应超限")
	}
	if !matcher.Match(mc) {
		t.Fatal("窗口内第二次命中应达到阈值——上限不得让计数失效")
	}
}

/**
 * TestCCRateStateSharingSurvivesCompileWithoutEviction 锁定「设计意图不能被上限误伤」。
 *
 * 在未触顶的正常路径上，同一 pattern 的两次 Compile 必须复用同一状态，
 * 否则每次配置重载都会清空 CC 计数窗口。
 */
func TestCCRateStateSharingSurvivesCompileWithoutEviction(t *testing.T) {
	pattern := `{"op":"cc_rate","window":3600,"threshold":2,"children":[{"kind":"path_contains","arg":"/ccrate-bound-shared"}]}`
	first := buildMatcher("compound", pattern)
	mc := matchCtxForCCRateBound("198.51.100.5", "/ccrate-bound-shared")
	if first.Match(mc) {
		t.Fatal("窗口内首次命中不应超限")
	}
	second := buildMatcher("compound", pattern)
	if !second.Match(mc) {
		t.Fatal("重新编译后未复用同一状态——计数被清空，cc_rate 窗口失效")
	}
}
