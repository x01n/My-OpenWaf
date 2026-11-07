package rules

import (
	"fmt"
	"regexp"
	"sync"
	"testing"
)

/**
 * regexCacheEntryCount 读取全局正则缓存的当前条目数。
 *
 * @return 缓存条目数
 */
func regexCacheEntryCount() int {
	regexCache.mu.RLock()
	defer regexCache.mu.RUnlock()
	return len(regexCache.cache)
}

/**
 * regexCacheEvictions 读取缓存的累计淘汰（整体换表）次数。
 *
 * @return 累计淘汰次数
 */
func regexCacheEvictions() uint64 {
	return regexCache.evictions.Load()
}

/**
 * resetRegexCacheForTest 把全局正则缓存恢复为空表。
 *
 * 淘汰计数一并归零：它是进程级累计值，只在每次使用前取基线、用差值断言，
 * 避免测试之间互相污染。
 */
func resetRegexCacheForTest() {
	regexCache.mu.Lock()
	regexCache.cache = make(map[string]*regexp.Regexp)
	regexCache.mu.Unlock()
	regexCache.evictions.Store(0)
}

/**
 * fillRegexCacheWithUniquePatterns 向缓存灌入 count 条互不相同的合法模式。
 *
 * @param t     测试句柄
 * @param prefix 模式前缀，用于跨测试区分
 * @param count  灌入条数
 */
func fillRegexCacheWithUniquePatterns(t *testing.T, prefix string, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		if _, err := cachedCompile(fmt.Sprintf(`^%s-%d$`, prefix, i)); err != nil {
			t.Fatalf("cachedCompile(%s-%d) 报错: %v", prefix, i, err)
		}
	}
}

/**
 * TestRegexCacheStaysWithinMaxEntries 锁定缓存的条目上限。
 *
 * 缓存条目来自进程内任意 pattern 字符串：管理员写入的规则有界，但
 * /api/v1/rules/validate 与 /api/v1/rules/test 会把未持久化的任意 pattern
 * 带进来，每次唯一 pattern 常驻一条编译结果。没有上限时灌入
 * regexCacheMaxEntries+N 条唯一模式后条目数会达到 regexCacheMaxEntries+N，
 * 即无界增长路径，本用例在无上限实现上必然失败。
 *
 * @param t 测试句柄
 */
func TestRegexCacheStaysWithinMaxEntries(t *testing.T) {
	resetRegexCacheForTest()
	defer resetRegexCacheForTest()

	fillRegexCacheWithUniquePatterns(t, "bounded", regexCacheMaxEntries+64)

	if got := regexCacheEntryCount(); got > regexCacheMaxEntries {
		t.Fatalf("正则缓存条目数 = %d，超过上限 %d：无界增长路径未封住", got, regexCacheMaxEntries)
	}
}

/**
 * TestRegexCacheEvictionResetsTable 锁定「达上限整体换表」的可观测结果。
 *
 * 恰好填到上限时不应发生清空（判定是 >= 上限才清），再插入一条新模式即触发
 * 清空；清空后表内只剩本次插入的那一条。无上限实现下这一步的条目数是
 * regexCacheMaxEntries+1，本用例失败。
 *
 * @param t 测试句柄
 */
func TestRegexCacheEvictionResetsTable(t *testing.T) {
	resetRegexCacheForTest()
	defer resetRegexCacheForTest()

	fillRegexCacheWithUniquePatterns(t, "evict-pre", regexCacheMaxEntries)
	baseEvictions := regexCacheEvictions()
	if got := regexCacheEntryCount(); got != regexCacheMaxEntries {
		t.Fatalf("填到上限后条目数 = %d，期望 %d（上限值本身必须放行）", got, regexCacheMaxEntries)
	}
	if got := regexCacheEvictions() - baseEvictions; got != 0 {
		t.Fatalf("未触顶时淘汰次数增量 = %d，期望 0", got)
	}

	if _, err := cachedCompile(`^evict-trigger$`); err != nil {
		t.Fatalf("触发清空的调用报错: %v", err)
	}
	entries := regexCacheEntryCount()
	if entries != 1 {
		t.Fatalf("清空后条目数 = %d，期望 1（整体换表并保留本次插入）", entries)
	}
	if got := regexCacheEvictions() - baseEvictions; got != 1 {
		t.Fatalf("触顶一次后淘汰次数增量 = %d，期望 1（淘汰计数是触顶的判据）", got)
	}

	// 重新查同一模式也必须命中原实例，而不是每次重新编译。
	first, err := cachedCompile(`^evict-trigger$`)
	if err != nil {
		t.Fatalf("清空后重新插入报错: %v", err)
	}
	second, err := cachedCompile(`^evict-trigger$`)
	if err != nil {
		t.Fatalf("清空后第二次查询报错: %v", err)
	}
	if first != second {
		t.Fatal("同一模式在清空后未被缓存，第二次调用返回了新实例")
	}
}

/**
 * TestRegexCacheConcurrentUniquePatternsStayBounded 在多写者并发下锁定上限。
 *
 * 并发写入是这条路径的真实形态：多个 admin 请求可同时携带不同 pattern，
 * 引擎也会为不同站点并行编译规则。写入总量刻意超过上限（workers*perWorker
 * > regexCacheMaxEntries），无上限实现下条目数会等于写入总量。
 *
 * 建议配合 -race 运行，同时覆盖换表与读方并发的情形。
 *
 * @param t 测试句柄
 */
func TestRegexCacheConcurrentUniquePatternsStayBounded(t *testing.T) {
	resetRegexCacheForTest()
	defer resetRegexCacheForTest()

	const workers = 8
	const perWorker = 600

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				if _, err := cachedCompile(fmt.Sprintf(`^concurrent-%d-%d$`, worker, i)); err != nil {
					t.Errorf("cachedCompile(concurrent-%d-%d) 报错: %v", worker, i, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	if got := regexCacheEntryCount(); got > regexCacheMaxEntries {
		t.Fatalf("并发写入后条目数 = %d，超过上限 %d", got, regexCacheMaxEntries)
	}

	// 并发下同一模式仍必须收敛到同一实例（双重检查的意义）。
	const shared = `^concurrent-shared$`
	var (
		mu      sync.Mutex
		holders []*regexp.Regexp
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			re, err := cachedCompile(shared)
			if err != nil {
				t.Errorf("并发编译共享模式报错: %v", err)
				return
			}
			mu.Lock()
			holders = append(holders, re)
			mu.Unlock()
		}()
	}
	wg.Wait()
	for _, re := range holders {
		if re != holders[0] {
			t.Fatal("并发查询同一模式返回了不同实例")
		}
		if !re.MatchString("concurrent-shared") {
			t.Fatal("并发取得的正则实例不可用")
		}
	}
}

/**
 * TestRegexCacheEvictionKeepsHandedOutRegexpsUsable 锁定清空不伤已分发实例。
 *
 * 换表只替换 map 本身，元素值（*regexp.Regexp）由匹配器持有，且
 * regexp.Regexp 可被多个 goroutine 并发使用，因此清空不得让任何已取出的
 * 实例失效。本用例在有无上限的实现上都通过，作用是防止将来把清空写成
 * 「置 nil 元素」或引入依赖 map 存活期的持有方式。
 *
 * @param t 测试句柄
 */
func TestRegexCacheEvictionKeepsHandedOutRegexpsUsable(t *testing.T) {
	resetRegexCacheForTest()
	defer resetRegexCacheForTest()

	live, err := cachedCompile(`^live-instance$`)
	if err != nil {
		t.Fatalf("cachedCompile(live-instance) 报错: %v", err)
	}
	fillRegexCacheWithUniquePatterns(t, "live-fill", regexCacheMaxEntries+1)

	if !live.MatchString("live-instance") {
		t.Fatal("清空后已分发的 *regexp.Regexp 实例不再可用")
	}
	if live.MatchString("live-instance-x") {
		t.Fatal("已分发实例的匹配语义在清空后发生变化")
	}
}
