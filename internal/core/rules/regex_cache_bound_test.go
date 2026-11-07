package rules

import (
	"fmt"
	"regexp"
	"testing"
)

/**
 * TestRegexCacheBoundedUnderValidationLoad 是「正则缓存无界膨胀」的守门测试。
 *
 * 触发面：POST /api/v1/rules/validate 与 /rules/test 会把任意未持久化的
 * pattern 交给 cachedCompile。修复前缓存只增不删，每提交一个唯一 pattern
 * 就常驻一条编译结果，Admin/Operator 可凭此把进程内存顶起来；编译失败的
 * 模式不入缓存，所以用合法且互不相同、但都不命中任何规则的 pattern。
 *
 * 断言：写入远超上限的条目后，缓存规模仍被限制在上限内，且缓存在被清空后
 * 仍能正常工作（新条目照常可编译、可命中）。
 */
func TestRegexCacheBoundedUnderValidationLoad(t *testing.T) {
	regexCache.mu.Lock()
	original := regexCache.cache
	regexCache.cache = make(map[string]*regexp.Regexp)
	regexCache.mu.Unlock()
	t.Cleanup(func() {
		regexCache.mu.Lock()
		regexCache.cache = original
		regexCache.mu.Unlock()
	})

	// 每个 pattern 都合法，但彼此不同——模拟逐个 /rules/validate 提交。
	total := regexCacheMaxEntries * 2
	for i := 0; i < total; i++ {
		pattern := fmt.Sprintf(`^__validate_probe_%d_[a-z]+$`, i)
		if _, err := cachedCompile(pattern); err != nil {
			t.Fatalf("cachedCompile(%q) 报错: %v", pattern, err)
		}
		if got := regexCacheSize(); got > regexCacheMaxEntries {
			t.Fatalf("第 %d 次写入后缓存规模 = %d，超过上限 %d（缓存仍在无界增长）",
				i+1, got, regexCacheMaxEntries)
		}
	}

	// 清空后必须仍可用：命中路径与未命中路径都要正常。
	probe := `^__validate_probe_after_eviction_[0-9]+$`
	first, err := cachedCompile(probe)
	if err != nil {
		t.Fatalf("清空后编译失败: %v", err)
	}
	second, err := cachedCompile(probe)
	if err != nil {
		t.Fatalf("清空后二次编译失败: %v", err)
	}
	if first != second {
		t.Fatal("同一 pattern 两次编译应复用同一实例")
	}
	if !second.MatchString("__validate_probe_after_eviction_42") {
		t.Fatal("清空后缓存返回的正则语义不正确")
	}
}

func regexCacheSize() int {
	regexCache.mu.RLock()
	defer regexCache.mu.RUnlock()
	return len(regexCache.cache)
}
