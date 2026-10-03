package owasp

import (
	"sync"

	"My-OpenWaf/internal/core/score"
)

var owaspAccPool = sync.Pool{
	New: func() any { return score.NewAccumulator(0) },
}

// acquireOWASPAcc 取出一个已重置并设定阈值的累加器。
//
// @param threshold 闭区间阈值（total >= threshold 视为过阈）
// @return 可直接用于 Add 的累加器实例
func acquireOWASPAcc(threshold int) *score.Accumulator {
	acc := owaspAccPool.Get().(*score.Accumulator)
	acc.Reset()
	acc.SetThreshold(threshold)
	return acc
}

// releaseOWASPAcc 归还累加器以便复用；acc 为 nil（从未命中任何规则）时不做任何事。
//
// 归还后累加器内的 hits/dangerIDs 元素会被后续 Reset 清零，调用方不得在归还后
// 继续持有 Attribution()/Hits() 返回的切片别名。归因 ID 取自规则表常量字符串，
// 值拷贝进 OWASPHit 后可安全带出。
//
// @param acc 待归还的累加器，允许为 nil
func releaseOWASPAcc(acc *score.Accumulator) {
	if acc != nil {
		owaspAccPool.Put(acc)
	}
}
