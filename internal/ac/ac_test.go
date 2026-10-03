package ac

import "testing"

/**
 * TestEmptyMatcherShortCircuits 验证零 needle 自动机的空短路语义:
 * Empty 为真且三种匹配入口全部返回零 mask / false,不产生任何命中。
 */
func TestEmptyMatcherShortCircuits(t *testing.T) {
	m := NewBuilder().Build()
	if !m.Empty() {
		t.Fatal("零 needle 自动机应报告 Empty")
	}
	if m.MatchAny("anything") {
		t.Fatal("空自动机 MatchAny 应恒为 false")
	}
	if hit := m.MatchMask("anything"); hit != (Mask{}) {
		t.Fatal("空自动机 MatchMask 应返回零 mask")
	}
	if hit := m.MatchMaskSlice([]string{"a", "bc"}); hit != (Mask{}) {
		t.Fatal("空自动机 MatchMaskSlice 应返回零 mask")
	}
}
