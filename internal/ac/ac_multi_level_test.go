package ac

import "testing"

/**
 * TestMultiLevelFailPropagation 验证 outputs 传播去除 len 条件后,
 * 多级 fail 链上中间态(自身无 output,但 fail 祖先携 output)的命中语义:
 * patterns "ab"、"cabd" 构造,输入 "cabd" 应命中两条。
 * 中间态(在链上但无输出)不再阻断祖先 outputs 的继承。
 */
func TestMultiLevelFailPropagation(t *testing.T) {
	b := NewBuilder()
	if b.AddPattern("ab") != 0 {
		t.Fatal("ab 索引应为 0")
	}
	if b.AddPattern("cabd") != 1 {
		t.Fatal("cabd 索引应为 1")
	}
	m := b.Build()

	got := m.MatchMask("cabd")
	if got.words[0]&(1<<0) == 0 {
		t.Fatal(`"cabd" 应命中 "ab"`)
	}
	if got.words[0]&(1<<1) == 0 {
		t.Fatal(`"cabd" 应命中 "cabd"`)
	}
}

/**
 * TestRootFailZeroStrictness 锁定 root fail=0 语义:未加 len>0 条件
 * 前 root 子节点不会把 root 的任何 outputs(恒无)拼到自己身上,
 * 语义与加条件完全一致,只影响中间 fail 态。
 */
func TestRootFailZeroStrictness(t *testing.T) {
	b := NewBuilder()
	b.AddPattern("a")
	m := b.Build()

	if got := m.MatchMask("b"); got != (Mask{}) {
		t.Fatalf(`"b" 不应有任何命中, got=%v`, got)
	}
	if !m.MatchAny("a") {
		t.Fatal(`"a" 应命中`)
	}
}
