package store

import "testing"

// TestComputeDedupKeyStable 验证摘要长度与稳定性。
func TestComputeDedupKeyStable(t *testing.T) {
	a := ComputeDedupKey(1, "GET", "example.com", "/a", "x=1")
	b := ComputeDedupKey(1, "GET", "example.com", "/a", "x=1")
	if a != b {
		t.Fatal("相同输入必须得到相同摘要")
	}
	if len(a) != 64 {
		t.Fatalf("摘要长度 = %d, want 64（char(64) 列宽依赖该长度）", len(a))
	}
}

// TestComputeDedupKeyDistinguishesFieldBoundary 是核心回归：
// 分隔符缺失会让字段边界产生歧义，把本应不同的资源判为同一条。
func TestComputeDedupKeyDistinguishesFieldBoundary(t *testing.T) {
	// host+path 拼接后同为 "ab/c"，必须得到不同摘要。
	x := ComputeDedupKey(1, "GET", "ab", "/c", "")
	y := ComputeDedupKey(1, "GET", "a", "b/c", "")
	if x == y {
		t.Fatal("字段边界不同的输入不得产生相同摘要")
	}

	// query 与 path 之间同理。
	p := ComputeDedupKey(1, "GET", "h", "/a", "b")
	q := ComputeDedupKey(1, "GET", "h", "/ab", "")
	if p == q {
		t.Fatal("path/query 边界不同的输入不得产生相同摘要")
	}
}

// TestComputeDedupKeyVariesWithEveryField 验证五个字段各自都参与摘要。
func TestComputeDedupKeyVariesWithEveryField(t *testing.T) {
	base := ComputeDedupKey(1, "GET", "example.com", "/a", "x=1")
	variants := map[string]string{
		"siteID": ComputeDedupKey(2, "GET", "example.com", "/a", "x=1"),
		"method": ComputeDedupKey(1, "POST", "example.com", "/a", "x=1"),
		"host":   ComputeDedupKey(1, "GET", "other.com", "/a", "x=1"),
		"path":   ComputeDedupKey(1, "GET", "example.com", "/b", "x=1"),
		"query":  ComputeDedupKey(1, "GET", "example.com", "/a", "x=2"),
	}
	for field, got := range variants {
		if got == base {
			t.Errorf("字段 %s 变化后摘要未改变，说明它未参与计算", field)
		}
	}
}

// TestEnsureDedupKeyFillsAndPreserves 验证仅在为空时填充，已有值不被覆盖。
func TestEnsureDedupKeyFillsAndPreserves(t *testing.T) {
	r := &RecordedResource{SiteID: 3, Method: "GET", Host: "h", Path: "/p", QueryString: "q=1"}
	if !r.EnsureDedupKey() {
		t.Fatal("空 DedupKey 应被填充")
	}
	want := ComputeDedupKey(3, "GET", "h", "/p", "q=1")
	if r.DedupKey != want {
		t.Fatalf("DedupKey = %q, want %q", r.DedupKey, want)
	}

	// 再次调用不应改动已有值。
	if r.EnsureDedupKey() {
		t.Error("已有 DedupKey 时不应重复填充")
	}
	if r.DedupKey != want {
		t.Error("已有 DedupKey 被覆盖")
	}
}

func TestEnsureDedupKeyNilReceiverSafe(t *testing.T) {
	var r *RecordedResource
	if r.EnsureDedupKey() {
		t.Error("nil 接收者应返回 false")
	}
}
