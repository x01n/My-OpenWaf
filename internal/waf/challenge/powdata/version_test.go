package powdata

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestVersionIsDerivedFromContent 锁定性质 1：版本串 = sha256(内容) 前 8 位 hex。
// 用独立算出的期望值比对，避免「拿实现去验实现」。
func TestVersionIsDerivedFromContent(t *testing.T) {
	cases := []struct {
		name    string
		content []byte
		want    string
	}{
		{"empty", nil, ""},
		{"single byte", []byte{0x00}, ""},
	}
	// 期望值现场用标准库独立算出（不调用 versionOf）。
	for i := range cases {
		sum := sha256.Sum256(cases[i].content)
		cases[i].want = hex.EncodeToString(sum[:4])
	}

	for _, tc := range cases {
		if got := versionOf(tc.content); got != tc.want {
			t.Fatalf("%s: versionOf = %q, want %q", tc.name, got, tc.want)
		}
	}

	// 特质化断言：**改一个字节，版本串必须变**。这是整条链的关键性质 ——
	// 若实现改成返回常量，本断言立刻失败。
	base := []byte("owaf-asset-base")
	mutated := []byte("owaf-asset-basf") // 末字节 f vs e
	if versionOf(base) == versionOf(mutated) {
		t.Fatal("changing asset content must change its version string")
	}
}

// TestVersionLengthIsStable 锁定性质 3：始终 8 位小写十六进制。
func TestVersionLengthIsStable(t *testing.T) {
	for _, in := range [][]byte{nil, {0x01}, []byte("x"), make([]byte, 1024)} {
		got := versionOf(in)
		if len(got) != 8 {
			t.Fatalf("versionOf(len=%d) = %q, want 8 hex chars", len(in), got)
		}
		for i := 0; i < len(got); i++ {
			c := got[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Fatalf("versionOf produced a non-lowercase-hex char: %q", got)
			}
		}
	}
}

// TestRealAssetsHaveDistinctVersions 锁定性质 2：两个真实资产的版本串必须不同。
// 若相同，说明派生逻辑退化（例如都读了同一个变量），槽位错位将不可检测。
func TestRealAssetsHaveDistinctVersions(t *testing.T) {
	wasm := WasmVersion()
	glue := GlueVersion()
	if wasm == "" || glue == "" {
		t.Fatal("asset versions must be non-empty")
	}
	if len(wasm) != 8 || len(glue) != 8 {
		t.Fatalf("unexpected version lengths: wasm=%q glue=%q", wasm, glue)
	}
	if wasm == glue {
		t.Fatalf("pow.wasm and pow_glue.js must not share a version string (got %q)", wasm)
	}
	// 幂等：多次读取必须一致（sync.Once 语义）。
	if WasmVersion() != wasm || GlueVersion() != glue {
		t.Fatal("version getters are not stable across calls")
	}
}

// TestVersionGettersUseSyncOnce 锁定「进程内只算一次」：并发读不得撕裂。
// sync.Once 的语义保证首次计算只发生一次，本用例用并发读验证可观测结果一致。
func TestVersionGettersUseSyncOnce(t *testing.T) {
	const workers = 32
	results := make(chan [2]string, workers)
	for i := 0; i < workers; i++ {
		go func() {
			results <- [2]string{WasmVersion(), GlueVersion()}
		}()
	}
	first := <-results
	for i := 1; i < workers; i++ {
		got := <-results
		if got != first {
			t.Fatalf("concurrent getters disagree: %v vs %v", got, first)
		}
	}
}
