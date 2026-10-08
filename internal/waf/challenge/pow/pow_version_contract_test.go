package pow

import (
	"strings"
	"testing"

	"My-OpenWaf/internal/waf/challenge/powdata"
)

/*
本文件用**位置断言**而非存在性断言。

原因：两个资产 URL 都在脚本正文里，`strings.Contains(script, wantWasm)` **恒为 true** ——
它锁的是「出现过」，不是「落在正确槽位」。槽位对调时存在性断言**不会变红**
（实测：把 pow.go 的 `PowGlueURL(), PowWasmURL()` 对调，存在性断言版本仍然通过）。

位置断言（`importScripts("'+location.origin+'<glueURL>")` 与
`module_or_path:location.origin+"<wasmURL>"`）才能锁住槽位。

这与 `EnvelopeVerifier` 那次的教训同源：**测试看起来在保护一个机制、实际保护另一个**。
断言类型决定它锁什么机制，用例名字锁不住。新增用例时请写明「本用例锁哪个机制」，
并以变异验证确认它会红。
*/

/**
 * TestPoWScriptInjectsPerAssetVersions 是本改动的核心契约测试。
 *
 * 背景：`generatePoWScriptBody` 的模板里 glue 与 wasm 是两个不同的 URL，
 * 历史上两个槽位共用同一个随机 cb —— 槽位错位不会编译报错，只会静默用错串。
 *
 * **必须用位置断言，不能用存在性断言**：两个 URL 都在正文里时，
 * `strings.Contains(script, wantWasm)` 在槽位对调后**依然成立**（实测：
 * 把 pow.go 的 `PowGlueURL(), PowWasmURL()` 对调，存在性断言版本不会变红）。
 * 因此这里逐位置核对：glue 必须落在 importScripts 里、wasm 必须落在
 * module_or_path 里。
 *
 * 变异验证（实测均变红）：
 *   - 两槽位对调            → FAIL: importScripts does not carry the glue URL
 *   - 两槽位都传 GlueURL()  → FAIL: module_or_path does not carry the wasm URL
 */
func TestPoWScriptInjectsPerAssetVersions(t *testing.T) {
	script := GeneratePoWWASMScript(1, "version-nonce")

	glueVer := powdata.GlueVersion()
	wasmVer := powdata.WasmVersion()
	if glueVer == "" || wasmVer == "" {
		t.Fatal("asset versions must be non-empty")
	}
	if glueVer == wasmVer {
		t.Fatal("test premise broken: the two assets must have distinct versions")
	}

	wantGlue := "/__owaf/pow_glue.js?v=" + glueVer
	wantWasm := "/__owaf/pow.wasm?v=" + wasmVer

	// 位置断言：worker 的模板是
	//   importScripts("'+location.origin+'<glue>")
	//   wasm_bindgen({module_or_path:location.origin+"<wasm>"})
	// 两处紧邻前缀在原样文本里出现，可直接作为锚点。
	if !strings.Contains(script, `importScripts("'+location.origin+'`+wantGlue+`")`) {
		t.Fatal("worker script: importScripts does not carry the glue URL with its own version (slot mismatch)")
	}
	if !strings.Contains(script, `module_or_path:location.origin+"`+wantWasm+`"`) {
		t.Fatal("worker script: module_or_path does not carry the wasm URL with its own version (slot mismatch)")
	}
	if strings.Contains(script, `importScripts("'+location.origin+'`+wantWasm+`")`) {
		t.Fatal("worker script: importScripts carries the wasm URL (slot mismatch)")
	}
	if strings.Contains(script, `module_or_path:location.origin+"`+wantGlue+`"`) {
		t.Fatal("worker script: module_or_path carries the glue URL (slot mismatch)")
	}

	// 不得再出现随机 cacheBust 形态。
	if strings.Contains(script, "?_=") {
		t.Fatal("random cacheBust form `?_=` must be gone")
	}
}

// TestPoWScriptVersionIsStableAcrossCalls 锁定「去随机」：同一进程内多次生成
// 的脚本必须携带**同一**版本串（否则缓存永远不命中，改动的收益归零）。
func TestPoWScriptVersionIsStableAcrossCalls(t *testing.T) {
	a := GeneratePoWWASMScript(3, "nonce-a")
	b := GeneratePoWWASMScript(5, "nonce-b")
	for _, ver := range []string{powdata.GlueVersion(), powdata.WasmVersion()} {
		if strings.Count(a, ver) == 0 {
			t.Fatalf("first script missing version %q", ver)
		}
		if strings.Count(b, ver) == 0 {
			t.Fatalf("second script missing version %q", ver)
		}
	}
	// 两段脚本的 URL 片段必须逐字相同（随机性只应存在于 nonce/变量名等处）。
	if got := extractAssetURLs(a); got != extractAssetURLs(b) {
		t.Fatalf("asset URLs unstable across calls:\n a=%q\n b=%q", got, extractAssetURLs(b))
	}
}

// extractAssetURLs 抽出脚本里两个资产 URL 片段（顺序固定：glue、wasm）。
func extractAssetURLs(script string) string {
	gi := strings.Index(script, "/__owaf/pow_glue.js?v=")
	wi := strings.Index(script, "/__owaf/pow.wasm?v=")
	if gi < 0 || wi < 0 {
		return ""
	}
	gEnd := strings.IndexAny(script[gi:], `"'`) + gi
	wEnd := strings.IndexAny(script[wi:], `"'`) + wi
	if gEnd <= gi || wEnd <= wi {
		return ""
	}
	return script[gi:gEnd] + "|" + script[wi:wEnd]
}
