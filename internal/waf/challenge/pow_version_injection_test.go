package challenge

import (
	"strings"
	"testing"

	"My-OpenWaf/internal/waf/challenge/pow"
	"My-OpenWaf/internal/waf/challenge/powdata"
)

/*
本文件用**位置断言**而非存在性断言。理由与 pow_version_contract_test.go 相同：
两个 URL 都在正文里时 `strings.Contains` 恒为 true，槽位对调不会变红。
这里逐位置核对锚点（`module_or_path:"<wasmURL>"` 与 `script.src="<glueURL>"`），
使「槽位对调」这一失效模式可被检测。

注意两个文件的槽位顺序**相反**：envcheck 是「先 wasm 后 glue」，
pow_shard 引导壳是「先 glue 后 wasm」（模板出现顺序不同）。这正是 Sprintf
槽位错位最易发生之处，两处都必须有位置断言覆盖。
*/

// TestEnvCheckJSInjectsPerAssetVersions 契约：envcheck 的两个模板各含 2 个
// 资产 URL 槽位（先 wasm、后 glue），必须分别注入各自版本。
func TestEnvCheckJSInjectsPerAssetVersions(t *testing.T) {
	key := make([]byte, envSessionKeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	for _, tc := range []struct {
		name string
		js   string
	}{
		{"plain", EnvCheckJSEncrypted(EnvSessionKeyHex(key), "aad-x")},
		{"behavior", EnvCheckJSEncryptedWithBehavior(EnvSessionKeyHex(key), "aad-x")},
	} {
		if tc.js == "" {
			t.Fatalf("%s: empty output", tc.name)
		}
		wantWasm := "/__owaf/pow.wasm?v=" + powdata.WasmVersion()
		wantGlue := "/__owaf/pow_glue.js?v=" + powdata.GlueVersion()
		// **位置断言，不只是存在性断言**：两个 URL 都在正文里时，槽位对调
		// 仍会让「包含」成立 —— 必须逐位置核对。
		if !strings.Contains(tc.js, `wasm_bindgen({module_or_path:"`+wantWasm+`"})`) {
			t.Fatalf("%s: module_or_path does not carry the wasm URL (slot mismatch)", tc.name)
		}
		if !strings.Contains(tc.js, `script.src="`+wantGlue+`"`) {
			t.Fatalf("%s: script.src does not carry the glue URL (slot mismatch)", tc.name)
		}
		if strings.Contains(tc.js, `wasm_bindgen({module_or_path:"`+wantGlue+`"})`) {
			t.Fatalf("%s: module_or_path carries the glue URL", tc.name)
		}
		if strings.Contains(tc.js, `script.src="`+wantWasm+`"`) {
			t.Fatalf("%s: script.src carries the wasm URL", tc.name)
		}
	}
}

// TestPowShardBootstrapInjectsPerAssetVersions 契约：pow_shard 引导壳的
// 两个 URL 槽位（先 glue、后 wasm）必须分别注入各自版本。
func TestPowShardBootstrapInjectsPerAssetVersions(t *testing.T) {
	key := make([]byte, envSessionKeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	_, bootstrap, err := GeneratePoWShardedEnvelope(pow.ChallengeProofDifficulty, "ver-nonce", key)
	if err != nil || bootstrap == "" {
		t.Fatalf("GeneratePoWShardedEnvelope: %v", err)
	}
	wantGlue := "/__owaf/pow_glue.js?v=" + powdata.GlueVersion()
	wantWasm := "/__owaf/pow.wasm?v=" + powdata.WasmVersion()
	// 位置断言：引导壳里 s.src 必须是 glue、module_or_path 必须是 wasm。
	if !strings.Contains(bootstrap, `s.src="`+wantGlue+`"`) {
		t.Fatalf("bootstrap: s.src does not carry the glue URL")
	}
	if !strings.Contains(bootstrap, `wasm_bindgen({module_or_path:"`+wantWasm+`"})`) {
		t.Fatalf("bootstrap: module_or_path does not carry the wasm URL")
	}
	if strings.Contains(bootstrap, `s.src="`+wantWasm+`"`) {
		t.Fatal("bootstrap: s.src carries the wasm URL (slot mismatch)")
	}
	if strings.Contains(bootstrap, `wasm_bindgen({module_or_path:"`+wantGlue+`"})`) {
		t.Fatal("bootstrap: module_or_path carries the glue URL (slot mismatch)")
	}
}
