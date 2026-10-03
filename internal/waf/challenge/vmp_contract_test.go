package challenge

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"My-OpenWaf/internal/pkg/vmpasm"
)

/*
本文件是 VMP ISA 的**跨语言契约测试**：Go 侧汇编器与 Rust 侧解释器
（`wasm-pow-solver/src/isa.rs` + `vmp.rs`）之间的真源锁定。

## 本文件锁哪些机制

1. **opcode 数值单一真源**：`isa.rs` 是权威，`internal/pkg/vmpasm` 是镜像。
   本文件**解析 isa.rs 的源文本**逐条比对，任何一侧改数值都会变红。
2. **字节码编码的黄金向量**：Go 汇编器产出的字节序列被逐字节锁定，
   Rust 侧解码器必须能解出同一组指令。
3. **容器格式**：魔数、版本、flags、长度字段、页数上限。
4. **反向断言**：篡改字节、未知 opcode、越界、非法跳转、超预算
   （预算由 Rust 侧执行循环强制，见 §"预算"）都必须被拒绝。

## 为什么必须解析源文本而不是另存一份常量

`ISA.md` §9 的裁决是**方案 A**：权威定义在 Rust `isa.rs`，Go 只做镜像。
若两侧各存一份数值再互相 import，就回到了「两处各写一份、无强制一致机制」
的老问题（这正是 `pow.go:159` 与 `vmp.rs:18` 的现状）。解析源文本让
**漂移与陈旧成为同一个失败模式**，且不需要生成器或构建链改动。

## 位置断言而非存在性断言

`pow_version_contract_test.go` 的教训：存在性断言锁不住槽位。
本文件的 opcode 比对是**逐名逐值**的，不是「含有一个 0x1E」这种存在性检查。
*/

// isaSourcePath 是 ISA 权威定义的位置（相对仓库根）。
const isaSourcePath = "../../../wasm-pow-solver/src/isa.rs"

// libSourcePath 是宿主侧 blob 布局镜像的位置（相对仓库根）。
const libSourcePath = "../../../wasm-pow-solver/src/lib.rs"

// opcodeConstRe 匹配 isa.rs 里 opcode 常量的**唯一合法书写形式**。
//
//	`pub const OP_SHA256_COMPRESS: u8 = 0x1E;`
//
// 契约测试不解析 Rust 语法，只认这一种形态。isa.rs 顶部的注释里写明了
// 这个格式约束；格式被改动时本测试会因为「解析不到任何一行」而失败，
// 而不是静默跳过。
var opcodeConstRe = regexp.MustCompile(`(?m)^pub const (OP_[A-Z0-9_]+): u8 = (0x[0-9A-F]{2});$`)

// headerConstRe 匹配容器常量（非 opcode 的 u 类型常量）。
var headerConstRe = regexp.MustCompile(`(?m)^pub const (VERSION|HEADER_LEN|MAX_CODE_BYTES|MAX_PAGES|MAX_IN_BYTES|MAX_OUT_BYTES|IN_BASE|IN_END|OUT_BASE|HEAP_BASE|PER_ITER_BUDGET|MAX_STEPS_ABS|BATCH_SIZE_LIMIT): (?:u8|usize|u32|u64) = ([^;]+);$`)

// readLibSource 读取 lib.rs 源文本（blob 布局的宿主侧镜像）。
func readLibSource(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(libSourcePath))
	if err != nil {
		t.Fatalf("read %s: %v", libSourcePath, err)
	}
	return string(raw)
}

// readISASource 读取 isa.rs 源文本。
func readISASource(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(isaSourcePath))
	if err != nil {
		t.Fatalf("read %s: %v", isaSourcePath, err)
	}
	return string(raw)
}

// TestISAOpcodesMatchGoMirror 是本改动的核心契约测试。
//
// 机制：isa.rs 里每一条 `pub const OP_*: u8 = 0xNN;` 都必须能在 Go 侧
// `vmpasm.OpcodeTable` 找到同值的镜像，且 Go 侧不得有 isa.rs 里没有的条目。
//
// 变异验证（实测均变红，见交付报告）：
//   - isa.rs 任一 opcode 数值改一位 → 本用例 FAIL（值不等）
//   - isa.rs 注释掉一行 opcode 常量 → 本用例 FAIL（Go 侧多出条目）
//   - Go 侧 opcode 常量改一位     → 本用例 FAIL（值不等）
func TestISAOpcodesMatchGoMirror(t *testing.T) {
	src := readISASource(t)
	matches := opcodeConstRe.FindAllStringSubmatch(src, -1)
	if len(matches) == 0 {
		t.Fatalf("no opcode constants matched in %s; the format contract `^pub const OP_X: u8 = 0xNN;$` was broken", isaSourcePath)
	}

	// rust 名 → 值
	fromRust := make(map[string]byte, len(matches))
	for _, m := range matches {
		name, lit := m[1], m[2]
		if _, dup := fromRust[name]; dup {
			t.Fatalf("duplicate opcode constant %s in %s", name, isaSourcePath)
		}
		var v int64
		if _, err := fmtSscanHex(lit, &v); err != nil {
			t.Fatalf("parse %s = %s: %v", name, lit, err)
		}
		fromRust[name] = byte(v)
	}

	// 逐条比对：Rust 的每条都必须在 Go 镜像里有同值条目。
	for rustName, want := range fromRust {
		goName := vmpasm.GoNameForRustConst(rustName)
		if goName == "" {
			t.Fatalf("GoNameForRustConst(%q) returned empty; the naming contract is broken", rustName)
		}
		got, ok := vmpasm.OpcodeTable[goName]
		if !ok {
			t.Fatalf("isa.rs defines %s (0x%02X) but the Go mirror has no %s", rustName, want, goName)
		}
		if got != want {
			t.Fatalf("opcode drift for %s: isa.rs says 0x%02X, Go mirror (%s) says 0x%02X",
				rustName, want, goName, got)
		}
	}

	// 反向：Go 侧不得有 isa.rs 里没有的条目。
	for goName := range vmpasm.OpcodeTable {
		found := false
		for rustName := range fromRust {
			if vmpasm.GoNameForRustConst(rustName) == goName {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Go mirror has %s but isa.rs defines no matching opcode constant", goName)
		}
	}

	if len(fromRust) != len(vmpasm.OpcodeTable) {
		t.Fatalf("opcode count mismatch: isa.rs has %d, Go mirror has %d",
			len(fromRust), len(vmpasm.OpcodeTable))
	}
	if len(fromRust) != 35 {
		t.Fatalf("expected 35 opcodes, isa.rs defines %d", len(fromRust))
	}
}

// TestISAOpcodesAreContiguousAndReserved 锁定 opcode 的数值布局。
//
// 机制：0x00..0x22 必须连续分配，0x23..0xFF 保留。
// 数值不连续意味着有人插入了一个 opcode 却没更新文档与 Go 镜像。
func TestISAOpcodesAreContiguousAndReserved(t *testing.T) {
	src := readISASource(t)
	matches := opcodeConstRe.FindAllStringSubmatch(src, -1)

	seen := make(map[byte]string, len(matches))
	for _, m := range matches {
		var v int64
		if _, err := fmtSscanHex(m[2], &v); err != nil {
			t.Fatalf("parse %s: %v", m[2], err)
		}
		if prev, dup := seen[byte(v)]; dup {
			t.Fatalf("opcode 0x%02X claimed by both %s and %s", byte(v), prev, m[1])
		}
		seen[byte(v)] = m[1]
	}
	for i := 0; i <= 0x22; i++ {
		if _, ok := seen[byte(i)]; !ok {
			t.Fatalf("opcode 0x%02X is unassigned; the ISA table must be contiguous 0x00..0x22", i)
		}
	}
	for i := 0x23; i <= 0xFF; i++ {
		if name, ok := seen[byte(i)]; ok {
			t.Fatalf("opcode 0x%02X (%s) is inside the reserved range 0x23..0xFF", i, name)
		}
	}
}

// TestISAContainerConstantsMatchGoMirror 锁定容器常量。
func TestISAContainerConstantsMatchGoMirror(t *testing.T) {
	src := readISASource(t)
	matches := headerConstRe.FindAllStringSubmatch(src, -1)
	if len(matches) == 0 {
		t.Fatalf("no container constants matched in %s", isaSourcePath)
	}
	want := map[string]uint64{
		"VERSION":        vmpasm.Version,
		"HEADER_LEN":     vmpasm.HeaderLen,
		"MAX_CODE_BYTES": vmpasm.MaxCodeBytes,
		"MAX_PAGES":      vmpasm.MaxPages,
		"MAX_IN_BYTES":   vmpasm.MaxInBytes,
		"MAX_OUT_BYTES":  vmpasm.MaxOutBytes,
		// 内存布局常量：此前漏锁 —— 两侧都已存在却无强制一致机制，
		// 改布局偏移会让两端静默不一致。
		"IN_BASE":   vmpasm.InBase,
		"IN_END":    vmpasm.InEnd,
		"OUT_BASE":  vmpasm.OutBase,
		"HEAP_BASE": vmpasm.HeapBase,
		// 注意：`OUT_END` 目前**只在 Go 侧存在**（isa.rs 没有对应常量）。
		// 它的推导关系由 TestMemoryLayoutIsSelfConsistent 的 Go 侧自洽锁覆盖；
		// 补 isa.rs 侧的对称常量需要线 B 确认（接口面变更），已上报。
		"PER_ITER_BUDGET":  vmpasm.PerIterBudget,
		"MAX_STEPS_ABS":    vmpasm.MaxStepsAbs,
		"BATCH_SIZE_LIMIT": vmpasm.BatchSizeLimit,
	}
	got := make(map[string]uint64, len(matches))
	// isa.rs 里 IN_END / OUT_BASE / HEAP_BASE 是对前面常量的表达式
	// （`IN_BASE + MAX_IN_BYTES as u64` 等）。按声明顺序解析并允许引用
	// 已解析的常量，这样"表达式链"也被锁住，而不是只锁字面量。
	for _, m := range matches {
		v, err := evalRustConst(m[2], got)
		if err != nil {
			t.Fatalf("parse %s = %s: %v", m[1], m[2], err)
		}
		got[m[1]] = v
	}
	for name, wantVal := range want {
		gotVal, ok := got[name]
		if !ok {
			t.Fatalf("isa.rs does not define %s", name)
		}
		if gotVal != wantVal {
			t.Fatalf("constant drift for %s: isa.rs = %d, Go mirror = %d", name, gotVal, wantVal)
		}
	}
}

// TestMemoryLayoutIsSelfConsistent 是**自洽锁**，与上面的值锁互补。
//
// # 为什么需要它（线 B 提出、team-lead 采纳）
//
// 值锁只比「isa.rs 的解析值 == Go 镜像的当前值」。若有人把 `MAX_IN_BYTES`
// 从 4096 改成 8192，Rust 侧的 `OUT_BASE`/`HEAP_BASE` 会**自动跟随**推导，
// 而 Go 镜像如果只是"被同步改成了同样的绝对值"，值锁依然通过 ——
// 漂移被掩盖了。
//
// 自洽锁断言的是**推导关系**而不是数值快照：
//
//	InEnd    == InBase + MaxInBytes
//	OutBase  == InEnd
//	OutEnd   == OutBase + MaxOutBytes
//	HeapBase == OutEnd
//
// 关系断裂即红，无论两侧的绝对值是否"看起来一致"。
// 这与 §9 否决「只写黄金向量」的理由同源：**锁关系，不只锁快照**。
func TestMemoryLayoutIsSelfConsistent(t *testing.T) {
	if got, want := vmpasm.InEnd, vmpasm.InBase+vmpasm.MaxInBytes; got != want {
		t.Fatalf("InEnd = %d, want InBase + MaxInBytes = %d", got, want)
	}
	if got, want := vmpasm.OutBase, vmpasm.InEnd; got != want {
		t.Fatalf("OutBase = %d, want InEnd = %d", got, want)
	}
	if got, want := vmpasm.OutEnd, vmpasm.OutBase+vmpasm.MaxOutBytes; got != want {
		t.Fatalf("OutEnd = %d, want OutBase + MaxOutBytes = %d", got, want)
	}
	if got, want := vmpasm.HeapBase, vmpasm.OutEnd; got != want {
		t.Fatalf("HeapBase = %d, want OutEnd = %d", got, want)
	}

	// 反向：三段区间必须有序且不重叠
	if !(vmpasm.InBase < vmpasm.InEnd && vmpasm.InEnd <= vmpasm.OutBase &&
		vmpasm.OutBase < vmpasm.OutEnd && vmpasm.OutEnd <= vmpasm.HeapBase) {
		t.Fatalf("memory regions are not ordered: in=[%d,%d) out=[%d,%d) heap=[%d,...)",
			vmpasm.InBase, vmpasm.InEnd, vmpasm.OutBase, vmpasm.OutEnd, vmpasm.HeapBase)
	}
}

// TestBlobLayoutMatchesHostConstants 是 blob 布局的**跨语言锁**。
//
// # 为什么需要它（team-lead 早先指出、本轮补上）
//
// 输入/输出 blob 的偏移在**三处**各有一份：
//
//  1. `internal/pkg/vmpasm/pow_program.go` —— **权威**（Go 汇编器与程序私约）
//  2. `wasm-pow-solver/src/lib.rs` 的 `mod blob` —— 宿主写入/读出用
//  3. `wasm-pow-solver/src/isa.rs` 的注释 —— 只作说明，不参与编译
//
// 三方一致**没有任何强制机制**。今天已经出现过一次真实事故的雏形：
// 两条线各自定义了互不兼容的布局而双方都自洽（因为当时无锁）。
//
// 本用例解析 `lib.rs` 的 `mod blob` 源文本，与 Go 侧权威常量逐条比对。
// 与 opcode 锁同构：**漂移即红**。
//
// 变异验证（实测）：
//   - 改 `lib.rs` 的 `OUT_MAGIC_OFF` 32 → 40 → 红
//   - 改 `lib.rs` 的 `IN_LEN` 表达式 → 红
func TestBlobLayoutMatchesHostConstants(t *testing.T) {
	src := readLibSource(t)

	// `pub(crate) const NAME: usize = <expr>;`
	constRe := regexp.MustCompile(`(?m)^\s*pub\(crate\) const ([A-Z][A-Z0-9_]*): usize = ([^;]+);$`)
	matches := constRe.FindAllStringSubmatch(src, -1)
	if len(matches) == 0 {
		t.Fatal("lib.rs: no `pub(crate) const NAME: usize = ...;` found; the blob layout block moved or changed shape")
	}

	// 按声明顺序求值，允许引用已解析的常量（与 isa.rs 的容器常量同理）。
	got := make(map[string]uint64, len(matches))
	for _, m := range matches {
		v, err := evalRustConst(m[2], got)
		if err != nil {
			// 非布局常量（如别的 usize 常量）不参与本锁，跳过。
			continue
		}
		got[m[1]] = v
	}

	want := map[string]uint64{
		// 输入侧
		"BATCH_SIZE_OFF":    uint64(vmpasm.BlobBatchSizeOff),
		"START_COUNTER_OFF": uint64(vmpasm.BlobStartCounterOff),
		"DIFFICULTY_OFF":    uint64(vmpasm.BlobDifficultyOff),
		"NONCE_LEN_OFF":     uint64(vmpasm.BlobNonceLenOff),
		"NONCE_OFF":         uint64(vmpasm.BlobNonceOff),
		"NONCE_MAX":         uint64(vmpasm.BlobNonceMax),
		"IN_LEN":            uint64(vmpasm.BlobMaxLen),
		// 输出侧
		"OUT_HASH_OFF":    uint64(vmpasm.BlobOutHashOff),
		"OUT_MAGIC_OFF":   uint64(vmpasm.BlobOutMagicOff),
		"OUT_COUNTER_OFF": uint64(vmpasm.BlobOutCounterOff),
		"OUT_LEN_MIN":     uint64(vmpasm.BlobOutLen),
	}
	// 收集**全部**漂移再报，而不是首个即 Fatalf。
	//
	// 理由：`want` 是 map，迭代顺序不确定 —— 首个即停会让「一次变异影响多个
	// 常量」时报出的名字随运行变化（实测：把 `NONCE_MAX` 改小，报告在
	// `NONCE_MAX` 与 `IN_LEN` 之间随机）。报全部才是稳定的、可复现的输出。
	var missing, drifted []string
	for name, wantVal := range want {
		gotVal, ok := got[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		if gotVal != wantVal {
			drifted = append(drifted, fmt.Sprintf("%s: lib.rs = %d, Go authority = %d", name, gotVal, wantVal))
		}
	}
	sort.Strings(missing)
	sort.Strings(drifted)
	if len(missing) > 0 {
		t.Fatalf("lib.rs does not define blob constant(s) %v; the host would write/read the wrong layout", missing)
	}
	if len(drifted) > 0 {
		t.Fatalf("blob layout drift:\n  %s", strings.Join(drifted, "\n  "))
	}

	// 反向：lib.rs 里的布局常量不得有 Go 侧不知道的条目 ——
	// 多一个偏移常量意味着宿主在用一份 Go 汇编器不认的布局。
	for name := range got {
		if _, known := want[name]; !known {
			// 允许非布局常量存在（本文件其它 usize 常量），但若名字带
			// OFF/LEN/MAX 语义又不在权威表里，就是漂移。
			if strings.Contains(name, "_OFF") || strings.HasSuffix(name, "_LEN") ||
				strings.HasSuffix(name, "_LEN_MIN") || strings.HasSuffix(name, "_MAX") {
				t.Fatalf("lib.rs defines layout-looking constant %s that the Go authority does not know", name)
			}
		}
	}
}

// TestBlobOutputMagicMatchesHostConstant 锁定输出魔数的**字节序列**。
//
// 三处写法各自独立：Go 侧是 u64 字面量、lib.rs 是字节串字面量、
// `isa.rs` 是注释里的 hex。本用例把 `lib.rs` 的字节串与 Go 的 u64 互转比对，
// 保证「小端存储后是同一串字节」。
func TestBlobOutputMagicMatchesHostConstant(t *testing.T) {
	src := readLibSource(t)
	m := regexp.MustCompile(`(?m)^\s*pub\(crate\) const OUT_MAGIC: \[u8; 8\] = \*b"([^"]*)";$`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("lib.rs: cannot find `OUT_MAGIC: [u8; 8] = *b\"...\";`")
	}
	raw := strings.ReplaceAll(m[1], `\0`, "\x00")
	lit := []byte(raw)
	if len(lit) != 8 {
		t.Fatalf("OUT_MAGIC literal is %d bytes, want 8: %q", len(lit), lit)
	}

	// Go 权威值 → 小端字节序列
	want := make([]byte, 8)
	for i := 0; i < 8; i++ {
		want[i] = byte(vmpasm.BlobOutputMagic >> (8 * uint(i)))
	}
	if !bytes.Equal(lit, want) {
		t.Fatalf("output magic drift:\nlib.rs = % x (%q)\nGo     = % x", lit, lit, want)
	}
}

// TestISAErrorCodeStringsAreStable 锁定错误码字符串。
//
// # 为什么错误码也要跨语言锁
//
// 错误码是**对 JS 侧可见的契约**：`solve_pow_batched` 用
// `{"found":false,"error":"<code>"}` 把它们透出给浏览器。因此它们和
// opcode 一样是「两处各写一份就会有漂移」的东西 —— Rust 侧定义、
// Go 侧在测试里断言，任何一侧改名都会变红。
//
// 同时锁定「变体数」：`isa.rs` 里 `ProgramError` 的变体数必须等于这里的
// 码位数，少一个（新增变体没同步）多一个（删了变体没同步）都报错。
func TestISAErrorCodeStringsAreStable(t *testing.T) {
	src := readISASource(t)

	// 1) 变体数：`pub enum ProgramError {` 到 `}` 之间的 `Name,` 行数
	enumBody := regexp.MustCompile(`(?s)pub enum ProgramError \{(.*?)\n\}`).FindStringSubmatch(src)
	if enumBody == nil {
		t.Fatal("isa.rs: cannot locate `pub enum ProgramError`")
	}
	variants := regexp.MustCompile(`(?m)^\s{4}([A-Z][A-Za-z0-9]*),$`).FindAllStringSubmatch(enumBody[1], -1)

	// 2) code() 里的 (变体, 字符串) 对
	codeBody := regexp.MustCompile(`(?s)pub const fn code\(self\) -> &'static str \{(.*?)\n    \}`).FindStringSubmatch(src)
	if codeBody == nil {
		t.Fatal("isa.rs: cannot locate `pub const fn code`")
	}
	pairs := regexp.MustCompile(`Self::([A-Z][A-Za-z0-9]*) => "([a-z0-9_]+)",`).FindAllStringSubmatch(codeBody[1], -1)
	if len(pairs) == 0 {
		t.Fatal("isa.rs: code() declares no error codes")
	}

	// 双向：每个变体必须有码；每个码必须对应一个变体
	haveCode := make(map[string]string, len(pairs))
	for _, p := range pairs {
		haveCode[p[1]] = p[2]
	}
	for _, v := range variants {
		if _, ok := haveCode[v[1]]; !ok {
			t.Fatalf("isa.rs variant %s has no code() arm — a variant without a stable code cannot be reported to JS", v[1])
		}
	}
	if len(haveCode) != len(variants) {
		t.Fatalf("ProgramError has %d variants but %d code arms", len(variants), len(haveCode))
	}

	// 3) 单一真源：Go 侧不得再写一份错误码表。这里断言的是
	//    「Go 侧只在测试里出现这些字面量」，因此逐条列出并在下方核对。
	want := map[string]string{
		"BadMagic":             "vm_bad_magic",
		"UnsupportedVersion":   "vm_unsupported_version",
		"BadFlags":             "vm_bad_flags",
		"TrailingBytes":        "vm_trailing_bytes",
		"ProgramTooLarge":      "vm_program_too_large",
		"BatchTooLarge":        "vm_batch_too_large",
		"UnknownOpcode":        "unknown_vm_opcode",
		"MalformedInstruction": "vm_malformed_instruction",
		"OutOfBounds":          "vm_out_of_bounds",
		"DivByZero":            "vm_div_by_zero",
		"BadJumpTarget":        "vm_bad_jump_target",
		"BudgetExhausted":      "vm_budget_exhausted",
		"InvalidHex":           "invalid_vm_hex",
		"OddHexLength":         "odd_vm_hex_length",
		"OutputMagic":          "vm_output_magic",
	}
	for name, code := range want {
		got, ok := haveCode[name]
		if !ok {
			t.Fatalf("isa.rs no longer defines variant %s", name)
		}
		if got != code {
			t.Fatalf("error code drift for %s: isa.rs says %q, contract expects %q", name, got, code)
		}
	}
	if len(want) != len(haveCode) {
		t.Fatalf("contract knows %d codes but isa.rs declares %d; the two lists must stay in step", len(want), len(haveCode))
	}
}

// TestISAMagicMatches 锁定魔数。
func TestISAMagicMatches(t *testing.T) {
	src := readISASource(t)
	m := regexp.MustCompile(`(?m)^pub const MAGIC: \[u8; 4\] = \[([^\]]+)\];$`).FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("isa.rs does not define MAGIC in the expected form")
	}
	parts := strings.Split(m[1], ",")
	if len(parts) != 4 {
		t.Fatalf("MAGIC has %d elements, want 4", len(parts))
	}
	for i, p := range parts {
		var v int64
		if _, err := fmtSscanHex(strings.TrimSpace(p), &v); err != nil {
			t.Fatalf("parse MAGIC[%d] = %q: %v", i, p, err)
		}
		if byte(v) != vmpasm.Magic[i] {
			t.Fatalf("MAGIC[%d]: isa.rs = 0x%02X, Go mirror = 0x%02X", i, byte(v), vmpasm.Magic[i])
		}
	}
}

// TestISADeclaresDelegationToVmp 锁定「执行循环不在 isa.rs」这条架构边界。
//
// 机制：isa.rs 的职责是常量 + 解码表 + 校验；dispatch 循环属于 vmp.rs。
// 本用例以文件内容断言这条边界，防止有人把执行循环塞回 isa.rs 而两侧重复实现。
func TestISADeclaresDelegationToVmp(t *testing.T) {
	src := readISASource(t)
	for _, marker := range []string{
		"执行循环（dispatch、预算、寄存器语义、标志）不在本文件",
		"pub fn parse(",
		"pub fn parse_bytes(",
		"pub enum ProgramError",
	} {
		if !strings.Contains(src, marker) {
			t.Fatalf("isa.rs is missing expected marker %q", marker)
		}
	}
	// 反向：isa.rs 不得出现「执行」相关的实现符号，避免与 vmp.rs 重复。
	for _, forbidden := range []string{"struct Vm", "fn run(", "fn step("} {
		if strings.Contains(src, forbidden) {
			t.Fatalf("isa.rs must not define execution machinery %q; that belongs to vmp.rs", forbidden)
		}
	}
}

// --- 黄金向量：逐字节锁定编码 ---

// goldens 是 Go 汇编器产出的黄金向量。
//
// 每条向量的十六进制串由 `vmpasm.Assemble` 生成，并已用**独立实现的
// Python 解码器**（不复用 Go 代码）逐指令核对：35 条指令的 opcode、操作数
// 与偏移全部一致。因此这份向量同时锁住 Go 编码器和 Rust 解码器。
var goldens = []struct {
	name   string
	layout vmpasm.Layout
	prog   []vmpasm.Instr
	hex    string
}{
	{
		name:   "minimal_halt",
		layout: vmpasm.Layout{Pages: 1},
		prog:   []vmpasm.Instr{{Op: vmpasm.OpHalt}},
		hex:    "4f57564d010000000100000000000000000000000100000022",
	},
	{
		name:   "every_format",
		layout: vmpasm.Layout{Pages: 1, InLen: 16, OutLen: 32},
		prog: []vmpasm.Instr{
			{Op: vmpasm.OpNop},
			{Op: vmpasm.OpMovi, A: vmpasm.R3, Imm: 0x0102030405060708},
			{Op: vmpasm.OpMov, A: vmpasm.R1, B: vmpasm.R2},
			{Op: vmpasm.OpLoad64, A: vmpasm.R4, B: vmpasm.R5, Off: -8},
			{Op: vmpasm.OpStore32, A: vmpasm.R6, B: vmpasm.R7, Off: 16},
			{Op: vmpasm.OpAdd, A: vmpasm.R8, B: vmpasm.R9, C: vmpasm.R10},
			{Op: vmpasm.OpCmp, A: vmpasm.R11, B: vmpasm.R12},
			{Op: vmpasm.OpSha256Compress, A: vmpasm.R13, B: vmpasm.R14},
			{Op: vmpasm.OpHalt},
		},
		hex: "4f57564d0100000001000000100000002000000021000000000130080706050403020102120645f8ffffff0967100000000b89a016bc1ede22",
	},
	{
		name:   "loop_with_labels",
		layout: vmpasm.Layout{Pages: 1, InLen: 16, OutLen: 32},
		prog: []vmpasm.Instr{
			{Op: vmpasm.OpMovi, A: vmpasm.R1, Imm: 8},
			{Op: vmpasm.OpMovi, A: vmpasm.R2, Imm: vmpasm.InBase},
			vmpasm.Label("loop"),
			{Op: vmpasm.OpSm3Compress, A: vmpasm.R3, B: vmpasm.R2},
			{Op: vmpasm.OpAdd, A: vmpasm.R2, B: vmpasm.R2, C: vmpasm.R1},
			{Op: vmpasm.OpSub, A: vmpasm.R1, B: vmpasm.R1, C: vmpasm.R4},
			{Op: vmpasm.OpCmp, A: vmpasm.R5, B: vmpasm.R6},
			{Op: vmpasm.OpJne, Target: "loop"},
			{Op: vmpasm.OpHalt},
		},
		hex: "4f57564d010000000100000010000000200000002400000001100800000000000000012000000000000000001f320b22100c1140165619f1ffffff22",
	},
	{
		name:   "all_opcodes",
		layout: vmpasm.Layout{Pages: 1},
		prog:   allOpcodeProgram(),
		hex:    "4f57564d010000000100000000000000000000008c000000000100000000000000000002000300000000000400000000000500000000000600000000000700000000000800000000000900000000000a00000000000b00000c00000d00000e00000f000010000011000012000013000014000015000016011e001f0020002100181e00000019190000001a140000001b0f0000001c0a0000001d05000000170000000022",
	},
}

// allOpcodeProgram 生成「35 条 opcode 各出现一次」且**控制流合法**的程序。
//
// 布局要求：每条指令都从入口可达，且每条可达指令都能到达 HALT。
// 因此 7 条跳转指令必须集中在倒数第二段，且无条件跳转 JMP 放在最后 ——
// 放前面会让它后面的条件跳转全部不可达。所有跳转都指向末尾的 HALT；
// 条件跳转的顺序后继恰好是下一条跳转指令，形成完整的链。
func allOpcodeProgram() []vmpasm.Instr {
	return []vmpasm.Instr{
		{Op: vmpasm.OpNop},
		{Op: vmpasm.OpMovi, A: vmpasm.R0, Imm: 0},
		{Op: vmpasm.OpMov, A: vmpasm.R0, B: vmpasm.R0},
		{Op: vmpasm.OpLoad8, A: vmpasm.R0, B: vmpasm.R0},
		{Op: vmpasm.OpLoad16, A: vmpasm.R0, B: vmpasm.R0},
		{Op: vmpasm.OpLoad32, A: vmpasm.R0, B: vmpasm.R0},
		{Op: vmpasm.OpLoad64, A: vmpasm.R0, B: vmpasm.R0},
		{Op: vmpasm.OpStore8, A: vmpasm.R0, B: vmpasm.R0},
		{Op: vmpasm.OpStore16, A: vmpasm.R0, B: vmpasm.R0},
		{Op: vmpasm.OpStore32, A: vmpasm.R0, B: vmpasm.R0},
		{Op: vmpasm.OpStore64, A: vmpasm.R0, B: vmpasm.R0},
		{Op: vmpasm.OpAdd, A: vmpasm.R0, B: vmpasm.R0, C: vmpasm.R0},
		{Op: vmpasm.OpSub, A: vmpasm.R0, B: vmpasm.R0, C: vmpasm.R0},
		{Op: vmpasm.OpMul, A: vmpasm.R0, B: vmpasm.R0, C: vmpasm.R0},
		{Op: vmpasm.OpDivu, A: vmpasm.R0, B: vmpasm.R0, C: vmpasm.R0},
		{Op: vmpasm.OpModu, A: vmpasm.R0, B: vmpasm.R0, C: vmpasm.R0},
		{Op: vmpasm.OpAnd, A: vmpasm.R0, B: vmpasm.R0, C: vmpasm.R0},
		{Op: vmpasm.OpOr, A: vmpasm.R0, B: vmpasm.R0, C: vmpasm.R0},
		{Op: vmpasm.OpXor, A: vmpasm.R0, B: vmpasm.R0, C: vmpasm.R0},
		{Op: vmpasm.OpShl, A: vmpasm.R0, B: vmpasm.R0, C: vmpasm.R0},
		{Op: vmpasm.OpShr, A: vmpasm.R0, B: vmpasm.R0, C: vmpasm.R0},
		{Op: vmpasm.OpSar, A: vmpasm.R0, B: vmpasm.R0, C: vmpasm.R0},
		{Op: vmpasm.OpCmp, A: vmpasm.R0, B: vmpasm.R1},
		{Op: vmpasm.OpSha256Compress, A: vmpasm.R0, B: vmpasm.R0},
		{Op: vmpasm.OpSm3Compress, A: vmpasm.R0, B: vmpasm.R0},
		{Op: vmpasm.OpSm4EncBlock, A: vmpasm.R0, B: vmpasm.R0},
		{Op: vmpasm.OpSm4DecBlock, A: vmpasm.R0, B: vmpasm.R0},
		{Op: vmpasm.OpJeq, Target: "end"},
		{Op: vmpasm.OpJne, Target: "end"},
		{Op: vmpasm.OpJlt, Target: "end"},
		{Op: vmpasm.OpJle, Target: "end"},
		{Op: vmpasm.OpJgt, Target: "end"},
		{Op: vmpasm.OpJge, Target: "end"},
		{Op: vmpasm.OpJmp, Target: "end"},
		vmpasm.Label("end"),
		{Op: vmpasm.OpHalt},
	}
}

// TestGoldenVectorsMatchAssembler 锁定 Go 汇编器的逐字节输出。
func TestGoldenVectorsMatchAssembler(t *testing.T) {
	for _, g := range goldens {
		t.Run(g.name, func(t *testing.T) {
			raw, err := vmpasm.Assemble(g.layout, g.prog)
			if err != nil {
				t.Fatalf("Assemble: %v", err)
			}
			if got := vmpasm.Hex(raw); got != g.hex {
				t.Fatalf("golden vector drift:\ngot  %s\nwant %s", got, g.hex)
			}
		})
	}
}

// TestGoldenVectorsVerifyClean 证明每条黄金向量都能通过 Go 侧校验器。
func TestGoldenVectorsVerifyClean(t *testing.T) {
	for _, g := range goldens {
		t.Run(g.name, func(t *testing.T) {
			raw, err := vmpasm.Unhex(g.hex)
			if err != nil {
				t.Fatalf("Unhex: %v", err)
			}
			rep, err := vmpasm.Verify(raw)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !rep.OK() {
				t.Fatalf("golden vector has structural errors: %+v", rep.Errors)
			}
		})
	}
}

// --- 反向断言 ---

// TestTamperedGoldenVectorsAreRejected 是本文件的核心反向锁。
//
// 机制：对每条黄金向量的每一个字节、每一位各翻转一次，断言该变异**不可能是
// 静默无效的** —— 要么被校验器拒绝，要么反汇编出的程序与原文不同。
//
// # 为什么不断言「一律被拒绝」
//
// 操作数字段（立即数、寄存器号、内存偏移）被翻转后往往仍是一个**合法但不同**
// 的程序 —— 那是正确行为，不是缺陷。把它们一律要求拒绝会写出假的反向锁。
// 「被拒绝 或 解码结果改变」才是真正要锁的机制：**校验器确实读了每一个字节**。
func TestTamperedGoldenVectorsAreRejected(t *testing.T) {
	for _, g := range goldens {
		t.Run(g.name, func(t *testing.T) {
			base, err := vmpasm.Unhex(g.hex)
			if err != nil {
				t.Fatalf("Unhex: %v", err)
			}
			baseText, err := vmpasm.Disassemble(base)
			if err != nil {
				t.Fatalf("Disassemble(base): %v", err)
			}

			rejected, altered := 0, 0
			for i := 0; i < len(base); i++ {
				for bit := 0; bit < 8; bit++ {
					mutated := append([]byte(nil), base...)
					mutated[i] ^= 1 << bit

					rep, verifyErr := vmpasm.Verify(mutated)
					if verifyErr != nil || !rep.OK() {
						rejected++
						continue
					}
					text, disErr := vmpasm.Disassemble(mutated)
					if disErr != nil || text != baseText {
						altered++
						continue
					}
					t.Errorf("byte %d bit %d flipped to 0x%02X: accepted AND disassembles identically; the byte is not significant",
						i, bit, mutated[i])
				}
			}
			if rejected+altered != len(base)*8 {
				t.Fatalf("classified %d mutations, want %d", rejected+altered, len(base)*8)
			}
			t.Logf("%d bytes: %d mutations rejected, %d decoded differently", len(base), rejected, altered)
		})
	}
}

// TestStructuralBytesAreAlwaysRejected 是本文件最严格的反向锁。
//
// 机制：容器头部（魔数、版本、flags、reserved、code_len）与 opcode 字节属于
// **结构字段**，它们的任何一位翻转都必须让校验器拒绝 —— 不允许出现
// "改了还是合法程序"的情况。
func TestStructuralBytesAreAlwaysRejected(t *testing.T) {
	base, err := vmpasm.Unhex(goldens[len(goldens)-1].hex) // all_opcodes：opcode 覆盖面最大
	if err != nil {
		t.Fatalf("Unhex: %v", err)
	}

	// 头部里必须"改一位即拒绝"的字段：magic(0..3)、version(4)、flags(5)、
	// reserved(6..7)、code_len(20..23)。
	structural := []int{0, 1, 2, 3, 4, 5, 6, 7, 20, 21, 22, 23}
	for _, i := range structural {
		for bit := 0; bit < 8; bit++ {
			mutated := append([]byte(nil), base...)
			mutated[i] ^= 1 << bit
			rep, verifyErr := vmpasm.Verify(mutated)
			if verifyErr == nil && rep.OK() {
				t.Errorf("header byte %d bit %d flipped to 0x%02X: Verify accepted it, but header fields are structural",
					i, bit, mutated[i])
			}
		}
	}

	// opcode 字节：**只有真正的取指边界**才允许被替换成保留区 opcode。
	// 操作数字节（立即数、寄存器号、偏移）被改成 0x7F 只是改变操作数取值，
	// 程序仍然合法 —— 把它们一并要求拒绝是假的反向锁。
	offsets, err := vmpasm.CodeOffsets(base)
	if err != nil {
		t.Fatalf("CodeOffsets: %v", err)
	}
	if len(offsets) == 0 {
		t.Fatal("CodeOffsets returned no instruction boundaries")
	}
	for _, off := range offsets {
		mutated := append([]byte(nil), base...)
		mutated[vmpasm.HeaderLen+off] = 0x7F
		rep, verifyErr := vmpasm.Verify(mutated)
		if verifyErr == nil && rep.OK() {
			t.Errorf("opcode at code offset %d replaced with reserved 0x7F: Verify accepted it", off)
		}
	}
}

// TestUnknownOpcodesAreRejected 反向：保留区 opcode 必须被拒绝。
func TestUnknownOpcodesAreRejected(t *testing.T) {
	for op := 0x23; op <= 0xFF; op++ {
		raw := rawContainer(vmpasm.Layout{Pages: 1}, []byte{byte(op)})
		if _, err := vmpasm.Verify(raw); err == nil {
			t.Fatalf("opcode 0x%02X is in the reserved range but Verify accepted it", op)
		}
	}
}

// TestOutOfBoundsAccessIsRejected 反向：越界必须被拒绝。
//
// 注意 Go 侧无法执行程序，因此这里锁的是**编码层**的越界：
// LOAD/STORE 的偏移字段超出声明内存时，校验器必须报 finding。
// 运行期越界由 Rust 侧的 `vm_out_of_bounds` 负责（isa.rs 的单元测试覆盖）。
func TestOutOfBoundsAccessIsRejected(t *testing.T) {
	// 偏移 = 0x7FFFFFFF，一页内存（64 KiB）下必然越界
	code := []byte{vmpasm.OpLoad64, 0x10}
	code = append(code, 0xFF, 0xFF, 0xFF, 0x7F)
	code = append(code, vmpasm.OpHalt)
	raw := rawContainer(vmpasm.Layout{Pages: 1}, code)

	rep, err := vmpasm.Verify(raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !hasFinding(rep.Findings, "offset_beyond_memory") {
		t.Fatalf("Verify did not report offset_beyond_memory: %+v", rep.Findings)
	}
	// 正向对照：同一指令在小偏移下必须干净
	ok := []byte{vmpasm.OpLoad64, 0x10, 0x00, 0x00, 0x00, 0x00, vmpasm.OpHalt}
	repOK, err := vmpasm.Verify(rawContainer(vmpasm.Layout{Pages: 1}, ok))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !repOK.Clean() {
		t.Fatalf("small in-range offset must be clean: %+v", repOK.Findings)
	}
}

// TestBadJumpTargetsAreRejected 反向：非法跳转目标必须被拒绝。
func TestBadJumpTargetsAreRejected(t *testing.T) {
	cases := []struct {
		name string
		code []byte
	}{
		// JMP +1 → 目标 = 6，超出 6 字节 code 的边界外
		{"past_end", []byte{vmpasm.OpJmp, 0x01, 0x00, 0x00, 0x00, vmpasm.OpHalt}},
		// JMP -6 → 目标 = -1
		{"before_start", []byte{vmpasm.OpJmp, 0xFA, 0xFF, 0xFF, 0xFF, vmpasm.OpHalt}},
		// JMP +2 → 目标 = 7，落在 HALT 之后（不存在）
		{"beyond_code", []byte{vmpasm.OpJmp, 0x02, 0x00, 0x00, 0x00, vmpasm.OpHalt}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := vmpasm.Verify(rawContainer(vmpasm.Layout{Pages: 1}, tc.code)); err == nil {
				t.Fatalf("Verify accepted %s jump target", tc.name)
			}
		})
	}
}

// TestLegacyFormatIsRejected 反向：旧格式（无头部）必须被拒绝。
//
// 这是裁决 12 的核心：旧的 6-opcode 裸串不再被容忍，否则那个
// 「固定 5 步状态机」就永远活着。
func TestLegacyFormatIsRejected(t *testing.T) {
	// 旧格式的两种形态：裸 opcode 串、以及 vmp.rs 历史测试里的 "VMPF" 帧头
	legacy := [][]byte{
		{0x10, 0x11, 0x12, 0x13, 0x14},                   // pow.go 旧生成器
		{0x00, 0x10, 0x11, 0x00, 0x12, 0x13, 0x00, 0x14}, // 带 NOP 填充
		{0x56, 0x4D, 0x50, 0x46, 0x01, 0xC9, 0x00, 0x05}, // "VMPF" 帧头
	}
	for _, raw := range legacy {
		if rep, err := vmpasm.Verify(raw); err == nil && rep.OK() {
			t.Fatalf("legacy program %x was accepted; the old format must be rejected", raw)
		}
	}
	// 正向对照：同一组 opcode 装进新容器后必须通过
	raw, err := vmpasm.Assemble(vmpasm.Layout{Pages: 1}, []vmpasm.Instr{{Op: vmpasm.OpHalt}})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	rep, err := vmpasm.Verify(raw)
	if err != nil || !rep.OK() {
		t.Fatalf("new-format program must verify: err=%v rep=%+v", err, rep)
	}
}

// TestBudgetIsBounded 反向：预算公式必须真的封顶。
//
// Go 侧不执行程序，因此这里锁的是**预算常量本身**：公式
// `min(PER_ITER_BUDGET * batch_size, MAX_STEPS_ABS)` 在 batch_size
// 达到上限时不得溢出成天文数字。
func TestBudgetIsBounded(t *testing.T) {
	atLimit := uint64(vmpasm.PerIterBudget) * uint64(vmpasm.BatchSizeLimit)
	if atLimit < vmpasm.MaxStepsAbs {
		t.Fatalf("PER_ITER_BUDGET(%d) * BATCH_SIZE_LIMIT(%d) = %d, which is below MAX_STEPS_ABS(%d); the cap is unreachable",
			vmpasm.PerIterBudget, vmpasm.BatchSizeLimit, atLimit, vmpasm.MaxStepsAbs)
	}
	budget := func(batch uint32) uint64 {
		b := uint64(vmpasm.PerIterBudget) * uint64(batch)
		if b > vmpasm.MaxStepsAbs {
			return vmpasm.MaxStepsAbs
		}
		return b
	}
	if got := budget(1); got != vmpasm.PerIterBudget {
		t.Fatalf("budget(1) = %d, want %d", got, vmpasm.PerIterBudget)
	}
	if got := budget(vmpasm.BatchSizeLimit); got != vmpasm.MaxStepsAbs {
		t.Fatalf("budget(BATCH_SIZE_LIMIT) = %d, want the cap %d", got, vmpasm.MaxStepsAbs)
	}
	// 反向：batch_size = 0 时预算为 0，程序不得推进
	if got := budget(0); got != 0 {
		t.Fatalf("budget(0) = %d, want 0", got)
	}
}

// --- 辅助 ---

func rawContainer(layout vmpasm.Layout, code []byte) []byte {
	return vmpasm.BuildRaw(layout, code)
}

func hasFinding(findings []vmpasm.Finding, code string) bool {
	for _, f := range findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func fmtSscanHex(lit string, out *int64) (int, error) {
	v, err := strconv.ParseInt(strings.TrimPrefix(lit, "0x"), 16, 64)
	if err != nil {
		return 0, err
	}
	*out = v
	return 1, nil
}

// evalRustConst 解析 isa.rs 里容器常量的右值。
//
// 支持三种形态（够用即可，不是通用 Rust 求值器）：
//
//  1. 字面量         `24` / `0x01` / `1 << 30` / `1_000_000`
//  2. 类型标注剥离   `MAX_IN_BYTES as u64`
//  3. 加法链         `IN_BASE + MAX_IN_BYTES as u64`
//
// 引用只解析**已声明**的常量（按源码顺序遍历），未定义即报错 ——
// 这样循环引用或改名都会被捕获。
func evalRustConst(expr string, defined map[string]uint64) (uint64, error) {
	sum := uint64(0)
	for _, term := range strings.Split(expr, "+") {
		term = strings.TrimSpace(term)
		term = strings.TrimSuffix(term, " as u64")
		term = strings.TrimSuffix(term, " as usize")
		term = strings.TrimSuffix(term, " as u32")
		term = strings.TrimSpace(term)
		if term == "" {
			return 0, fmt.Errorf("empty term in %q", expr)
		}
		// 标识符 → 已解析常量
		if term[0] >= 'A' && term[0] <= 'Z' {
			v, ok := defined[term]
			if !ok {
				return 0, fmt.Errorf("reference to undefined constant %q", term)
			}
			sum += v
			continue
		}
		var v int64
		if _, err := fmtSscanDecOrHex(term, &v); err != nil {
			return 0, err
		}
		if v < 0 {
			return 0, fmt.Errorf("negative term %d in %q", v, expr)
		}
		sum += uint64(v)
	}
	return sum, nil
}

func fmtSscanDecOrHex(lit string, out *int64) (int, error) {
	lit = strings.TrimSpace(lit)
	if strings.HasPrefix(lit, "0x") {
		return fmtSscanHex(lit, out)
	}
	// 支持 `1 << 30` 形态：isa.rs 用移位表达式写 MAX_STEPS_ABS。
	if i := strings.Index(lit, "<<"); i >= 0 {
		base, err := strconv.ParseInt(strings.TrimSpace(lit[:i]), 10, 64)
		if err != nil {
			return 0, err
		}
		shift, err := strconv.ParseInt(strings.TrimSpace(lit[i+2:]), 10, 64)
		if err != nil {
			return 0, err
		}
		*out = base << uint(shift)
		return 1, nil
	}
	// 支持下划线分隔的数字（如 1_000_000）
	lit = strings.ReplaceAll(lit, "_", "")
	v, err := strconv.ParseInt(lit, 10, 64)
	if err != nil {
		return 0, err
	}
	*out = v
	return 1, nil
}
