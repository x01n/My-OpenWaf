package vmpasm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"
)

// 本文件端到端验证 **PoW 字节码程序**：Go 汇编器生成程序 → 参考解释器执行
// → 结果必须等于 Go 标准库算出的 SHA-256 前导零判定。
//
// 这是「ISA 真的能表达 PoW」的证据。程序里**没有任何 PoW 专用指令**：
// 前导零检查是「循环 + 无符号比较 + 条件跳转」（ISA §4.3.6）。
//
// 生产定义在 `pow_program.go`（`pow.go` 的 `GenerateVMProgram` 直接汇编它）。
//
// # 关于「批」的语义（v2）
//
// 程序**自己**遍历 `[start_counter, start_counter + batch_size)`。
// 因此所有端到端用例都以「批」为单位断言，不再是单 counter。

// goPoWMatches 是 Go 标准库侧的判定：SHA-256(nonce‖decimal(counter)) 的
// 前 `difficulty` 个十六进制位是否为 0。与字节码程序的语义定义必须一致。
func goPoWMatches(nonce string, counter uint64, difficulty uint32) bool {
	if difficulty > 64 {
		panic("goPoWMatches: difficulty too large for this helper")
	}
	msg := nonce + strconv.FormatUint(counter, 10)
	sum := sha256.Sum256([]byte(msg))
	for i := uint32(0); i < difficulty; i++ {
		b := sum[i/2]
		nib := b >> 4
		if i%2 == 1 {
			nib = b & 0x0F
		}
		if nib != 0 {
			return false
		}
	}
	return true
}

// goPoWHash 返回标准库算出的摘要。
func goPoWHash(nonce string, counter uint64) [32]byte {
	return sha256.Sum256([]byte(nonce + strconv.FormatUint(counter, 10)))
}

// powProgramHex 返回 PoW 程序的十六进制串（确定性 —— 程序无随机成分）。
func powProgramHex(t *testing.T) string {
	t.Helper()
	raw, err := Assemble(PoWProgramLayout(), BuildPoWProgram())
	if err != nil {
		t.Fatalf("Assemble(PoW program): %v", err)
	}
	rep, err := Verify(raw)
	if err != nil {
		t.Fatalf("Verify(PoW program): %v", err)
	}
	if !rep.OK() {
		t.Fatalf("PoW program has structural errors: %+v", rep.Errors)
	}
	return Hex(raw)
}

// powBlob 按 §7.2.1 布局构造输入 blob。
//
// **恒返回 `BlobMaxLen` 字节**（nonce 区补零）—— 与 `PoWProgramLayout().InLen`
// 一致，这样「宿主写入量 == header.in_len」这条防线才成立。
func powBlob(nonce string, counter uint64, difficulty uint32, batchSize uint64) []byte {
	blob := make([]byte, BlobMaxLen)
	binary.LittleEndian.PutUint64(blob[BlobBatchSizeOff:], batchSize)
	binary.LittleEndian.PutUint64(blob[BlobStartCounterOff:], counter)
	binary.LittleEndian.PutUint64(blob[BlobDifficultyOff:], uint64(difficulty))
	binary.LittleEndian.PutUint64(blob[BlobNonceLenOff:], uint64(len(nonce)))
	copy(blob[BlobNonceOff:], nonce)
	return blob
}

// powRunResult 是一次执行的完整结果。
type powRunResult struct {
	// Found 是 R0（1 = 命中，0 = 未命中）。
	Found uint64
	// Hash 是输出区前 32 字节（仅 Found == 1 时有意义）。
	Hash []byte
	// Magic 是输出区偏移 32 的 u64（仅 Found == 1 时有意义）。
	Magic uint64
	// Counter 是输出区偏移 40 的 u64（仅 Found == 1 时有意义）。
	Counter uint64
	// Raw 是完整的 out_len 字节输出区，供「未命中必须全零」断言使用。
	Raw []byte
	// Steps 是消耗的指令步数。
	Steps uint64
}

// runPoW 执行一次 PoW 程序，返回 R0 与输出区。
func runPoW(t *testing.T, hexProgram string, nonce string, start uint64, difficulty, batchSize uint32) powRunResult {
	t.Helper()
	raw, err := Unhex(hexProgram)
	if err != nil {
		t.Fatalf("Unhex: %v", err)
	}
	m, err := NewRefMachine(raw)
	if err != nil {
		t.Fatalf("NewRefMachine: %v", err)
	}
	if err := m.WriteInput(powBlob(nonce, start, difficulty, uint64(batchSize))); err != nil {
		t.Fatalf("WriteInput: %v", err)
	}
	r0, err := m.Run(0)
	if err != nil {
		t.Fatalf("Run: %v (steps=%d)", err, m.Steps())
	}
	out := append([]byte(nil), m.mem[OutBase:OutBase+BlobOutLen]...)
	return powRunResult{
		Found:   r0,
		Hash:    out[:32],
		Magic:   binary.LittleEndian.Uint64(out[BlobOutMagicOff:]),
		Counter: binary.LittleEndian.Uint64(out[BlobOutCounterOff:]),
		Raw:     out,
		Steps:   m.Steps(),
	}
}

// powInBatch 返回批 `[start, start+batchSize)` 内**最小**的解。
func powInBatch(nonce string, start uint64, batchSize uint32, difficulty uint32) (uint64, bool) {
	for i := uint64(0); i < uint64(batchSize); i++ {
		c := start + i
		if goPoWMatches(nonce, c, difficulty) {
			return c, true
		}
	}
	return 0, false
}

// TestPoWProgramFindsSolutionWithinBatch 是**核心正向断言**：
// counter 在批内某处时，程序必须找到它、写对输出区、并返回 R0 = 1。
//
// 这条同时锁三件事：
//   - 批内循环真的在推进（不再是每次调用只试一个 counter）
//   - 写出的 hash 与 Go 标准库逐字节相同
//   - 写出的 found_counter 是**真正的解**，不是 start_counter
func TestPoWProgramFindsSolutionWithinBatch(t *testing.T) {
	prog := powProgramHex(t)
	const nonce = "deadbeefcafebabe0011223344556677"
	const difficulty = 3
	const batchSize = 4096

	sol, ok := powInBatch(nonce, 0, batchSize, difficulty)
	if !ok {
		t.Fatal("no solution in [0,4096) — test vector is unusable")
	}
	if sol == 0 {
		t.Fatal("solution at counter 0 would not exercise the loop; test vector is unusable")
	}

	got := runPoW(t, prog, nonce, 0, difficulty, batchSize)
	if got.Found != 1 {
		t.Fatalf("program did not find the solution at counter=%d (R0=%d, %d steps)", sol, got.Found, got.Steps)
	}
	if got.Counter != sol {
		t.Fatalf("program reported counter=%d, want %d", got.Counter, sol)
	}
	want := goPoWHash(nonce, sol)
	if !bytes.Equal(got.Hash, want[:]) {
		t.Fatalf("output hash mismatch:\ngot  %x\nwant %x", got.Hash, want[:])
	}
	if got.Magic != BlobOutputMagic {
		t.Fatalf("output magic = 0x%016X, want 0x%016X", got.Magic, BlobOutputMagic)
	}
}

// TestPoWProgramReportsFirstSolutionInBatch 正向：批内若有多个解，
// 程序必须报告**最小的那个**（因为它从 start 递增遍历）。
func TestPoWProgramReportsFirstSolutionInBatch(t *testing.T) {
	prog := powProgramHex(t)
	const nonce = "00112233445566778899aabbccddeeff"
	const difficulty = 2 // 解更密集，一个批内大概率有多个
	const batchSize = 2048

	first, ok := powInBatch(nonce, 0, batchSize, difficulty)
	if !ok {
		t.Fatal("no solution in the batch — test vector is unusable")
	}
	// 统计批内解的数量，确认这个向量确实覆盖「多解」情形
	multi := 0
	for i := uint64(0); i < batchSize; i++ {
		if goPoWMatches(nonce, i, difficulty) {
			multi++
		}
	}
	if multi < 2 {
		t.Fatalf("test vector has only %d solution(s) in the batch; it does not cover 'first of many'", multi)
	}

	got := runPoW(t, prog, nonce, 0, difficulty, batchSize)
	if got.Found != 1 {
		t.Fatalf("R0 = %d, want 1", got.Found)
	}
	if got.Counter != first {
		t.Fatalf("program reported counter=%d, want the first solution %d (of %d in batch)", got.Counter, first, multi)
	}
}

// TestPoWProgramLeavesOutputZeroOnMiss 是**反向断言**，同时覆盖两个方向。
//
// 未命中：R0 == 0 且输出区 `out_len` 字节**全零**（程序不得触碰输出区）。
// 命中：  R0 == 1 且三段（hash / OUTPUT_MAGIC / counter）全部正确。
//
// # 为什么「未命中必须全零」是可测的不变量
//
// 宿主的观测表把「R0 == 0 + 输出区非零」判为**程序实现违规** —— 这是一个
// 免费的实现自检：不需要额外数据，只靠输出区是否为全零就能发现「程序在未
// 命中路径上也写了东西」这类错误。
func TestPoWProgramLeavesOutputZeroOnMiss(t *testing.T) {
	prog := powProgramHex(t)
	const nonce = "cafebabedeadbeef"
	const difficulty = 6 // 期望 16^6 次才有一个解，小批内几乎必然无解

	// 先确认这个批内确实无解（否则用例无意义）
	const batchSize = 4096
	if _, ok := powInBatch(nonce, 0, batchSize, difficulty); ok {
		t.Fatal("batch unexpectedly contains a solution; test vector is unusable")
	}

	got := runPoW(t, prog, nonce, 0, difficulty, batchSize)
	if got.Found != 0 {
		t.Fatalf("R0 = %d, want 0 for a batch with no solution", got.Found)
	}
	if !bytes.Equal(got.Raw, make([]byte, BlobOutLen)) {
		t.Fatalf("unmet batch wrote to the output area (all %d bytes must stay zero): %x", BlobOutLen, got.Raw)
	}

	// 正向对照：同一 nonce 用低难度必须命中，且三段全部正确 ——
	// 否则"未命中返回 0"可能只是"程序永远返回 0"。
	low := runPoW(t, prog, nonce, 0, 2, 4096)
	if low.Found != 1 {
		t.Fatal("the same program failed to find a low-difficulty solution; the miss result is not meaningful")
	}
	sol, ok := powInBatch(nonce, 0, 4096, 2)
	if !ok {
		t.Fatal("helper disagrees: batch has no solution")
	}
	if low.Counter != sol {
		t.Fatalf("hit reported counter %d, want %d", low.Counter, sol)
	}
	if h := goPoWHash(nonce, sol); !bytes.Equal(low.Hash, h[:]) {
		t.Fatalf("hit hash mismatch:\ngot  %x\nwant %x", low.Hash, h[:])
	}
	if low.Magic != BlobOutputMagic {
		t.Fatalf("hit magic = 0x%016X, want 0x%016X", low.Magic, BlobOutputMagic)
	}
}

// TestPoWProgramMatchesStandardLibrary 逐批核对：程序判定与标准库一致。
//
// 批大小取小值并覆盖多个起始点，验证 `start_counter` 与 `batch_size`
// 两个字段都被正确读取。
func TestPoWProgramMatchesStandardLibrary(t *testing.T) {
	prog := powProgramHex(t)
	const nonce = "00112233445566778899aabbccddeeff"
	const difficulty = 3
	const batchSize = 64

	for _, start := range []uint64{0, 1000, 65536, 1000000} {
		got := runPoW(t, prog, nonce, start, difficulty, batchSize)
		want := uint64(0)
		if _, ok := powInBatch(nonce, start, batchSize, difficulty); ok {
			want = 1
		}
		if got.Found != want {
			t.Fatalf("start=%d batch=%d: program says %d, standard library says %d",
				start, batchSize, got.Found, want)
		}
		if want == 1 {
			sol, _ := powInBatch(nonce, start, batchSize, difficulty)
			if got.Counter != sol {
				t.Fatalf("start=%d: reported counter %d, want %d", start, got.Counter, sol)
			}
			if h := goPoWHash(nonce, sol); !bytes.Equal(got.Hash, h[:]) {
				t.Fatalf("start=%d: hash mismatch", start)
			}
		}
	}
}

// TestPoWProgramCoversBothBlockPaths 是**分支覆盖**断言：
// msgLen < 56 走单块路径，msgLen ≥ 56 走双块路径，两条都要真实跑到并正确。
//
// # 这是「假覆盖」的反面教材（方法论）
//
// 本用例初版只测 32 字节 nonce（msgLen ≈ 33），**永远进不了双块分支** ——
// 测试是绿的，但双块路径从未被执行过。这与「假注入」「无区分力取值」并列，
// 是同一类错误：**测试看起来在保护一个机制，实际保护另一个**。
// 修法是把 nonce 长度分档，让两条分支都被真实走到。
//
// **这条修法的回报是立刻的**：加档后 `max_nonce_double_block` 立刻变红，
// 暴露出「主循环无条件清零长度字段位会抹掉长 nonce 尾部」这个**真缺陷**
// （实测 `nonceLen = 58` 起算错哈希，且是**假阳性**——无解报有解）。
// 该缺陷在 `BlobNonceMax = 64` 这个**合法输入**上出现；「生产 nonce 是 32 字节」
// 是当前行为而非规格。详见 `pow_program.go` 单块分支的注释。
func TestPoWProgramCoversBothBlockPaths(t *testing.T) {
	prog := powProgramHex(t)
	const difficulty = 2
	const batchSize = 512

	// msgLen = nonceLen + 十进制位数（1..20）。
	// nonceLen ≤ 34 时 msgLen ≤ 54 → 单块；nonceLen ≥ 40 时必然双块。
	cases := []struct {
		name     string
		nonceLen int
	}{
		{"short_nonce_single_block", 8},
		{"medium_nonce_single_block", 32},
		{"long_nonce_double_block", 40},
		{"max_nonce_double_block", BlobNonceMax},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nonce := make([]byte, tc.nonceLen)
			for i := range nonce {
				nonce[i] = byte('a' + i%26)
			}
			n := string(nonce)
			got := runPoW(t, prog, n, 0, difficulty, batchSize)
			sol, ok := powInBatch(n, 0, batchSize, difficulty)
			wantFound := uint64(0)
			if ok {
				wantFound = 1
			}
			if got.Found != wantFound {
				t.Fatalf("nonceLen=%d: R0 = %d, want %d", tc.nonceLen, got.Found, wantFound)
			}
			if ok {
				if got.Counter != sol {
					t.Fatalf("nonceLen=%d: counter=%d, want %d", tc.nonceLen, got.Counter, sol)
				}
				h := goPoWHash(n, sol)
				if !bytes.Equal(got.Hash, h[:]) {
					t.Fatalf("nonceLen=%d: hash mismatch:\ngot  %x\nwant %x", tc.nonceLen, got.Hash, h[:])
				}
				if got.Magic != BlobOutputMagic {
					t.Fatalf("nonceLen=%d: magic = 0x%016X, want 0x%016X", tc.nonceLen, got.Magic, BlobOutputMagic)
				}
			}
		})
	}
}

// TestPoWProgramStaysWithinBudget 锁定「最坏情况下程序仍有一倍预算余量」。
//
// # 口径（v2：批内循环后的步数）
//
// 程序现在每次调用遍历 `batch_size` 个 counter，因此**总步数 ≈ batch_size ×
// 单次步数**。校验的是总步数与总预算的关系，不是单次。
//
// `PER_ITER_BUDGET = 2048`，`step_budget_for(batch_size) = min(2048 × bs, 1<<30)`。
// 因此「单次 ≤ 2048 步」等价于「总步数 ≤ 总预算」。这里用单次步数表达，
// 与 ISA §6.2 的口径一致。
func TestPoWProgramStaysWithinBudget(t *testing.T) {
	prog := powProgramHex(t)
	raw, err := Unhex(prog)
	if err != nil {
		t.Fatalf("Unhex: %v", err)
	}

	// 最坏路径：64 字节 nonce（双块）+ 20 位 counter + 大 batch
	nonce := ""
	for i := 0; i < BlobNonceMax; i++ {
		nonce += "a"
	}
	const batchSize = 4096
	start := uint64(9999999999999999999) // 20 位十进制

	m, err := NewRefMachine(raw)
	if err != nil {
		t.Fatalf("NewRefMachine: %v", err)
	}
	blob := powBlob(nonce, start, 7, uint64(batchSize))
	if err := m.WriteInput(blob); err != nil {
		t.Fatalf("WriteInput: %v", err)
	}
	if _, err := m.Run(0); err != nil {
		t.Fatalf("Run: %v", err)
	}
	total := m.Steps()
	budget := uint64(PerIterBudget) * uint64(batchSize)
	perIter := total / uint64(batchSize)

	if total > budget {
		t.Fatalf("program used %d steps for a batch of %d, budget is %d", total, batchSize, budget)
	}
	t.Logf("batch of %d: %d steps total, ~%d steps per counter (per-iteration budget %d, %.0f%% used)",
		batchSize, total, perIter, PerIterBudget, 100*float64(perIter)/float64(PerIterBudget))

	// 防回归阈值：单次不得超过预算的一半
	if perIter > PerIterBudget/2 {
		t.Fatalf("per-counter cost is %d steps, more than half the per-iteration budget %d; headroom is too thin",
			perIter, PerIterBudget)
	}
}

// TestPoWProgramIsDeterministic 反向：同一输入必须给出同一结果。
func TestPoWProgramIsDeterministic(t *testing.T) {
	prog := powProgramHex(t)
	const nonce = "0123456789abcdef"
	const difficulty = 3
	const batchSize = 256

	first := runPoW(t, prog, nonce, 500, difficulty, batchSize)
	for i := 0; i < 3; i++ {
		got := runPoW(t, prog, nonce, 500, difficulty, batchSize)
		if got.Found != first.Found || got.Counter != first.Counter || !bytes.Equal(got.Hash, first.Hash) {
			t.Fatalf("non-deterministic result: %+v vs %+v", got, first)
		}
	}
}

// TestPoWProgramRejectsOversizedInput 反向：超出布局上限的输入必须被拒绝
// （R0 = 0），且不得 panic、不得越界读。
func TestPoWProgramRejectsOversizedInput(t *testing.T) {
	prog := powProgramHex(t)
	raw, err := Unhex(prog)
	if err != nil {
		t.Fatalf("Unhex: %v", err)
	}

	run := func(mutate func([]byte)) powRunResult {
		t.Helper()
		m, err := NewRefMachine(raw)
		if err != nil {
			t.Fatalf("NewRefMachine: %v", err)
		}
		blob := powBlob("short", 0, 3, 64)
		mutate(blob)
		if err := m.WriteInput(blob); err != nil {
			t.Fatalf("WriteInput: %v", err)
		}
		r0, err := m.Run(0)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		out := m.mem[OutBase : OutBase+BlobOutLen]
		return powRunResult{Found: r0, Hash: append([]byte(nil), out[:32]...),
			Counter: binary.LittleEndian.Uint64(out[BlobOutCounterOff:])}
	}

	// nonce_len 超限
	got := run(func(b []byte) { binary.LittleEndian.PutUint64(b[BlobNonceLenOff:], BlobNonceMax+1) })
	if got.Found != 0 {
		t.Fatalf("oversized nonce_len: R0 = %d, want 0", got.Found)
	}
	// difficulty 超限
	got = run(func(b []byte) { binary.LittleEndian.PutUint64(b[BlobDifficultyOff:], 65) })
	if got.Found != 0 {
		t.Fatalf("oversized difficulty: R0 = %d, want 0", got.Found)
	}
	// batch_size = 0 → 空批，必须直接判未命中
	got = run(func(b []byte) { binary.LittleEndian.PutUint64(b[BlobBatchSizeOff:], 0) })
	if got.Found != 0 {
		t.Fatalf("empty batch: R0 = %d, want 0", got.Found)
	}
	// 正向对照：正常输入必须跑完不报错
	_ = run(func([]byte) {})
}

// TestPoWProgramHexIsStable 锁定程序的关键结构，防止有人无意中改动程序
// 或 ISA 而契约测试察觉不到。
func TestPoWProgramHexIsStable(t *testing.T) {
	got := powProgramHex(t)
	raw, err := Unhex(got)
	if err != nil {
		t.Fatalf("Unhex: %v", err)
	}
	if len(raw) > MaxCodeBytes {
		t.Fatalf("program is %d bytes, limit %d", len(raw), MaxCodeBytes)
	}

	// 三处 SHA256_COMPRESS：单块路径 1 条 + 双块路径 2 条
	count := 0
	for _, b := range raw[HeaderLen:] {
		if b == OpSha256Compress {
			count++
		}
	}
	if count != 3 {
		t.Fatalf("program contains %d SHA256_COMPRESS instructions, want 3 (one on the single-block path, two on the double-block path)", count)
	}
	if !bytes.Contains([]byte(got), []byte(fmt.Sprintf("%02x", OpHalt))) {
		t.Fatal("program hex does not contain HALT")
	}
	rep, err := Verify(raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.OK() {
		t.Fatalf("program must be structurally valid: %+v", rep.Errors)
	}
	if rep.Instrs < 100 {
		t.Fatalf("program has only %d instructions; a real SHA-256 implementation needs more", rep.Instrs)
	}

	// 头部声明的长度必须与布局常量一致（宿主据此断言写入量）
	if rep.Layout.InLen != BlobMaxLen {
		t.Fatalf("header in_len = %d, want BlobMaxLen = %d", rep.Layout.InLen, BlobMaxLen)
	}
	if rep.Layout.OutLen != BlobOutLen {
		t.Fatalf("header out_len = %d, want BlobOutLen = %d", rep.Layout.OutLen, BlobOutLen)
	}
}

// TestPoWLayoutConstantsAreCoherent 锁定布局常量自身的推导关系。
func TestPoWLayoutConstantsAreCoherent(t *testing.T) {
	if BlobMaxLen != BlobNonceOff+BlobNonceMax {
		t.Fatalf("BlobMaxLen = %d, want NonceOff + NonceMax = %d", BlobMaxLen, BlobNonceOff+BlobNonceMax)
	}
	if BlobMaxLen > MaxInBytes {
		t.Fatalf("BlobMaxLen = %d exceeds MAX_IN_BYTES = %d", BlobMaxLen, MaxInBytes)
	}
	if BlobOutLen > MaxOutBytes {
		t.Fatalf("BlobOutLen = %d exceeds MAX_OUT_BYTES = %d", BlobOutLen, MaxOutBytes)
	}
	if BlobOutCounterOff+8 != BlobOutLen {
		t.Fatalf("output layout is not tight: counter off %d + 8 != len %d", BlobOutCounterOff, BlobOutLen)
	}
	if BlobOutHashOff != 0 || BlobOutMagicOff != 32 || BlobOutCounterOff != 40 {
		t.Fatalf("output field offsets drifted: hash=%d magic=%d counter=%d, want 0/32/40",
			BlobOutHashOff, BlobOutMagicOff, BlobOutCounterOff)
	}
	if BlobOutLen != 48 {
		t.Fatalf("BlobOutLen = %d, want 48 (32 hash + 8 magic + 8 counter)", BlobOutLen)
	}
	l := PoWProgramLayout()
	if l.InLen != BlobMaxLen {
		t.Fatalf("PoWProgramLayout().InLen = %d, want %d", l.InLen, BlobMaxLen)
	}
	if l.OutLen != BlobOutLen {
		t.Fatalf("PoWProgramLayout().OutLen = %d, want %d", l.OutLen, BlobOutLen)
	}
}

// TestPoWProgramHandlesDigitLengthTransitions 反向：十进制位数变化
// （9→10、99→100、999→1000）是「残留字节」缺陷的高发点。
//
// 初版程序没有清零脏区，实测从 counter=1140 起开始出错 —— 本用例就是
// 那个缺陷的回归锁：批必须跨越位数边界。
func TestPoWProgramHandlesDigitLengthTransitions(t *testing.T) {
	prog := powProgramHex(t)
	const nonce = "deadbeefcafebabe0011223344556677"
	const difficulty = 2
	const batchSize = 2048

	// 起点选在 4 位数区间之前，让批内跨过 999→1000
	const start = uint64(900)
	got := runPoW(t, prog, nonce, start, difficulty, batchSize)
	sol, ok := powInBatch(nonce, start, batchSize, difficulty)
	wantFound := uint64(0)
	if ok {
		wantFound = 1
	}
	if got.Found != wantFound {
		t.Fatalf("batch [%d,%d): R0 = %d, want %d", start, start+batchSize, got.Found, wantFound)
	}
	if ok {
		if got.Counter != sol {
			t.Fatalf("reported counter %d, want %d", got.Counter, sol)
		}
		if h := goPoWHash(nonce, sol); !bytes.Equal(got.Hash, h[:]) {
			t.Fatalf("hash mismatch at counter=%d:\ngot  %x\nwant %x", sol, got.Hash, h[:])
		}
		t.Logf("solution at counter=%d (%d digits) found across the digit-length transition", sol, len(strconv.FormatUint(sol, 10)))
	}
}

// 确保 hex 导入被使用（错误信息里打印 hex）。
var _ = hex.EncodeToString
