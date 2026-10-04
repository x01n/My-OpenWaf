package vmpasm

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// 本文件的用例同时包含**正向**（合法程序被正确编码/解码）与**反向**
// （非法程序被拒绝、被篡改的字节被识破）断言。

// layout1p 是单页内存的最小布局。
func layout1p() Layout { return Layout{Pages: 1} }

// buildContainerFor 直接构造容器字节，用于制造"手工字节码"——这是反向
// 用例唯一能绕开汇编器自身校验的路径。
func buildContainerFor(layout Layout, code []byte) []byte {
	return buildContainer(layout, code)
}

// 正向：编码

func TestAssembleEncodesMinimalProgram(t *testing.T) {
	prog := []Instr{{Op: OpHalt}}
	got, err := Assemble(layout1p(), prog)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(got) != HeaderLen+1 {
		t.Fatalf("program length = %d, want %d", len(got), HeaderLen+1)
	}
	if !bytes.Equal(got[0:4], Magic[:]) {
		t.Fatalf("magic = %x, want %x", got[0:4], Magic)
	}
	if got[4] != Version {
		t.Fatalf("version = 0x%02x, want 0x%02x", got[4], Version)
	}
	if got[5] != 0 || got[6] != 0 || got[7] != 0 {
		t.Fatalf("flags/reserved must be zero, got %x", got[5:8])
	}
	if got[HeaderLen] != OpHalt {
		t.Fatalf("code = %x, want [%02x]", got[HeaderLen:], OpHalt)
	}
}

func TestAssembleEncodesEveryFormat(t *testing.T) {
	prog := []Instr{
		{Op: OpNop},
		{Op: OpMovi, A: R3, Imm: 0x0102030405060708},
		{Op: OpMov, A: R1, B: R2},
		{Op: OpLoad64, A: R4, B: R5, Off: -8},
		{Op: OpStore32, A: R6, B: R7, Off: 16},
		{Op: OpAdd, A: R8, B: R9, C: R10},
		{Op: OpCmp, A: R11, B: R12},
		{Op: OpSha256Compress, A: R13, B: R14},
		{Op: OpHalt},
	}
	got, err := Assemble(layout1p(), prog)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	want := []byte{
		OpNop,
		OpMovi, 0x30, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
		OpMov, 0x12,
		OpLoad64, 0x45, 0xF8, 0xFF, 0xFF, 0xFF,
		OpStore32, 0x67, 0x10, 0x00, 0x00, 0x00,
		OpAdd, 0x89, 0xA0,
		OpCmp, 0xBC,
		OpSha256Compress, 0xDE,
		OpHalt,
	}
	if !bytes.Equal(got[HeaderLen:], want) {
		t.Fatalf("code mismatch:\ngot  %x\nwant %x", got[HeaderLen:], want)
	}
}

func TestAssembleResolvesForwardAndBackwardLabels(t *testing.T) {
	// 循环：MOVI r1,0 / loop: ADD r1,r1,r1 / CMP r1,r2 / JLT loop / HALT
	prog := []Instr{
		{Op: OpMovi, A: R1},
		Label("loop"),
		{Op: OpAdd, A: R1, B: R1, C: R1},
		{Op: OpCmp, A: R1, B: R2},
		{Op: OpJlt, Target: "loop"},
		{Op: OpJmp, Target: "end"},
		{Op: OpMovi, A: R9, Imm: 0xFF}, // 被跳过
		Label("end"),
		{Op: OpHalt},
	}
	got, err := Assemble(layout1p(), prog)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	code := got[HeaderLen:]
	// 布局：MOVI(10) 在 0，ADD(3) 在 10，CMP(2) 在 13，JLT(5) 在 15，JMP(5) 在 20，
	// 被跳过的 MOVI(10) 在 25，HALT(1) 在 35。
	jltPC := 15
	if code[jltPC] != OpJlt {
		t.Fatalf("expected JLT at pc=%d, got 0x%02x", jltPC, code[jltPC])
	}
	rel := int32(uint32(code[jltPC+1]) | uint32(code[jltPC+2])<<8 |
		uint32(code[jltPC+3])<<16 | uint32(code[jltPC+4])<<24)
	if want := int32(10 - (jltPC + 5)); rel != want {
		t.Fatalf("JLT rel = %d, want %d", rel, want)
	}
	jmpPC := jltPC + 5
	relJmp := int32(uint32(code[jmpPC+1]) | uint32(code[jmpPC+2])<<8 |
		uint32(code[jmpPC+3])<<16 | uint32(code[jmpPC+4])<<24)
	haltPC := jmpPC + 5 + 10 // 跳过 MOVI(10) 之后就是 HALT
	if got := jmpPC + 5 + int(relJmp); got != haltPC {
		t.Fatalf("JMP target = %d, want %d", got, haltPC)
	}
	if code[haltPC] != OpHalt {
		t.Fatalf("expected HALT at pc=%d, got 0x%02x", haltPC, code[haltPC])
	}
}

func TestAssembleRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		prog []Instr
	}{
		{"unknown opcode", []Instr{{Op: 0x7F}, {Op: OpHalt}}},
		{"register out of range", []Instr{{Op: OpMov, A: 16, B: R0}, {Op: OpHalt}}},
		{"undefined label", []Instr{{Op: OpJmp, Target: "nope"}, {Op: OpHalt}}},
		{"duplicate label", []Instr{Label("x"), Label("x"), {Op: OpHalt}}},
		{"empty label name", []Instr{Label(""), {Op: OpHalt}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Assemble(layout1p(), tc.prog); err == nil {
				t.Fatalf("Assemble accepted %s", tc.name)
			}
		})
	}
}

func TestAssembleRejectsBadLayout(t *testing.T) {
	prog := []Instr{{Op: OpHalt}}
	for _, l := range []Layout{
		{Pages: 0},
		{Pages: MaxPages + 1},
		{Pages: 1, InLen: MaxInBytes + 1},
		{Pages: 1, OutLen: MaxOutBytes + 1},
	} {
		if _, err := Assemble(l, prog); err == nil {
			t.Fatalf("Assemble accepted layout %+v", l)
		}
	}
}

// 正向/反向：解码往返

func TestDisassembleRoundTripsThroughParser(t *testing.T) {
	prog := []Instr{
		{Op: OpMovi, A: R1, Imm: 0xDEADBEEF},
		Label("top"),
		{Op: OpLoad8, A: R2, B: R1, Off: 4},
		{Op: OpStore8, A: R1, B: R2, Off: 8},
		{Op: OpXor, A: R3, B: R1, C: R2},
		{Op: OpCmp, A: R3, B: R1},
		{Op: OpJne, Target: "top"},
		{Op: OpSm4EncBlock, A: R1, B: R2},
		{Op: OpHalt},
	}
	raw, err := Assemble(Layout{Pages: 1, InLen: 16}, prog)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	text, err := Disassemble(raw)
	if err != nil {
		t.Fatalf("Disassemble: %v", err)
	}
	parsed, _, err := ParseText(text)
	if err != nil {
		t.Fatalf("ParseText: %v\n%s", err, text)
	}
	// 去掉 disasm 里的布局注释行带来的差异：直接比对重新汇编出的字节
	// 与再次反汇编出的文本（去掉首行注释）。
	raw2, err := Assemble(Layout{Pages: 1, InLen: 16}, parsed)
	if err != nil {
		t.Fatalf("Assemble(parsed): %v\n%s", err, text)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("disasm/asm round trip changed the encoding:\n%x\n%x", raw, raw2)
	}
}

// 反向：校验器必须拒绝缺陷形态

func TestVerifyRejectsUnreachableInstruction(t *testing.T) {
	// HALT; HALT —— 第二条不可达
	raw := buildContainerFor(layout1p(), []byte{OpHalt, OpHalt})
	rep, err := Verify(raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.OK() {
		t.Fatalf("Verify accepted an unreachable instruction: %+v", rep)
	}
	if !hasCode(rep.Errors, "unreachable") {
		t.Fatalf("expected unreachable error, got %+v", rep.Errors)
	}
}

func TestVerifyRejectsInfiniteLoop(t *testing.T) {
	// JMP 0 —— 到不了 HALT
	code := []byte{OpJmp, 0xFB, 0xFF, 0xFF, 0xFF}
	raw := buildContainerFor(layout1p(), code)
	rep, err := Verify(raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.OK() {
		t.Fatalf("Verify accepted a program with no path to HALT: %+v", rep)
	}
	if !hasCode(rep.Errors, "no_path_to_halt") {
		t.Fatalf("expected no_path_to_halt, got %+v", rep.Errors)
	}
}

func TestVerifyRejectsTamperedByte(t *testing.T) {
	base, err := Assemble(layout1p(), []Instr{{Op: OpMovi, A: R1, Imm: 7}, {Op: OpHalt}})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	// 正向：原程序干净
	rep, err := Verify(base)
	if err != nil {
		t.Fatalf("Verify(base): %v", err)
	}
	if !rep.Clean() {
		t.Fatalf("base program must be clean: %+v", rep)
	}

	// 反向：篡改 MOVI 的 opcode 为保留区 opcode
	tampered := append([]byte(nil), base...)
	tampered[HeaderLen] = 0x7F
	if _, err := Verify(tampered); err == nil {
		t.Fatal("Verify accepted a tampered opcode")
	}

	// 反向：篡改魔数
	tampered = append([]byte(nil), base...)
	tampered[1] ^= 0x01
	if _, err := Verify(tampered); err == nil {
		t.Fatal("Verify accepted a tampered magic")
	}

	// 反向：篡改 code_len
	tampered = append([]byte(nil), base...)
	tampered[20]++
	if _, err := Verify(tampered); err == nil {
		t.Fatal("Verify accepted a tampered code_len")
	}

	// 反向：篡改未用 nibble
	tampered = append([]byte(nil), base...)
	tampered[HeaderLen+1] |= 0x0F
	if _, err := Verify(tampered); err == nil {
		t.Fatal("Verify accepted a nonzero reserved nibble")
	}
}

func TestVerifyAcceptsRealisticLoopProgram(t *testing.T) {
	// 真实形态：计数器循环 + 原语调用，全部可达且能终止。
	prog := []Instr{
		{Op: OpMovi, A: R1, Imm: 8},       // 迭代次数
		{Op: OpMovi, A: R2, Imm: InBase},  // 输入基址
		{Op: OpMovi, A: R3, Imm: OutBase}, // 输出基址
		Label("loop"),
		{Op: OpSha256Compress, A: R3, B: R2},
		{Op: OpSub, A: R1, B: R1, C: R5}, // R5 未知 → R1 不可证为零
		{Op: OpCmp, A: R1, B: R6},        // 两个操作数都不可证为零
		{Op: OpJne, Target: "loop"},
		{Op: OpHalt},
	}
	raw, err := Assemble(Layout{Pages: 1, OutLen: 32}, prog)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	rep, err := Verify(raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.OK() {
		t.Fatalf("realistic program must be structurally valid: %+v", rep)
	}
	if !rep.Clean() {
		t.Fatalf("realistic loop must have no findings: %+v", rep.Findings)
	}
}

func TestVerifyFlagsProvablyZeroCompare(t *testing.T) {
	// SUB R1, R1, R1 → R1 恒为零；随后的 CMP R1, R1 是恒真比较。
	// 该程序控制流合法（有 HALT 可达），只有数据流分析能发现。
	prog := []Instr{
		{Op: OpSub, A: R1, B: R1, C: R1},
		{Op: OpCmp, A: R1, B: R1},
		{Op: OpHalt},
	}
	raw, err := Assemble(layout1p(), prog)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	rep, err := Verify(raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.OK() {
		t.Fatalf("program is structurally valid: %+v", rep.Errors)
	}
	if !hasCode(rep.Findings, "zero_constant_compare") {
		t.Fatalf("expected zero_constant_compare finding, got %+v", rep.Findings)
	}
}

func TestVerifyDoesNotFlagZeroCompareAcrossBranchMerge(t *testing.T) {
	// 分支合流：只有一条路径把 R1 置零，合流点的 CMP R1,R2 不应被报为零常量比较。
	prog := []Instr{
		{Op: OpMov, A: R1, B: R2}, // R1 未知
		{Op: OpCmp, A: R3, B: R4},
		{Op: OpJeq, Target: "skip"},
		{Op: OpMovi, A: R1, Imm: 0}, // 只有这条路径置零
		Label("skip"),
		{Op: OpCmp, A: R1, B: R2}, // 合流点：R1 不必然为零
		{Op: OpHalt},
	}
	raw, err := Assemble(layout1p(), prog)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	findings, err := Inspect(raw)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if hasCode(findings, "zero_constant_compare") {
		t.Fatalf("false positive across branch merge: %+v", findings)
	}
}

// 反向：opcode 表镜像

func TestOpcodeTableIsCompleteAndUnique(t *testing.T) {
	if len(OpcodeTable) != 35 {
		t.Fatalf("OpcodeTable has %d entries, want 35", len(OpcodeTable))
	}
	seen := make(map[byte]string, len(OpcodeTable))
	for name, op := range OpcodeTable {
		if prev, dup := seen[op]; dup {
			t.Fatalf("opcode 0x%02X claimed by both %s and %s", op, prev, name)
		}
		seen[op] = name
	}
	for i := byte(0); i <= 0x22; i++ {
		if _, ok := seen[i]; !ok {
			t.Fatalf("opcode 0x%02X is unassigned; the ISA reserves 0x23..0xFF", i)
		}
	}
	for i := byte(0x23); i != 0; i++ {
		if _, ok := seen[i]; ok {
			t.Fatalf("opcode 0x%02X must be reserved", i)
		}
	}
}

func TestGoNameForRustConstMatchesTable(t *testing.T) {
	for name := range OpcodeTable {
		rust := "OP_" + mnemonicForTest(name)
		if got := GoNameForRustConst(rust); got != name {
			t.Fatalf("GoNameForRustConst(%q) = %q, want %q", rust, got, name)
		}
	}
	if got := GoNameForRustConst("OP_"); got != "" {
		t.Fatalf("GoNameForRustConst(\"OP_\") = %q, want empty", got)
	}
	if got := GoNameForRustConst("NOPE"); got != "" {
		t.Fatalf("GoNameForRustConst(\"NOPE\") = %q, want empty", got)
	}
}

// mnemonicForTest 返回 Go 常量名对应的 Rust 助记符（`OpSm3Compress` → `SM3_COMPRESS`）。
func mnemonicForTest(goName string) string {
	return rustMnemonic(goName)
}

func TestHexRoundTrip(t *testing.T) {
	raw, err := Assemble(layout1p(), []Instr{{Op: OpHalt}})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	h := Hex(raw)
	if _, err := hex.DecodeString(h); err != nil {
		t.Fatalf("Hex produced undecodable output %q: %v", h, err)
	}
	back, err := Unhex(h)
	if err != nil {
		t.Fatalf("Unhex: %v", err)
	}
	if !bytes.Equal(back, raw) {
		t.Fatalf("hex round trip changed bytes")
	}
	// 反向：奇数长度与非 hex 字符必须被拒绝
	if _, err := Unhex("abc"); err == nil {
		t.Fatal("Unhex accepted odd-length input")
	}
	if _, err := Unhex("zz"); err == nil {
		t.Fatal("Unhex accepted non-hex input")
	}
}

func TestInstructionTextIsParseable(t *testing.T) {
	// 每条格式的文本形态都必须能被 ParseText 解析回来（同 opcode 与操作数）。
	instrs := []Instr{
		{Op: OpNop},
		{Op: OpHalt},
		{Op: OpMovi, A: R3, Imm: 0xAB},
		{Op: OpMov, A: R1, B: R2},
		{Op: OpLoad16, A: R4, B: R5, Off: -2},
		{Op: OpStore64, A: R6, B: R7, Off: 32},
		{Op: OpShl, A: R8, B: R9, C: R10},
		{Op: OpCmp, A: R11, B: R12},
		{Op: OpSm3Compress, A: R13, B: R14},
	}
	for _, in := range instrs {
		text := in.Text()
		got, err := parseTextInstr(text)
		if err != nil {
			t.Fatalf("parseTextInstr(%q): %v", text, err)
		}
		if got.Op != in.Op || got.A != in.A || got.B != in.B || got.C != in.C ||
			got.Imm != in.Imm || got.Off != in.Off {
			t.Fatalf("round trip changed instruction %q: %+v vs %+v", text, got, in)
		}
	}
}

func TestDisassembleRejectsMalformedContainer(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"short", []byte{0x4F}},
		{"bad magic", append([]byte{0x00, 0x00, 0x00, 0x00}, make([]byte, 21)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Disassemble(tc.raw); err == nil {
				t.Fatalf("Disassemble accepted %s", tc.name)
			}
		})
	}
}

func TestDisassembleMarksJumpTargets(t *testing.T) {
	prog := []Instr{
		Label("top"),
		{Op: OpJmp, Target: "top"},
		{Op: OpHalt},
	}
	raw, err := Assemble(layout1p(), prog)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	text, err := Disassemble(raw)
	if err != nil {
		t.Fatalf("Disassemble: %v", err)
	}
	if !strings.Contains(text, "L0000:") {
		t.Fatalf("disassembly does not emit a label line:\n%s", text)
	}
	if !strings.Contains(text, "JMP L0000") {
		t.Fatalf("disassembly does not render the jump target:\n%s", text)
	}
}

func hasCode(findings []Finding, code string) bool {
	for _, f := range findings {
		if f.Code == code {
			return true
		}
	}
	return false
}
