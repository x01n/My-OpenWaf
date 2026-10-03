package vmpasm

import "fmt"

// Instr 是一条待编码或已解码的指令。
//
// 各字段按指令类别使用：
//   - 无操作数指令只用 Op
//   - 含一个寄存器操作数的指令用 A
//   - 含两个寄存器操作数的指令用 A、B
//   - 含三个寄存器操作数的指令用 A、B、C
//   - 含立即数的指令用 A（寄存器）与 Imm
//   - 含跳转偏移的指令用 Target，汇编期由 Label 解析填入
type Instr struct {
	// Op 是 opcode 常量。
	Op byte
	// A 是第一个寄存器操作数（0..15）。
	A Reg
	// B 是第二个寄存器操作数（0..15）。
	B Reg
	// C 是第三个寄存器操作数（0..15）。
	C Reg
	// Imm 是 64 位立即数（大端序无关，编码为小端）。
	Imm uint64
	// Off 是内存操作的 32 位有符号偏移。
	Off int32
	// Target 是跳转目标标签。汇编期解析成相对偏移后写入 Imm。
	Target string
}

// Text 返回指令的汇编文本形态，用于反汇编与测试可读性。
//
// 输出是**规范性**的：同一条指令的文本形态唯一，且能被 ParseText 重新解析，
// 再被 Assemble 汇编回逐字节相同的编码（往返闭合，见 vmpasm_test.go）。
func (in Instr) Text() string {
	switch in.Op {
	case OpNop:
		return "NOP"
	case OpHalt:
		return "HALT"
	case OpMovi:
		return fmt.Sprintf("MOVI %s, 0x%X", regName(in.A), in.Imm)
	case OpMov:
		return fmt.Sprintf("MOV %s, %s", regName(in.A), regName(in.B))
	case OpLoad8, OpLoad16, OpLoad32, OpLoad64:
		return fmt.Sprintf("%s %s, [%s%+d]", mnemonicOf(in.Op), regName(in.A), regName(in.B), in.Off)
	case OpStore8, OpStore16, OpStore32, OpStore64:
		return fmt.Sprintf("%s [%s%+d], %s", mnemonicOf(in.Op), regName(in.A), in.Off, regName(in.B))
	case OpAdd, OpSub, OpMul, OpDivu, OpModu, OpAnd, OpOr, OpXor, OpShl, OpShr, OpSar:
		return fmt.Sprintf("%s %s, %s, %s", mnemonicOf(in.Op), regName(in.A), regName(in.B), regName(in.C))
	case OpCmp:
		return fmt.Sprintf("CMP %s, %s", regName(in.A), regName(in.B))
	case OpJmp, OpJeq, OpJne, OpJlt, OpJle, OpJgt, OpJge:
		if in.Target != "" {
			return fmt.Sprintf("%s %s", mnemonicOf(in.Op), in.Target)
		}
		return fmt.Sprintf("%s .%d", mnemonicOf(in.Op), int32(in.Imm))
	case OpSha256Compress, OpSm3Compress, OpSm4EncBlock, OpSm4DecBlock:
		return fmt.Sprintf("%s %s, %s", mnemonicOf(in.Op), regName(in.A), regName(in.B))
	default:
		return fmt.Sprintf("DB 0x%02X", in.Op)
	}
}

// mnemonicOf 返回 opcode 的助记符，未知 opcode 返回 "???"。
//
// 助记符与 wasm-pow-solver/src/isa.rs 的常量名去前缀形态一致
// （`OP_SHA256_COMPRESS` → `SHA256_COMPRESS`），便于对照两侧的调试输出。
func mnemonicOf(op byte) string {
	if name, ok := goNames[op]; ok {
		return rustMnemonic(name)
	}
	return "???"
}

// rustMnemonic 把本包的标识符名转成 isa.rs 常量名的助记符部分。
//
// `OpSha256Compress` → `SHA256_COMPRESS`。
// 规则：去掉 `Op` 前缀后，在大写字母前插入下划线（仅当其前一字符是小写字母
// 或数字），再把所有小写字母转大写。
func rustMnemonic(goName string) string {
	const prefix = "Op"
	if len(goName) <= len(prefix) || goName[:len(prefix)] != prefix {
		return goName
	}
	s := goName[len(prefix):]
	out := make([]byte, 0, len(s)+4)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' && i > 0 {
			prev := s[i-1]
			if (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9') {
				out = append(out, '_')
			}
		}
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}

// classify 返回指令的编码格式，供编码与解码共用。
type format uint8

const (
	fmtNone format = iota // op
	fmtR                  // op + regs[A:B]
	fmtRR                 // op + regs[A:B] + regs[C:0]
	fmtRI64               // op + regs[A:0] + imm64
	fmtRI32               // op + regs[A:B] + off32
	fmtJ                  // op + rel32
)

// formatOf 返回 opcode 的编码格式。
func formatOf(op byte) (format, bool) {
	switch op {
	case OpNop, OpHalt:
		return fmtNone, true
	case OpMov, OpCmp, OpSha256Compress, OpSm3Compress, OpSm4EncBlock, OpSm4DecBlock:
		return fmtR, true
	case OpAdd, OpSub, OpMul, OpDivu, OpModu, OpAnd, OpOr, OpXor, OpShl, OpShr, OpSar:
		return fmtRR, true
	case OpMovi:
		return fmtRI64, true
	case OpLoad8, OpLoad16, OpLoad32, OpLoad64, OpStore8, OpStore16, OpStore32, OpStore64:
		return fmtRI32, true
	case OpJmp, OpJeq, OpJne, OpJlt, OpJle, OpJgt, OpJge:
		return fmtJ, true
	default:
		return 0, false
	}
}

// lenOfFormat 返回格式的编码长度（跳转指令的 rel32 与 LOAD/STORE 的 off32 不参与）。
func lenOfFormat(f format) int {
	switch f {
	case fmtNone:
		return 1
	case fmtR:
		return 2
	case fmtRR:
		return 3
	case fmtRI64:
		return 10
	case fmtRI32:
		return 6
	case fmtJ:
		return 5
	default:
		return 0
	}
}
