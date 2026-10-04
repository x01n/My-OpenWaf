package vmpasm

import (
	"fmt"
	"strconv"
	"strings"
)

/**
 * Disassemble 把程序容器反汇编成文本，每行形如：
 *
 * 0000  01 30 08 07 06 05 04 03 02 01   MOVI R3, 0x102030405060708
 * 000A  17 FB FF FF FF                  JMP 0000
 *
 * 第一列是字节码段内的偏移，第二列是原始编码字节，第三列是指令文本。
 * 跳转指令的第三种形态回显目标偏移（`JMP 0000`）而不是相对量，
 * 便于与汇编器的标签对照。
 *
 * 反汇编是**规范性**的：对同一份字节码，输出唯一；且 Asm 能把它汇编回
 * 逐字节相同的编码（见 vmpasm_test.go 的往返用例）。
 */
func Disassemble(program []byte) (string, error) {
	dec, layout, err := decodeContainer(program)
	if err != nil {
		return "", err
	}
	code := program[HeaderLen:]

	var b strings.Builder
	fmt.Fprintf(&b, "; layout pages=%d in_len=%d out_len=%d code_len=%d\n",
		layout.Pages, layout.InLen, layout.OutLen, len(code))

	// 先标出跳转目标，便于阅读时定位标签。
	// 注意键是**指令下标**（decoded.dest 的语义），不是字节偏移。
	targets := make(map[int]bool)
	for _, d := range dec {
		if d.dest >= 0 {
			targets[d.dest] = true
		}
	}

	for i, d := range dec {
		if targets[i] {
			fmt.Fprintf(&b, "L%04X:\n", d.pc)
		}
		raw := code[d.pc : d.pc+d.len]
		in := d.in
		if d.dest >= 0 {
			in.Imm = uint64(int64(dec[d.dest].pc))
		}
		fmt.Fprintf(&b, "%04X  %-*s  %s\n", d.pc, maxRawWidth, hexBytes(raw), disasmText(in, d))
	}
	return b.String(), nil
}

// maxRawWidth 是原始字节列的固定宽度（8 字节指令的 hex 形态 + 空格）。
const maxRawWidth = 23

func hexBytes(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, " ")
}

/**
 * disasmText 渲染指令文本；跳转指令回显目标偏移（`JNE L000A`），
 * 使输出能被 ParseText 重新解析。
 */
func disasmText(in Instr, d decoded) string {
	if d.dest >= 0 {
		return fmt.Sprintf("%s L%04X", rustMnemonic(nameOf(in.Op)), int(in.Imm))
	}
	switch in.Op {
	case OpMovi:
		return fmt.Sprintf("MOVI %s, 0x%X", regName(in.A), in.Imm)
	case OpMov:
		return fmt.Sprintf("MOV %s, %s", regName(in.A), regName(in.B))
	case OpLoad8, OpLoad16, OpLoad32, OpLoad64:
		return fmt.Sprintf("%s %s, [%s%+d]", rustMnemonic(nameOf(in.Op)), regName(in.A), regName(in.B), in.Off)
	case OpStore8, OpStore16, OpStore32, OpStore64:
		return fmt.Sprintf("%s [%s%+d], %s", rustMnemonic(nameOf(in.Op)), regName(in.A), in.Off, regName(in.B))
	case OpAdd, OpSub, OpMul, OpDivu, OpModu, OpAnd, OpOr, OpXor, OpShl, OpShr, OpSar:
		return fmt.Sprintf("%s %s, %s, %s", rustMnemonic(nameOf(in.Op)), regName(in.A), regName(in.B), regName(in.C))
	case OpCmp:
		return fmt.Sprintf("CMP %s, %s", regName(in.A), regName(in.B))
	case OpSha256Compress, OpSm3Compress, OpSm4EncBlock, OpSm4DecBlock:
		return fmt.Sprintf("%s %s, %s", rustMnemonic(nameOf(in.Op)), regName(in.A), regName(in.B))
	default:
		return rustMnemonic(nameOf(in.Op))
	}
}

// nameOf 返回 opcode 对应的本包常量名，未知返回空串。
func nameOf(op byte) string {
	if n, ok := goNames[op]; ok {
		return n
	}
	return ""
}

// goNames 是 opcode 到本包常量名的查表。
var goNames = func() map[byte]string {
	out := make(map[byte]string, len(OpcodeTable))
	for name, op := range OpcodeTable {
		out[op] = name
	}
	return out
}()

/**
 * ParseText 解析 Disassemble 的输出（忽略注释行、空行与标签行），
 * 返回可交给 Assemble 的指令序列。
 *
 * 支持的文本形态与 disasmText 的输出一致，另外接受 `Lxxxx:` 标签行，
 * 使反汇编输出可以被重新汇编（往返闭合）。
 */
func ParseText(text string) ([]Instr, map[int]string, error) {
	var (
		prog   []Instr
		labels = make(map[int]string)
	)
	for lineNo, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasSuffix(line, ":") {
			name := strings.TrimSuffix(line, ":")
			labels[len(prog)] = name
			prog = append(prog, Label(name))
			continue
		}
		in, err := parseTextInstr(line)
		if err != nil {
			return nil, nil, fmt.Errorf("vmpasm: line %d: %w", lineNo+1, err)
		}
		prog = append(prog, in)
	}
	return prog, labels, nil
}

/**
 * parseTextInstr 解析单行指令文本，形如 `MOVI R3, 0x10` 或 `JMP L0000`。
 *
 * 只接受助记符（与 disasmText 输出一致），不接受十六进制字节列。
 */
func parseTextInstr(line string) (Instr, error) {
	// 去掉 disasm 输出里的原始字节列（形如 "01 30 08 ..."）
	fields := strings.Fields(line)
	mnemonic := ""
	rest := ""
	for i, f := range fields {
		if isMnemonic(f) {
			mnemonic = f
			rest = strings.Join(fields[i+1:], " ")
			break
		}
	}
	if mnemonic == "" {
		return Instr{}, fmt.Errorf("no mnemonic in %q", line)
	}
	op, ok := opcodeByMnemonic(mnemonic)
	if !ok {
		return Instr{}, fmt.Errorf("unknown mnemonic %q", mnemonic)
	}
	in := Instr{Op: op}
	args := splitArgs(rest)

	switch op {
	case OpNop, OpHalt:
		return in, nil

	case OpMovi:
		if len(args) != 2 {
			return Instr{}, fmt.Errorf("%s wants 2 operands, got %d", mnemonic, len(args))
		}
		r, err := parseReg(args[0])
		if err != nil {
			return Instr{}, err
		}
		v, err := strconv.ParseUint(strings.TrimPrefix(args[1], "0x"), 16, 64)
		if err != nil {
			return Instr{}, fmt.Errorf("bad immediate %q", args[1])
		}
		in.A, in.Imm = r, v

	case OpMov, OpCmp, OpSha256Compress, OpSm3Compress, OpSm4EncBlock, OpSm4DecBlock:
		if len(args) != 2 {
			return Instr{}, fmt.Errorf("%s wants 2 operands, got %d", mnemonic, len(args))
		}
		a, err := parseReg(args[0])
		if err != nil {
			return Instr{}, err
		}
		b, err := parseReg(args[1])
		if err != nil {
			return Instr{}, err
		}
		in.A, in.B = a, b

	case OpAdd, OpSub, OpMul, OpDivu, OpModu, OpAnd, OpOr, OpXor, OpShl, OpShr, OpSar:
		if len(args) != 3 {
			return Instr{}, fmt.Errorf("%s wants 3 operands, got %d", mnemonic, len(args))
		}
		a, err := parseReg(args[0])
		if err != nil {
			return Instr{}, err
		}
		b, err := parseReg(args[1])
		if err != nil {
			return Instr{}, err
		}
		c, err := parseReg(args[2])
		if err != nil {
			return Instr{}, err
		}
		in.A, in.B, in.C = a, b, c

	case OpLoad8, OpLoad16, OpLoad32, OpLoad64, OpStore8, OpStore16, OpStore32, OpStore64:
		return parseMemInstr(in, args, mnemonic)

	case OpJmp, OpJeq, OpJne, OpJlt, OpJle, OpJgt, OpJge:
		if len(args) != 1 {
			return Instr{}, fmt.Errorf("%s wants 1 operand, got %d", mnemonic, len(args))
		}
		target := args[0]
		if strings.HasPrefix(target, "L") {
			in.Target = target
			return in, nil
		}
		rel, err := strconv.ParseInt(strings.TrimPrefix(target, "."), 10, 32)
		if err != nil {
			return Instr{}, fmt.Errorf("bad jump target %q", target)
		}
		in.Imm = uint64(int64(rel))
		return in, nil

	default:
		return Instr{}, fmt.Errorf("unhandled mnemonic %q", mnemonic)
	}
	return in, nil
}

/**
 * parseMemInstr 解析 LOAD/STORE 的两种书写方向：
 *
 * LOAD64 R4, [R5-8]       ; 目标在前
 * STORE64 [R5-8], R4      ; 地址在前
 */
func parseMemInstr(in Instr, args []string, mnemonic string) (Instr, error) {
	if len(args) != 2 {
		return Instr{}, fmt.Errorf("%s wants 2 operands, got %d", mnemonic, len(args))
	}
	isLoad := strings.HasPrefix(mnemonic, "LOAD")
	memArg, regArg := "", ""
	if isLoad {
		regArg, memArg = args[0], args[1]
	} else {
		memArg, regArg = args[0], args[1]
	}
	r, err := parseReg(regArg)
	if err != nil {
		return Instr{}, err
	}
	base, off, err := parseMemOperand(memArg)
	if err != nil {
		return Instr{}, err
	}
	if isLoad {
		in.A, in.B = r, base
	} else {
		in.A, in.B = base, r
	}
	in.Off = off
	return in, nil
}

// parseMemOperand 解析 `[R5-8]` 形态的内存操作数。
func parseMemOperand(s string) (Reg, int32, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		return 0, 0, fmt.Errorf("bad memory operand %q", s)
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	inner = strings.ReplaceAll(inner, " ", "")
	// 找寄存器号之后的第一个 +/-（寄存器名形如 R12）
	i := 1
	for i < len(inner) && inner[i] >= '0' && inner[i] <= '9' {
		i++
	}
	regPart := inner[:i]
	if len(inner) == i {
		r, err := parseReg(regPart)
		return r, 0, err
	}
	r, err := parseReg(regPart)
	if err != nil {
		return 0, 0, err
	}
	off, err := strconv.ParseInt(inner[i:], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("bad memory offset in %q", s)
	}
	return r, int32(off), nil
}

func parseReg(s string) (Reg, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "R") {
		return 0, fmt.Errorf("bad register %q", s)
	}
	n, err := strconv.Atoi(s[1:])
	if err != nil || n < 0 || n >= RegCount {
		return 0, fmt.Errorf("register %q out of range 0..%d", s, RegCount-1)
	}
	return Reg(n), nil
}

func splitArgs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

func isMnemonic(s string) bool {
	_, ok := opcodeByMnemonic(s)
	return ok
}

func opcodeByMnemonic(m string) (byte, bool) {
	for name, op := range OpcodeTable {
		if rustMnemonic(name) == m {
			return op, true
		}
	}
	return 0, false
}
