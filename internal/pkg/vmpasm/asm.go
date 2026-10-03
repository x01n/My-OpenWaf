package vmpasm

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
)

// Assemble 把带标签的指令序列汇编成完整程序容器（头部 + 字节码）。
//
// 标签以 `Label` 指令在指令流中声明，跳转指令的 Target 引用标签名。
// 标签可以前向引用（跳转目标在声明之前）。
//
// 任何编码错误（未知 opcode、寄存器越界、标签未定义/重复、指令被截断）
// 都返回 error，不会产出部分结果。
func Assemble(layout Layout, prog []Instr) ([]byte, error) {
	if err := validateLayout(layout); err != nil {
		return nil, err
	}

	// 第一遍：分配各指令的偏移，收集标签。
	offsets := make([]int, len(prog))
	labels := make(map[string]int)
	pc := 0
	for i, in := range prog {
		if in.Op == opLabel {
			name := in.Target
			if name == "" {
				return nil, fmt.Errorf("vmpasm: Label at index %d has empty name", i)
			}
			if _, dup := labels[name]; dup {
				return nil, fmt.Errorf("vmpasm: duplicate label %q", name)
			}
			labels[name] = pc
			offsets[i] = pc
			continue
		}
		if _, ok := formatOf(in.Op); !ok {
			return nil, fmt.Errorf("vmpasm: unknown opcode 0x%02x at index %d", in.Op, i)
		}
		offsets[i] = pc
		pc += encodedLen(in)
	}

	if pc > MaxCodeBytes {
		return nil, fmt.Errorf("vmpasm: code is %d bytes, limit is %d", pc, MaxCodeBytes)
	}

	// 第二遍：编码。
	code := make([]byte, 0, pc)
	for i, in := range prog {
		if in.Op == opLabel {
			continue
		}
		if err := checkRegs(in); err != nil {
			return nil, fmt.Errorf("vmpasm: instruction %d (%s): %w", i, in.Text(), err)
		}
		encoded, err := encodeInstr(in, offsets[i], labels)
		if err != nil {
			return nil, fmt.Errorf("vmpasm: instruction %d (%s): %w", i, in.Text(), err)
		}
		code = append(code, encoded...)
	}

	return buildContainer(layout, code), nil
}

// opLabel 是伪 opcode，只在本包的指令流里有效，不进入字节码。
const opLabel byte = 0xFF

// Label 声明一个汇编期标签，编码时不产出任何字节。
func Label(name string) Instr {
	return Instr{Op: opLabel, Target: name}
}

// encodedLen 返回指令的编码长度。跳转类指令固定 5 字节（rel32 不压缩）。
func encodedLen(in Instr) int {
	f, ok := formatOf(in.Op)
	if !ok {
		return 0
	}
	return lenOfFormat(f)
}

func validateLayout(layout Layout) error {
	if layout.Pages == 0 || layout.Pages > MaxPages {
		return fmt.Errorf("vmpasm: pages %d out of range 1..%d", layout.Pages, MaxPages)
	}
	if layout.InLen > MaxInBytes {
		return fmt.Errorf("vmpasm: in_len %d exceeds %d", layout.InLen, MaxInBytes)
	}
	if layout.OutLen > MaxOutBytes {
		return fmt.Errorf("vmpasm: out_len %d exceeds %d", layout.OutLen, MaxOutBytes)
	}
	if layout.InLen > 0 && uint64(layout.InLen) > layout.MemoryLen() {
		return fmt.Errorf("vmpasm: in_len %d exceeds memory %d", layout.InLen, layout.MemoryLen())
	}
	if uint64(OutBase+uint64(layout.OutLen)) > layout.MemoryLen() {
		return fmt.Errorf("vmpasm: output blob end exceeds memory %d", layout.MemoryLen())
	}
	return nil
}

func checkRegs(in Instr) error {
	f, ok := formatOf(in.Op)
	if !ok {
		return fmt.Errorf("unknown opcode 0x%02x", in.Op)
	}
	need := 0
	switch f {
	case fmtR:
		need = 2
	case fmtRR:
		need = 3
	case fmtRI64, fmtRI32:
		need = 2
	}
	regs := []struct {
		name string
		val  Reg
	}{{"A", in.A}, {"B", in.B}, {"C", in.C}}
	for i := 0; i < need; i++ {
		if regs[i].val > 15 {
			return fmt.Errorf("register %s = %d out of range 0..15", regs[i].name, regs[i].val)
		}
	}
	return nil
}

func encodeInstr(in Instr, pc int, labels map[string]int) ([]byte, error) {
	f, ok := formatOf(in.Op)
	if !ok {
		return nil, fmt.Errorf("unknown opcode 0x%02x", in.Op)
	}
	switch f {
	case fmtNone:
		return []byte{in.Op}, nil

	case fmtR:
		return []byte{in.Op, packRegs(in.A, in.B)}, nil

	case fmtRR:
		return []byte{in.Op, packRegs(in.A, in.B), packRegs(in.C, 0)}, nil

	case fmtRI64:
		out := make([]byte, 10)
		out[0] = in.Op
		out[1] = packRegs(in.A, 0)
		binary.LittleEndian.PutUint64(out[2:], in.Imm)
		return out, nil

	case fmtRI32:
		out := make([]byte, 6)
		out[0] = in.Op
		out[1] = packRegs(in.A, in.B)
		binary.LittleEndian.PutUint32(out[2:], uint32(in.Off))
		return out, nil

	case fmtJ:
		rel, err := resolveRel(in, pc, labels)
		if err != nil {
			return nil, err
		}
		out := make([]byte, 5)
		out[0] = in.Op
		binary.LittleEndian.PutUint32(out[1:], uint32(rel))
		return out, nil
	}
	return nil, fmt.Errorf("unhandled format")
}

// resolveRel 把一个跳转指令解析成相对下一条指令的 32 位有符号偏移。
//
// 目标是标签时用标签偏移；否则用 Imm 里已经算好的相对值（允许内联偏移）。
func resolveRel(in Instr, pc int, labels map[string]int) (int32, error) {
	next := pc + 5
	var target int64
	if in.Target != "" {
		off, ok := labels[in.Target]
		if !ok {
			return 0, fmt.Errorf("undefined label %q", in.Target)
		}
		target = int64(off)
	} else {
		target = int64(next) + int64(in.Imm)
	}
	rel := target - int64(next)
	if rel < math.MinInt32 || rel > math.MaxInt32 {
		return 0, fmt.Errorf("jump displacement %d out of int32 range", rel)
	}
	return int32(rel), nil
}

func packRegs(hi, lo Reg) byte {
	return byte(hi)<<4 | byte(lo)
}

func buildContainer(layout Layout, code []byte) []byte {
	out := make([]byte, 0, HeaderLen+len(code))
	out = append(out, Magic[:]...)
	out = append(out, Version)
	out = append(out, 0)    // flags
	out = append(out, 0, 0) // reserved
	out = binary.LittleEndian.AppendUint32(out, layout.Pages)
	out = binary.LittleEndian.AppendUint32(out, layout.InLen)
	out = binary.LittleEndian.AppendUint32(out, layout.OutLen)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(code)))
	out = append(out, code...)
	return out
}

// Hex 把程序容器编码成十六进制串，即 solve_pow_batched 接受的 program 形态。
func Hex(program []byte) string {
	return hex.EncodeToString(program)
}

// BuildRaw 用**未经汇编器编码**的字节码构造容器。
//
// 这是给校验器/反汇编器测试用的入口：反向用例必须能构造出「汇编器自己
// 会拒绝」的字节码（保留 opcode、越界偏移、非法跳转），否则永远测不到
// 校验器的拒绝路径。生产调用链（pow.go）不使用本函数。
func BuildRaw(layout Layout, code []byte) []byte {
	return buildContainer(layout, code)
}

// CodeOffsets 返回字节码段里每条指令的**起始字节偏移**（相对字节码段）。
//
// 用途：变异测试需要知道哪些字节是 opcode、哪些是操作数 —— 把操作数当成
// opcode 去断言「必须被拒绝」会写出假的反向锁。返回的偏移由真实解码过程
// 得到，与解释器的取指边界一致。
func CodeOffsets(program []byte) ([]int, error) {
	dec, _, err := decodeContainer(program)
	if err != nil {
		return nil, err
	}
	out := make([]int, 0, len(dec))
	for _, d := range dec {
		out = append(out, d.pc)
	}
	return out, nil
}

// Unhex 解析十六进制串为程序容器字节。
func Unhex(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("vmpasm: bad hex: %w", err)
	}
	return b, nil
}
