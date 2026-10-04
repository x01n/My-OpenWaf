package vmpasm

import "fmt"

// 本文件是 ISA 的**参考解释器**，用途只有一个：让「一段字节码执行后到底
// 算出什么」可以在纯 Go、不依赖 WASM 工具链的前提下被断言。
//
// ⚠️ **这是验证用参照，不进生产调用链。** 生产执行路径是
// `wasm-pow-solver/src/vmp.rs` 的 `Vm` —— 本文件只被 `go test` 使用。
// **正确性锚定在外部权威**：密码原语对照 Go 标准库 `crypto/sha256` 与
// `github.com/emmansun/gmsm/sm3`（见 `crypto_ref_test.go`），
// **不是自证**。改动本文件前请先读那组对照测试。
//
// # 与生产路径的关系
//
// **生产执行路径是 `wasm-pow-solver/src/vmp.rs` 的 `Vm`，不是这里。**
// 本文件不参与任何生产调用链（`pow.go` 只用到汇编器与校验器）。
// 它存在的理由是：字节码程序（例如 PoW 程序）的正确性必须能被端到端验证，
// 而 `wasm-pack` 构建不在本仓的常规测试链上；把参考解释器留在 Go 侧，
// 就能在 `go test` 里对「程序 → 执行 → 结果」做真实断言。
//
// # 为什么这是有效证据而不是自证
//
// 参考解释器**从字节流解码**（走 `decodeContainer`，与校验器同一条路径），
// 而不是从汇编器的中间表示执行。因此「编码器与解码器同错」无法逃过检查：
// 编码错则解码出的指令与预期不符，断言失败。加密原语（SHA-256 / SM3 / SM4）
// 不经任何自研实现，直接调标准库/crate 同源的算法，与字节码里的原语指令
// 语义逐位对齐。
//
// # 语义对齐
//
// 与 Rust `Vm` 保持一致的语义：标志只在 `CMP` 写入；移位量按 `& 63`；
// 除法/取余除数为零即错误；`pc` 等于指令条数视为隐式停机（等价显式 `HALT`），
// 越过即错误 —— **不 fail-open**。

// RefMachine 是一台参考解释器的实例。
type RefMachine struct {
	prog  []decoded
	mem   []byte
	regs  [RegCount]uint64
	flag  refFlag
	pc    int
	steps uint64
}

// refFlag 是 CMP 的三态结果。
type refFlag uint8

const (
	refFlagEq refFlag = iota
	refFlagLt
	refFlagGt
)

/**
 * NewRefMachine 解码字节码容器并分配线性内存。
 *
 * 解码失败（含一切结构缺陷）在此返回错误，与 `Verify` 同一条解码路径。
 */
func NewRefMachine(program []byte) (*RefMachine, error) {
	dec, layout, err := decodeContainer(program)
	if err != nil {
		return nil, err
	}
	if len(dec) == 0 {
		return nil, fmt.Errorf("vmpasm: program has no instructions")
	}
	return &RefMachine{
		prog: dec,
		mem:  make([]byte, layout.MemoryLen()),
		flag: refFlagEq,
	}, nil
}

// WriteInput 把输入 blob 写到 `IN_BASE`。
func (m *RefMachine) WriteInput(data []byte) error {
	if uint64(len(data)) > uint64(MaxInBytes) {
		return fmt.Errorf("vmpasm: input is %d bytes, limit is %d", len(data), MaxInBytes)
	}
	copy(m.mem[InBase:], data)
	return nil
}

// ReadOutput 从 `OUT_BASE` 起读出 n 字节。
func (m *RefMachine) ReadOutput(n int) ([]byte, error) {
	if uint64(n) > uint64(MaxOutBytes) {
		return nil, fmt.Errorf("vmpasm: output request %d exceeds %d", n, MaxOutBytes)
	}
	out := make([]byte, n)
	copy(out, m.mem[OutBase:OutBase+n])
	return out, nil
}

/**
 * Reg 返回寄存器的当前值（越界索引按 `% RegCount` 折叠，与 Rust 侧一致：
 * `panic = "abort"` 下越界 panic 会杀实例，宁可折叠不可崩）。
 */
func (m *RefMachine) Reg(r Reg) uint64 { return m.regs[uint(r)%RegCount] }

// Steps 返回已消耗的步数。
func (m *RefMachine) Steps() uint64 { return m.steps }

// Flags 便于测试断言。
const (
	RefFlagEq = refFlagEq
	RefFlagLt = refFlagLt
	RefFlagGt = refFlagGt
)

// FlagName 返回标志的可读名。
func (m *RefMachine) FlagName() string {
	switch m.flag {
	case refFlagLt:
		return "LT"
	case refFlagGt:
		return "GT"
	default:
		return "EQ"
	}
}

/**
 * Run 执行到停机。返回 R0 的值（程序的返回码）。
 *
 * `maxSteps` 为零表示不设预算（仅测试用）；耗尽返回 `vm_budget_exhausted`。
 * 每执行一条指令计 1 步，与 ISA §6.1 的口径一致。
 */
func (m *RefMachine) Run(maxSteps uint64) (uint64, error) {
	total := len(m.prog)
	for {
		if m.pc == total {
			return m.regs[0], nil
		}
		if m.pc > total {
			return 0, RefErr(ProgramErrorCodeBadJumpTarget)
		}
		if maxSteps > 0 && m.steps >= maxSteps {
			return 0, RefErr(ProgramErrorCodeBudgetExhausted)
		}
		m.steps++
		halt, err := m.step()
		if err != nil {
			return 0, err
		}
		if halt {
			return m.regs[0], nil
		}
	}
}

// 参考解释器用的错误码常量（与 isa.rs 的 ProgramError::code 字符串一一对应）。
const (
	ProgramErrorCodeBadJumpTarget   = "vm_bad_jump_target"
	ProgramErrorCodeOutOfBounds     = "vm_out_of_bounds"
	ProgramErrorCodeDivByZero       = "vm_div_by_zero"
	ProgramErrorCodeBudgetExhausted = "vm_budget_exhausted"
	ProgramErrorCodeMalformed       = "vm_malformed_instruction"
	ProgramErrorCodeUnknownOpcode   = "unknown_vm_opcode"
)

// RefError 是参考解释器的执行期错误，携带与 Rust 侧一致的错误码字符串。
type RefError struct {
	Code   string
	Detail string
}

func (e *RefError) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

// RefErr 构造一个只有错误码的 RefError。
func RefErr(code string) error { return &RefError{Code: code} }

func refErrf(code, format string, args ...any) error {
	return &RefError{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// CodeOf 返回错误的错误码字符串；非 RefError 返回空串。
func CodeOf(err error) string {
	if e, ok := err.(*RefError); ok {
		return e.Code
	}
	return ""
}

func (m *RefMachine) step() (bool, error) {
	d := m.prog[m.pc]
	in := d.in
	switch in.Op {
	case OpNop:
		m.pc++
		return false, nil
	case OpHalt:
		return true, nil
	case OpMovi:
		m.regs[uint(in.A)%RegCount] = in.Imm
		m.pc++
		return false, nil
	case OpMov:
		m.regs[uint(in.A)%RegCount] = m.regs[uint(in.B)%RegCount]
		m.pc++
		return false, nil
	case OpLoad8, OpLoad16, OpLoad32, OpLoad64:
		width := loadWidth(in.Op)
		addr, err := m.ea(in.B, in.Off)
		if err != nil {
			return false, err
		}
		var v uint64
		for i := 0; i < width; i++ {
			v |= uint64(m.mem[addr+i]) << (8 * uint(i))
		}
		m.regs[uint(in.A)%RegCount] = v
		m.pc++
		return false, nil
	case OpStore8, OpStore16, OpStore32, OpStore64:
		width := storeWidth(in.Op)
		addr, err := m.ea(in.A, in.Off)
		if err != nil {
			return false, err
		}
		v := m.regs[uint(in.B)%RegCount]
		for i := 0; i < width; i++ {
			m.mem[addr+i] = byte(v >> (8 * uint(i)))
		}
		m.pc++
		return false, nil
	case OpAdd, OpSub, OpMul, OpDivu, OpModu, OpAnd, OpOr, OpXor, OpShl, OpShr, OpSar:
		a := m.regs[uint(in.B)%RegCount]
		b := m.regs[uint(in.C)%RegCount]
		var v uint64
		switch in.Op {
		case OpAdd:
			v = a + b
		case OpSub:
			v = a - b
		case OpMul:
			v = a * b
		case OpDivu:
			if b == 0 {
				return false, RefErr(ProgramErrorCodeDivByZero)
			}
			v = a / b
		case OpModu:
			if b == 0 {
				return false, RefErr(ProgramErrorCodeDivByZero)
			}
			v = a % b
		case OpAnd:
			v = a & b
		case OpOr:
			v = a | b
		case OpXor:
			v = a ^ b
		case OpShl:
			v = a << (b & 63)
		case OpShr:
			v = a >> (b & 63)
		case OpSar:
			v = uint64(int64(a) >> (b & 63))
		}
		m.regs[uint(in.A)%RegCount] = v
		m.pc++
		return false, nil
	case OpCmp:
		a := m.regs[uint(in.A)%RegCount]
		b := m.regs[uint(in.B)%RegCount]
		switch {
		case a < b:
			m.flag = refFlagLt
		case a > b:
			m.flag = refFlagGt
		default:
			m.flag = refFlagEq
		}
		m.pc++
		return false, nil
	case OpJmp, OpJeq, OpJne, OpJlt, OpJle, OpJgt, OpJge:
		taken := true
		switch in.Op {
		case OpJmp:
			taken = true
		case OpJeq:
			taken = m.flag == refFlagEq
		case OpJne:
			taken = m.flag != refFlagEq
		case OpJlt:
			taken = m.flag == refFlagLt
		case OpJle:
			taken = m.flag == refFlagLt || m.flag == refFlagEq
		case OpJgt:
			taken = m.flag == refFlagGt
		case OpJge:
			taken = m.flag == refFlagGt || m.flag == refFlagEq
		}
		if taken {
			if d.dest < 0 || d.dest >= len(m.prog) {
				return false, RefErr(ProgramErrorCodeBadJumpTarget)
			}
			m.pc = d.dest
		} else {
			m.pc++
		}
		return false, nil
	case OpSha256Compress:
		state, err := m.regAddr(in.A)
		if err != nil {
			return false, err
		}
		block, err := m.regAddr(in.B)
		if err != nil {
			return false, err
		}
		if err := refSha256Compress(m.mem, state, block); err != nil {
			return false, err
		}
		m.pc++
		return false, nil
	case OpSm3Compress:
		state, err := m.regAddr(in.A)
		if err != nil {
			return false, err
		}
		block, err := m.regAddr(in.B)
		if err != nil {
			return false, err
		}
		if err := refSm3Compress(m.mem, state, block); err != nil {
			return false, err
		}
		m.pc++
		return false, nil
	case OpSm4EncBlock, OpSm4DecBlock:
		key, err := m.regAddr(in.A)
		if err != nil {
			return false, err
		}
		blk, err := m.regAddr(in.B)
		if err != nil {
			return false, err
		}
		if err := refSm4Block(m.mem, key, blk, in.Op == OpSm4EncBlock); err != nil {
			return false, err
		}
		m.pc++
		return false, nil
	default:
		return false, refErrf(ProgramErrorCodeUnknownOpcode, "opcode 0x%02x at pc=%d", in.Op, d.pc)
	}
}

// ea 计算有效地址：基址寄存器 + 有符号偏移，越界返回错误。
func (m *RefMachine) ea(base Reg, off int32) (int, error) {
	b := m.regs[uint(base)%RegCount]
	var addr uint64
	if off < 0 {
		neg := uint64(-int64(off))
		if b < neg {
			return 0, RefErr(ProgramErrorCodeOutOfBounds)
		}
		addr = b - neg
	} else {
		addr = b + uint64(off)
		if addr < b {
			return 0, RefErr(ProgramErrorCodeOutOfBounds)
		}
	}
	if addr >= uint64(len(m.mem)) {
		return 0, RefErr(ProgramErrorCodeOutOfBounds)
	}
	return int(addr), nil
}

/**
 * checkedRange 是 `checked_range` 的包内别名，供参考解释器的原语使用。
 * 语义与 Rust `isa::checked_range` 一致：溢出与越界都报 `vm_out_of_bounds`。
 */
func checkedRange(addr, width, memLen uint64) (int, error) {
	end := addr + width
	if end < addr || end > memLen {
		return 0, RefErr(ProgramErrorCodeOutOfBounds)
	}
	return int(addr), nil
}

// regAddr 把寄存器值当作地址，校验其落在内存内。
func (m *RefMachine) regAddr(r Reg) (uint64, error) {
	a := m.regs[uint(r)%RegCount]
	if a >= uint64(len(m.mem)) {
		return 0, RefErr(ProgramErrorCodeOutOfBounds)
	}
	return a, nil
}

func loadWidth(op byte) int {
	switch op {
	case OpLoad8:
		return 1
	case OpLoad16:
		return 2
	case OpLoad32:
		return 4
	default:
		return 8
	}
}

func storeWidth(op byte) int {
	switch op {
	case OpStore8:
		return 1
	case OpStore16:
		return 2
	case OpStore32:
		return 4
	default:
		return 8
	}
}
