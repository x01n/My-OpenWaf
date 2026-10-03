package vmpasm

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// Severity 表示一条校验发现的严重程度。
type Severity uint8

const (
	// SeverityError 是结构性缺陷：仅凭控制流即可判定非法，任何解释器都会拒绝。
	SeverityError Severity = iota
	// SeverityFinding 是语义缺陷：编码合法、控制流也合法，但程序形态可疑。
	//
	// 这类问题解释器无法拒绝（它"能跑"），只能在静态分析层发现。
	SeverityFinding
)

// Finding 是一条校验发现。
type Finding struct {
	Severity Severity
	// PC 是相关指令在字节码段的字节偏移。
	PC int
	// Code 是稳定的短标识，用于测试断言。
	Code string
	// Detail 是人类可读的说明。
	Detail string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s at pc=%d: %s", f.Code, f.PC, f.Detail)
}

// Report 是一次程序校验的结果。
//
// Errors 非空意味着字节码非法；Findings 非空意味着程序虽然合法但存在可疑形态。
type Report struct {
	Layout   Layout
	CodeLen  int
	Instrs   int
	Errors   []Finding
	Findings []Finding
}

// OK 返回程序是否无结构性错误（解释器会接受它）。
func (r *Report) OK() bool { return len(r.Errors) == 0 }

// Clean 返回程序是否既无结构性错误、也无语义可疑点。
func (r *Report) Clean() bool { return len(r.Errors) == 0 && len(r.Findings) == 0 }

type decoded struct {
	pc   int
	len  int
	in   Instr
	dest int // 目标指令下标，仅跳转指令有效；-1 表示"下一条"
}

// successors 返回指令的后继下标。
//
// `HALT` 没有后继 —— 它不是"落到下一条"，这是终止性分析的基石：
// 若把 HALT 当成有顺序后继，紧跟其后的死指令会被误判为可达。
func (d decoded) successors(idx, total int) []int {
	if d.in.Op == OpHalt {
		return nil
	}
	if d.dest < 0 {
		if idx+1 < total {
			return []int{idx + 1}
		}
		return nil
	}
	if d.in.Op == OpJmp {
		return []int{d.dest}
	}
	if idx+1 < total {
		return []int{d.dest, idx + 1}
	}
	return []int{d.dest}
}

// Verify 在 Go 侧对字节码做完整静态校验，不依赖 WASM 解释器。
//
// 检查项：
//   - 容器头部（魔数、版本、flags、长度、页数、blob 长度）
//   - 指令编码（保留 opcode、未用 nibble、截断）
//   - 跳转目标落在指令起始位置
//   - 控制流：入口可达性与到达 HALT 的能力（结构性错误）
//   - 语义：内存操作数的可疑偏移、恒真比较（advisory findings）
//
// # 为什么内存检查是 finding 而不是 error
//
// 基址是运行期寄存器值，可以是任意 u64。`base + offset` 在什么语义下回绕
// 由解释器定义，静态不可知，因此除「偏移本身超过内存长度」这类极端情形外，
// 都不能断言程序必然越界。把它们报成 error 会让校验器拒绝合法程序。
func Verify(program []byte) (*Report, error) {
	dec, layout, err := decodeContainer(program)
	if err != nil {
		return nil, err
	}
	rep := &Report{Layout: layout, CodeLen: len(program) - HeaderLen, Instrs: len(dec)}

	if len(dec) == 0 {
		rep.Errors = append(rep.Errors, Finding{
			Severity: SeverityError,
			PC:       0,
			Code:     "empty_code",
			Detail:   "bytecode section has no instructions",
		})
		return rep, nil
	}

	rep.Errors = append(rep.Errors, checkControlFlow(dec)...)
	rep.Findings = append(rep.Findings, checkMemoryOperands(dec, layout)...)
	rep.Findings = append(rep.Findings, checkZeroConstantCompares(dec)...)
	sortFindings(rep.Errors)
	sortFindings(rep.Findings)
	return rep, nil
}

// Inspect 只做语义分析，不重复结构性校验。返回的发现按 PC 排序。
func Inspect(program []byte) ([]Finding, error) {
	dec, layout, err := decodeContainer(program)
	if err != nil {
		return nil, err
	}
	f := checkMemoryOperands(dec, layout)
	f = append(f, checkZeroConstantCompares(dec)...)
	sortFindings(f)
	return f, nil
}

func sortFindings(f []Finding) {
	sort.Slice(f, func(i, j int) bool {
		if f[i].PC != f[j].PC {
			return f[i].PC < f[j].PC
		}
		return f[i].Code < f[j].Code
	})
}

// decodeContainer 是 Go 侧的字节码解码器，与 Rust 侧 isa.rs 的 decode_code 平行。
func decodeContainer(program []byte) ([]decoded, Layout, error) {
	if len(program) < HeaderLen {
		return nil, Layout{}, fmt.Errorf("vmpasm: %d bytes is shorter than the %d-byte header", len(program), HeaderLen)
	}
	if program[0] != Magic[0] || program[1] != Magic[1] || program[2] != Magic[2] || program[3] != Magic[3] {
		return nil, Layout{}, fmt.Errorf("vmpasm: bad magic %x", program[0:4])
	}
	if program[4] != Version {
		return nil, Layout{}, fmt.Errorf("vmpasm: unsupported version 0x%02x", program[4])
	}
	if program[5] != 0 || program[6] != 0 || program[7] != 0 {
		return nil, Layout{}, fmt.Errorf("vmpasm: flags/reserved must be zero")
	}
	layout := Layout{
		Pages:  binary.LittleEndian.Uint32(program[8:12]),
		InLen:  binary.LittleEndian.Uint32(program[12:16]),
		OutLen: binary.LittleEndian.Uint32(program[16:20]),
	}
	codeLen := binary.LittleEndian.Uint32(program[20:24])
	if int(codeLen) != len(program)-HeaderLen {
		return nil, Layout{}, fmt.Errorf("vmpasm: code_len %d does not match payload %d", codeLen, len(program)-HeaderLen)
	}
	if err := validateLayout(layout); err != nil {
		return nil, Layout{}, err
	}

	code := program[HeaderLen:]
	dec := make([]decoded, 0, len(code))
	boundary := make(map[int]bool)
	pc := 0
	for pc < len(code) {
		boundary[pc] = true
		in, n, err := decodeAt(code, pc)
		if err != nil {
			return nil, Layout{}, err
		}
		dec = append(dec, decoded{pc: pc, len: n, in: in, dest: -1})
		pc += n
	}
	boundary[len(code)] = true

	index := make(map[int]int, len(dec))
	for i, d := range dec {
		index[d.pc] = i
	}
	for i := range dec {
		f, ok := formatOf(dec[i].in.Op)
		if !ok || f != fmtJ {
			continue
		}
		rel := int32(binary.LittleEndian.Uint32(code[dec[i].pc+1 : dec[i].pc+5]))
		target := dec[i].pc + dec[i].len + int(rel)
		if target < 0 || target >= len(code) || !boundary[target] {
			return nil, Layout{}, fmt.Errorf(
				"vmpasm: jump at pc=%d targets %d, which is not an instruction boundary in [0,%d)",
				dec[i].pc, target, len(code))
		}
		dec[i].dest = index[target]
	}
	return dec, layout, nil
}

// decodeAt 解码一条指令，与 isa.rs 的 decode_at 平行。
func decodeAt(code []byte, pc int) (Instr, int, error) {
	op := code[pc]
	f, ok := formatOf(op)
	if !ok {
		return Instr{}, 0, fmt.Errorf("vmpasm: unknown opcode 0x%02x at pc=%d", op, pc)
	}
	n := lenOfFormat(f)
	if pc+n > len(code) {
		return Instr{}, 0, fmt.Errorf(
			"vmpasm: instruction at pc=%d is truncated (needs %d bytes, %d available)",
			pc, n, len(code)-pc)
	}
	in := Instr{Op: op}
	switch f {
	case fmtNone:
		// 无操作数
	case fmtR:
		in.A, in.B = splitRegs(code[pc+1])
	case fmtRR:
		in.A, in.B = splitRegs(code[pc+1])
		c, lo := splitRegs(code[pc+2])
		if lo != 0 {
			return Instr{}, 0, fmt.Errorf("vmpasm: reserved nibble must be zero at pc=%d", pc+2)
		}
		in.C = c
	case fmtRI64:
		a, lo := splitRegs(code[pc+1])
		if lo != 0 {
			return Instr{}, 0, fmt.Errorf("vmpasm: reserved nibble must be zero at pc=%d", pc+1)
		}
		in.A = a
		in.Imm = binary.LittleEndian.Uint64(code[pc+2 : pc+10])
	case fmtRI32:
		in.A, in.B = splitRegs(code[pc+1])
		in.Off = int32(binary.LittleEndian.Uint32(code[pc+2 : pc+6]))
	case fmtJ:
		in.Imm = uint64(int64(int32(binary.LittleEndian.Uint32(code[pc+1 : pc+5]))))
	}
	return in, n, nil
}

func splitRegs(b byte) (Reg, Reg) { return Reg(b >> 4), Reg(b & 0x0F) }

// checkControlFlow 校验入口可达性与终止性 —— 这两项只依赖控制流，是结构性错误。
func checkControlFlow(dec []decoded) []Finding {
	var out []Finding

	reachable := make([]bool, len(dec))
	reachable[0] = true
	stack := []int{0}
	for len(stack) > 0 {
		i := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, s := range dec[i].successors(i, len(dec)) {
			if !reachable[s] {
				reachable[s] = true
				stack = append(stack, s)
			}
		}
	}
	for i, d := range dec {
		if !reachable[i] {
			out = append(out, Finding{
				Severity: SeverityError,
				PC:       d.pc,
				Code:     "unreachable",
				Detail:   "instruction is unreachable from the entry point",
			})
		}
	}

	// 反向可达性：能到达 HALT 的指令集合。
	canHalt := make([]bool, len(dec))
	preds := make([][]int, len(dec))
	for i, d := range dec {
		for _, s := range d.successors(i, len(dec)) {
			preds[s] = append(preds[s], i)
		}
	}
	stack = stack[:0]
	for i, d := range dec {
		if d.in.Op == OpHalt {
			canHalt[i] = true
			stack = append(stack, i)
		}
	}
	for len(stack) > 0 {
		i := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, p := range preds[i] {
			if !canHalt[p] {
				canHalt[p] = true
				stack = append(stack, p)
			}
		}
	}
	for i, d := range dec {
		if reachable[i] && !canHalt[i] {
			out = append(out, Finding{
				Severity: SeverityError,
				PC:       d.pc,
				Code:     "no_path_to_halt",
				Detail:   "reachable instruction cannot reach HALT",
			})
		}
	}
	return out
}

// checkMemoryOperands 报告可疑的内存操作数。
//
// 判定口径见 Verify 的注释：基址是任意 u64，静态不可知，因此这里只报告
// 「偏移本身就超出内存上界」这一种无论基址取何值都至少在一个方向上可疑的情形，
// 且一律降为 finding。
func checkMemoryOperands(dec []decoded, layout Layout) []Finding {
	memLen := layout.MemoryLen()
	var out []Finding
	for _, d := range dec {
		var width int64
		switch d.in.Op {
		case OpLoad8, OpStore8:
			width = 1
		case OpLoad16, OpStore16:
			width = 2
		case OpLoad32, OpStore32:
			width = 4
		case OpLoad64, OpStore64:
			width = 8
		default:
			continue
		}
		off := int64(d.in.Off)
		if off < 0 {
			out = append(out, Finding{
				Severity: SeverityFinding,
				PC:       d.pc,
				Code:     "negative_offset",
				Detail:   fmt.Sprintf("memory offset %d is negative; its validity depends on the run-time base register", off),
			})
			continue
		}
		if uint64(off)+uint64(width) > memLen {
			out = append(out, Finding{
				Severity: SeverityFinding,
				PC:       d.pc,
				Code:     "offset_beyond_memory",
				Detail:   fmt.Sprintf("offset %d + width %d exceeds the declared memory size %d", off, width, memLen),
			})
		}
	}
	return out
}

// checkZeroConstantCompares 是「多态性缺陷」检查。
//
// 背景：字节码的多态价值在于**分支结构依赖运行期输入**。若某条 `CMP` 的两个
// 操作数在该点都能被证明恒为零，这条比较的结果恒为相等，它所在的分支在程序
// 结构上就是固定的一条路径 —— 这样的程序段是填充物，不是真实计算。
//
// # 为什么必须做 CFG 数据流而不是线性扫描
//
// 线性扫描在分支合流处会把「某个分支写入了 0」误当成「所有路径都是 0」，
// 从而对合法程序报假阳性。这里做的是标准的前向 must-analysis：
// 抽象状态是 16 个寄存器的「可证为零」位，入口全 false（未知），
// `in[s] = AND over preds p of out[p]`，迭代到最小不动点。
//
// 每条转移规则都取保守方向（宁可判为未知）：静态不可知的写一律置 false。
// 因此**报出的每一处都是真正的恒零比较**，不存在假阳性。
func checkZeroConstantCompares(dec []decoded) []Finding {
	n := len(dec)
	if n == 0 {
		return nil
	}
	in := make([][RegCount]bool, n)
	out := make([][RegCount]bool, n)

	preds := make([][]int, n)
	for i, d := range dec {
		for _, s := range d.successors(i, n) {
			preds[s] = append(preds[s], i)
		}
	}

	changed := true
	for round := 0; changed; round++ {
		// 抽象状态空间是 16 位格，每轮至少有一位从 false 抬到 true，
		// 因此迭代次数上界是 16 * n；超出即实现有误。
		if round > 16*n+16 {
			break
		}
		changed = false
		for i := range dec {
			var cur [RegCount]bool
			if len(preds[i]) == 0 {
				// 入口（或不可达点）：全未知
				cur = [RegCount]bool{}
			} else {
				cur = out[preds[i][0]]
				for _, p := range preds[i][1:] {
					other := out[p]
					for r := 0; r < RegCount; r++ {
						cur[r] = cur[r] && other[r]
					}
				}
			}
			if cur != in[i] {
				in[i] = cur
				changed = true
			}
			next := cur
			stepZero(dec[i].in, &next)
			if next != out[i] {
				out[i] = next
				changed = true
			}
		}
	}

	var found []Finding
	for i, d := range dec {
		if d.in.Op != OpCmp {
			continue
		}
		if in[i][d.in.A] && in[i][d.in.B] {
			found = append(found, Finding{
				Severity: SeverityFinding,
				PC:       d.pc,
				Code:     "zero_constant_compare",
				Detail: fmt.Sprintf(
					"both operands of CMP are provably zero (%s, %s); the comparison is constant and its branch is fixed structure",
					regName(d.in.A), regName(d.in.B)),
			})
		}
	}
	return found
}

// stepZero 对一条指令做一次抽象状态转移。保守方向：不确定就置 false。
func stepZero(in Instr, s *[RegCount]bool) {
	setZero := func(r Reg, v bool) {
		if r < RegCount {
			s[r] = v
		}
	}
	switch in.Op {
	case OpMovi:
		setZero(in.A, in.Imm == 0)
	case OpMov:
		setZero(in.A, s[in.B])
	case OpAdd:
		setZero(in.A, s[in.B] && s[in.C])
	case OpSub:
		// `r - r == 0` 与操作数取值无关；此外 `0 - 0 == 0`。
		setZero(in.A, in.B == in.C || (s[in.B] && s[in.C]))
	case OpMul, OpAnd:
		setZero(in.A, s[in.B] || s[in.C])
	case OpOr:
		setZero(in.A, s[in.B] && s[in.C])
	case OpXor:
		// `r ^ r == 0` 恒成立，与状态无关
		setZero(in.A, (s[in.B] && s[in.C]) || in.B == in.C)
	case OpDivu, OpShl, OpShr, OpSar:
		// `0 / b == 0`、`0 << b == 0`、`0 >> b == 0`，均与移位/除数无关
		// （除数为零是运行期错误，不是零性问题）
		setZero(in.A, s[in.B])
	case OpModu, OpLoad8, OpLoad16, OpLoad32, OpLoad64:
		// 静态不可知
		setZero(in.A, false)
	default:
		// 其余指令不写通用寄存器
	}
}

func regName(r Reg) string {
	if r < RegCount {
		return fmt.Sprintf("R%d", r)
	}
	return fmt.Sprintf("R?(%d)", r)
}
