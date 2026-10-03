// Package vmpasm 是 VMP 指令集在 Go 侧的通用汇编器、反汇编器与字节码校验器。
//
// 它把「程序意图」编码为字节码，供 WASM 侧的解释器执行；也可以反过来把
// 字节码还原成可读文本，以及在不依赖 WASM 的前提下拒绝非法程序。
//
// # 单一真源
//
// opcode 数值的**权威定义在 Rust 侧** `wasm-pow-solver/src/isa.rs`。本包保存
// 一份镜像常量，并由 `internal/waf/challenge/vmp_contract_test.go` 解析
// `isa.rs` 的源文本逐条比对。因此修改任一侧的 opcode 数值都会让契约测试变红。
//
// 为此，本文件里的 opcode 常量命名必须与 `isa.rs` 保持机械可转的对应关系：
// `OP_SHA256_COMPRESS` ↔ `OpSha256Compress`（见 GoNameForRustConst）。
//
// # 与解释器的边界
//
// 本包**不实现执行语义**。寄存器语义、标志位、步数预算的执行循环在 Rust 侧
// `vmp.rs`。本包只负责编码、解码与静态合法性。
package vmpasm

// Reg 是通用寄存器编号，取值 0..15。
//
// 寄存器编号就是指令里 4-bit 字段的值，没有隐含约定：R15 不是栈指针，
// R0 不是零寄存器，寄存器语义完全由字节码程序决定。
type Reg uint8

const (
	R0  Reg = 0
	R1  Reg = 1
	R2  Reg = 2
	R3  Reg = 3
	R4  Reg = 4
	R5  Reg = 5
	R6  Reg = 6
	R7  Reg = 7
	R8  Reg = 8
	R9  Reg = 9
	R10 Reg = 10
	R11 Reg = 11
	R12 Reg = 12
	R13 Reg = 13
	R14 Reg = 14
	R15 Reg = 15
)

// RegCount 是通用寄存器个数。
const RegCount = 16

// opcode 常量。**权威定义在 wasm-pow-solver/src/isa.rs**，此处为镜像；
// 数值不得单方面修改，契约测试会逐条比对。
//
// 命名与 Rust 侧 `OP_SHA256_COMPRESS` ↔ `OpSha256Compress` 机械对应，
// 映射规则见 GoNameForRustConst。
const (
	OpNop            byte = 0x00
	OpMovi           byte = 0x01
	OpMov            byte = 0x02
	OpLoad8          byte = 0x03
	OpLoad16         byte = 0x04
	OpLoad32         byte = 0x05
	OpLoad64         byte = 0x06
	OpStore8         byte = 0x07
	OpStore16        byte = 0x08
	OpStore32        byte = 0x09
	OpStore64        byte = 0x0A
	OpAdd            byte = 0x0B
	OpSub            byte = 0x0C
	OpMul            byte = 0x0D
	OpDivu           byte = 0x0E
	OpModu           byte = 0x0F
	OpAnd            byte = 0x10
	OpOr             byte = 0x11
	OpXor            byte = 0x12
	OpShl            byte = 0x13
	OpShr            byte = 0x14
	OpSar            byte = 0x15
	OpCmp            byte = 0x16
	OpJmp            byte = 0x17
	OpJeq            byte = 0x18
	OpJne            byte = 0x19
	OpJlt            byte = 0x1A
	OpJle            byte = 0x1B
	OpJgt            byte = 0x1C
	OpJge            byte = 0x1D
	OpSha256Compress byte = 0x1E
	OpSm3Compress    byte = 0x1F
	OpSm4EncBlock    byte = 0x20
	OpSm4DecBlock    byte = 0x21
	OpHalt           byte = 0x22
)

// OpcodeTable 是 opcode 数值的 Go 侧镜像，键为 Go 侧常量名。
//
// 权威定义在 `wasm-pow-solver/src/isa.rs`；本表由契约测试逐条核对。
// 新增指令必须同时改 `isa.rs`、本表与 `decodeLen`。
var OpcodeTable = map[string]byte{
	"OpNop":            OpNop,
	"OpMovi":           OpMovi,
	"OpMov":            OpMov,
	"OpLoad8":          OpLoad8,
	"OpLoad16":         OpLoad16,
	"OpLoad32":         OpLoad32,
	"OpLoad64":         OpLoad64,
	"OpStore8":         OpStore8,
	"OpStore16":        OpStore16,
	"OpStore32":        OpStore32,
	"OpStore64":        OpStore64,
	"OpAdd":            OpAdd,
	"OpSub":            OpSub,
	"OpMul":            OpMul,
	"OpDivu":           OpDivu,
	"OpModu":           OpModu,
	"OpAnd":            OpAnd,
	"OpOr":             OpOr,
	"OpXor":            OpXor,
	"OpShl":            OpShl,
	"OpShr":            OpShr,
	"OpSar":            OpSar,
	"OpCmp":            OpCmp,
	"OpJmp":            OpJmp,
	"OpJeq":            OpJeq,
	"OpJne":            OpJne,
	"OpJlt":            OpJlt,
	"OpJle":            OpJle,
	"OpJgt":            OpJgt,
	"OpJge":            OpJge,
	"OpSha256Compress": OpSha256Compress,
	"OpSm3Compress":    OpSm3Compress,
	"OpSm4EncBlock":    OpSm4EncBlock,
	"OpSm4DecBlock":    OpSm4DecBlock,
	"OpHalt":           OpHalt,
}

// GoNameForRustConst 把 `isa.rs` 里的 opcode 常量名转成本包的标识符名。
//
// `OP_SHA256_COMPRESS` → `OpSha256Compress`。
// 契约测试用它把 Rust 源文本里的常量名映射到 Go 侧镜像表。
func GoNameForRustConst(rustName string) string {
	const prefix = "OP_"
	if len(rustName) <= len(prefix) || rustName[:len(prefix)] != prefix {
		return ""
	}
	out := make([]byte, 0, len(rustName))
	out = append(out, 'O', 'p')
	upperNext := true
	for i := len(prefix); i < len(rustName); i++ {
		c := rustName[i]
		if c == '_' {
			upperNext = true
			continue
		}
		if upperNext && c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		} else if !upperNext && c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		upperNext = false
		out = append(out, c)
	}
	return string(out)
}

// 容器常量。与 `isa.rs` 的同名常量一一对应。
const (
	// HeaderLen 是字节码容器的头部字节数。
	HeaderLen = 24
	// MaxCodeBytes 是字节码段上限。
	MaxCodeBytes = 65536
	// MaxPages 是线性内存页数上限（每页 64 KiB）。
	MaxPages = 256
	// MaxInBytes 是输入 blob 上限。
	MaxInBytes = 4096
	// MaxOutBytes 是输出 blob 上限。
	MaxOutBytes = 4096
	// InBase 是输入 blob 基址。
	InBase = 0
	// InEnd 是输入 blob 结束（不含）。等于 OutBase。
	InEnd = InBase + MaxInBytes
	// OutBase 是输出 blob 基址。
	OutBase = InEnd
	// OutEnd 是输出 blob 结束（不含）。等于 HeapBase。
	OutEnd = OutBase + MaxOutBytes
	// HeapBase 是程序自由使用区基址。
	HeapBase = OutEnd
	// PerIterBudget 是单次 batch_size 迭代允许的指令步数。
	PerIterBudget = 2048
	// MaxStepsAbs 是预算绝对上限。
	MaxStepsAbs = 1 << 30
	// BatchSizeLimit 是 batch_size 上限。
	BatchSizeLimit = 1_000_000
)

// Magic 是程序容器魔数（ASCII "OWVM"）。
var Magic = [4]byte{0x4F, 0x57, 0x56, 0x4D}

// Version 是当前 ISA 版本。
const Version = 0x01

// Layout 描述程序的内存布局，决定头部字段。
type Layout struct {
	// Pages 是线性内存页数（1..MaxPages）。
	Pages uint32
	// InLen 是输入 blob 字节数（0..MaxInBytes）。
	InLen uint32
	// OutLen 是输出 blob 字节数（0..MaxOutBytes）。
	OutLen uint32
}

// MemoryLen 返回线性内存总字节数。
func (l Layout) MemoryLen() uint64 { return uint64(l.Pages) * 65536 }
