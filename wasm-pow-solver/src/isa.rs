//! ```text
//! 常量    OP_* (35 条) / MAGIC / VERSION / HEADER_LEN / MAX_CODE_BYTES /
//!         MAX_PAGES / MAX_IN_BYTES / MAX_OUT_BYTES / IN_BASE / OUT_BASE /
//!         HEAP_BASE / PER_ITER_BUDGET / MAX_STEPS_ABS / BATCH_SIZE_LIMIT
//!         （数值与含义见 §「容器常量」；权威性由 Go 契约测试锁定）
//!
//! 类型    Header  { pages, in_len, out_len, code_len, memory_len() }
//!         Instr   { pc: usize, len: usize, op: Op }
//!         Program { header: Header, instrs: Vec<Instr> }
//!                 —— 执行器直接读 `program.instrs`，按 `pc` 下标寻址
//!         Op      —— 35 条指令，寄存器字段是 u8（解码期已保证 < 16）
//!         Flag    —— Lt / Eq / Gt，仅 CMP 写、条件跳转读
//!         ProgramError —— 见下
//!
//! 函数    parse(hex: &str) -> Result<Program, ProgramError>      入口
//!         parse_bytes(&[u8]) -> Result<Program, ProgramError>
//!         parse_header(&[u8]) -> Result<Header, ProgramError>
//!         decode_program_hex(&str) -> Result<Vec<u8>, ProgramError>
//!         checked_range(addr, width, mem_len) -> Result<usize, ProgramError>
//!         sha256_compress_at / sm3_compress_at / sm4_enc_block_at / sm4_dec_block_at
//!                 —— 操作数地址由执行器解析，越界返回 OutOfBounds，绝不 panic
//! ```
//!
//! # 跳转语义
//!
//! `Op::Jmp { rel }` 等携带的是**原始 i32 相对量**，目标 = **下一条指令的
//! 起始字节偏移**（即 `instr.pc + instr.len`，不是 `instr.pc + 1`）+ `rel`。
//! 本文件在**解码期**已校验目标落在指令边界且不越界。
//!
//! 注意 `Program.instrs` 是**紧凑数组**（`instrs[i].pc` 是它在该数组里的
//! 字节偏移，不是下标）：跳转目标的字节偏移需要映射成**数组下标**。
//! `vmp.rs` 用 `binary_search_by_key(&target, |i| i.pc)` 完成映射，
//! 并把 `Vm.pc` 定义为**数组下标** —— 与解码器的 `Instr.pc`（字节偏移）
//! 是两种量，不要混用。
//!
//! # 错误码：单一真源在本文件，但**分两层**
//!
//! 14 个变体全部定义在本文件（见 §「错误」），`vmp.rs` 只 `use` 不另定义。
//! 分层的含义是**哪一层能报出**，不是类型分家：
//!
//! - **解码期**（`parse` 阶段，不分配内存、不执行任何指令即可全量报出）：
//!   `BadMagic` / `UnsupportedVersion` / `BadFlags` / `TrailingBytes` /
//!   `ProgramTooLarge` / `MalformedInstruction` / `UnknownOpcode` /
//!   `BadJumpTarget` / `InvalidHex` / `OddHexLength`
//! - **执行期**（只有跑起来才知道）：`OutOfBounds` / `DivByZero` /
//!   `BudgetExhausted` / `BatchTooLarge` / `OutputMagic`（后两者由**宿主**
//!   构造：`BatchTooLarge` 在进入 VM 前、`OutputMagic` 在 `read_output` 之后）
//!
//! 对外的 `ProgramError::code()` 字符串仍是**唯一一份**，`solve_pow_batched`
//! 直接透出。
//!
//! # 解码期保证（执行器可依赖，无需重复检查）
//!
//! - 所有 `rd` / `rs` / `ra` / `rb` 严格 < 16。
//! - 未使用的 nibble 已校验为零 → 同一指令只有一种编码。
//! - 每条跳转指令的目标落在 `Program.instrs` 的某个下标上（不会指到指令中间）。
//!
//!  - `code_len >= 1`，`instrs` 非空。
//!
//!  输入 blob 布局
//!
//!	偏移  宽度  字段
//!	 0     8    batch_size（宿主已用于算步数预算，程序内不使用）
//!	 8     8    start_counter
//!	16     8    difficulty
//!	24     8    nonce_len（0..64）
//!	32   ...   nonce 的 ASCII 字节

pub const OP_NOP: u8 = 0x00;
pub const OP_MOVI: u8 = 0x01;
pub const OP_MOV: u8 = 0x02;
pub const OP_LOAD8: u8 = 0x03;
pub const OP_LOAD16: u8 = 0x04;
pub const OP_LOAD32: u8 = 0x05;
pub const OP_LOAD64: u8 = 0x06;
pub const OP_STORE8: u8 = 0x07;
pub const OP_STORE16: u8 = 0x08;
pub const OP_STORE32: u8 = 0x09;
pub const OP_STORE64: u8 = 0x0A;
pub const OP_ADD: u8 = 0x0B;
pub const OP_SUB: u8 = 0x0C;
pub const OP_MUL: u8 = 0x0D;
pub const OP_DIVU: u8 = 0x0E;
pub const OP_MODU: u8 = 0x0F;
pub const OP_AND: u8 = 0x10;
pub const OP_OR: u8 = 0x11;
pub const OP_XOR: u8 = 0x12;
pub const OP_SHL: u8 = 0x13;
pub const OP_SHR: u8 = 0x14;
pub const OP_SAR: u8 = 0x15;
pub const OP_CMP: u8 = 0x16;
pub const OP_JMP: u8 = 0x17;
pub const OP_JEQ: u8 = 0x18;
pub const OP_JNE: u8 = 0x19;
pub const OP_JLT: u8 = 0x1A;
pub const OP_JLE: u8 = 0x1B;
pub const OP_JGT: u8 = 0x1C;
pub const OP_JGE: u8 = 0x1D;
pub const OP_SHA256_COMPRESS: u8 = 0x1E;
pub const OP_SM3_COMPRESS: u8 = 0x1F;
pub const OP_SM4_ENC_BLOCK: u8 = 0x20;
pub const OP_SM4_DEC_BLOCK: u8 = 0x21;
pub const OP_HALT: u8 = 0x22;


/// 程序魔数：ASCII `OWVM`。
pub const MAGIC: [u8; 4] = [0x4F, 0x57, 0x56, 0x4D];
/// 当前 ISA 版本。未知版本一律拒绝（不做向后兼容）。
pub const VERSION: u8 = 0x01;
/// 头部字节数：magic(4) + version(1) + flags(1) + reserved(2) + pages(4)
/// + in_len(4) + out_len(4) + code_len(4)。
pub const HEADER_LEN: usize = 24;
/// 字节码段上限。
pub const MAX_CODE_BYTES: usize = 65536;
/// 线性内存页数上限（每页 64 KiB，合计 16 MiB）。
pub const MAX_PAGES: u32 = 256;
/// 输入 blob 上限。
pub const MAX_IN_BYTES: u32 = 4096;
/// 输出 blob 上限。
pub const MAX_OUT_BYTES: u32 = 4096;

/// 输入 blob 基址（宿主写入）。
pub const IN_BASE: u64 = 0;
/// 输入 blob 结束（不含）。同时是输出 blob 的基址。
pub const IN_END: u64 = IN_BASE + MAX_IN_BYTES as u64;
/// 输出 blob 基址（程序写入，宿主读出）。
pub const OUT_BASE: u64 = IN_END;
/// 程序自由使用区基址。`[HEAP_BASE, pages * 65536)` 是临时区/软件栈。
#[allow(dead_code)]
pub const HEAP_BASE: u64 = OUT_BASE + MAX_OUT_BYTES as u64;
pub const PER_ITER_BUDGET: u64 = 2048;
/// 预算绝对上限，防止 `batch_size` 极大时溢出为天文数字。
pub const MAX_STEPS_ABS: u64 = 1 << 30;
/// `batch_size` 上限。
pub const BATCH_SIZE_LIMIT: u32 = 1_000_000;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramError {
    /// 头部 magic 不符，或长度不足以构成头部（含一切旧格式程序）。
    BadMagic,
    /// `version` 不是 `VERSION`。
    UnsupportedVersion,
    /// `flags` 或 `reserved` 非零。
    BadFlags,
    /// `HEADER_LEN + code_len` 与实际字节数不符。
    TrailingBytes,
    /// `code_len` / `pages` / `in_len` / `out_len` 超限，或 `pages` 为 0。
    ProgramTooLarge,
    /// `batch_size` 超过 `BATCH_SIZE_LIMIT`。
    BatchTooLarge,
    /// opcode 落在保留区。
    UnknownOpcode,
    /// 指令编码非法：未用 nibble 非零、指令被 `code` 末尾截断。
    MalformedInstruction,
    /// 内存访问越界。
    OutOfBounds,
    /// `DIVU` / `MODU` 的除数为零。
    DivByZero,
    /// 跳转目标不在 `code` 范围内，或未落在指令起始位置。
    BadJumpTarget,
    /// 步数超预算。
    BudgetExhausted,
    /// program 串不是合法 hex。
    InvalidHex,
    /// program 串长度为奇数。
    OddHexLength,
    /// 宿主读回输出后校验失败：`R0 == 1` 但输出区魔数不符（或全零）。
    ///
    /// **不在 VM 内触发** —— VM 执行结束时不知道输出区的语义，在 VM 内校验
    /// 会把 PoW 语义泄漏进 ISA（§7.2「ISA 层完全没有 PoW 语义」）。
    /// 触发点在宿主（`solve_pow_batched` 的 `read_output` 之后）。
    /// 与 [`Self::BatchTooLarge`] 同类：执行期码、由宿主构造。
    OutputMagic,
}

impl ProgramError {
    /// 稳定的错误码字符串（对 JS 侧可见，不可随意改名）。
    pub const fn code(self) -> &'static str {
        match self {
            Self::BadMagic => "vm_bad_magic",
            Self::UnsupportedVersion => "vm_unsupported_version",
            Self::BadFlags => "vm_bad_flags",
            Self::TrailingBytes => "vm_trailing_bytes",
            Self::ProgramTooLarge => "vm_program_too_large",
            Self::BatchTooLarge => "vm_batch_too_large",
            Self::UnknownOpcode => "unknown_vm_opcode",
            Self::MalformedInstruction => "vm_malformed_instruction",
            Self::OutOfBounds => "vm_out_of_bounds",
            Self::DivByZero => "vm_div_by_zero",
            Self::BadJumpTarget => "vm_bad_jump_target",
            Self::BudgetExhausted => "vm_budget_exhausted",
            Self::InvalidHex => "invalid_vm_hex",
            Self::OddHexLength => "odd_vm_hex_length",
            Self::OutputMagic => "vm_output_magic",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    /// `ra < rb`（无符号）。
    Lt,
    /// `ra == rb`。
    Eq,
    /// `ra > rb`（无符号）。
    Gt,
}

/// 一条解码后的指令。`rd`/`rs`/`ra`/`rb` 均为 0..15 的寄存器号。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Nop,
    /// `rd = imm`
    Movi { rd: u8, imm: u64 },
    /// `rd = rs`
    Mov { rd: u8, rs: u8 },
    /// `rd = zext(mem[rs + off ..])`，小端
    Load8 { rd: u8, rs: u8, off: i32 },
    /// 同 `Load8`，2 字节
    Load16 { rd: u8, rs: u8, off: i32 },
    /// 同 `Load8`，4 字节
    Load32 { rd: u8, rs: u8, off: i32 },
    /// 同 `Load8`，8 字节
    Load64 { rd: u8, rs: u8, off: i32 },
    /// `mem[rd + off ..] = rs & 0xFF`
    Store8 { rd: u8, rs: u8, off: i32 },
    /// 同 `Store8`，小端写 2 字节
    Store16 { rd: u8, rs: u8, off: i32 },
    /// 同 `Store8`，小端写 4 字节
    Store32 { rd: u8, rs: u8, off: i32 },
    /// 同 `Store8`，小端写 8 字节
    Store64 { rd: u8, rs: u8, off: i32 },
    /// `rd = ra + rb`（wrapping）
    Add { rd: u8, ra: u8, rb: u8 },
    /// `rd = ra - rb`（wrapping）
    Sub { rd: u8, ra: u8, rb: u8 },
    /// `rd = ra * rb`（wrapping）
    Mul { rd: u8, ra: u8, rb: u8 },
    /// `rd = ra / rb`（无符号；`rb == 0` → `DivByZero`）
    Divu { rd: u8, ra: u8, rb: u8 },
    /// `rd = ra % rb`（无符号；`rb == 0` → `DivByZero`）
    Modu { rd: u8, ra: u8, rb: u8 },
    /// `rd = ra & rb`
    And { rd: u8, ra: u8, rb: u8 },
    /// `rd = ra | rb`
    Or { rd: u8, ra: u8, rb: u8 },
    /// `rd = ra ^ rb`
    Xor { rd: u8, ra: u8, rb: u8 },
    /// `rd = ra << (rb & 63)`
    Shl { rd: u8, ra: u8, rb: u8 },
    /// `rd = ra >> (rb & 63)`（逻辑右移）
    Shr { rd: u8, ra: u8, rb: u8 },
    /// `rd = ra >> (rb & 63)`（算术右移）
    Sar { rd: u8, ra: u8, rb: u8 },
    /// 置标志：`ra` 与 `rb` 的无符号比较结果
    Cmp { ra: u8, rb: u8 },
    /// 无条件跳转，`rel` 相对下一条指令
    Jmp { rel: i32 },
    /// 标志为 `Eq` 时跳转
    Jeq { rel: i32 },
    /// 标志不为 `Eq` 时跳转
    Jne { rel: i32 },
    /// 标志为 `Lt` 时跳转
    Jlt { rel: i32 },
    /// 标志为 `Lt` 或 `Eq` 时跳转
    Jle { rel: i32 },
    /// 标志为 `Gt` 时跳转
    Jgt { rel: i32 },
    /// 标志为 `Gt` 或 `Eq` 时跳转
    Jge { rel: i32 },
    /// SHA-256 单块压缩：`mem[rd..rd+32]`（8×u32 大端状态）就地更新，
    /// `mem[rs..rs+64]` 是数据块。
    Sha256Compress { rd: u8, rs: u8 },
    /// SM3 单块压缩：`mem[rd..rd+32]`（8×u32 大端状态）就地更新，
    /// `mem[rs..rs+64]` 是数据块。
    Sm3Compress { rd: u8, rs: u8 },
    /// SM4 单块加密：`mem[rd..rd+16]` 是密钥，`mem[rs..rs+16]` 就地加密。
    Sm4EncBlock { rd: u8, rs: u8 },
    /// SM4 单块解密：`mem[rd..rd+16]` 是密钥，`mem[rs..rs+16]` 就地解密。
    Sm4DecBlock { rd: u8, rs: u8 },
    /// 正常结束，返回码在 R0。
    Halt,
}

/// 一条指令在 `code` 中的位置与解码结果。
#[derive(Debug, Clone, Copy)]
pub struct Instr {
    /// 相对 `code` 起始的字节偏移。
    pub pc: usize,
    /// 编码长度（字节）。
    pub len: usize,
    /// 解码后的指令。
    pub op: Op,
}

/// 头部字段（已校验）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// 线性内存页数（1..=`MAX_PAGES`）。
    pub pages: u32,
    /// 输入 blob 字节数（0..=`MAX_IN_BYTES`）。
    pub in_len: u32,
    /// 输出 blob 字节数（0..=`MAX_OUT_BYTES`）。
    pub out_len: u32,
    /// 字节码字节数（1..=`MAX_CODE_BYTES`）。
    pub code_len: u32,
}

impl Header {
    /// 线性内存总字节数。
    pub const fn memory_len(&self) -> u64 {
        self.pages as u64 * 65536
    }
}

/// 解析并校验通过的程序。
#[derive(Debug, Clone)]
pub struct Program {
    pub header: Header,
    /// 按 `pc` 升序排列的全部指令。
    pub instrs: Vec<Instr>,
}

/// 解码 program 的 hex 串。
pub fn decode_program_hex(hex: &str) -> Result<Vec<u8>, ProgramError> {
    if hex.len() % 2 != 0 {
        return Err(ProgramError::OddHexLength);
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]).ok_or(ProgramError::InvalidHex)?;
        let lo = hex_nibble(bytes[i + 1]).ok_or(ProgramError::InvalidHex)?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub fn parse(program_hex: &str) -> Result<Program, ProgramError> {
    let bytes = decode_program_hex(program_hex)?;
    parse_bytes(&bytes)
}

/// 解析 program（已解码字节形态）。
pub fn parse_bytes(bytes: &[u8]) -> Result<Program, ProgramError> {
    let header = parse_header(bytes)?;
    let code = &bytes[HEADER_LEN..];
    let instrs = decode_code(code)?;
    Ok(Program { header, instrs })
}

/// 只解析并校验头部。
pub fn parse_header(bytes: &[u8]) -> Result<Header, ProgramError> {
    // 长度不足以构成头部时无法确认格式，统一按 magic 不符处理。
    // 旧格式（无头部的裸 opcode 串）也落在这条路径上。
    if bytes.len() < HEADER_LEN {
        return Err(ProgramError::BadMagic);
    }
    if bytes[0..4] != MAGIC {
        return Err(ProgramError::BadMagic);
    }
    if bytes[4] != VERSION {
        return Err(ProgramError::UnsupportedVersion);
    }
    if bytes[5] != 0 || bytes[6] != 0 || bytes[7] != 0 {
        return Err(ProgramError::BadFlags);
    }

    let pages = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let in_len = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let out_len = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let code_len = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);

    if pages == 0 || pages > MAX_PAGES {
        return Err(ProgramError::ProgramTooLarge);
    }
    if in_len > MAX_IN_BYTES || out_len > MAX_OUT_BYTES {
        return Err(ProgramError::ProgramTooLarge);
    }
    if code_len == 0 || code_len as usize > MAX_CODE_BYTES {
        return Err(ProgramError::ProgramTooLarge);
    }
    if bytes.len() != HEADER_LEN + code_len as usize {
        return Err(ProgramError::TrailingBytes);
    }

    Ok(Header {
        pages,
        in_len,
        out_len,
        code_len,
    })
}

/// 解码字节码段，并校验全部跳转目标。
fn decode_code(code: &[u8]) -> Result<Vec<Instr>, ProgramError> {
    let mut instrs: Vec<Instr> = Vec::new();
    // 指令起始位置标记，用于跳转对齐校验。多一个哨兵位表示 code 末尾。
    let mut boundary = vec![false; code.len() + 1];
    let mut pc = 0usize;

    while pc < code.len() {
        boundary[pc] = true;
        let (op, len) = decode_at(code, pc)?;
        instrs.push(Instr { pc, len, op });
        pc += len;
    }
    boundary[code.len()] = true;

    for instr in &instrs {
        let rel = match instr.op {
            Op::Jmp { rel }
            | Op::Jeq { rel }
            | Op::Jne { rel }
            | Op::Jlt { rel }
            | Op::Jle { rel }
            | Op::Jgt { rel }
            | Op::Jge { rel } => rel,
            _ => continue,
        };
        let next = instr.pc as i64 + instr.len as i64;
        let target = next + rel as i64;
        if target < 0 || target as usize >= code.len() {
            return Err(ProgramError::BadJumpTarget);
        }
        if !boundary[target as usize] {
            return Err(ProgramError::BadJumpTarget);
        }
    }

    Ok(instrs)
}

/// 解码 `code[pc]` 处的一条指令，返回 (指令, 编码长度)。
fn decode_at(code: &[u8], pc: usize) -> Result<(Op, usize), ProgramError> {
    let opcode = code[pc];
    match opcode {
        OP_NOP => Ok((Op::Nop, 1)),
        OP_HALT => Ok((Op::Halt, 1)),
        OP_MOVI => {
            let regs = fetch(code, pc + 1, 1)?;
            let rd = hi_nibble(regs);
            if lo_nibble(regs) != 0 {
                return Err(ProgramError::MalformedInstruction);
            }
            let imm = fetch_u64(code, pc + 2)?;
            Ok((Op::Movi { rd, imm }, 10))
        }
        OP_MOV => {
            let regs = fetch(code, pc + 1, 1)?;
            Ok((
                Op::Mov {
                    rd: hi_nibble(regs),
                    rs: lo_nibble(regs),
                },
                2,
            ))
        }
        OP_LOAD8 | OP_LOAD16 | OP_LOAD32 | OP_LOAD64 => {
            let regs = fetch(code, pc + 1, 1)?;
            let off = fetch_i32(code, pc + 2)?;
            let rd = hi_nibble(regs);
            let rs = lo_nibble(regs);
            let op = match opcode {
                OP_LOAD8 => Op::Load8 { rd, rs, off },
                OP_LOAD16 => Op::Load16 { rd, rs, off },
                OP_LOAD32 => Op::Load32 { rd, rs, off },
                _ => Op::Load64 { rd, rs, off },
            };
            Ok((op, 6))
        }
        OP_STORE8 | OP_STORE16 | OP_STORE32 | OP_STORE64 => {
            let regs = fetch(code, pc + 1, 1)?;
            let off = fetch_i32(code, pc + 2)?;
            let rd = hi_nibble(regs);
            let rs = lo_nibble(regs);
            let op = match opcode {
                OP_STORE8 => Op::Store8 { rd, rs, off },
                OP_STORE16 => Op::Store16 { rd, rs, off },
                OP_STORE32 => Op::Store32 { rd, rs, off },
                _ => Op::Store64 { rd, rs, off },
            };
            Ok((op, 6))
        }
        OP_ADD | OP_SUB | OP_MUL | OP_DIVU | OP_MODU | OP_AND | OP_OR | OP_XOR | OP_SHL
        | OP_SHR | OP_SAR => {
            let r1 = fetch(code, pc + 1, 1)?;
            let r2 = fetch(code, pc + 2, 1)?;
            if lo_nibble(r2) != 0 {
                return Err(ProgramError::MalformedInstruction);
            }
            let rd = hi_nibble(r1);
            let ra = lo_nibble(r1);
            let rb = hi_nibble(r2);
            let op = match opcode {
                OP_ADD => Op::Add { rd, ra, rb },
                OP_SUB => Op::Sub { rd, ra, rb },
                OP_MUL => Op::Mul { rd, ra, rb },
                OP_DIVU => Op::Divu { rd, ra, rb },
                OP_MODU => Op::Modu { rd, ra, rb },
                OP_AND => Op::And { rd, ra, rb },
                OP_OR => Op::Or { rd, ra, rb },
                OP_XOR => Op::Xor { rd, ra, rb },
                OP_SHL => Op::Shl { rd, ra, rb },
                OP_SHR => Op::Shr { rd, ra, rb },
                _ => Op::Sar { rd, ra, rb },
            };
            Ok((op, 3))
        }
        OP_CMP => {
            let regs = fetch(code, pc + 1, 1)?;
            Ok((
                Op::Cmp {
                    ra: hi_nibble(regs),
                    rb: lo_nibble(regs),
                },
                2,
            ))
        }
        OP_JMP | OP_JEQ | OP_JNE | OP_JLT | OP_JLE | OP_JGT | OP_JGE => {
            let rel = fetch_i32(code, pc + 1)?;
            let op = match opcode {
                OP_JMP => Op::Jmp { rel },
                OP_JEQ => Op::Jeq { rel },
                OP_JNE => Op::Jne { rel },
                OP_JLT => Op::Jlt { rel },
                OP_JLE => Op::Jle { rel },
                OP_JGT => Op::Jgt { rel },
                _ => Op::Jge { rel },
            };
            Ok((op, 5))
        }
        OP_SHA256_COMPRESS | OP_SM3_COMPRESS | OP_SM4_ENC_BLOCK | OP_SM4_DEC_BLOCK => {
            let regs = fetch(code, pc + 1, 1)?;
            let rd = hi_nibble(regs);
            let rs = lo_nibble(regs);
            let op = match opcode {
                OP_SHA256_COMPRESS => Op::Sha256Compress { rd, rs },
                OP_SM3_COMPRESS => Op::Sm3Compress { rd, rs },
                OP_SM4_ENC_BLOCK => Op::Sm4EncBlock { rd, rs },
                _ => Op::Sm4DecBlock { rd, rs },
            };
            Ok((op, 2))
        }
        _ => Err(ProgramError::UnknownOpcode),
    }
}

const fn hi_nibble(b: u8) -> u8 {
    b >> 4
}

const fn lo_nibble(b: u8) -> u8 {
    b & 0x0F
}

/// 取 `code[at .. at+width]`，越界即判为指令被截断。
fn fetch(code: &[u8], at: usize, width: usize) -> Result<u8, ProgramError> {
    if width != 1 {
        return Err(ProgramError::MalformedInstruction);
    }
    code.get(at)
        .copied()
        .ok_or(ProgramError::MalformedInstruction)
}

fn fetch_u64(code: &[u8], at: usize) -> Result<u64, ProgramError> {
    let end = at.checked_add(8).ok_or(ProgramError::MalformedInstruction)?;
    let slice = code
        .get(at..end)
        .ok_or(ProgramError::MalformedInstruction)?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(slice);
    Ok(u64::from_le_bytes(buf))
}

fn fetch_i32(code: &[u8], at: usize) -> Result<i32, ProgramError> {
    let end = at.checked_add(4).ok_or(ProgramError::MalformedInstruction)?;
    let slice = code
        .get(at..end)
        .ok_or(ProgramError::MalformedInstruction)?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(slice);
    Ok(i32::from_le_bytes(buf))
}

pub fn checked_range(addr: u64, width: u64, mem_len: u64) -> Result<usize, ProgramError> {
    let end = addr.checked_add(width).ok_or(ProgramError::OutOfBounds)?;
    if end > mem_len {
        return Err(ProgramError::OutOfBounds);
    }
    Ok(addr as usize)
}

/// SHA-256 单块压缩（FIPS 180-4 §6.2.2）。
///
/// `mem[state_addr..+32]` 是 8 个 u32 大端状态，就地更新；
/// `mem[block_addr..+64]` 是数据块。
pub fn sha256_compress_at(
    state_addr: u64,
    block_addr: u64,
    mem: &mut [u8],
) -> Result<(), ProgramError> {
    let mem_len = mem.len() as u64;
    let s = checked_range(state_addr, 32, mem_len)?;
    let b = checked_range(block_addr, 64, mem_len)?;

    let mut state = [0u32; 8];
    for (i, word) in state.iter_mut().enumerate() {
        let at = s + 4 * i;
        *word = u32::from_be_bytes([mem[at], mem[at + 1], mem[at + 2], mem[at + 3]]);
    }
    let mut block = [0u8; 64];
    block.copy_from_slice(&mem[b..b + 64]);

    sha2::block_api::compress256(&mut state, &[block]);

    for (i, word) in state.iter().enumerate() {
        let at = s + 4 * i;
        mem[at..at + 4].copy_from_slice(&word.to_be_bytes());
    }
    Ok(())
}

/// SM3 单块压缩（GB/T 32907-2016）。
///
/// `mem[state_addr..+32]` 是 8 个 u32 大端状态，就地更新；
/// `mem[block_addr..+64]` 是数据块。
pub fn sm3_compress_at(
    state_addr: u64,
    block_addr: u64,
    mem: &mut [u8],
) -> Result<(), ProgramError> {
    let mem_len = mem.len() as u64;
    let s = checked_range(state_addr, 32, mem_len)?;
    let b = checked_range(block_addr, 64, mem_len)?;

    let mut state = [0u32; 8];
    for (i, word) in state.iter_mut().enumerate() {
        let at = s + 4 * i;
        *word = u32::from_be_bytes([mem[at], mem[at + 1], mem[at + 2], mem[at + 3]]);
    }
    let mut block = [0u8; 64];
    block.copy_from_slice(&mem[b..b + 64]);

    crate::sm3::sm3_compress(&mut state, &block);

    for (i, word) in state.iter().enumerate() {
        let at = s + 4 * i;
        mem[at..at + 4].copy_from_slice(&word.to_be_bytes());
    }
    Ok(())
}

/// SM4 单块 ECB 加密。
///
/// `mem[key_addr..+16]` 是密钥；`mem[block_addr..+16]` 就地替换为密文。
pub fn sm4_enc_block_at(
    key_addr: u64,
    block_addr: u64,
    mem: &mut [u8],
) -> Result<(), ProgramError> {
    let mem_len = mem.len() as u64;
    let k = checked_range(key_addr, 16, mem_len)?;
    let b = checked_range(block_addr, 16, mem_len)?;

    let mut key = [0u8; 16];
    key.copy_from_slice(&mem[k..k + 16]);
    let mut block = [0u8; 16];
    block.copy_from_slice(&mem[b..b + 16]);

    let out = crate::gm::sm4_ecb_encrypt_block(&key, &block);
    mem[b..b + 16].copy_from_slice(&out);
    Ok(())
}

/// SM4 单块 ECB 解密。
///
/// `mem[key_addr..+16]` 是密钥；`mem[block_addr..+16]` 就地替换为明文。
pub fn sm4_dec_block_at(
    key_addr: u64,
    block_addr: u64,
    mem: &mut [u8],
) -> Result<(), ProgramError> {
    let mem_len = mem.len() as u64;
    let k = checked_range(key_addr, 16, mem_len)?;
    let b = checked_range(block_addr, 16, mem_len)?;

    let mut key = [0u8; 16];
    key.copy_from_slice(&mem[k..k + 16]);
    let mut block = [0u8; 16];
    block.copy_from_slice(&mem[b..b + 16]);

    let out = crate::gm::sm4_ecb_decrypt_block(&key, &block);
    mem[b..b + 16].copy_from_slice(&out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个合法头部 + 任意 code 的完整程序字节。
    fn build(pages: u32, in_len: u32, out_len: u32, code: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + code.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(0);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&pages.to_le_bytes());
        out.extend_from_slice(&in_len.to_le_bytes());
        out.extend_from_slice(&out_len.to_le_bytes());
        out.extend_from_slice(&(code.len() as u32).to_le_bytes());
        out.extend_from_slice(code);
        out
    }

    fn hex_of(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    #[test]
    fn parses_minimal_halt_program() {
        let prog = parse(&hex_of(&build(1, 0, 0, &[OP_HALT]))).expect("valid program");
        assert_eq!(prog.header.pages, 1);
        assert_eq!(prog.header.code_len, 1);
        assert_eq!(prog.instrs.len(), 1);
        assert_eq!(prog.instrs[0].op, Op::Halt);
        assert_eq!(prog.instrs[0].pc, 0);
        assert_eq!(prog.instrs[0].len, 1);
    }

    #[test]
    fn parses_every_opcode_form() {
        let mut code = Vec::new();
        // F_NONE
        code.push(OP_NOP);
        code.push(OP_HALT);
        // F_RI64: MOVI r3, 0x0102030405060708
        code.push(OP_MOVI);
        code.push(0x30);
        code.extend_from_slice(&0x0102030405060708u64.to_le_bytes());
        // F_R: MOV r1, r2
        code.push(OP_MOV);
        code.push(0x12);
        // F_RI32: LOAD64 r4, [r5-8]
        code.push(OP_LOAD64);
        code.push(0x45);
        code.extend_from_slice(&(-8i32).to_le_bytes());
        // F_RR: ADD r6, r7, r8
        code.push(OP_ADD);
        code.push(0x67);
        code.push(0x80);
        // F_R: CMP r9, r10
        code.push(OP_CMP);
        code.push(0x9A);
        // F_J: JNE -10，目标 = 25 + 5 - 10 = 20（ADD 的起始位置）
        code.push(OP_JNE);
        code.extend_from_slice(&(-10i32).to_le_bytes());
        // 原语：SHA256 r11, r12
        code.push(OP_SHA256_COMPRESS);
        code.push(0xBC);

        let prog = parse(&hex_of(&build(1, 0, 0, &code))).expect("valid program");
        assert_eq!(prog.instrs.len(), 9);
        assert_eq!(prog.instrs[0].op, Op::Nop);
        assert_eq!(prog.instrs[1].op, Op::Halt);
        assert_eq!(
            prog.instrs[2].op,
            Op::Movi {
                rd: 3,
                imm: 0x0102030405060708
            }
        );
        assert_eq!(prog.instrs[2].len, 10);
        assert_eq!(prog.instrs[3].op, Op::Mov { rd: 1, rs: 2 });
        assert_eq!(
            prog.instrs[4].op,
            Op::Load64 {
                rd: 4,
                rs: 5,
                off: -8
            }
        );
        assert_eq!(
            prog.instrs[5].op,
            Op::Add {
                rd: 6,
                ra: 7,
                rb: 8
            }
        );
        assert_eq!(prog.instrs[6].op, Op::Cmp { ra: 9, rb: 10 });
        assert_eq!(prog.instrs[7].op, Op::Jne { rel: -10 });
        assert_eq!(prog.instrs[7].pc, 1 + 1 + 10 + 2 + 6 + 3 + 2);
        assert_eq!(prog.instrs[8].op, Op::Sha256Compress { rd: 11, rs: 12 });
        assert_eq!(prog.instrs[8].pc, 30);
    }

    #[test]
    fn accepts_backward_jump_to_first_instruction() {
        // JMP -5 落在偏移 0（自身），是合法的自旋循环（预算负责终止）。
        let mut code = Vec::new();
        code.push(OP_JMP);
        code.extend_from_slice(&(-5i32).to_le_bytes());
        let prog = parse(&hex_of(&build(1, 0, 0, &code))).expect("self loop is well-formed");
        assert_eq!(prog.instrs[0].op, Op::Jmp { rel: -5 });
    }

    #[test]
    fn rejects_legacy_program_without_magic() {
        // 旧格式（裸 opcode 串）必须被拒绝，且错误码是 vm_bad_magic。
        assert_eq!(
            parse("1011121314").unwrap_err(),
            ProgramError::BadMagic
        );
        assert_eq!(parse("1011121314").unwrap_err().code(), "vm_bad_magic");
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut bytes = build(1, 0, 0, &[OP_HALT]);
        bytes[0] = 0x4E; // 'N'
        assert_eq!(parse_bytes(&bytes).unwrap_err(), ProgramError::BadMagic);
    }

    #[test]
    fn rejects_tampered_magic_one_bit() {
        // 逐位翻转 magic：任何一位变化都必须被拒绝。
        let base = build(1, 0, 0, &[OP_HALT]);
        for byte_idx in 0..4 {
            for bit in 0..8 {
                let mut bytes = base.clone();
                bytes[byte_idx] ^= 1 << bit;
                assert_eq!(
                    parse_bytes(&bytes).unwrap_err(),
                    ProgramError::BadMagic,
                    "magic byte {} bit {} must be significant",
                    byte_idx,
                    bit
                );
            }
        }
    }

    #[test]
    fn rejects_unknown_version() {
        let mut bytes = build(1, 0, 0, &[OP_HALT]);
        bytes[4] = 0x02;
        assert_eq!(
            parse_bytes(&bytes).unwrap_err(),
            ProgramError::UnsupportedVersion
        );
    }

    #[test]
    fn rejects_nonzero_flags_and_reserved() {
        let mut flags = build(1, 0, 0, &[OP_HALT]);
        flags[5] = 0x01;
        assert_eq!(parse_bytes(&flags).unwrap_err(), ProgramError::BadFlags);

        let mut reserved = build(1, 0, 0, &[OP_HALT]);
        reserved[6] = 0x01;
        assert_eq!(parse_bytes(&reserved).unwrap_err(), ProgramError::BadFlags);
    }

    #[test]
    fn rejects_zero_and_oversized_pages() {
        assert_eq!(
            parse_bytes(&build(0, 0, 0, &[OP_HALT])).unwrap_err(),
            ProgramError::ProgramTooLarge
        );
        assert_eq!(
            parse_bytes(&build(MAX_PAGES + 1, 0, 0, &[OP_HALT])).unwrap_err(),
            ProgramError::ProgramTooLarge
        );
    }

    #[test]
    fn rejects_oversized_blobs() {
        assert_eq!(
            parse_bytes(&build(1, MAX_IN_BYTES + 1, 0, &[OP_HALT])).unwrap_err(),
            ProgramError::ProgramTooLarge
        );
        assert_eq!(
            parse_bytes(&build(1, 0, MAX_OUT_BYTES + 1, &[OP_HALT])).unwrap_err(),
            ProgramError::ProgramTooLarge
        );
    }

    #[test]
    fn rejects_trailing_bytes_and_truncated_code() {
        let mut extra = build(1, 0, 0, &[OP_HALT]);
        extra.push(0x00);
        assert_eq!(
            parse_bytes(&extra).unwrap_err(),
            ProgramError::TrailingBytes
        );

        let mut short = build(1, 0, 0, &[OP_HALT, OP_HALT]);
        short.pop();
        assert_eq!(parse_bytes(&short).unwrap_err(), ProgramError::TrailingBytes);
    }

    #[test]
    fn rejects_empty_code() {
        assert_eq!(
            parse_bytes(&build(1, 0, 0, &[])).unwrap_err(),
            ProgramError::ProgramTooLarge
        );
    }
    #[test]
    fn rejects_every_reserved_opcode() {
        for opcode in 0x23u8..=0xFF {
            let bytes = build(1, 0, 0, &[opcode]);
            assert_eq!(
                parse_bytes(&bytes).unwrap_err(),
                ProgramError::UnknownOpcode,
                "opcode {:#04x} must be reserved",
                opcode
            );
        }
    }

    #[test]
    fn rejects_nonzero_unused_nibbles() {
        // F_RI64 的 regs 低 nibble 必须为 0
        let mut movi = vec![OP_MOVI, 0x0F];
        movi.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(
            parse_bytes(&build(1, 0, 0, &movi)).unwrap_err(),
            ProgramError::MalformedInstruction
        );

        // F_RR 的第二个 regs 字节低 nibble 必须为 0
        let mut add = vec![OP_ADD, 0x11, 0x2F];
        add.push(OP_HALT);
        assert_eq!(
            parse_bytes(&build(1, 0, 0, &add)).unwrap_err(),
            ProgramError::MalformedInstruction
        );
    }

    #[test]
    fn rejects_truncated_instruction_at_end_of_code() {
        // MOVI 声明了 10 字节，但 code 只有 3 字节
        let code = vec![OP_MOVI, 0x00, 0x00];
        assert_eq!(
            parse_bytes(&build(1, 0, 0, &code)).unwrap_err(),
            ProgramError::MalformedInstruction
        );

        // 跳转指令只有 2 字节（应为 5）
        let code = vec![OP_JMP, 0x00];
        assert_eq!(
            parse_bytes(&build(1, 0, 0, &code)).unwrap_err(),
            ProgramError::MalformedInstruction
        );
    }

    #[test]
    fn rejects_jump_past_end_of_code() {
        // JMP +1 → 目标 = 5 + 1 = 6 > code.len()==5
        let mut code = vec![OP_JMP];
        code.extend_from_slice(&1i32.to_le_bytes());
        assert_eq!(
            parse_bytes(&build(1, 0, 0, &code)).unwrap_err(),
            ProgramError::BadJumpTarget
        );
    }

    #[test]
    fn rejects_jump_before_code_start() {
        let mut code = vec![OP_JMP];
        code.extend_from_slice(&(-6i32).to_le_bytes());
        assert_eq!(
            parse_bytes(&build(1, 0, 0, &code)).unwrap_err(),
            ProgramError::BadJumpTarget
        );
    }

    #[test]
    fn rejects_jump_into_middle_of_instruction() {
        // MOVI(10 字节) + JMP(-5)：目标 = 10 + 5 - 5 = 10，合法起始
        // 改为 -6 → 目标 9，落在 MOVI 中间，必须拒绝。
        let mut code = vec![OP_MOVI, 0x00];
        code.extend_from_slice(&0u64.to_le_bytes());
        code.push(OP_JMP);
        code.extend_from_slice(&(-6i32).to_le_bytes());
        assert_eq!(
            parse_bytes(&build(1, 0, 0, &code)).unwrap_err(),
            ProgramError::BadJumpTarget
        );

        // 同一程序改成 -5（目标 10 = JMP 自身起始）必须接受
        let mut ok = vec![OP_MOVI, 0x00];
        ok.extend_from_slice(&0u64.to_le_bytes());
        ok.push(OP_JMP);
        ok.extend_from_slice(&(-5i32).to_le_bytes());
        assert!(parse_bytes(&build(1, 0, 0, &ok)).is_ok());
    }

    #[test]
    fn rejects_bad_hex() {
        assert_eq!(
            parse("101112131").unwrap_err(),
            ProgramError::OddHexLength
        );
        assert_eq!(parse("zz").unwrap_err(), ProgramError::InvalidHex);
        assert_eq!(parse("4f57564d0").unwrap_err(), ProgramError::OddHexLength);
    }

    #[test]
    fn checked_range_rejects_overflow_and_oob() {
        assert_eq!(checked_range(0, 8, 1024).unwrap(), 0);
        assert_eq!(checked_range(1016, 8, 1024).unwrap(), 1016);
        // 刚好越界一个字节
        assert_eq!(
            checked_range(1017, 8, 1024).unwrap_err(),
            ProgramError::OutOfBounds
        );
        // u64 回绕
        assert_eq!(
            checked_range(u64::MAX, 8, 1024).unwrap_err(),
            ProgramError::OutOfBounds
        );
        assert_eq!(
            checked_range(u64::MAX - 3, 8, 1024).unwrap_err(),
            ProgramError::OutOfBounds
        );
    }

    #[test]
    fn primitives_reject_out_of_bounds_operands() {
        let mut mem = vec![0u8; 1024];
        assert_eq!(
            sha256_compress_at(1000, 0, &mut mem).unwrap_err(),
            ProgramError::OutOfBounds
        );
        assert_eq!(
            sha256_compress_at(0, 1000, &mut mem).unwrap_err(),
            ProgramError::OutOfBounds
        );
        assert_eq!(
            sm3_compress_at(u64::MAX, 0, &mut mem).unwrap_err(),
            ProgramError::OutOfBounds
        );
        assert_eq!(
            sm4_enc_block_at(0, 1010, &mut mem).unwrap_err(),
            ProgramError::OutOfBounds
        );
        assert_eq!(
            sm4_dec_block_at(1010, 0, &mut mem).unwrap_err(),
            ProgramError::OutOfBounds
        );
    }

    #[test]
    fn sha256_compress_matches_standard_vector() {
        // FIPS 180-4 附录 B.1 的第二个块：状态为第一个块的结果时，
        // 压缩 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        // 后得到完整摘要。这里用单块路径验证：压缩一个块后状态即为该摘要。
        let mut mem = vec![0u8; 4096];
        let iv: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        for (i, w) in iv.iter().enumerate() {
            mem[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
        // "abc" 的填充块
        let mut block = [0u8; 64];
        block[0] = b'a';
        block[1] = b'b';
        block[2] = b'c';
        block[3] = 0x80;
        block[63] = 24; // 比特长度 3*8
        mem[64..128].copy_from_slice(&block);

        sha256_compress_at(0, 64, &mut mem).expect("in-bounds compress");

        let want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let mut got = String::new();
        for i in 0..8 {
            let w = u32::from_be_bytes([mem[4 * i], mem[4 * i + 1], mem[4 * i + 2], mem[4 * i + 3]]);
            got.push_str(&format!("{:08x}", w));
        }
        assert_eq!(got, want);

        // 反向：篡改输入块的一个字节，结果必须改变
        let mut tampered = vec![0u8; 4096];
        tampered[..128].copy_from_slice(&mem[..128]);
        for (i, w) in iv.iter().enumerate() {
            tampered[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
        tampered[64] ^= 0x01;
        sha256_compress_at(0, 64, &mut tampered).expect("in-bounds compress");
        let mut got2 = String::new();
        for i in 0..8 {
            let w = u32::from_be_bytes([
                tampered[4 * i],
                tampered[4 * i + 1],
                tampered[4 * i + 2],
                tampered[4 * i + 3],
            ]);
            got2.push_str(&format!("{:08x}", w));
        }
        assert_ne!(got2, want);
    }

    #[test]
    fn sm3_compress_matches_sm3_digest() {
        // 单块路径压缩 "abc" 的填充块，结果必须等于 sm3_digest("abc")。
        let mut mem = vec![0u8; 4096];
        let iv: [u32; 8] = [
            0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d,
            0xb0fb0e4e,
        ];
        for (i, w) in iv.iter().enumerate() {
            mem[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
        let mut block = [0u8; 64];
        block[0] = b'a';
        block[1] = b'b';
        block[2] = b'c';
        block[3] = 0x80;
        block[63] = 24;
        mem[64..128].copy_from_slice(&block);

        sm3_compress_at(0, 64, &mut mem).expect("in-bounds compress");

        let want = crate::sm3::sm3_digest(b"abc");
        let mut got = [0u8; 32];
        got.copy_from_slice(&mem[..32]);
        assert_eq!(got, want);

        // 反向：篡改块内容必须改变状态
        let mut tampered = vec![0u8; 4096];
        for (i, w) in iv.iter().enumerate() {
            tampered[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
        tampered[64..128].copy_from_slice(&block);
        tampered[65] ^= 0x01;
        sm3_compress_at(0, 64, &mut tampered).expect("in-bounds compress");
        assert_ne!(&tampered[..32], &want[..]);
    }

    #[test]
    fn sm4_block_roundtrip_and_rejects_tamper() {
        let mut mem = vec![0u8; 4096];
        let key: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let plain: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        mem[..16].copy_from_slice(&key);
        mem[64..80].copy_from_slice(&plain);

        sm4_enc_block_at(0, 64, &mut mem).expect("encrypt");
        let cipher: Vec<u8> = mem[64..80].to_vec();
        assert_ne!(cipher, plain, "ciphertext must differ from plaintext");

        sm4_dec_block_at(0, 64, &mut mem).expect("decrypt");
        assert_eq!(&mem[64..80], &plain, "decrypt must invert encrypt");

        // 反向：改密钥后密文必须不同
        mem[0] ^= 0xFF;
        mem[64..80].copy_from_slice(&plain);
        sm4_enc_block_at(0, 64, &mut mem).expect("encrypt with other key");
        assert_ne!(&mem[64..80], &cipher[..]);
    }

    #[test]
    fn error_codes_are_stable() {
        // 错误码是对 JS 侧可见的契约，逐条锁定。
        let cases = [
            (ProgramError::BadMagic, "vm_bad_magic"),
            (ProgramError::UnsupportedVersion, "vm_unsupported_version"),
            (ProgramError::BadFlags, "vm_bad_flags"),
            (ProgramError::TrailingBytes, "vm_trailing_bytes"),
            (ProgramError::ProgramTooLarge, "vm_program_too_large"),
            (ProgramError::BatchTooLarge, "vm_batch_too_large"),
            (ProgramError::UnknownOpcode, "unknown_vm_opcode"),
            (ProgramError::MalformedInstruction, "vm_malformed_instruction"),
            (ProgramError::OutOfBounds, "vm_out_of_bounds"),
            (ProgramError::DivByZero, "vm_div_by_zero"),
            (ProgramError::BadJumpTarget, "vm_bad_jump_target"),
            (ProgramError::BudgetExhausted, "vm_budget_exhausted"),
            (ProgramError::InvalidHex, "invalid_vm_hex"),
            (ProgramError::OddHexLength, "odd_vm_hex_length"),
            (ProgramError::OutputMagic, "vm_output_magic"),
        ];
        for (err, want) in cases {
            assert_eq!(err.code(), want);
        }
    }
}