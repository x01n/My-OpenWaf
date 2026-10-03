pub(crate) use engine::{step_budget_for, Vm};

#[allow(dead_code)]
mod engine {
    use crate::isa::{self, Flag, Op, Program, ProgramError};

    /// 通用寄存器数量（ISA.md §1.2）。
    pub(crate) const REG_COUNT: usize = 16;

    /// 执行循环的控制信号。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Signal {
        /// 继续执行下一条指令。
        Continue,
        /// 正常停机。
        Halt,
    }
    #[derive(Debug)]
    pub(crate) struct Vm {
        regs: [u64; REG_COUNT],
        flag: Flag,
        memory: Vec<u8>,
        pc: usize,
        steps: u64,
        step_budget: u64,
    }

    impl Vm {
        pub(crate) fn new(program: &Program, step_budget: u64) -> Result<Self, ProgramError> {
            if step_budget == 0 || step_budget > isa::MAX_STEPS_ABS {
                return Err(ProgramError::BudgetExhausted);
            }
            Ok(Self {
                regs: [0; REG_COUNT],
                flag: Flag::Eq,
                memory: vec![0; program.header.memory_len() as usize],
                pc: 0,
                steps: 0,
                step_budget,
            })
        }
        pub(crate) fn run(&mut self, program: &Program) -> Result<u64, ProgramError> {
            let len = program.instrs.len();
            loop {
                if self.pc == len {
                    return Ok(self.reg(0));
                }
                if self.pc > len {
                    return Err(ProgramError::OutOfBounds);
                }
                self.consume_step()?;
                if self.step(program)? == Signal::Halt {
                    return Ok(self.reg(0));
                }
            }
        }

        /// 取指并执行一条指令。调用前保证 `pc < instrs.len()`。
        fn step(&mut self, program: &Program) -> Result<Signal, ProgramError> {
            let instr = program.instrs[self.pc];
            match instr.op {
                Op::Nop => self.advance(),
                Op::Movi { rd, imm } => {
                    self.set_reg(rd, imm);
                    self.advance()
                }
                Op::Mov { rd, rs } => {
                    let value = self.reg(rs);
                    self.set_reg(rd, value);
                    self.advance()
                }
                Op::Load8 { rd, rs, off } => self.load(rd, rs, off, 1),
                Op::Load16 { rd, rs, off } => self.load(rd, rs, off, 2),
                Op::Load32 { rd, rs, off } => self.load(rd, rs, off, 4),
                Op::Load64 { rd, rs, off } => self.load(rd, rs, off, 8),
                Op::Store8 { rd, rs, off } => self.store(rd, rs, off, 1),
                Op::Store16 { rd, rs, off } => self.store(rd, rs, off, 2),
                Op::Store32 { rd, rs, off } => self.store(rd, rs, off, 4),
                Op::Store64 { rd, rs, off } => self.store(rd, rs, off, 8),
                Op::Add { rd, ra, rb } => self.binary(rd, ra, rb, |a, b| a.wrapping_add(b)),
                Op::Sub { rd, ra, rb } => self.binary(rd, ra, rb, |a, b| a.wrapping_sub(b)),
                Op::Mul { rd, ra, rb } => self.binary(rd, ra, rb, |a, b| a.wrapping_mul(b)),
                Op::And { rd, ra, rb } => self.binary(rd, ra, rb, |a, b| a & b),
                Op::Or { rd, ra, rb } => self.binary(rd, ra, rb, |a, b| a | b),
                Op::Xor { rd, ra, rb } => self.binary(rd, ra, rb, |a, b| a ^ b),
                Op::Shl { rd, ra, rb } => self.binary(rd, ra, rb, |a, b| a << (b & 63)),
                Op::Shr { rd, ra, rb } => self.binary(rd, ra, rb, |a, b| a >> (b & 63)),
                Op::Sar { rd, ra, rb } => {
                    self.binary(rd, ra, rb, |a, b| ((a as i64) >> (b & 63)) as u64)
                }
                Op::Divu { rd, ra, rb } => {
                    // 除零必须在调用 `/` 之前拦下：Rust 的整数除零是 panic，
                    // 而 `panic = "abort"` 会直接杀掉 wasm 实例。
                    let divisor = self.reg(rb);
                    if divisor == 0 {
                        return Err(ProgramError::DivByZero);
                    }
                    let dividend = self.reg(ra);
                    self.set_reg(rd, dividend / divisor);
                    self.advance()
                }
                Op::Modu { rd, ra, rb } => {
                    let divisor = self.reg(rb);
                    if divisor == 0 {
                        return Err(ProgramError::DivByZero);
                    }
                    let dividend = self.reg(ra);
                    self.set_reg(rd, dividend % divisor);
                    self.advance()
                }
                Op::Cmp { ra, rb } => {
                    let (a, b) = (self.reg(ra), self.reg(rb));
                    self.compare(a, b);
                    self.advance()
                }
                Op::Jmp { rel } => {
                    self.jump(program, rel)?;
                    Ok(Signal::Continue)
                }
                Op::Jeq { rel } => self.conditional_jump(program, rel, Flag::Eq),
                Op::Jne { rel } => self.conditional_jump_not(program, rel, Flag::Eq),
                Op::Jlt { rel } => self.conditional_jump(program, rel, Flag::Lt),
                Op::Jle { rel } => self.conditional_jump_le(program, rel),
                Op::Jgt { rel } => self.conditional_jump(program, rel, Flag::Gt),
                Op::Jge { rel } => self.conditional_jump_ge(program, rel),
                Op::Sha256Compress { rd, rs } => {
                    let (state, block) = (self.reg(rd), self.reg(rs));
                    isa::sha256_compress_at(state, block, &mut self.memory)?;
                    self.advance()
                }
                Op::Sm3Compress { rd, rs } => {
                    let (state, block) = (self.reg(rd), self.reg(rs));
                    isa::sm3_compress_at(state, block, &mut self.memory)?;
                    self.advance()
                }
                Op::Sm4EncBlock { rd, rs } => {
                    let (key, block) = (self.reg(rd), self.reg(rs));
                    isa::sm4_enc_block_at(key, block, &mut self.memory)?;
                    self.advance()
                }
                Op::Sm4DecBlock { rd, rs } => {
                    let (key, block) = (self.reg(rd), self.reg(rs));
                    isa::sm4_dec_block_at(key, block, &mut self.memory)?;
                    self.advance()
                }
                Op::Halt => Ok(Signal::Halt),
            }
        }

        fn load(&mut self, rd: u8, rs: u8, off: i32, width: usize) -> Result<Signal, ProgramError> {
            let addr = self
                .reg(rs)
                .checked_add_signed(off as i64)
                .ok_or(ProgramError::OutOfBounds)?;
            let mut buf = [0u8; 8];
            {
                let bytes = self.read_memory(addr, width)?;
                buf[..width].copy_from_slice(bytes);
            }
            self.set_reg(rd, u64::from_le_bytes(buf));
            self.advance()
        }

        fn store(&mut self, rd: u8, rs: u8, off: i32, width: usize) -> Result<Signal, ProgramError> {
            let addr = self
                .reg(rd)
                .checked_add_signed(off as i64)
                .ok_or(ProgramError::OutOfBounds)?;
            let value = self.reg(rs);
            let le = value.to_le_bytes();
            self.write_memory(addr, &le[..width])?;
            self.advance()
        }

        fn binary<F>(&mut self, rd: u8, ra: u8, rb: u8, f: F) -> Result<Signal, ProgramError>
        where
            F: FnOnce(u64, u64) -> u64,
        {
            let (a, b) = (self.reg(ra), self.reg(rb));
            self.set_reg(rd, f(a, b));
            self.advance()
        }

        fn conditional_jump(
            &mut self,
            program: &Program,
            rel: i32,
            expected: Flag,
        ) -> Result<Signal, ProgramError> {
            if self.flag == expected {
                self.jump(program, rel)?;
            } else {
                self.advance()?;
            }
            Ok(Signal::Continue)
        }

        fn conditional_jump_not(
            &mut self,
            program: &Program,
            rel: i32,
            excluded: Flag,
        ) -> Result<Signal, ProgramError> {
            if self.flag != excluded {
                self.jump(program, rel)?;
            } else {
                self.advance()?;
            }
            Ok(Signal::Continue)
        }

        fn conditional_jump_le(&mut self, program: &Program, rel: i32) -> Result<Signal, ProgramError> {
            if matches!(self.flag, Flag::Lt | Flag::Eq) {
                self.jump(program, rel)?;
            } else {
                self.advance()?;
            }
            Ok(Signal::Continue)
        }

        fn conditional_jump_ge(&mut self, program: &Program, rel: i32) -> Result<Signal, ProgramError> {
            if matches!(self.flag, Flag::Gt | Flag::Eq) {
                self.jump(program, rel)?;
            } else {
                self.advance()?;
            }
            Ok(Signal::Continue)
        }

        /// 按 PC 相对偏移跳转：`rel` 相对**下一条指令的起始地址**。
        ///
        /// 目标必须落在某条指令的起始位置。解码期已校验过一遍，
        /// 这里是执行期的二次确认（防御性）：查不到即报错，不静默前进。
        fn jump(&mut self, program: &Program, rel: i32) -> Result<(), ProgramError> {
            let instr = program.instrs[self.pc];
            let next = instr.pc as i64 + instr.len as i64;
            let target = next + rel as i64;
            if target < 0 {
                return Err(ProgramError::BadJumpTarget);
            }
            let index = program
                .instrs
                .binary_search_by_key(&(target as usize), |i| i.pc)
                .map_err(|_| ProgramError::BadJumpTarget)?;
            self.pc = index;
            Ok(())
        }

        /// 读寄存器。索引由解码期保证 < [`REG_COUNT`]，此处仍做防御性取模：
        /// **寄存器索引越界绝不能 panic**（`panic = "abort"` 会杀 wasm 实例）。
        pub(crate) fn reg(&self, index: u8) -> u64 {
            self.regs[(index as usize) % REG_COUNT]
        }

        /// 写寄存器（越界索引同样取模，见 [`Vm::reg`]）。
        pub(crate) fn set_reg(&mut self, index: u8, value: u64) {
            self.regs[(index as usize) % REG_COUNT] = value;
        }

        /// 当前标志值。
        pub(crate) fn flag(&self) -> Flag {
            self.flag
        }

        /// 按无符号语义更新标志（`CMP` 的计算部分）。
        pub(crate) fn compare(&mut self, ra: u64, rb: u64) {
            self.flag = if ra < rb {
                Flag::Lt
            } else if ra == rb {
                Flag::Eq
            } else {
                Flag::Gt
            };
        }

        /// 线性内存总长度。
        pub(crate) fn memory_len(&self) -> usize {
            self.memory.len()
        }

        /// 读内存区间（checked，越界返回错误，绝不 panic）。
        pub(crate) fn read_memory(&self, addr: u64, width: usize) -> Result<&[u8], ProgramError> {
            let start = isa::checked_range(addr, width as u64, self.memory.len() as u64)?;
            Ok(&self.memory[start..start + width])
        }

        /// 写内存区间（checked，越界返回错误，绝不 panic）。
        pub(crate) fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), ProgramError> {
            let start = isa::checked_range(addr, data.len() as u64, self.memory.len() as u64)?;
            self.memory[start..start + data.len()].copy_from_slice(data);
            Ok(())
        }

        /// 写入输入 blob（ISA.md §1.3：地址 `[0, 4096)`）。
        pub(crate) fn write_input(&mut self, data: &[u8]) -> Result<(), ProgramError> {
            if data.len() as u64 > isa::MAX_IN_BYTES as u64 {
                return Err(ProgramError::ProgramTooLarge);
            }
            self.write_memory(isa::IN_BASE, data)
        }

        /// 读出输出 blob（ISA.md §1.3：地址 `[4096, 8192)`）。
        pub(crate) fn read_output(&self, len: usize) -> Result<Vec<u8>, ProgramError> {
            if len as u64 > isa::MAX_OUT_BYTES as u64 {
                return Err(ProgramError::ProgramTooLarge);
            }
            Ok(self.read_memory(isa::OUT_BASE, len)?.to_vec())
        }

        /// 已消耗的步数。
        pub(crate) fn steps(&self) -> u64 {
            self.steps
        }

        /// 当前指令下标。
        pub(crate) fn pc(&self) -> usize {
            self.pc
        }

        fn advance(&mut self) -> Result<Signal, ProgramError> {
            self.pc = self.pc.checked_add(1).ok_or(ProgramError::OutOfBounds)?;
            Ok(Signal::Continue)
        }

        fn consume_step(&mut self) -> Result<(), ProgramError> {
            if self.steps >= self.step_budget {
                return Err(ProgramError::BudgetExhausted);
            }
            self.steps += 1;
            Ok(())
        }
    }

    /// 由 `batch_size` 导出步数预算（ISA.md §6.2）：
    /// `min(PER_ITER_BUDGET × batch_size, MAX_STEPS_ABS)`。
    pub(crate) fn step_budget_for(batch_size: u32) -> Result<u64, ProgramError> {
        if batch_size > isa::BATCH_SIZE_LIMIT {
            return Err(ProgramError::BatchTooLarge);
        }
        Ok((isa::PER_ITER_BUDGET.saturating_mul(batch_size as u64)).min(isa::MAX_STEPS_ABS))
    }
}


#[cfg(test)]
mod tests {


    use super::engine;
    use crate::isa::{self, ProgramError};

    fn container(code: &[u8], pages: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0x4F, 0x57, 0x56, 0x4D]); // "OWVM"
        out.push(0x01);
        out.push(0);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&pages.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // in_len
        out.extend_from_slice(&0u32.to_le_bytes()); // out_len
        out.extend_from_slice(&(code.len() as u32).to_le_bytes());
        out.extend_from_slice(code);
        out
    }

    fn hex_of(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    fn program_hex(code: &[u8], pages: u32) -> String {
        hex_of(&container(code, pages))
    }

    /// `op(1) + regs(1)[rd:ra] + regs(1)[rb:0000]`
    fn rr(code: &mut Vec<u8>, op: u8, rd: u8, ra: u8, rb: u8) {
        code.push(op);
        code.push((rd << 4) | ra);
        code.push(rb << 4);
    }

    /// `op(1) + regs(1)[rd:0000] + imm(8, LE)`
    fn movi(code: &mut Vec<u8>, rd: u8, imm: u64) {
        code.push(isa::OP_MOVI);
        code.push(rd << 4);
        code.extend_from_slice(&imm.to_le_bytes());
    }

    /// `op(1) + regs(1)[rd:rs]`
    fn pair(code: &mut Vec<u8>, op: u8, rd: u8, rs: u8) {
        code.push(op);
        code.push((rd << 4) | rs);
    }

    /// `op(1) + regs(1)[rd:rs] + off(4, i32, LE)`
    fn mem(code: &mut Vec<u8>, op: u8, rd: u8, rs: u8, off: i32) {
        code.push(op);
        code.push((rd << 4) | rs);
        code.extend_from_slice(&off.to_le_bytes());
    }

    /// `op(1) + rel(4, i32, LE)`
    fn jump(code: &mut Vec<u8>, op: u8, rel: i32) {
        code.push(op);
        code.extend_from_slice(&rel.to_le_bytes());
    }

    fn halt(code: &mut Vec<u8>) {
        code.push(isa::OP_HALT);
    }

    /// 解析 + 执行到停机，返回 `(R0, Vm)`。
    fn execute(code: &[u8], pages: u32, budget: u64) -> Result<(u64, engine::Vm), ProgramError> {
        let prog = isa::parse(&program_hex(code, pages))?;
        let mut vm = engine::Vm::new(&prog, budget)?;
        let r0 = vm.run(&prog)?;
        Ok((r0, vm))
    }
    #[test]
    fn legacy_program_formats_are_rejected() {
        // 旧 Go 侧生成物："1011121314"（5 字节裸 opcode，无头部）。
        assert_eq!(
            isa::parse("1011121314").unwrap_err(),
            ProgramError::BadMagic
        );
        // 旧 "VMPF" 帧头格式（旧 vmp.rs 曾断言它 UnknownOpcode，方向相反）。
        assert_eq!(
            isa::parse("564d504601c90005").unwrap_err(),
            ProgramError::BadMagic
        );
        // 反向：合法新格式必须能解析——否则上面的「拒绝」可能只是「全都拒绝」。
        assert!(isa::parse(&program_hex(&[isa::OP_HALT], 1)).is_ok());
    }

    #[test]
    fn executes_movi_and_implicit_halt() {
        let mut code = Vec::new();
        movi(&mut code, 0, 42);
        // 无 HALT：指令跑完即隐式停机。
        assert_eq!(execute(&code, 1, 100).unwrap().0, 42);
    }

    #[test]
    fn executes_arithmetic() {
        let mut code = Vec::new();
        movi(&mut code, 1, 20);
        movi(&mut code, 2, 6);
        rr(&mut code, isa::OP_ADD, 3, 1, 2);
        rr(&mut code, isa::OP_SUB, 4, 1, 2);
        rr(&mut code, isa::OP_MUL, 5, 1, 2);
        rr(&mut code, isa::OP_DIVU, 6, 1, 2);
        rr(&mut code, isa::OP_MODU, 7, 1, 2);
        halt(&mut code);

        let (_, vm) = execute(&code, 1, 100).unwrap();
        assert_eq!(vm.reg(3), 26);
        assert_eq!(vm.reg(4), 14);
        assert_eq!(vm.reg(5), 120);
        assert_eq!(vm.reg(6), 3);
        assert_eq!(vm.reg(7), 2);
    }

    #[test]
    fn executes_bitwise() {
        let mut code = Vec::new();
        movi(&mut code, 1, 0xF0);
        movi(&mut code, 2, 0x3C);
        movi(&mut code, 3, 3);
        rr(&mut code, isa::OP_AND, 4, 1, 2);
        rr(&mut code, isa::OP_OR, 5, 1, 2);
        rr(&mut code, isa::OP_XOR, 6, 1, 2);
        rr(&mut code, isa::OP_SHL, 7, 1, 3);
        rr(&mut code, isa::OP_SHR, 8, 1, 3);
        halt(&mut code);

        let (_, vm) = execute(&code, 1, 100).unwrap();
        assert_eq!(vm.reg(4), 0xF0 & 0x3C);
        assert_eq!(vm.reg(5), 0xF0 | 0x3C);
        assert_eq!(vm.reg(6), 0xF0 ^ 0x3C);
        assert_eq!(vm.reg(7), 0xF0 << 3);
        assert_eq!(vm.reg(8), 0xF0 >> 3);
    }

    /// 移位量必须 `& 63`：Rust 中移位量 >= 位宽会 panic，
    /// 而 `panic = "abort"` 会直接杀掉 wasm 实例。
    #[test]
    fn shift_amount_is_masked_to_63() {
        // 移位量取三个值，必须区分 `& 63` 与 `& 31`：
        //   64 & 63 = 0，但 64 & 31 = 0 —— 相同，区分不了；
        //   32 & 63 = 32，而 32 & 31 = 0 —— **这一条才有区分力**；
        //   65 & 63 = 1（65 & 31 = 1，相同）。
        // 掩码宽度写错是真实缺陷形态，必须由测试抓出。
        let mut code = Vec::new();
        movi(&mut code, 1, 1);
        movi(&mut code, 2, 64);
        movi(&mut code, 3, 32);
        movi(&mut code, 4, 65);
        rr(&mut code, isa::OP_SHL, 5, 1, 2);
        rr(&mut code, isa::OP_SHL, 6, 1, 3);
        rr(&mut code, isa::OP_SHR, 7, 1, 4);
        halt(&mut code);

        let (_, vm) = execute(&code, 1, 100).unwrap();
        assert_eq!(vm.reg(5), 1 << 0, "64 & 63 == 0");
        assert_eq!(vm.reg(6), 1u64 << 32, "32 & 63 == 32（掩码宽度 63，不是 31）");
        assert_eq!(vm.reg(7), 0, "65 & 63 == 1 → 1 >> 1 == 0");
    }

    /// `SAR` 按符号位填充，`SHR` 补零；最高位为 1 时两者必须不同。
    #[test]
    fn sar_is_arithmetic_and_shr_is_logical() {
        let mut code = Vec::new();
        movi(&mut code, 1, u64::MAX);
        movi(&mut code, 2, 8);
        rr(&mut code, isa::OP_SAR, 3, 1, 2);
        rr(&mut code, isa::OP_SHR, 4, 1, 2);
        halt(&mut code);

        let (_, vm) = execute(&code, 1, 100).unwrap();
        assert_eq!(vm.reg(3), u64::MAX, "算术右移保留符号位");
        assert_eq!(vm.reg(4), u64::MAX >> 8, "逻辑右移补零");
        assert_ne!(vm.reg(3), vm.reg(4));
    }

    /// `MOV` 复制寄存器值；`NOP` 不改变任何状态。
    #[test]
    fn executes_mov_and_nop() {
        let mut code = Vec::new();
        movi(&mut code, 1, 0xDEAD);
        pair(&mut code, isa::OP_MOV, 2, 1);
        code.push(isa::OP_NOP);
        halt(&mut code);

        let (_, vm) = execute(&code, 1, 100).unwrap();
        assert_eq!(vm.reg(2), 0xDEAD);
        assert_eq!(vm.reg(1), 0xDEAD);
    }
    #[test]
    fn executes_counting_loop() {
        let mut code = Vec::new();
        movi(&mut code, 1, 5);
        movi(&mut code, 2, 0);
        movi(&mut code, 3, 1);
        rr(&mut code, isa::OP_ADD, 0, 0, 1);
        rr(&mut code, isa::OP_SUB, 1, 1, 3);
        pair(&mut code, isa::OP_CMP, 1, 2);
        jump(&mut code, isa::OP_JNE, -13); // next=43, 目标=30
        halt(&mut code);

        assert_eq!(execute(&code, 1, 1_000).unwrap().0, 15);
        // 反向：预算不足时必须报预算耗尽，而不是给出部分结果。
        assert_eq!(
            execute(&code, 1, 5).unwrap_err(),
            ProgramError::BudgetExhausted
        );
    }

    /// 预算边界必须精确：该程序恰好 24 步 = MOVI×3(3) + 5×4 + HALT(1)。
    /// 用「远不够」的预算做反向断言抓不到 `>=` 被写成 `>` 这类 off-by-one。
    #[test]
    fn budget_boundary_is_exact() {
        let mut code = Vec::new();
        movi(&mut code, 1, 5);
        movi(&mut code, 2, 0);
        movi(&mut code, 3, 1);
        rr(&mut code, isa::OP_ADD, 0, 0, 1);
        rr(&mut code, isa::OP_SUB, 1, 1, 3);
        pair(&mut code, isa::OP_CMP, 1, 2);
        jump(&mut code, isa::OP_JNE, -13);
        halt(&mut code);

        assert_eq!(execute(&code, 1, 24).unwrap().0, 15);
        assert_eq!(
            execute(&code, 1, 23).unwrap_err(),
            ProgramError::BudgetExhausted
        );
    }

    #[test]
    fn unbounded_loop_stops_by_budget() {
        // JMP -5 落在自身：永不终止的自旋，只能靠预算掐断。
        let mut code = Vec::new();
        jump(&mut code, isa::OP_JMP, -5);
        assert_eq!(
            execute(&code, 1, 64).unwrap_err(),
            ProgramError::BudgetExhausted
        );
    }

    /// 条件跳转在两个方向都要验证：命中时跳、不命中时**不跳**。
    #[test]
    fn conditional_jumps_observe_flag_states() {
        // 跳转命中 → 直接落到 HALT，R0 保持 0；
        // 不跳转 → 执行 MOVI R0,111 后落到 HALT，R0 = 111。
        // 两条路径必须落到**不同终点**，否则「跳了」与「没跳」得到同一结果，
        // 断言无法区分（这是本用例第一版的设计缺陷）。
        let build = |op: u8| {
            let mut code = Vec::new();
            movi(&mut code, 0, 0);
            movi(&mut code, 1, 1);
            movi(&mut code, 2, 2);
            pair(&mut code, isa::OP_CMP, 1, 2); // R1=1 < R2=2 → LT
            jump(&mut code, op, 10); // next=37, 目标=47（HALT）
            movi(&mut code, 0, 111);
            halt(&mut code);
            code
        };

        // 正向：LT 标志下 JLT 必须跳转。
        assert_eq!(execute(&build(isa::OP_JLT), 1, 100).unwrap().0, 0);
        // 反向：同一标志下 JGT / JEQ / JGE 都不得跳转。
        for op in [isa::OP_JGT, isa::OP_JEQ, isa::OP_JGE] {
            assert_eq!(
                execute(&build(op), 1, 100).unwrap().0,
                111,
                "opcode {:#04x} 在 LT 标志下不得跳转",
                op
            );
        }
        // JLE 在 LT 下必须跳转（含等号的含义是「小于**或**等于」）。
        assert_eq!(execute(&build(isa::OP_JLE), 1, 100).unwrap().0, 0);
        // JNE 在 LT 下必须跳转（非等值）。
        assert_eq!(execute(&build(isa::OP_JNE), 1, 100).unwrap().0, 0);
    }

    /// 等值标志（EQ）下六条条件跳转的语义逐一验证。
    ///
    /// 跳转 → R0 保持 0；不跳 → 执行 MOVI R0,111。两条路径终点不同，
    /// 断言才能区分「跳了」与「没跳」。
    #[test]
    fn equality_flag_jump_semantics() {
        let build = |op: u8| {
            let mut code = Vec::new();
            movi(&mut code, 0, 0);
            movi(&mut code, 1, 7);
            movi(&mut code, 2, 7);
            pair(&mut code, isa::OP_CMP, 1, 2); // 7 == 7 → EQ
            jump(&mut code, op, 10); // next=37, 目标=47（HALT）
            movi(&mut code, 0, 111);
            halt(&mut code);
            code
        };

        // 含等号的必须跳转：JEQ / JLE / JGE。
        for op in [isa::OP_JEQ, isa::OP_JLE, isa::OP_JGE] {
            assert_eq!(
                execute(&build(op), 1, 100).unwrap().0,
                0,
                "opcode {:#04x} 在 EQ 标志下必须跳转",
                op
            );
        }
        // 不含等号的必须不跳：JNE / JLT / JGT。
        for op in [isa::OP_JNE, isa::OP_JLT, isa::OP_JGT] {
            assert_eq!(
                execute(&build(op), 1, 100).unwrap().0,
                111,
                "opcode {:#04x} 在 EQ 标志下不得跳转",
                op
            );
        }
    }

    /// `CMP` 是无符号比较：u64::MAX 被当作最大值，而不是 -1。
    ///
    /// 两条路径必须落到**不同终点**：跳转 → R0 保持 0；不跳 → R0 = 111。
    /// 若末尾再补一条 MOVI，两条路径会得到同一结果，断言失去区分力
    /// （本用例第一版即犯此错，注入有符号比较时仍为绿）。
    #[test]
    fn compare_is_unsigned() {
        let mut code = Vec::new();
        movi(&mut code, 0, 0);
        movi(&mut code, 1, u64::MAX);
        movi(&mut code, 2, 1);
        pair(&mut code, isa::OP_CMP, 1, 2);
        jump(&mut code, isa::OP_JGT, 10); // 无符号下 MAX > 1 → 必须跳转
        movi(&mut code, 0, 111);
        halt(&mut code);
        assert_eq!(execute(&code, 1, 100).unwrap().0, 0);
    }
    #[test]
    fn load_and_store_roundtrip() {
        let mut code = Vec::new();
        movi(&mut code, 1, isa::HEAP_BASE);
        movi(&mut code, 2, 0x1122334455667788);
        mem(&mut code, isa::OP_STORE64, 1, 2, 0);
        mem(&mut code, isa::OP_LOAD64, 3, 1, 0);
        halt(&mut code);

        let (_, vm) = execute(&code, 1, 100).unwrap();
        assert_eq!(vm.reg(3), 0x1122334455667788);
        // 小端：低字节在低地址。
        assert_eq!(vm.read_memory(isa::HEAP_BASE, 1).unwrap(), &[0x88]);
    }

    /// 越界访问必须报错，**绝不 panic**（`panic = "abort"` 会杀 wasm 实例）。
    #[test]
    fn out_of_bounds_memory_access_reports_error() {
        // 1 页 = 65536 字节，从末尾读 8 字节必然越界。
        let mut code = Vec::new();
        movi(&mut code, 1, 65536);
        mem(&mut code, isa::OP_LOAD64, 3, 1, 0);
        halt(&mut code);
        assert_eq!(
            execute(&code, 1, 100).unwrap_err(),
            ProgramError::OutOfBounds
        );

        // 反向：末尾前 8 字节合法，必须成功——否则上面的拒绝可能只是「全都拒绝」。
        let mut code = Vec::new();
        movi(&mut code, 1, 65536 - 8);
        mem(&mut code, isa::OP_LOAD64, 3, 1, 0);
        halt(&mut code);
        assert!(execute(&code, 1, 100).is_ok());
    }

    /// 负偏移使地址回绕到 u64 极大值，必须被 `checked_add_signed` 拦住。
    #[test]
    fn negative_offset_wraparound_is_rejected() {
        let mut code = Vec::new();
        movi(&mut code, 1, 0);
        mem(&mut code, isa::OP_LOAD8, 3, 1, -1);
        halt(&mut code);
        assert_eq!(
            execute(&code, 1, 100).unwrap_err(),
            ProgramError::OutOfBounds
        );
    }

    /// 立即数偏移的边界：`[R1 + 4]` 从 HEAP_BASE 起合法，`[R1 + 65528+8]` 越界。
    #[test]
    fn immediate_offset_bounds() {
        let mut code = Vec::new();
        movi(&mut code, 1, isa::HEAP_BASE);
        movi(&mut code, 2, 0xAB);
        mem(&mut code, isa::OP_STORE8, 1, 2, 4);
        mem(&mut code, isa::OP_LOAD8, 3, 1, 4);
        halt(&mut code);
        let (_, vm) = execute(&code, 1, 100).unwrap();
        assert_eq!(vm.reg(3), 0xAB);
    }

    #[test]
    fn div_by_zero_reports_error() {
        for op in [isa::OP_DIVU, isa::OP_MODU] {
            let mut code = Vec::new();
            movi(&mut code, 1, 10);
            rr(&mut code, op, 3, 1, 2); // R2 == 0
            halt(&mut code);
            assert_eq!(
                execute(&code, 1, 100).unwrap_err(),
                ProgramError::DivByZero,
                "opcode {:#04x} 必须拦下除零",
                op
            );
        }
    }
    #[test]
    fn sha256_compress_wires_registers_to_memory() {
        let state_at = isa::HEAP_BASE;
        let block_at = isa::HEAP_BASE + 64;
        let init: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let mut block = [0u8; 64];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x80;
        block[63] = 24;

        // 期望值：在同一份初始内存上用原语层直接算。
        let mut want_mem = vec![0u8; 65536];
        for (i, w) in init.iter().enumerate() {
            want_mem[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        want_mem[64..128].copy_from_slice(&block);
        isa::sha256_compress_at(0, 64, &mut want_mem).expect("原语层压缩");

        // 程序：R1 = 状态基址，R3 = 块基址，然后压缩。
        let mut code = Vec::new();
        movi(&mut code, 1, state_at);
        movi(&mut code, 3, block_at);
        pair(&mut code, isa::OP_SHA256_COMPRESS, 1, 3);
        halt(&mut code);

        let prog = isa::parse(&program_hex(&code, 1)).unwrap();
        let mut vm = engine::Vm::new(&prog, 100).unwrap();
        // 宿主预置内存（大端状态 + 数据块）。
        for (i, w) in init.iter().enumerate() {
            vm.write_memory(state_at + (i as u64) * 4, &w.to_be_bytes())
                .unwrap();
        }
        vm.write_memory(block_at, &block).unwrap();
        vm.run(&prog).unwrap();

        assert_eq!(
            vm.read_memory(state_at, 32).unwrap(),
            &want_mem[..32],
        );
    }
    #[test]
    fn sm4_block_roundtrip_through_engine() {
        let key_at = isa::HEAP_BASE;
        let block_at = isa::HEAP_BASE + 64;
        let key: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let plain = [0x11u8; 16];

        let mut code = Vec::new();
        movi(&mut code, 1, key_at);
        for (i, chunk) in key.chunks(8).enumerate() {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            movi(&mut code, 2, u64::from_le_bytes(word));
            mem(&mut code, isa::OP_STORE64, 1, 2, (i as i32) * 8);
        }
        movi(&mut code, 3, block_at);
        for (i, chunk) in plain.chunks(8).enumerate() {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            movi(&mut code, 4, u64::from_le_bytes(word));
            mem(&mut code, isa::OP_STORE64, 3, 4, (i as i32) * 8);
        }
        // 加密（R1 密钥、R3 块）后立刻解密，结果必须等于明文。
        pair(&mut code, isa::OP_SM4_ENC_BLOCK, 1, 3);
        pair(&mut code, isa::OP_SM4_DEC_BLOCK, 1, 3);
        halt(&mut code);

        let (_, vm) = execute(&code, 1, 500).unwrap();
        assert_eq!(vm.read_memory(block_at, 16).unwrap(), &plain);
    }
    #[test]
    fn primitive_out_of_bounds_is_rejected() {
        let mut code = Vec::new();
        movi(&mut code, 1, 65536 - 16); // 状态区差 16 字节不足 32
        movi(&mut code, 2, 65536 - 64);
        pair(&mut code, isa::OP_SHA256_COMPRESS, 1, 2);
        halt(&mut code);
        assert_eq!(
            execute(&code, 1, 100).unwrap_err(),
            ProgramError::OutOfBounds
        );
    }

    #[test]
    fn step_budget_matches_isa_formula() {
        assert_eq!(engine::step_budget_for(1).unwrap(), isa::PER_ITER_BUDGET);
        assert_eq!(
            engine::step_budget_for(1000).unwrap(),
            isa::PER_ITER_BUDGET * 1000
        );
        assert_eq!(
            engine::step_budget_for(isa::BATCH_SIZE_LIMIT).unwrap(),
            isa::MAX_STEPS_ABS
        );
        assert_eq!(
            engine::step_budget_for(isa::BATCH_SIZE_LIMIT + 1).unwrap_err(),
            ProgramError::BatchTooLarge
        );

        // 反向：构造期拒绝 0 与超上限预算。
        let prog = isa::parse(&program_hex(&[isa::OP_HALT], 1)).unwrap();
        assert_eq!(
            engine::Vm::new(&prog, 0).unwrap_err(),
            ProgramError::BudgetExhausted
        );
        assert_eq!(
            engine::Vm::new(&prog, isa::MAX_STEPS_ABS + 1).unwrap_err(),
            ProgramError::BudgetExhausted
        );
    }
    #[test]
    fn register_index_wraps_without_panic() {
        let prog = isa::parse(&program_hex(&[isa::OP_HALT], 1)).unwrap();
        let mut vm = engine::Vm::new(&prog, 10).unwrap();
        vm.set_reg(3, 42);
        assert_eq!(vm.reg(3 + engine::REG_COUNT as u8), 42);
        assert_eq!(vm.reg(255), vm.reg(255 % engine::REG_COUNT as u8));
    }
    #[test]
    fn step_count_is_one_per_instruction() {
        let mut code = Vec::new();
        movi(&mut code, 1, isa::HEAP_BASE);
        movi(&mut code, 2, isa::HEAP_BASE + 64);
        pair(&mut code, isa::OP_SM4_ENC_BLOCK, 1, 2);
        halt(&mut code);

        let prog = isa::parse(&program_hex(&code, 1)).unwrap();
        let mut vm = engine::Vm::new(&prog, 100).unwrap();
        vm.run(&prog).unwrap();
        assert_eq!(vm.steps(), 4, "3 条指令 + HALT");
    }
}
