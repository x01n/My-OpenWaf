#![recursion_limit = "512"]

use wasm_bindgen::prelude::*;

mod crypto;
mod env;
mod fingerprint;
mod gm;
mod isa;
mod label;
mod obfuscate;
mod sm3;
mod vmp;
mod blob {
    /// 输入：本批尝试次数（程序用它作循环上界）。
    pub(crate) const BATCH_SIZE_OFF: usize = 0;
    /// 输入：本批起始 counter。
    pub(crate) const START_COUNTER_OFF: usize = 8;
    /// 输入：前导零 nibble 数。
    pub(crate) const DIFFICULTY_OFF: usize = 16;
    /// 输入：nonce 字节数。
    pub(crate) const NONCE_LEN_OFF: usize = 24;
    /// 输入：nonce 起始。
    pub(crate) const NONCE_OFF: usize = 32;
    /// 输入：nonce 长度上限（超出即宿主拒绝，程序也会自行拒绝）。
    pub(crate) const NONCE_MAX: usize = 64;
    /// 输入 blob 定长（`header.in_len` 必须等于它）。
    pub(crate) const IN_LEN: usize = NONCE_OFF + NONCE_MAX;

    /// 输出：SHA-256 原始摘要（32 字节，程序按大端搬运状态区）。
    pub(crate) const OUT_HASH_OFF: usize = 0;
    /// 输出：帧魔数（u64 小端，内存字节 `"OWAOUTP\0"`）。
    pub(crate) const OUT_MAGIC_OFF: usize = 32;
    /// 输出：命中的 counter（u64 小端）。
    pub(crate) const OUT_COUNTER_OFF: usize = 40;
    /// 输出区最小可校验长度（hash + magic + counter）。
    pub(crate) const OUT_LEN_MIN: usize = OUT_COUNTER_OFF + 8;
    pub(crate) const OUT_MAGIC: [u8; 8] = *b"OWAOUTP\0";

}

/// 按布局构造 96 字节输入 blob；`nonce` 超长时返回 `None`。
fn build_pow_blob(nonce: &str, difficulty: u32, batch_size: u32, start_counter: u64) -> Option<[u8; blob::IN_LEN]> {
    if nonce.len() > blob::NONCE_MAX {
        return None;
    }
    let mut out = [0u8; blob::IN_LEN];
    out[blob::BATCH_SIZE_OFF..blob::BATCH_SIZE_OFF + 8]
        .copy_from_slice(&u64::from(batch_size).to_le_bytes());
    out[blob::START_COUNTER_OFF..blob::START_COUNTER_OFF + 8]
        .copy_from_slice(&start_counter.to_le_bytes());
    out[blob::DIFFICULTY_OFF..blob::DIFFICULTY_OFF + 8]
        .copy_from_slice(&u64::from(difficulty).to_le_bytes());
    out[blob::NONCE_LEN_OFF..blob::NONCE_LEN_OFF + 8]
        .copy_from_slice(&(nonce.len() as u64).to_le_bytes());
    out[blob::NONCE_OFF..blob::NONCE_OFF + nonce.len()].copy_from_slice(nonce.as_bytes());
    Some(out)
}

#[wasm_bindgen]
pub fn solve_pow_batched(
    nonce: &str,
    difficulty: u32,
    program: &str,
    batch_size: u32,
    start_counter: u64,
) -> String {
    // 解码 + 校验：全部在 isa::parse 内完成，**不分配内存、不执行任何指令**。
    // 因此这一段是「喂字节串即可全量验证解码面」的可测属性。
    let parsed = match isa::parse(program) {
        Ok(parsed) => parsed,
        Err(err) => return format!(r#"{{"found":false,"error":"{}"}}"#, err.code()),
    };
    if difficulty > 64 {
        return r#"{"found":false,"error":"invalid_difficulty"}"#.to_string();
    }

    // 输入合法性：blob 的 nonce 区定长 64，超出即无法按契约构造。
    // 复用既有的「超出声明长度」码，不新增码（team-lead 2026-10-03 裁决）。
    let blob_bytes = match build_pow_blob(nonce, difficulty, batch_size, start_counter) {
        Some(bytes) => bytes,
        None => {
            return format!(
                r#"{{"found":false,"error":"{}"}}"#,
                isa::ProgramError::ProgramTooLarge.code()
            )
        }
    };

    let step_budget = match vmp::step_budget_for(batch_size) {
        Ok(budget) => budget,
        Err(err) => return format!(r#"{{"found":false,"error":"{}"}}"#, err.code()),
    };
    let mut vm = match vmp::Vm::new(&parsed, step_budget) {
        Ok(vm) => vm,
        Err(err) => return format!(r#"{{"found":false,"error":"{}"}}"#, err.code()),
    };

    // 三道防线之二：宿主写入量必须等于容器声明的 in_len。
    // 它挡住「写入量与声明量不一致」这一类，与 blob 内的魔数（挡「长度自洽
    // 但内容协议不一致」）互补。
    let expected_in_len = parsed.header.in_len as usize;
    if blob_bytes.len() != expected_in_len {
        return format!(
            r#"{{"found":false,"error":"{}"}}"#,
            isa::ProgramError::ProgramTooLarge.code()
        );
    }
    if let Err(err) = vm.write_input(&blob_bytes) {
        return format!(r#"{{"found":false,"error":"{}"}}"#, err.code());
    }

    let r0 = match vm.run(&parsed) {
        Ok(r0) => r0,
        Err(err) => return format!(r#"{{"found":false,"error":"{}"}}"#, err.code()),
    };

    // 读出长度按容器声明（契约式），不写死数字。
    let out = match vm.read_output(parsed.header.out_len as usize) {
        Ok(out) => out,
        Err(err) => return format!(r#"{{"found":false,"error":"{}"}}"#, err.code()),
    };

    if r0 != 1 {
        // 未命中不变量：程序只在命中时写输出区，故此处必须全零。
        // 非零说明程序实现违规 —— 静默放过会让宿主把「没找到」当成正常，
        // 掩盖真实的实现缺陷。
        if out.iter().any(|byte| *byte != 0) {
            return format!(
                r#"{{"found":false,"error":"{}"}}"#,
                isa::ProgramError::OutputMagic.code()
            );
        }
        return r#"{"found":false}"#.to_string();
    }

    // 命中路径：magic 必须正确（检出「程序写到了错误的位置」——
    // 这是 R0 一致性检查覆盖不到的盲区），且三个字段必须齐全。
    if out.len() < blob::OUT_LEN_MIN
        || out[blob::OUT_MAGIC_OFF..blob::OUT_MAGIC_OFF + 8] != blob::OUT_MAGIC
    {
        return format!(
            r#"{{"found":false,"error":"{}"}}"#,
            isa::ProgramError::OutputMagic.code()
        );
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&out[blob::OUT_HASH_OFF..blob::OUT_HASH_OFF + 32]);
    let mut counter_bytes = [0u8; 8];
    counter_bytes.copy_from_slice(&out[blob::OUT_COUNTER_OFF..blob::OUT_COUNTER_OFF + 8]);
    let counter = u64::from_le_bytes(counter_bytes);

    format!(
        r#"{{"found":true,"counter":{},"hash":"{}"}}"#,
        counter,
        hex_encode(&hash),
    )
}

#[wasm_bindgen]
pub fn verify_pow(nonce: &str, counter: u64, hash: &str, difficulty: u32) -> bool {
    let prefix = "0".repeat(difficulty as usize);
    if !hash.starts_with(&prefix) {
        return false;
    }
    let message = format!("{}{}", nonce, counter);
    hex_encode(&obfuscate::sha256_compute(message.as_bytes())) == hash
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX_CHARS[(byte >> 4) as usize] as char);
        output.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{blob, build_pow_blob, solve_pow_batched};
    use crate::isa;

    /// 旧伪 VMP 的裸 opcode 程序（Go 侧历史生成物）必须被 `vm_bad_magic` 拒绝。
    /// 这是**破坏性切换**的回归锁：只要旧格式还被容忍，那个固定 5 步状态机
    /// 就仍有生存空间。
    #[test]
    fn rejects_legacy_program_with_bad_magic() {
        let result = solve_pow_batched("nonce", 0, "1011121314", 1, 7);
        assert_eq!(result, r#"{"found":false,"error":"vm_bad_magic"}"#);
    }

    /// 解码期错误必须在**不执行任何指令**的前提下报出：畸形程序即使
    /// `batch_size` 很大也不进入执行路径（否则会先烧掉预算才报错）。
    #[test]
    fn decodes_before_executing() {
        // 合法头部 + 保留 opcode 0x23。头部全部小端，逐字段写避免大端错误。
        let mut program = Vec::new();
        program.extend_from_slice(&[0x4F, 0x57, 0x56, 0x4D]); // magic "OWVM"
        program.push(0x01); // version
        program.push(0x00); // flags
        program.extend_from_slice(&0u16.to_le_bytes()); // reserved
        program.extend_from_slice(&1u32.to_le_bytes()); // pages
        program.extend_from_slice(&0u32.to_le_bytes()); // in_len
        program.extend_from_slice(&0u32.to_le_bytes()); // out_len
        program.extend_from_slice(&2u32.to_le_bytes()); // code_len
        program.extend_from_slice(&[0x23, 0x00]); // 保留 opcode

        let hex: String = program.iter().map(|b| format!("{:02x}", b)).collect();
        let result = solve_pow_batched("nonce", 0, &hex, 1_000_000, 0);
        assert_eq!(result, r#"{"found":false,"error":"unknown_vm_opcode"}"#);
    }
    fn hex_of(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    #[test]
    fn blob_matches_cross_language_vector_nonce32() {
        let blob = build_pow_blob("00112233445566778899aabbccddeeff", 3, 50000, 12345)
            .expect("nonce fits");
        assert_eq!(blob.len(), blob::IN_LEN);
        assert_eq!(hex_of(&blob), "50c300000000000039300000000000000300000000000000200000000000000030303131323233333434353536363737383839396161626263636464656566660000000000000000000000000000000000000000000000000000000000000000");
    }

    #[test]
    fn blob_matches_cross_language_vector_empty_nonce() {
        let blob = build_pow_blob("", 1, 1, 0).expect("empty nonce fits");
        assert_eq!(hex_of(&blob), "010000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    }

    #[test]
    fn blob_matches_cross_language_vector_nonce64() {
        let nonce = "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcd";
        assert_eq!(nonce.len(), 64);
        let blob = build_pow_blob(nonce, 7, 50000, 7).expect("nonce fits exactly");
        assert_eq!(hex_of(&blob), "50c30000000000000700000000000000070000000000000040000000000000006162636465666768696a6162636465666768696a6162636465666768696a6162636465666768696a6162636465666768696a6162636465666768696a61626364");
    }

    /// 反向：nonce 超过 64 必须被拒绝，而不是截断或静默写越界。
    #[test]
    fn blob_rejects_oversized_nonce() {
        let nonce = "a".repeat(65);
        assert!(build_pow_blob(&nonce, 1, 1, 0).is_none());
        // 边界：恰好 64 合法。
        assert!(build_pow_blob(&"a".repeat(64), 1, 1, 0).is_some());
    }

    /// 反向：每个字段都写在声明的偏移上 —— 改一个字段值，只有那一段字节变化。
    ///
    /// 这条挡住「字段顺序写反」：整体向量比对对它不敏感（换两组输入仍可能整体
    /// 正确），而这里会立刻红。
    #[test]
    fn blob_fields_land_at_declared_offsets() {
        let a = build_pow_blob("nn", 1, 2, 3).unwrap();

        /// 断言 diff 非空、且完全落在 `[off, off+8)` 内。
        ///
        /// 不用「diff 恰好等于整个区间」：改一个小值（如 3→4）只翻最低位字节，
        /// 于是 diff 只有 1 个元素 —— 那样断言会假红（本测试第一版即犯此错）。
        /// 「非空 + 落在区间内」已足够抓住「字段顺序写反」：顺序反了 diff 会落
        /// 在**别的**字段区间，此处立刻失败。
        fn assert_only_field_changed(
            a: &[u8],
            b: &[u8],
            off: usize,
            label: &str,
        ) {
            let diff: Vec<usize> = (0..a.len()).filter(|i| a[*i] != b[*i]).collect();
            assert!(!diff.is_empty(), "{label} 改动后必须有字节变化");
            assert!(
                diff.iter().all(|i| *i >= off && *i < off + 8),
                "{label} 的改动必须只落在 [{off}, {}) 内，实际 diff = {diff:?}",
                off + 8
            );
        }

        let b = build_pow_blob("nn", 1, 2, 4).unwrap();
        assert_only_field_changed(&a, &b, blob::START_COUNTER_OFF, "start_counter");

        // 另一组：用大差值让 8 字节全变，此时 diff 必须恰好等于整段。
        let big = build_pow_blob("nn", 1, 2, 0x0102_0304_0506_0708).unwrap();
        let diff: Vec<usize> = (0..blob::IN_LEN).filter(|i| a[*i] != big[*i]).collect();
        assert_eq!(
            diff,
            (blob::START_COUNTER_OFF..blob::START_COUNTER_OFF + 8).collect::<Vec<_>>(),
            "大差值下 start_counter 的 8 字节必须全部变化"
        );

        let c = build_pow_blob("nn", 1, 9, 3).unwrap();
        assert_only_field_changed(&a, &c, blob::BATCH_SIZE_OFF, "batch_size");

        let d = build_pow_blob("nn", 5, 2, 3).unwrap();
        assert_only_field_changed(&a, &d, blob::DIFFICULTY_OFF, "difficulty");

        // nonce 加长一个字节：只允许 nonce_len 段与新增的那个 nonce 字节变化。
        // 同样不用「恰好等于整段」（nonce_len 2→3 只翻最低位字节，见上面的说明）。
        let e = build_pow_blob("nnn", 1, 2, 3).unwrap();
        let diff: Vec<usize> = (0..blob::IN_LEN).filter(|i| a[*i] != e[*i]).collect();
        assert!(!diff.is_empty(), "nonce 加长必须产生字节变化");
        let allowed = blob::NONCE_LEN_OFF..blob::NONCE_LEN_OFF + 8;
        assert!(
            diff.iter().all(|i| allowed.contains(i) || *i == blob::NONCE_OFF + 2),
            "nonce 加长的改动只允许落在 nonce_len 段或新增字节，实际 diff = {diff:?}"
        );
        // 反向：nonce 区的第 3 个字节必须确实变了（否则说明 nonce 没被复制）。
        assert!(
            diff.contains(&(blob::NONCE_OFF + 2)),
            "新增的 nonce 字节必须被写入，实际 diff = {diff:?}"
        );
    }


    // ---- 宿主检出逻辑：OutputMagic 的两条触发分支 ----
    //
    // 为什么要构造「故意有缺陷的字节码」：这一层端到端探针造不出来 ——
    // 它只能观测宿主返回什么，无法造出 `R0==0` 却写脏输出区的程序。
    //
    // ⚠️ 时序（值得记）：线 A 的探针初版写「宿主的检出逻辑由 lib.rs 的测试
    // 负责」，但**当时本文件只有常量锁测试 —— 那条分工是空的**。线 B 读到
    // 那句话后才去查、才发现，随后补上了下面这三条。
    // **「由 X 负责」不等于「X 已有」，写之前要核。**
    // 线 A 已独立复现本组的三项注入（各只红对应一条、无连带）。

    /// 构造最小容器：合法头部 + 给定字节码。
    fn container(code: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0x4F, 0x57, 0x56, 0x4D]); // "OWVM"
        out.push(0x01);
        out.push(0x00);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // pages
        out.extend_from_slice(&(blob::IN_LEN as u32).to_le_bytes()); // in_len = 96
        out.extend_from_slice(&(blob::OUT_LEN_MIN as u32).to_le_bytes()); // out_len = 48
        out.extend_from_slice(&(code.len() as u32).to_le_bytes());
        out.extend_from_slice(code);
        out
    }

    fn emit_movi(code: &mut Vec<u8>, rd: u8, imm: u64) {
        code.push(isa::OP_MOVI);
        code.push(rd << 4);
        code.extend_from_slice(&imm.to_le_bytes());
    }

    fn emit_store64(code: &mut Vec<u8>, rd: u8, rs: u8, off: i32) {
        code.push(isa::OP_STORE64);
        code.push((rd << 4) | rs);
        code.extend_from_slice(&off.to_le_bytes());
    }

    fn emit_store8(code: &mut Vec<u8>, rd: u8, rs: u8, off: i32) {
        code.push(isa::OP_STORE8);
        code.push((rd << 4) | rs);
        code.extend_from_slice(&off.to_le_bytes());
    }

    fn hex(program: &[u8]) -> String {
        program.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// 分支一：`R0 == 0` 但程序写了输出区 → 必须报 `vm_output_magic`。
    ///
    /// 这是「未命中不变量」的执行侧守卫：静默放过会让宿主把「程序写脏了却
    /// 说没命中」当成正常未命中，掩盖真实的实现缺陷。
    #[test]
    fn reports_output_magic_when_miss_but_output_dirty() {
        let mut code = Vec::new();
        emit_movi(&mut code, 1, isa::OUT_BASE);
        emit_movi(&mut code, 2, 0xAB);
        emit_store8(&mut code, 1, 2, 0); // OUT_BASE+0 = 0xAB
        emit_movi(&mut code, 0, 0); // R0 = 0（声称未命中）
        code.push(isa::OP_HALT);

        let result = solve_pow_batched("probe", 0, &hex(&container(&code)), 1, 0);
        assert_eq!(
            result,
            r#"{"found":false,"error":"vm_output_magic"}"#,
            "R0=0 但输出区被写脏时必须报 OutputMagic"
        );
    }

    /// 分支二：`R0 == 1` 但输出区 magic 不符 → 必须报 `vm_output_magic`。
    ///
    /// 这是 `OUTPUT_MAGIC` 的**存在理由**：`R0` 一致性检查覆盖不到「程序写到
    /// 了错误位置」这一类，只有 magic 能检出。
    #[test]
    fn reports_output_magic_when_hit_but_magic_wrong() {
        let mut code = Vec::new();
        emit_movi(&mut code, 1, isa::OUT_BASE);
        emit_movi(&mut code, 2, 0xDEAD_BEEF); // 错误 magic
        emit_store64(&mut code, 1, 2, blob::OUT_MAGIC_OFF as i32);
        emit_movi(&mut code, 0, 1); // R0 = 1（声称命中）
        code.push(isa::OP_HALT);

        let result = solve_pow_batched("probe", 0, &hex(&container(&code)), 1, 0);
        assert_eq!(
            result,
            r#"{"found":false,"error":"vm_output_magic"}"#,
            "R0=1 但 magic 不符时必须报 OutputMagic"
        );
    }

    /// 反向：magic 正确、`R0 == 1` 时必须正常命中 ——
    /// 否则上面两条测试可能只是「什么都报错」。
    #[test]
    fn accepts_hit_with_correct_magic() {
        let mut code = Vec::new();
        emit_movi(&mut code, 1, isa::OUT_BASE);
        emit_movi(&mut code, 2, u64::from_le_bytes(blob::OUT_MAGIC));
        emit_store64(&mut code, 1, 2, blob::OUT_MAGIC_OFF as i32);
        emit_movi(&mut code, 3, 0); // counter = 0
        emit_store64(&mut code, 1, 3, blob::OUT_COUNTER_OFF as i32);
        emit_movi(&mut code, 0, 1);
        code.push(isa::OP_HALT);

        let result = solve_pow_batched("probe", 0, &hex(&container(&code)), 1, 0);
        // hash 区未写（全零），counter = 0
        assert!(
            result.starts_with(r#"{"found":true,"counter":0,"hash":"0000000000000000"#),
            "magic 正确时不应报错，实际：{result}"
        );
    }

    /// 分支三（不是 OutputMagic）：`R0 == 0` 且输出区干净 → 干净的未命中，
    /// **不得**带 `error` 字段（否则端到端探针无法区分「未命中」与「违规」）。
    #[test]
    fn clean_miss_has_no_error_field() {
        let mut code = Vec::new();
        emit_movi(&mut code, 0, 0);
        code.push(isa::OP_HALT);

        let result = solve_pow_batched("probe", 0, &hex(&container(&code)), 1, 0);
        assert_eq!(result, r#"{"found":false}"#);
    }

    #[test]
    fn magic_constant_matches_declared_bytes() {
        // 内存字节必须是 `OWAOUTP\0` —— 程序用 `STORE64`（小端）写 u64 常量，
        // 两侧的字节序约定必须一致。上面的 u64 值即 `BlobOutputMagic`。
        assert_eq!(&blob::OUT_MAGIC, b"OWAOUTP\0");
        assert_eq!(u64::from_le_bytes(blob::OUT_MAGIC), 0x0050_5455_4F41_574F);
    }
}
