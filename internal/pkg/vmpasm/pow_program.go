package vmpasm

// 本文件是 **PoW 字节码程序**的生产定义：`pow.go` 的 `GenerateVMProgram`
// 直接汇编它。ISA 层不含任何 PoW 语义；本文件是「Go 汇编器与 PoW 程序之间的
// 私约」的 Go 侧一半，另一半是 `wasm-pow-solver/src/vmp.rs` 的宿主接线。
//
// 程序端到端正确性由 `pow_program_test.go` 验证：Go 汇编器生成程序 →
// 参考解释器执行 → 结果必须等于 Go 标准库算出的 SHA-256 前导零判定。
// 前导零检查是「循环 + 无符号比较 + 条件跳转」（ISA §4.3.6），
// **没有任何 PoW 专用指令**。
//
// # 批内循环（v2，2026-10-03 裁决 1）
//
// 程序**自己**遍历 `[start_counter, start_counter + batch_size)` 内的全部
// counter，而不是每次调用只试一个。这不是性能优化，是**契约要求**：
// Go worker 的推进约定是 `off += bs * nc`（`pow.go` 的 worker 模板），
// 即「本次调用已覆盖 `bs` 个 counter」。若程序只试一个，其余 `bs-1` 个会被
// **永久跳过** —— 找到解仍可能（稀疏算术级数），但轮次会多约 `bs` 倍。
// 旧的 Rust 实现是 `while counter < end`，v2 必须保持同一语义。
//
// # 输出区（v2，2026-10-03 裁决 3）
//
// 命中时程序把 `hash`(32 字节原始摘要) 与 `found_counter`(u64 LE) 写进输出区，
// 而不是让宿主自己推算 —— 宿主推算要求它知道程序的内部计数方式，
// 那是隐性契约。未命中时输出区不写，**以 `R0 == 0` 为准**。

// PoW 输入 blob 布局（`ISA.md` §7.2.1）。
//
// 全部整数字段为**小端 u64**，固定 32 字节头 + nonce 区：
//
//	偏移  长度  字段
//	 0     8    batch_size（u64；**程序用它决定内循环次数**）
//	 8     8    start_counter（u64）
//	16     8    difficulty（u64，程序用它决定检查几个前导零 nibble）
//	24     8    nonce_len（u64，0..64）
//	32   ...   nonce 的 ASCII 字节
//
// 为什么 `nonce_len` 是 u64 而不是 u32：程序统一用 `LOAD64` 取头部字段，
// 少两条拼接指令，也少一处字节序约定。
const (
	BlobBatchSizeOff    = 0
	BlobStartCounterOff = 8
	BlobDifficultyOff   = 16
	BlobNonceLenOff     = 24
	BlobNonceOff        = 32
	BlobNonceMax        = 64

	// BlobMinLen 是「刚好装下头部、nonce 为空」的长度。
	BlobMinLen = BlobNonceOff
	// BlobMaxLen 是布局允许的最大长度。**宿主恒写这个长度**（nonce 区补零），
	// 这样「宿主断言写入量 == header.in_len」这条防线才有意义
	// （2026-10-03 裁决 2）：放弃固定长度换来的只是省最多 64 字节。
	BlobMaxLen = BlobNonceOff + BlobNonceMax
)

// PoW 输出 blob 布局（`ISA.md` §7.2.4）。**仅命中时写入**。
//
//	偏移  长度  字段
//	 0    32    SHA-256 原始摘要（标准摘要的字节序列，即大端字序）
//	32     8    OUTPUT_MAGIC（u64 小端）
//	40     8    found_counter（u64 小端）
//
// # 为什么输出侧要 magic 而输入侧不要
//
// 输入 blob 由**宿主**写：写 magic 与写其它字段是同一批代码，不会单独漂移。
// 输出 blob 由**程序**写、**宿主**读：程序写 magic 与写 hash/counter 是同一批
// 指令。magic 在这里防的是「**程序写了但宿主读错位置**」与「**`R0 == 1` 但
// 输出区其实没写**」—— 后者的判据是「全零」，而「全零」与「程序真写了全零」
// 在没有 magic 时不可区分（2026-10-03 裁决）。
const (
	BlobOutHashOff    = 0
	BlobOutMagicOff   = 32
	BlobOutCounterOff = 40
	// BlobOutLen 是输出区长度，也是汇编期声明的 `out_len`。
	BlobOutLen = BlobOutCounterOff + 8
)

// BlobOutputMagic 是输出帧的魔数：ASCII `"OWAOUTP\0"`，按 u64 小端存储。
//
// 与容器魔数 `OWVM`（4 字节）、输入侧 `OWAINPT\0` 都不同长不同拼写，
// 便于在 hex dump 里一眼区分是哪一侧出错。
const BlobOutputMagic uint64 = 0x005054554F41574F // "OWAOUTP\0" little-endian

// PoW 工作区在内存里的偏移（相对 `HeapBase`）。
//
//	 0.. 32    SHA-256 状态区（大端 8×u32）
//	32.. 96    消息块 1（64 字节）
//	96..160    消息块 2（64 字节）
//
// 两个消息块**连续**排布是刻意的：消息从 `block1[0]` 起线性铺开，
// 超过 64 字节时自动流进块 2。「块」只是压缩指令的调用边界，不是写入边界 ——
// 这省掉了所有跨块拼接的分支。
const (
	powStateOff  = 0
	powBlock1Off = 32
	powBlock2Off = 96
	// powLenOff1 是单块情形下 8 字节大端长度字段在块 1 内的偏移。
	// 单块条件是 msgLen ≤ 55，故 0x80 不会与 [56,64) 的长度字段相撞。
	powLenOff1 = 56
	// powLenOff2 是双块情形下长度字段在块 2 内的偏移。
	powLenOff2 = 56
	// powDirtyMax 是「每个 counter 可能变脏的最大区间长度」：
	// 最多 20 位十进制数字 + 1 个 0x80 填充字节。
	powDirtyMax = 21
)

// bswap32 返回 32 位字按字节反转后的值。
//
// 用途：ISA 的 `STORE32` 是**小端**（§4.1），而 SHA-256 / SM3 的状态区在内存里
// 要求**大端**表示（`isa.rs` 的 `sha256_compress_at` 用 `from_be_bytes` 读）。
// 因此在汇编期把常量反转，`STORE32` 写出的内存就恰好是大端形式。
// 这条约束由 `TestProbeByteOrder` 实测锁定。
func bswap32(v uint32) uint64 {
	return uint64(v>>24) |
		uint64((v>>16)&0xFF)<<8 |
		uint64((v>>8)&0xFF)<<16 |
		uint64(v&0xFF)<<24
}

// sha256IV 是 SHA-256 的 8 个初始状态字（FIPS 180-4 §5.3.3）。
var sha256IV = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

// PoWProgramLayout 返回 PoW 程序应使用的汇编布局。
//
// `InLen` 固定为 [`BlobMaxLen`]（宿主恒写满，nonce 区补零），
// `OutLen` 为 [`BlobOutLen`]。
func PoWProgramLayout() Layout {
	return Layout{Pages: 1, InLen: BlobMaxLen, OutLen: BlobOutLen}
}

// BuildPoWProgram 汇编 PoW 程序：在 `[start_counter, start_counter+batch_size)`
// 内查找使 `SHA-256(nonce ‖ decimal(counter))` 有 `difficulty` 个前导零 nibble
// 的 counter。找到返回 1 并写输出区；本批耗尽返回 0。
//
// # 程序结构（无子程序调用 —— ISA §4.2 刻意不提供 CALL/RET）
//
//	序言（每批一次）
//	  校验 nonceLen / difficulty
//	  清零 128 字节消息区（块 1 + 块 2）
//	  nonce → block1[0, nonceLen)
//	  counter ← start_counter，end ← start_counter + batch_size
//	主循环（每个 counter 一次）
//	  清零 [nonceLen, nonceLen+21)（上一轮的数字与填充残留）
//	  十进制 counter → block1[nonceLen, msgLen)
//	  0x80 填充字节 → block1[msgLen]
//	  SHA-256 初始状态 → 状态区
//	  单块：清 block1[56,64) → 写 bitLen → 压缩一次
//	  双块：清 block2[56,64) → 写 bitLen → 压缩两次
//	  逐 nibble 检查前导零
//	    命中 → 写输出区（hash + OUTPUT_MAGIC + counter），R0 = 1，HALT
//	    未命中 → counter += 1，回到主循环（**不触碰输出区**）
//	耗尽 → R0 = 0，HALT（输出区保持全零）
//
// # 为什么「清零脏区」是必要的（实测过，不是防御性编程）
//
// 十进制位数随 counter 变化（`9 → 10`、`99 → 100`），上一轮写下的数字
// 或填充字节长度与本轮不同。若不清零，`[msgLen, 上一轮 msgLen)` 之间会残留
// **上一轮的字节**，而它们本该是全零填充 —— 哈希就会算错。
// 实测：不清零时从 counter=1140 起开始出错（位数由 3 变 4 的那一批）。
//
// # 寄存器约定（修改本函数时必须维持）
//
//	R4  工作区基址（HeapBase），全程不变
//	R5  nonceLen，序言之后不变
//	R6  difficulty，序言之后不变
//	R9  当前 counter（主循环变量）
//	R10 结束 counter（不含），主循环期间不变
//	R12 块 1 基址，全程不变
//	R14 常数 1，主循环期间不变
//	R15 常数 0，主循环期间不变
//
// 其余寄存器（R0..R3、R7、R8、R11、R13）在主循环体内随意用作临时量。
func BuildPoWProgram() []Instr {
	var p []Instr

	// ---- 序言 1：校验输入 ----
	p = append(p,
		Instr{Op: OpMovi, A: R4, Imm: HeapBase},
		Instr{Op: OpMovi, A: R1, Imm: BlobNonceLenOff},
		Instr{Op: OpLoad64, A: R5, B: R1, Off: 0}, // R5 = nonceLen
		Instr{Op: OpMovi, A: R2, Imm: BlobNonceMax},
		Instr{Op: OpCmp, A: R5, B: R2},
		Instr{Op: OpJgt, Target: "miss"}, // nonceLen > 64 → 本批无解
		Instr{Op: OpMovi, A: R1, Imm: BlobDifficultyOff},
		Instr{Op: OpLoad64, A: R6, B: R1, Off: 0}, // R6 = difficulty
		Instr{Op: OpCmp, A: R6, B: R2},            // R2 仍是 64
		Instr{Op: OpJgt, Target: "miss"},          // difficulty > 64 → 本批无解
		Instr{Op: OpMovi, A: R14, Imm: 1},         // 常数 1
		Instr{Op: OpMovi, A: R15, Imm: 0},         // 常数 0
	)

	// ---- 序言 2：清零 128 字节消息区（块 1 + 块 2，各 8 条 STORE64） ----
	p = append(p,
		Instr{Op: OpMovi, A: R12, Imm: powBlock1Off},
		Instr{Op: OpAdd, A: R12, B: R4, C: R12}, // R12 = &block1[0]
		Instr{Op: OpMovi, A: R2, Imm: powBlock2Off},
		Instr{Op: OpAdd, A: R2, B: R4, C: R2}, // R2 = &block2[0]
	)
	for off := 0; off < 64; off += 8 {
		p = append(p, Instr{Op: OpStore64, A: R12, B: R15, Off: int32(off)})
	}
	for off := 0; off < 64; off += 8 {
		p = append(p, Instr{Op: OpStore64, A: R2, B: R15, Off: int32(off)})
	}

	// ---- 序言 3：nonce → block1[0, nonceLen)（每批只做一次） ----
	p = append(p,
		Instr{Op: OpMovi, A: R11, Imm: BlobNonceOff},
		Instr{Op: OpMovi, A: R7, Imm: 0},
		Label("ncpy"),
		Instr{Op: OpCmp, A: R7, B: R5},
		Instr{Op: OpJge, Target: "ncdone"},
		Instr{Op: OpAdd, A: R0, B: R11, C: R7},
		Instr{Op: OpLoad8, A: R13, B: R0, Off: 0},
		Instr{Op: OpAdd, A: R0, B: R12, C: R7},
		Instr{Op: OpStore8, A: R0, B: R13, Off: 0},
		Instr{Op: OpAdd, A: R7, B: R7, C: R14},
		Instr{Op: OpJmp, Target: "ncpy"},
		Label("ncdone"),
	)

	// ---- 序言 4：counter ← start_counter，end ← start_counter + batch_size ----
	p = append(p,
		Instr{Op: OpMovi, A: R1, Imm: BlobBatchSizeOff},
		Instr{Op: OpLoad64, A: R10, B: R1, Off: 0}, // R10 = batch_size
		Instr{Op: OpMovi, A: R1, Imm: BlobStartCounterOff},
		Instr{Op: OpLoad64, A: R9, B: R1, Off: 0}, // R9 = start_counter
		Instr{Op: OpAdd, A: R10, B: R9, C: R10},   // R10 = end（不含）
	)

	// ---- 主循环 ----
	p = append(p, Label("mainloop"),
		Instr{Op: OpCmp, A: R9, B: R10},
		Instr{Op: OpJge, Target: "miss"}, // 本批耗尽 → 未命中
	)

	// 清零脏区 [nonceLen, nonceLen+powDirtyMax)：
	// 上一轮的数字（位数可能更多）与 0x80 填充字节都落在这里。
	p = append(p,
		Instr{Op: OpAdd, A: R7, B: R12, C: R5}, // R7 = &block1[nonceLen]
		Instr{Op: OpMovi, A: R13, Imm: powDirtyMax},
		Instr{Op: OpAdd, A: R13, B: R7, C: R13}, // R13 = 脏区末尾（不含）
		Label("zloop"),
		Instr{Op: OpCmp, A: R7, B: R13},
		Instr{Op: OpJge, Target: "zdone"},
		Instr{Op: OpStore8, A: R7, B: R15, Off: 0},
		Instr{Op: OpAdd, A: R7, B: R7, C: R14},
		Instr{Op: OpJmp, Target: "zloop"},
		Label("zdone"),
	)

	// ---- 十进制 counter → block1[nonceLen, nonceLen+numDigits) ----
	//
	// 先数位数（反复除 10），再从末位向前写。全部在副本 R7 上做，
	// R9（循环变量）必须保持原值。
	p = append(p,
		Instr{Op: OpMov, A: R7, B: R9}, // R7 = counter（会被除尽）
		Instr{Op: OpMovi, A: R8, Imm: 1},
		Instr{Op: OpMovi, A: R2, Imm: 10},
		Instr{Op: OpDivu, A: R3, B: R7, C: R2}, // R3 = counter / 10
		Label("count"),
		Instr{Op: OpCmp, A: R3, B: R15},
		Instr{Op: OpJeq, Target: "countdone"},
		Instr{Op: OpAdd, A: R8, B: R8, C: R14},
		Instr{Op: OpDivu, A: R3, B: R3, C: R2},
		Instr{Op: OpJmp, Target: "count"},
		Label("countdone"),
		// R11 = &block1[nonceLen + numDigits - 1]（末位）
		Instr{Op: OpAdd, A: R11, B: R12, C: R5},
		Instr{Op: OpAdd, A: R11, B: R11, C: R8},
		Instr{Op: OpSub, A: R11, B: R11, C: R14},
		Label("decloop"),
		Instr{Op: OpModu, A: R13, B: R7, C: R2}, // R13 = counter % 10
		Instr{Op: OpMovi, A: R3, Imm: '0'},
		Instr{Op: OpAdd, A: R13, B: R13, C: R3},
		Instr{Op: OpStore8, A: R11, B: R13, Off: 0},
		Instr{Op: OpDivu, A: R7, B: R7, C: R2}, // counter /= 10
		Instr{Op: OpCmp, A: R7, B: R15},
		Instr{Op: OpJeq, Target: "decdone"},
		Instr{Op: OpSub, A: R11, B: R11, C: R14},
		Instr{Op: OpJmp, Target: "decloop"},
		Label("decdone"),
		Instr{Op: OpAdd, A: R8, B: R8, C: R5}, // R8 = msgLen
	)

	// ---- 0x80 填充字节（地址 = block1 + msgLen） ----
	//
	// msgLen ≥ 64 时该地址自动落进块 2（两块连续），无需分支。
	p = append(p,
		Instr{Op: OpAdd, A: R1, B: R12, C: R8},
		Instr{Op: OpMovi, A: R2, Imm: 0x80},
		Instr{Op: OpStore8, A: R1, B: R2, Off: 0},
	)

	// ---- SHA-256 初始状态（bswap32 后小端写 = 内存里的大端） ----
	p = append(p,
		Instr{Op: OpMovi, A: R1, Imm: powStateOff},
		Instr{Op: OpAdd, A: R1, B: R4, C: R1}, // R1 = &state[0]
	)
	for i, iv := range sha256IV {
		p = append(p,
			Instr{Op: OpMovi, A: R2, Imm: bswap32(iv)},
			Instr{Op: OpStore32, A: R1, B: R2, Off: int32(4 * i)},
		)
	}

	// ---- 单块 / 双块分支 ----
	//
	// 单块条件：0x80 不撞长度字段，即 msgLen ≤ 55。
	// 长度字段 = msgLen*8 ≤ 672 < 65536，大端 u64 的高 6 字节恒为 0
	// （长度字段已清零），因此只需两条 STORE8 写第 6、7 字节。
	const singleLimit = powLenOff1 - 1 // = 55
	p = append(p,
		Instr{Op: OpMovi, A: R2, Imm: singleLimit},
		Instr{Op: OpCmp, A: R8, B: R2},
		Instr{Op: OpJgt, Target: "double"},
	)
	// 单块：长度字段在 block1[56..64)，压缩一次。
	// 注意长度字段的绝对偏移 = powBlock1Off + powLenOff1 + 6（写第 6、7 字节）。
	p = append(p,
		// 先清 8 字节长度字段（上一轮的 bitLen 残留），再写低 2 字节。
		// **必须在分支内清**：长 nonce（nonceLen > 56）会占用 block1[56,64)，
		// 无条件清它会把消息尾部抹掉 —— 实测 nonceLen=58 起开始出错。
		//
		// 这是一个**真缺陷**，不是"只在测试输入上出现的问题"：
		// `BlobNonceMax = 64` 是布局允许的合法输入，**任何合法输入都必须正确**。
		// 当前生产 nonce 是 32 字节（`hex.EncodeToString(16 随机字节)`），
		// 但那是**当前行为，不是规格** —— 规格是 0..64。将来为抗碰撞加长
		// nonce 时会直接踩上它。
		// 单块分支的 nonceLen ≤ 54（否则 msgLen > 55 走双块），故此处安全。
		Instr{Op: OpStore64, A: R12, B: R15, Off: powLenOff1},
		Instr{Op: OpMovi, A: R2, Imm: 8},
		Instr{Op: OpMul, A: R3, B: R8, C: R2}, // R3 = bitLen = msgLen * 8
		Instr{Op: OpMovi, A: R13, Imm: 0xFF},
		Instr{Op: OpAnd, A: R11, B: R3, C: R13}, // 低字节
		Instr{Op: OpShr, A: R3, B: R3, C: R2},   // 高字节
		Instr{Op: OpMovi, A: R1, Imm: powBlock1Off + powLenOff1 + 6},
		Instr{Op: OpAdd, A: R1, B: R4, C: R1},
		Instr{Op: OpStore8, A: R1, B: R3, Off: 0},
		Instr{Op: OpStore8, A: R1, B: R11, Off: 1},
		Instr{Op: OpMovi, A: R1, Imm: powStateOff},
		Instr{Op: OpAdd, A: R1, B: R4, C: R1},
		Instr{Op: OpSha256Compress, A: R1, B: R12},
		Instr{Op: OpJmp, Target: "hashdone1"},
	)
	// 双块：长度字段在 block2[56..64)，压缩两次
	p = append(p,
		Label("double"),
		// 长度字段在 block2[56..64)：block2 的消息部分最多到 [64, 84) 的
		// block2[0..20)，故 [56,64) 恒在消息之外，清理安全。
		Instr{Op: OpStore64, A: R2, B: R15, Off: powLenOff2},
		Instr{Op: OpMovi, A: R2, Imm: 8},
		Instr{Op: OpMul, A: R3, B: R8, C: R2},
		Instr{Op: OpMovi, A: R13, Imm: 0xFF},
		Instr{Op: OpAnd, A: R11, B: R3, C: R13},
		Instr{Op: OpShr, A: R3, B: R3, C: R2},
		Instr{Op: OpMovi, A: R1, Imm: powBlock2Off + powLenOff2 + 6},
		Instr{Op: OpAdd, A: R1, B: R4, C: R1},
		Instr{Op: OpStore8, A: R1, B: R3, Off: 0},
		Instr{Op: OpStore8, A: R1, B: R11, Off: 1},
		Instr{Op: OpMovi, A: R1, Imm: powStateOff},
		Instr{Op: OpAdd, A: R1, B: R4, C: R1},
		Instr{Op: OpSha256Compress, A: R1, B: R12},
		Instr{Op: OpMovi, A: R2, Imm: powBlock2Off},
		Instr{Op: OpAdd, A: R2, B: R4, C: R2},
		Instr{Op: OpSha256Compress, A: R1, B: R2},
		Label("hashdone1"),
	)

	// ---- 逐 nibble 检查前导零（ISA §4.3.6 的等价实现） ----
	//
	// R2 = 已检查的 nibble 数，R3 = 当前字节下标，R6 = difficulty。
	// 每轮查高 nibble；若还没查够再查低 nibble 并前进一字节。
	p = append(p,
		Instr{Op: OpMovi, A: R2, Imm: 0},
		Instr{Op: OpMovi, A: R3, Imm: 0},
		Instr{Op: OpMovi, A: R1, Imm: powStateOff},
		Instr{Op: OpAdd, A: R1, B: R4, C: R1}, // R1 = &state[0]
		Label("nibloop"),
		Instr{Op: OpCmp, A: R2, B: R6},
		Instr{Op: OpJge, Target: "pass"},
		Instr{Op: OpAdd, A: R0, B: R1, C: R3},
		Instr{Op: OpLoad8, A: R13, B: R0, Off: 0},
		// 高 nibble
		Instr{Op: OpMovi, A: R11, Imm: 0xF0},
		Instr{Op: OpAnd, A: R7, B: R13, C: R11},
		Instr{Op: OpCmp, A: R7, B: R15},
		Instr{Op: OpJne, Target: "nextiter"},
		Instr{Op: OpAdd, A: R2, B: R2, C: R14},
		Instr{Op: OpCmp, A: R2, B: R6},
		Instr{Op: OpJge, Target: "pass"},
		// 低 nibble
		Instr{Op: OpMovi, A: R11, Imm: 0x0F},
		Instr{Op: OpAnd, A: R7, B: R13, C: R11},
		Instr{Op: OpCmp, A: R7, B: R15},
		Instr{Op: OpJne, Target: "nextiter"},
		Instr{Op: OpAdd, A: R2, B: R2, C: R14},
		Instr{Op: OpAdd, A: R3, B: R3, C: R14},
		Instr{Op: OpJmp, Target: "nibloop"},
	)

	// ---- 命中：写输出区，R0 = 1 ----
	//
	// 状态区是大端字节序，直接按 8 字节块搬运即得标准摘要的字节序列。
	p = append(p,
		Label("pass"),
		Instr{Op: OpMovi, A: R1, Imm: OutBase},
		Instr{Op: OpMovi, A: R2, Imm: powStateOff},
		Instr{Op: OpAdd, A: R2, B: R4, C: R2}, // R2 = &state[0]
	)
	for off := 0; off < 32; off += 8 {
		p = append(p,
			Instr{Op: OpLoad64, A: R3, B: R2, Off: int32(off)},
			Instr{Op: OpStore64, A: R1, B: R3, Off: int32(off)},
		)
	}
	p = append(p,
		Instr{Op: OpMovi, A: R2, Imm: BlobOutputMagic},
		Instr{Op: OpStore64, A: R1, B: R2, Off: BlobOutMagicOff},
		Instr{Op: OpStore64, A: R1, B: R9, Off: BlobOutCounterOff}, // found_counter
		Instr{Op: OpMovi, A: R0, Imm: 1},
		Instr{Op: OpHalt},
	)

	// ---- 本 counter 不是解 → 试下一个 ----
	p = append(p,
		Label("nextiter"),
		Instr{Op: OpAdd, A: R9, B: R9, C: R14},
		Instr{Op: OpJmp, Target: "mainloop"},
	)

	// ---- 本批耗尽 / 输入非法 → 未命中（输出区不写） ----
	p = append(p,
		Label("miss"),
		Instr{Op: OpMovi, A: R0, Imm: 0},
		Instr{Op: OpHalt},
	)
	return p
}
