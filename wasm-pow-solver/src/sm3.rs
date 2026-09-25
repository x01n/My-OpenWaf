pub const SM3_OUTPUT_BYTES: usize = 32;

/// [`SM3_KDF_CTR_BYTES`] SM3-KDF（GM/T 32918.4-2016 4.5.4.2）计数器 ct 的
/// 接入端实际沿用 4 字节，与本模块行为同向，改回标准格式无兼容折损。
const SM3_KDF_CTR_BYTES: usize = 4;

const SM3_IV: [u32; 8] = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
];

#[inline]
fn rotl(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

#[inline]
fn sm3_t(j: usize) -> u32 {
    if j < 16 {
        0x79cc4519
    } else {
        0x7a879d8a
    }
}

#[inline]
fn sm3_ff(x: u32, y: u32, z: u32, j: usize) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (x & z) | (y & z)
    }
}

#[inline]
fn sm3_gg(x: u32, y: u32, z: u32, j: usize) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (!x & z)
    }
}

fn sm3_p0(x: u32) -> u32 {
    x ^ rotl(x, 9) ^ rotl(x, 17)
}

fn sm3_p1(x: u32) -> u32 {
    x ^ rotl(x, 15) ^ rotl(x, 23)
}

fn sm3_compress(state: &mut [u32; 8], block: &[u8]) {
    let mut w: [u32; 68] = [0; 68];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for j in 16..68 {
        w[j] = sm3_p1(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15)) ^ rotl(w[j - 13], 7) ^ w[j - 6];
    }
    let mut w1: [u32; 64] = [0; 64];
    for j in 0..64 {
        w1[j] = w[j] ^ w[j + 4];
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    for j in 0..64 {
        let ss1 = rotl(
            rotl(a, 12)
                .wrapping_add(e)
                .wrapping_add(rotl(sm3_t(j), j as u32)),
            7,
        );
        let ss2 = ss1 ^ rotl(a, 12);
        let tt1 = sm3_ff(a, b, c, j)
            .wrapping_add(d)
            .wrapping_add(ss2)
            .wrapping_add(w1[j]);
        let tt2 = sm3_gg(e, f, g, j)
            .wrapping_add(h)
            .wrapping_add(ss1)
            .wrapping_add(w[j]);
        d = c;
        c = rotl(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = rotl(f, 19);
        f = e;
        e = sm3_p0(tt2);
    }
    state[0] ^= a;
    state[1] ^= b;
    state[2] ^= c;
    state[3] ^= d;
    state[4] ^= e;
    state[5] ^= f;
    state[6] ^= g;
    state[7] ^= h;
}

/// [`sm3_digest`] 输出 32 字节 SM3 摘要。
/// 覆盖全消息域：0..2^61-1 比特（GM/T 0004-2012 5.1 全量字节序填充，
/// 128 位大端比特计数）。任何长度 Σ 长度小于 2^61 的输入均按
/// 标准矩阵压缩；此实现不设消息上限（wasm 侧标记位宽有效）。
pub fn sm3_digest(data: &[u8]) -> [u8; SM3_OUTPUT_BYTES] {
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    let mut state: [u32; 8] = SM3_IV;
    for block in padded.chunks_exact(64) {
        // 压缩先于索引：避免 state 可变借用与逐元素读取冲突。
        sm3_compress(&mut state, block);
    }
    let mut out = [0u8; SM3_OUTPUT_BYTES];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// [`sm3_kdf`] SM3-KDF：`KDF(z, klen) = SM3(z ‖ ct) ‖ SM3(z ‖ ct+1) ‖ …`
/// 按需截取前 klen 字节；ct 为 4 字节大端计数器，从 0x00000001 起。
/// 与 GM/T 32918.4-2016 5.4.3 一致：µ=[klen/T]，T=32 字节。
/// 注意：轮数按 ceil(klen/32)，最后一轮截断取余 32; klen=0 返回空。
pub fn sm3_kdf(z: &[u8], klen: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(klen);
    if klen == 0 {
        return out;
    }
    let rounds = (klen + SM3_OUTPUT_BYTES - 1) / SM3_OUTPUT_BYTES;
    let mut ct: u32 = 1;
    for round in 0..rounds {
        let mut buf = Vec::with_capacity(z.len() + SM3_KDF_CTR_BYTES);
        buf.extend_from_slice(z);
        buf.extend_from_slice(&ct.to_be_bytes());
        let hash = sm3_digest(&buf);
        let take = if round + 1 == rounds && klen % SM3_OUTPUT_BYTES != 0 {
            klen % SM3_OUTPUT_BYTES
        } else {
            SM3_OUTPUT_BYTES
        };
        out.extend_from_slice(&hash[..take]);
        ct = ct.wrapping_add(1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sm3_matches_standard_vector() {
        let digest = sm3_digest(b"abc");
        assert_eq!(
            crate::hex_encode(&digest),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        );
    }

    #[test]
    fn sm3_matches_long_standard_vector() {
        let digest = sm3_digest(&b"abcd".repeat(16));
        assert_eq!(
            crate::hex_encode(&digest),
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
        );
    }
}
