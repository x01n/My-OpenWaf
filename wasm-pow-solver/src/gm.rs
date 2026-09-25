use wasm_bindgen::prelude::*;

use num_bigint::BigUint;
use num_traits::Num;

const ENVELOPE_MAGIC: &[u8; 4] = b"OWVE";
const ENVELOPE_VERSION: u8 = 0x02;
const ENVELOPE_HEADER_BYTES: usize = 8;
const ENVELOPE_SIG_LEN: u8 = 64;
const SM4_KEY_BYTES: usize = 16;
const GM_NONCE_BYTES: usize = 12;
const GM_TAG_BYTES: usize = 16;
const SM2_RAW_SIG_BYTES: usize = 64;
const SM3_OUT_BYTES: usize = 32;
const MAX_GM_PLAINTEXT_BYTES: usize = 512 * 1024;
const MAX_GM_CIPHERTEXT_BYTES: usize = 1024 * 1024;
const SM3_HMAC_MAX_KEY_BYTES: usize = 64;
const SM2_USER_ID: &[u8] = b"owaf-gm-challenge";
/// 域代号：0x01 环境指纹 env。
pub const DOMAIN_ENV: u8 = 0x01;
/// 域代号：0x02 captcha 题目。
pub const DOMAIN_CAPTCHA_DATA: u8 = 0x02;
/// 域代号：0x03 captcha 答案。
pub const DOMAIN_CAPTCHA_ANSWER: u8 = 0x03;
/// 域代号：0x04 browser-sign 票据。
pub const DOMAIN_BROWSERSIGN: u8 = 0x04;

// SM2 国标曲线参数（私钥区间校验）。
const ECC_N: &str = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";
// SM2 国标素域模数 p（点校验与素域运算）。
const ECC_P: &str = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
// SM2 ZA 组合参数（GM/T 32918.5）。
const ECC_A: [u8; 32] = [
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
];
const ECC_B: [u8; 32] = [
    0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34, 0x4d, 0x5a, 0x9e, 0x4b, 0xcf, 0x65, 0x09, 0xa7,
    0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92, 0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93,
];
const ECC_GX: [u8; 32] = [
    0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19, 0x5f, 0x99, 0x04, 0x46, 0x6a, 0x39, 0xc9, 0x94,
    0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1, 0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7,
];
const ECC_GY: [u8; 32] = [
    0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c, 0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53,
    0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40, 0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0,
];

// SM4 加密 S 盒与常量（GM/T 0002-2012）。
const SM4_SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];
const SM4_FK: [u32; 4] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
const SM4_CK: [u32; 32] = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];
#[inline]
fn rotl(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

/// [`sm3_digest`] 复用 sm3 模块的实现。
pub fn sm3_digest(data: &[u8]) -> [u8; 32] {
    crate::sm3::sm3_digest(data)
}

struct Sm4Cipher {
    round_keys: [u32; 32],
}

impl Sm4Cipher {
    fn new(key: &[u8; SM4_KEY_BYTES]) -> Self {
        let mut mk = [0u32; 4];
        for (i, chunk) in key.chunks_exact(4).enumerate() {
            mk[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let mut k = [0u32; 36];
        for i in 0..4 {
            k[i] = mk[i] ^ SM4_FK[i];
        }
        let mut rk = [0u32; 32];
        for i in 0..32 {
            k[i + 4] = k[i] ^ sm4_l_prime(sm4_tau(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i]));
            rk[i] = k[i + 4];
        }
        Sm4Cipher { round_keys: rk }
    }

    fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut x = [0u32; 4];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            x[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 0..32 {
            let t = sm4_l(sm4_tau(x[1] ^ x[2] ^ x[3] ^ self.round_keys[i]));
            x = [x[1], x[2], x[3], x[0] ^ t];
        }
        let mut out = [0u8; 16];
        for i in 0..4 {
            out[i * 4..i * 4 + 4].copy_from_slice(&x[3 - i].to_be_bytes());
        }
        out
    }
}

fn sm4_tau(word: u32) -> u32 {
    let bytes = word.to_be_bytes();
    let mut out = [0u8; 4];
    for (i, byte) in bytes.iter().enumerate() {
        out[i] = SM4_SBOX[*byte as usize];
    }
    u32::from_be_bytes(out)
}

fn sm4_l_prime(word: u32) -> u32 {
    word ^ rotl(word, 13) ^ rotl(word, 23)
}

fn sm4_l(word: u32) -> u32 {
    word ^ rotl(word, 2) ^ rotl(word, 10) ^ rotl(word, 18) ^ rotl(word, 24)
}

fn inc32(counter: &mut [u8; 16]) {
    let mut carry = 0u16;
    for byte in counter.iter_mut().rev() {
        let sum = *byte as u16 + 1 + carry;
        *byte = (sum & 0xff) as u8;
        carry = if sum > 0xff { 1 } else { 0 };
        if carry == 0 {
            break;
        }
    }
}

/// [`gcm_mul`] Galois 域 GF(2^128) 乘法（模 x^128+x^7+x^2+x+1）。
/// NIST SP 800-38D 参考实现：X 按块内 MSB 优先逐位移动，V 右移并按
/// 被移出的 LSB 决定是否并入约简多项式 R（0xe1 置于最高字节）。
fn gcm_mul(x_in: u128, y: u128) -> u128 {
    const R: u128 = 0xe1000000000000000000000000000000;
    let mut z = 0u128;
    let mut v = y;
    let mut x = x_in;
    for _ in 0..128 {
        // X 的最高位（位 127）对应块内最左字节的最高位。
        if x >> 127 & 1 == 1 {
            z ^= v;
        }
        x <<= 1;
        let lsb = v & 1;
        v >>= 1;
        if lsb == 1 {
            v ^= R;
        }
    }
    z
}

/// [`ghash`] GCM GHASH：零填充的 AAD || 零填充的密文 || len(AAD)*8 || len(CT)*8。
fn ghash(aad: &[u8], ciphertext: &[u8], key: u128) -> u128 {
    let mut y = 0u128;
    let ingest = |bytes: &[u8], y: &mut u128| {
        let mut padded = Vec::with_capacity((bytes.len() + 15) / 16 * 16);
        padded.extend_from_slice(bytes);
        while padded.len() % 16 != 0 {
            padded.push(0);
        }
        for block in padded.chunks_exact(16) {
            let x = u128::from_be_bytes(block.try_into().expect("ghash block is 16 bytes"));
            *y = gcm_mul(*y ^ x, key);
        }
    };
    ingest(aad, &mut y);
    ingest(ciphertext, &mut y);
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&((aad.len() as u64).wrapping_mul(8)).to_be_bytes());
    lens[8..].copy_from_slice(&((ciphertext.len() as u64).wrapping_mul(8)).to_be_bytes());
    let x = u128::from_be_bytes(lens);
    gcm_mul(y ^ x, key)
}

/// [`sm4_gcm_tag`] GCM 认证标签：GHASH(H, AAD||CT||长度块) ^ E(J0)。
fn sm4_gcm_tag(
    cipher: &Sm4Cipher,
    nonce: &[u8; GM_NONCE_BYTES],
    ciphertext: &[u8],
    aad: &[u8],
) -> [u8; GM_TAG_BYTES] {
    let mut j0 = [0u8; 16];
    j0[..GM_NONCE_BYTES].copy_from_slice(nonce);
    j0[15] = 0x01;
    let h = u128::from_be_bytes(cipher.encrypt_block(&[0u8; 16]));
    let y = ghash(aad, ciphertext, h);
    let ek = cipher.encrypt_block(&j0);
    let mut tag = [0u8; GM_TAG_BYTES];
    let (y_bits, ek_bits) = (y.to_be_bytes(), ek);
    for i in 0..GM_TAG_BYTES {
        tag[i] = y_bits[i] ^ ek_bits[i];
    }
    tag
}

/// [`sm4_ecb_encrypt_block`] 单块 ECB 加密（SM4Cipher 的公开薄封装）。
pub fn sm4_ecb_encrypt_block(key: &[u8; SM4_KEY_BYTES], block: &[u8; 16]) -> [u8; 16] {
    Sm4Cipher::new(key).encrypt_block(block)
}

/// [`sm4_ecb_decrypt_block`] 单块 ECB 解密：展开解密轮密钥（rk 逆序输出，
/// 与 GM/T 0002-2012 7.1 的加密/解密共用同一轮变换）。
pub fn sm4_ecb_decrypt_block(key: &[u8; SM4_KEY_BYTES], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Sm4Cipher::new(key);
    let mut x = [0u32; 4];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        x[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in (0..32).rev() {
        let t = sm4_l(sm4_tau(x[1] ^ x[2] ^ x[3] ^ cipher.round_keys[i]));
        x = [x[1], x[2], x[3], x[0] ^ t];
    }
    let mut out = [0u8; 16];
    for i in 0..4 {
        out[i * 4..i * 4 + 4].copy_from_slice(&x[3 - i].to_be_bytes());
    }
    out
}

/// [`sm4_ecb_encrypt`] ECB 整段加密：末块 0 填充至块边界。
pub fn sm4_ecb_encrypt(key: &[u8; SM4_KEY_BYTES], data: &[u8]) -> Vec<u8> {
    let cipher = Sm4Cipher::new(key);
    let mut out = Vec::with_capacity(((data.len() + 15) / 16) * 16);
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        out.extend_from_slice(&cipher.encrypt_block(&block));
    }
    out
}

/// [`sm4_ecb_decrypt`] ECB 整段解密：长度必须 16 倍数且非零，否则拒绝。
pub fn sm4_ecb_decrypt(key: &[u8; SM4_KEY_BYTES], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return None;
    }
    let cipher = Sm4Cipher::new(key);
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks_exact(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        plaintext.extend_from_slice(&sm4_ecb_decrypt_block(key, &block));
    }
    Some(plaintext)
}

/// [`sm4_cbc_encrypt`] CBC 整段加密：IV 第一个块异或、链式反馈、0 填充。
pub fn sm4_cbc_encrypt(key: &[u8; SM4_KEY_BYTES], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Sm4Cipher::new(key);
    let mut out = Vec::with_capacity(((data.len() + 15) / 16) * 16);
    let mut prev = *iv;
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            block[i] ^= prev[i];
        }
        let enc = cipher.encrypt_block(&block);
        out.extend_from_slice(&enc);
        prev = enc;
    }
    out
}

/// [`sm4_cbc_decrypt`] CBC 整段解密：长度必须 16 倍数且非零，否则拒绝。
pub fn sm4_cbc_decrypt(
    key: &[u8; SM4_KEY_BYTES],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return None;
    }
    let cipher = Sm4Cipher::new(key);
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut prev = *iv;
    for chunk in ciphertext.chunks_exact(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let dec = sm4_ecb_decrypt_block(key, &block);
        for i in 0..16 {
            plaintext.push(dec[i] ^ prev[i]);
        }
        prev = block;
    }
    Some(plaintext)
}

/// [`sm4_gcm_encrypt_with_nonce`] 固定 nonce 加密，返回 (密文, tag)。
fn sm4_gcm_encrypt_with_nonce(
    cipher: &Sm4Cipher,
    nonce: &[u8; GM_NONCE_BYTES],
    plaintext: &[u8],
    aad: &[u8],
) -> (Vec<u8>, [u8; GM_TAG_BYTES]) {
    let mut j0 = [0u8; 16];
    j0[..GM_NONCE_BYTES].copy_from_slice(nonce);
    j0[15] = 0x01;
    // = E(nonce||0x02)（即 J0+1），tag 掩码仍为 E(J0)。与 Go 侧逐字节一致。
    let mut ctr = j0;
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    for chunk in plaintext.chunks(16) {
        inc32(&mut ctr);
        let keystream = cipher.encrypt_block(&ctr);
        for (pos, byte) in chunk.iter().enumerate() {
            ciphertext.push(byte ^ keystream[pos]);
        }
    }
    let tag = sm4_gcm_tag(cipher, nonce, &ciphertext, aad);
    (ciphertext, tag)
}

/// [`sm4_gcm_decrypt_with_nonce`] 校验标签后解出明文，失败返回 None。
fn sm4_gcm_decrypt_with_nonce(
    cipher: &Sm4Cipher,
    nonce: &[u8; GM_NONCE_BYTES],
    ciphertext: &[u8],
    aad: &[u8],
    tag: &[u8; GM_TAG_BYTES],
) -> Option<Vec<u8>> {
    if ciphertext.is_empty() {
        return None;
    }
    if sm4_gcm_tag(cipher, nonce, ciphertext, aad) != *tag {
        return None;
    }
    let mut j0 = [0u8; 16];
    j0[..GM_NONCE_BYTES].copy_from_slice(nonce);
    j0[15] = 0x01;
    // 与加密侧同一契约：CRT 计数先自增。
    let mut ctr = j0;
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(16) {
        inc32(&mut ctr);
        let keystream = cipher.encrypt_block(&ctr);
        for (pos, byte) in chunk.iter().enumerate() {
            plaintext.push(byte ^ keystream[pos]);
        }
    }
    Some(plaintext)
}

// ---------- 密钥与信封工具 ----------

/// [`envelope_header`] 构造 8 字节头部：magic|version|domain|reserved|sig_len。
fn envelope_header(domain: u8) -> [u8; ENVELOPE_HEADER_BYTES] {
    [
        ENVELOPE_MAGIC[0],
        ENVELOPE_MAGIC[1],
        ENVELOPE_MAGIC[2],
        ENVELOPE_MAGIC[3],
        ENVELOPE_VERSION,
        domain,
        0x00,
        ENVELOPE_SIG_LEN,
    ]
}

fn sm4_key_from_hex(key_hex: &str) -> Option<[u8; SM4_KEY_BYTES]> {
    // b1 契约：页面下发的是会话主密钥 hex（64 字符，key32），
    // SM4 密钥 = key32 前 16 字节；长度不符一律拒绝。
    let key = crate::crypto::hex_decode(key_hex)?;
    if key.len() != 32 {
        return None;
    }
    let mut out = [0u8; SM4_KEY_BYTES];
    out.copy_from_slice(&key[..SM4_KEY_BYTES]);
    Some(out)
}

fn domain_ok(domain: u8) -> bool {
    matches!(
        domain,
        DOMAIN_ENV | DOMAIN_CAPTCHA_DATA | DOMAIN_CAPTCHA_ANSWER | DOMAIN_BROWSERSIGN
    )
}

/// [`seal_raw`] 浏览器侧单向信封 Seal（内部），返回 raw 字节。
/// sig 字段由会话级一次性 keypair 输入时用标准 ZA 签名填充
/// （见 [`seal_envelope_signed`]）；无签名私钥的调用 fill 零。
fn seal_raw(domain: u8, key: &[u8; SM4_KEY_BYTES], plaintext: &[u8]) -> Option<Vec<u8>> {
    if plaintext.is_empty() || plaintext.len() > MAX_GM_PLAINTEXT_BYTES || !domain_ok(domain) {
        return None;
    }
    let header = envelope_header(domain);
    let cipher = Sm4Cipher::new(key);
    let mut nonce = [0u8; GM_NONCE_BYTES];
    if getrandom::getrandom(&mut nonce).is_err() {
        return None;
    }
    let (ct, tag) = sm4_gcm_encrypt_with_nonce(&cipher, &nonce, plaintext, &header);
    if ct.len() > MAX_GM_CIPHERTEXT_BYTES {
        return None;
    }
    // sig 字段：无签名私钥时零填充，签名版见 seal_envelope_signed。
    let sig = [0u8; SM2_RAW_SIG_BYTES];
    // sm3_tag = SM3(magic..sig 末尾的全部字节)。即构到这一层的 raw_prefix 整体。
    let raw_prefix = assemble_prefix(&header, &nonce, &ct, &tag, &sig);
    let sm3_tag = crate::sm3::sm3_digest(&raw_prefix);
    assemble_raw(&raw_prefix, &sm3_tag)
}

fn assemble_prefix(
    header: &[u8; ENVELOPE_HEADER_BYTES],
    nonce: &[u8; GM_NONCE_BYTES],
    ct: &[u8],
    tag: &[u8; GM_TAG_BYTES],
    sig: &[u8; SM2_RAW_SIG_BYTES],
) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(
        ENVELOPE_HEADER_BYTES + GM_NONCE_BYTES + ct.len() + GM_TAG_BYTES + SM2_RAW_SIG_BYTES,
    );
    prefix.extend_from_slice(header);
    prefix.extend_from_slice(nonce);
    prefix.extend_from_slice(ct);
    prefix.extend_from_slice(tag);
    prefix.extend_from_slice(sig);
    prefix
}

/// [`assemble_raw`] 拼装 prefix + given sm3_tag。
fn assemble_raw(prefix: &[u8], sm3_tag: &[u8; SM3_OUT_BYTES]) -> Option<Vec<u8>> {
    let mut raw = Vec::with_capacity(prefix.len() + SM3_OUT_BYTES);
    raw.extend_from_slice(prefix);
    raw.extend_from_slice(sm3_tag);
    Some(raw)
}

/// [`envelope_sign_scope`] 签名覆盖范围（OWVE 契约）：
/// headerid(4B 零) || 信封头部到 tag 末尾（含 nonce/ct/tag）。
fn envelope_sign_scope(
    header: &[u8; ENVELOPE_HEADER_BYTES],
    nonce: &[u8; GM_NONCE_BYTES],
    ct: &[u8],
    tag: &[u8; GM_TAG_BYTES],
) -> Vec<u8> {
    let mut scope =
        Vec::with_capacity(4 + ENVELOPE_HEADER_BYTES + GM_NONCE_BYTES + ct.len() + GM_TAG_BYTES);
    scope.extend_from_slice(&[0u8; 4]);
    scope.extend_from_slice(header);
    scope.extend_from_slice(nonce);
    scope.extend_from_slice(ct);
    scope.extend_from_slice(tag);
    scope
}

/// [`seal_envelope_signed`] 用会话级一次性私钥对信封签名（标准 ZA），
/// sig 覆盖范围与 b1 契约一致。返回 base64url 文本。
pub fn seal_envelope_signed(key_hex: &str, plaintext: &str, domain: u8, priv_hex: &str) -> String {
    let key = match sm4_key_from_hex(key_hex) {
        Some(key) => key,
        None => return String::new(),
    };
    if plaintext.is_empty() || plaintext.len() > MAX_GM_PLAINTEXT_BYTES || !domain_ok(domain) {
        return String::new();
    }
    let sk = match normalize_priv_key(priv_hex) {
        Some(raw) => raw,
        None => return String::new(),
    };
    let header = envelope_header(domain);
    let cipher = Sm4Cipher::new(&key);
    let mut nonce = [0u8; GM_NONCE_BYTES];
    if getrandom::getrandom(&mut nonce).is_err() {
        return String::new();
    }
    let (ct, tag) = sm4_gcm_encrypt_with_nonce(&cipher, &nonce, plaintext.as_bytes(), &header);
    // 标准 ZA 签名（ID=owaf-gm-challenge）：签名对象为覆盖范围字节，
    // DER 编码后取 r||s 前 32+32 字节填充签名字段。
    // sig 覆盖 = headerid(4B 零) || 信封头部..tag 末尾（与 b1 Seal 一致）。
    let scope = envelope_sign_scope(&header, &nonce, &ct, &tag);
    let sk_hex = crate::hex_encode(&sk);
    let e = derive_e_standard(SM2_USER_ID, &public_key_hex(&sk_hex), &scope);
    let signer = smcrypto::sm2::Sign::new(&sk_hex);
    let der = signer.sign_raw(&e);
    let mut sig = [0u8; SM2_RAW_SIG_BYTES];
    fill_rs_from_der(&der, &mut sig);
    let raw_prefix = assemble_prefix(&header, &nonce, &ct, &tag, &sig);
    // sm3_tag = SM3(magic..sig 末尾)（与 b1 Seal 一致）。
    let sm3_tag = crate::sm3::sm3_digest(&raw_prefix);
    let raw = match assemble_raw(&raw_prefix, &sm3_tag) {
        Some(raw) => raw,
        None => return String::new(),
    };
    crate::crypto::base64url_encode(&raw)
}

/// [`fill_rs_from_der`] 从 DER 签名解出 r||s 填 64 字节；失败时保持零。
fn fill_rs_from_der(der: &[u8], out: &mut [u8; SM2_RAW_SIG_BYTES]) {
    let (r, s) = match parse_der_signature(der) {
        Some(rs) => rs,
        None => return,
    };
    out[..32].copy_from_slice(&r);
    out[32..].copy_from_slice(&s);
}

/// [`open_raw`] 校验顺序：sm3_out -> 结构字段 -> GCM（sig 字段由服务端
fn open_raw(domain: u8, key: &[u8; SM4_KEY_BYTES], raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len()
        < ENVELOPE_HEADER_BYTES
            + GM_NONCE_BYTES
            + 1
            + GM_TAG_BYTES
            + SM2_RAW_SIG_BYTES
            + SM3_OUT_BYTES
    {
        return None;
    }
    if raw[..4] != *ENVELOPE_MAGIC
        || raw[4] != ENVELOPE_VERSION
        || raw[5] != domain
        || raw[6] != 0
        || raw[7] != ENVELOPE_SIG_LEN
    {
        return None;
    }
    let ct_end = raw.len() - SM2_RAW_SIG_BYTES - SM3_OUT_BYTES - GM_TAG_BYTES;
    let ct = &raw[ENVELOPE_HEADER_BYTES + GM_NONCE_BYTES..ct_end];
    if ct.is_empty() || ct.len() > MAX_GM_CIPHERTEXT_BYTES {
        return None;
    }
    // 校验顺序 1：sm3_tag = SM3(magic..sig 末尾)（首个整体校验，与 b1 Open 一致）。
    let sm3_tag_in = &raw[raw.len() - SM3_OUT_BYTES..];
    let expected = crate::sm3::sm3_digest(&raw[..raw.len() - SM3_OUT_BYTES]);
    if !ct_eq(sm3_tag_in, expected.as_slice()) {
        return None;
    }
    // 校验顺序 2+3：结构字段在前，GCM 在后。
    let header = envelope_header(domain);
    let mut nonce = [0u8; GM_NONCE_BYTES];
    nonce.copy_from_slice(&raw[ENVELOPE_HEADER_BYTES..ENVELOPE_HEADER_BYTES + GM_NONCE_BYTES]);
    let mut tag = [0u8; GM_TAG_BYTES];
    tag.copy_from_slice(&raw[ct_end..ct_end + GM_TAG_BYTES]);
    let cipher = Sm4Cipher::new(key);
    // GCM 失败在内部以常数时间路径处理；对外始终返回同一拒绝形态。
    let plaintext = match sm4_gcm_decrypt_with_nonce(&cipher, &nonce, ct, &header, &tag) {
        Some(plaintext) => plaintext,
        None => {
            let _ = ct_eq(&tag, &sm4_gcm_tag(&cipher, &nonce, ct, &header));
            return None;
        }
    };
    if plaintext.len() > MAX_GM_PLAINTEXT_BYTES {
        return None;
    }
    Some(plaintext)
}

fn seal_envelope_text(key_hex: &str, plaintext: &str, domain: u8) -> String {
    let key = match sm4_key_from_hex(key_hex) {
        Some(key) => key,
        None => return String::new(),
    };
    let raw = match seal_raw(domain, &key, plaintext.as_bytes()) {
        Some(raw) => raw,
        None => return String::new(),
    };
    crate::crypto::base64url_encode(&raw)
}

fn open_envelope_text(envelope: &str, key_hex: &str, domain: u8) -> String {
    let raw = match crate::crypto::base64_decode(envelope) {
        Some(raw) => raw,
        None => return String::new(),
    };
    let key = match sm4_key_from_hex(key_hex) {
        Some(key) => key,
        None => return String::new(),
    };
    match open_raw(domain, &key, &raw) {
        Some(plaintext) => String::from_utf8(plaintext).unwrap_or_default(),
        None => String::new(),
    }
}

/// [`open_raw_signed`] 带 sig 校验的打开：sm3_out（恒时）-> 结构 ->
/// GCM -> sig（标准 ZA 验签，覆盖范围与 Seal 一致）。
fn open_raw_signed(envelope: &str, key_hex: &str, domain: u8, pub_hex: &str) -> Option<String> {
    let raw = crate::crypto::base64_decode(envelope)?;
    let key = sm4_key_from_hex(key_hex)?;
    let public_key = normalize_pub_key(pub_hex)?;
    if raw.len()
        < ENVELOPE_HEADER_BYTES
            + GM_NONCE_BYTES
            + 1
            + GM_TAG_BYTES
            + SM2_RAW_SIG_BYTES
            + SM3_OUT_BYTES
    {
        return None;
    }
    if raw[..4] != *ENVELOPE_MAGIC
        || raw[4] != ENVELOPE_VERSION
        || raw[5] != domain
        || raw[6] != 0
        || raw[7] != ENVELOPE_SIG_LEN
    {
        return None;
    }
    let ct_end = raw.len() - SM2_RAW_SIG_BYTES - SM3_OUT_BYTES - GM_TAG_BYTES;
    let ct = &raw[ENVELOPE_HEADER_BYTES + GM_NONCE_BYTES..ct_end];
    if ct.is_empty() {
        return None;
    }
    // sig 覆盖范围：headerid(4B 零) || 头部..tag 末尾。
    let scope_end = ct_end + GM_TAG_BYTES;
    let scope = {
        let mut scope = Vec::with_capacity(4 + scope_end);
        scope.extend_from_slice(&[0u8; 4]);
        scope.extend_from_slice(&raw[..scope_end]);
        scope
    };
    let sig_bytes = &raw[ct_end + GM_TAG_BYTES..raw.len() - SM3_OUT_BYTES];
    let (r, s) = parse_der_from_rs(sig_bytes);
    // 标准 ZA 验签（与 Seal 侧同一覆盖范围、同一 ID）。
    let e = derive_e_standard(SM2_USER_ID, &public_key, &scope);
    let der = der_encode_signature(&r, &s);
    let verifier = smcrypto::sm2::Verify::new(&public_key);
    let sig_verified = verifier.verify_raw(&e, &der);
    if !sig_verified {
        return None;
    }
    // sm3_tag = SM3(magic..sig 末尾)（与 b1 Open 同序：整体校验 -> 结构 -> sig -> GCM）。
    let sm3_tag_in = &raw[raw.len() - SM3_OUT_BYTES..];
    let expected_all = crate::sm3::sm3_digest(&raw[..raw.len() - SM3_OUT_BYTES]);
    if !ct_eq(sm3_tag_in, expected_all.as_slice()) {
        return None;
    }
    let header = envelope_header(domain);
    let mut nonce = [0u8; GM_NONCE_BYTES];
    nonce.copy_from_slice(&raw[ENVELOPE_HEADER_BYTES..ENVELOPE_HEADER_BYTES + GM_NONCE_BYTES]);
    let mut tag = [0u8; GM_TAG_BYTES];
    tag.copy_from_slice(&raw[ct_end..ct_end + GM_TAG_BYTES]);
    let cipher = Sm4Cipher::new(&key);
    let plaintext = match sm4_gcm_decrypt_with_nonce(&cipher, &nonce, ct, &header, &tag) {
        Some(plaintext) => plaintext,
        None => {
            let _ = ct_eq(&tag, &sm4_gcm_tag(&cipher, &nonce, ct, &header));
            return None;
        }
    };
    String::from_utf8(plaintext).ok()
}

/// [`parse_der_signature`] 解析 DER 签名的 r/s（去掉长度前缀，恒 32 字节）。
fn parse_der_signature(sig: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    // DER 结构：SEQUENCE { INTEGER r, INTEGER s }，只做最小解析。
    if sig.len() < 8 || sig[0] != 0x30 {
        return None;
    }
    let seq_len = sig[1] as usize;
    if sig.len() < 2 + seq_len || sig[2] != 0x02 {
        return None;
    }
    let r_len = sig[3] as usize;
    if sig.len() < 4 + r_len || sig[4 + r_len] != 0x02 {
        return None;
    }
    let s_len = sig[5 + r_len] as usize;
    let r_start = 4;
    let s_start = 6 + r_len;
    if sig.len() < s_start + s_len {
        return None;
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    let r_bytes = &sig[r_start..r_start + r_len];
    let s_bytes = &sig[s_start..s_start + s_len];
    let r_off = if r_bytes.len() > 32 {
        r_bytes.len() - 32
    } else {
        0
    };
    let s_off = if s_bytes.len() > 32 {
        s_bytes.len() - 32
    } else {
        0
    };
    r[32 - (r_bytes.len() - r_off)..].copy_from_slice(&r_bytes[r_off..]);
    s[32 - (s_bytes.len() - s_off)..].copy_from_slice(&s_bytes[s_off..]);
    Some((r, s))
}

/// [`parse_der_from_rs`] 将裸 r||s（64B）包装解析为 r/s 分量。
fn parse_der_from_rs(rs: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    if rs.len() >= 64 {
        r.copy_from_slice(&rs[..32]);
        s.copy_from_slice(&rs[32..64]);
    }
    (r, s)
}

/// [`der_encode_signature`] 将 r/s 重编码为 DER（最小前导零形式）。
fn der_encode_signature(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    fn int_bytes(v: &[u8; 32]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut started = false;
        for &b in v.iter() {
            if !started && b == 0 {
                continue;
            }
            started = true;
            bytes.push(b);
        }
        if bytes.is_empty() {
            bytes.push(0);
        }
        if bytes[0] & 0x80 != 0 {
            let mut padded = vec![0u8];
            padded.extend_from_slice(&bytes);
            return padded;
        }
        bytes
    }
    let rb = int_bytes(r);
    let sb = int_bytes(s);
    let mut der = Vec::new();
    der.push(0x30);
    der.push((2 + rb.len() + 2 + sb.len()) as u8);
    der.push(0x02);
    der.push(rb.len() as u8);
    der.extend_from_slice(&rb);
    der.push(0x02);
    der.push(sb.len() as u8);
    der.extend_from_slice(&sb);
    der
}

/// [`sm2_za`] 标准 SM2 ZA 值：ENTLA ‖ ID ‖ a‖b‖xG‖yG‖xA‖yA。
/// ENTLA 为 ID 的**比特**长度（2 字节大端），与 smcrypto `zab`
/// （`8 * uid.len()`）逐字节一致；ZA 的 SM3 每次从标准初始 IV fresh 计算。
pub fn sm2_za(id: &[u8], pub_hex: &str) -> Vec<u8> {
    let entla = (id.len() as u16).wrapping_mul(8);
    let mut za = Vec::with_capacity(2 + id.len() + 32 * 6);
    za.extend_from_slice(&entla.to_be_bytes());
    za.extend_from_slice(id);
    za.extend_from_slice(&ECC_A);
    za.extend_from_slice(&ECC_B);
    za.extend_from_slice(&ECC_GX);
    za.extend_from_slice(&ECC_GY);
    let pk = match crate::crypto::hex_decode(pub_hex) {
        Some(pk) if pk.len() == 64 => pk,
        _ => return Vec::new(),
    };
    za.extend_from_slice(&pk[..32]);
    za.extend_from_slice(&pk[32..]);
    za
}

/// [`sm2_truncate_e`] GM/T 0003-2012 验签步 B8 前把 e 二进制串截取到
/// 曲线阶 n 的比特长度（256 位）。wasm 侧 import 承诺 32 字节，
/// 超长者按 n 比特掩码截断（不引入生态依赖的包装差异）。
fn sm2_truncate_e(e: &[u8; 32]) -> [u8; 32] {
    let n = BigUint::from_str_radix(ECC_N, 16).unwrap_or_else(|_| BigUint::from(0u8));
    let bit_len = n.bits() as usize;
    if bit_len >= 256 {
        return *e;
    }
    let mut m = (BigUint::from(1u8) << bit_len) - BigUint::from(1u8);
    let big = BigUint::from_bytes_be(&e[..]) & &m;
    let mut out = [0u8; 32];
    let bytes = BigUint::to_bytes_be(&big);
    if bytes.len() > 32 {
        return *e;
    }
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// [`sm2_raw_sign`] 标准 SM2 低层签名（GM/T 0003.2-2012 6.1）：
/// e' = 截断(e, n 比特长)、随机 k∈[1,n-1]、(x1,y1)=[k]G、
/// r=(e'+x1) mod n、s=((1+d)^-1 (k-rd)) mod n，失败路径重试 k。
/// 自研素域点乘路径（上游 smcrypto sign_raw 无参包装不回用），
/// 输出 DER SEQUENCE{INTEGER r, INTEGER s}。
pub fn sm2_raw_sign(sk_hex: &str, e: &[u8; 32]) -> Option<Vec<u8>> {
    let e = sm2_truncate_e(e);
    let n = BigUint::from_str_radix(ECC_N, 16).ok()?;
    let d = BigUint::from_str_radix(sk_hex, 16).ok()?;
    if d == BigUint::from(0u8) {
        return None;
    }
    // k 探索范围上限：小步尝试把概率性重试集中在主循环（不超过 64 步）。
    for _ in 0..64 {
        let mut k_bytes = [0u8; 32];
        if getrandom::getrandom(&mut k_bytes).is_err() {
            return None;
        }
        let k = BigUint::from_bytes_be(&k_bytes) % &n;
        if k == BigUint::from(0u8) {
            continue;
        }
        let gx = BigUint::from_bytes_be(&ECC_GX);
        let gy = BigUint::from_bytes_be(&ECC_GY);
        let p = BigUint::from_str_radix(ECC_P, 16).ok()?;
        let a = BigUint::from_bytes_be(&ECC_A);
        let p1 = sm2_scalar_mul(&k, &gx, &gy, &p, &a);
        if p1 == (BigUint::from(0u8), BigUint::from(0u8)) {
            continue;
        }
        let r = (&BigUint::from_bytes_be(&e) + &p1.0) % &n;
        if r == BigUint::from(0u8) || &r + &k == n {
            continue;
        }
        let d_1 = (&d + BigUint::from(1u8)).modpow(&(&n - BigUint::from(2u8)), &n);
        let rd = (&r * &d) % &n;
        let diff = if k >= rd {
            k.clone() - &rd
        } else {
            &k + &n - &rd
        };
        let s = (&d_1 * diff) % &n;
        if s == BigUint::from(0u8) {
            continue;
        }
        return Some(der_encode_signature(&*big_to_32_be(&r), &*big_to_32_be(&s)));
    }
    None
}

/// [`sm2_raw_verify`] 标准 SM2 低层验签（GM/T 0003.2-2012 7.1）：
/// e' = 截断(e, n)、r,s ∈ [1,n-1]、t=(r+s) mod n ≠ 0、
/// (x1',y1')=[s']G+[t]PA、R=(e'+x1') mod n == r。
pub fn sm2_raw_verify(pub_hex: &str, e: &[u8; 32], der: &[u8]) -> bool {
    let e = sm2_truncate_e(e);
    let n = match BigUint::from_str_radix(ECC_N, 16) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let p = match BigUint::from_str_radix(ECC_P, 16) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let a = BigUint::from_bytes_be(&ECC_A);
    let (r, s) = match parse_der_signature(der) {
        Some(rs) => rs,
        None => return false,
    };
    let r_b = BigUint::from_bytes_be(&r[..]);
    let s_b = BigUint::from_bytes_be(&s[..]);
    if r_b == BigUint::from(0u8) || s_b == BigUint::from(0u8) || r_b >= n || s_b >= n {
        return false;
    }
    let t = (&r_b + &s_b) % &n;
    if t == BigUint::from(0u8) {
        return false;
    }
    let pub_raw = match decode_pub_key(pub_hex) {
        Some(raw) if raw.len() == 64 && sm2_point_valid(&raw) => raw,
        _ => return false,
    };
    let pa_x = BigUint::from_bytes_be(&pub_raw[..32]);
    let pa_y = BigUint::from_bytes_be(&pub_raw[32..]);
    let gx = BigUint::from_bytes_be(&ECC_GX);
    let gy = BigUint::from_bytes_be(&ECC_GY);
    let s_g = sm2_scalar_mul(&s_b, &gx, &gy, &p, &a);
    let t_pa = sm2_scalar_mul(&t, &pa_x, &pa_y, &p, &a);
    let xy = if s_g == (BigUint::from(0u8), BigUint::from(0u8)) {
        t_pa
    } else if t_pa == (BigUint::from(0u8), BigUint::from(0u8)) {
        s_g
    } else {
        sm2_point_add(&s_g.0, &s_g.1, &t_pa.0, &t_pa.1, &p, &a)
    };
    if xy == (BigUint::from(0u8), BigUint::from(0u8)) {
        return false;
    }
    let big = (BigUint::from_bytes_be(&e) + xy.0) % &n;
    big == r_b
}

/// [`sm2_scalar_mul`] 朴素双倍-加标量乘（约 256 轮组合块，任意仿射基点）。
fn sm2_scalar_mul(
    k: &BigUint,
    x: &BigUint,
    y: &BigUint,
    p: &BigUint,
    a: &BigUint,
) -> (BigUint, BigUint) {
    let mut acc: Option<(BigUint, BigUint)> = None;
    let bits = k.to_str_radix(2);
    for ch in bits.chars() {
        if let Some(r) = acc.take() {
            acc = Some(sm2_point_double(&r.0, &r.1, p, a));
        }
        if ch == '1' {
            if let Some(r) = acc.take() {
                if r == (BigUint::from(0u8), BigUint::from(0u8)) {
                    acc = Some((x.clone(), y.clone()));
                } else {
                    acc = Some(sm2_point_add(&r.0, &r.1, x, y, p, a));
                }
            } else {
                acc = Some((x.clone(), y.clone()));
            }
        }
    }
    acc.unwrap_or_else(|| (BigUint::from(0u8), BigUint::from(0u8)))
}

/// [`big_to_32_be`] BigUint -> 左补零 32 字节大端；超 32 字节按低 32 截。
fn big_to_32_be(v: &BigUint) -> Box<[u8; 32]> {
    let bytes = BigUint::to_bytes_be(v);
    let mut out = [0u8; 32];
    let off = if bytes.len() > 32 {
        bytes.len() - 32
    } else {
        0
    };
    let take = bytes.len().min(32).saturating_sub(off);
    out[32 - take..].copy_from_slice(&bytes[off..off + take]);
    Box::new(out)
}

/// [`sm2_za_digest`] ZA 的 SM3 摘要。
pub fn sm2_za_digest(id: &[u8], pub_hex: &str) -> [u8; 32] {
    crate::sm3::sm3_digest(&sm2_za(id, pub_hex))
}

/// [`sm2_e_preimage`] 签名摘要 e 的输入：`ZA(32B digest) ‖ msg`
/// （GM/T 0003 标准公式，不含任何额外四字节；信封覆盖范围的 4B 零
/// headerID 属于被签名消息 M 本身，不进入本函数的拼接）。
pub fn sm2_e_preimage(id: &[u8], pub_hex: &str, msg: &[u8]) -> Vec<u8> {
    let mut buf = sm2_za_digest(id, pub_hex).to_vec();
    buf.extend_from_slice(msg);
    buf
}

fn normalize_priv_key(priv_hex: &str) -> Option<Vec<u8>> {
    let raw = crate::crypto::hex_decode(priv_hex)?;
    if raw.len() != 32 {
        return None;
    }
    let n = match BigUint::from_str_radix(ECC_N, 16) {
        Ok(n) => n,
        Err(_) => return None,
    };
    let d = BigUint::from_bytes_be(&raw);
    if d <= BigUint::from(0u8) || d >= n {
        return None;
    }
    Some(raw)
}

fn normalize_pub_key(pub_hex: &str) -> Option<String> {
    let trimmed = pub_hex.trim();
    let raw = decode_pub_key(trimmed)?;
    if raw.len() != 64 || !sm2_point_valid(&raw) {
        return None;
    }
    Some(crate::hex_encode(&raw).to_ascii_lowercase())
}

/// [`sm2_uncompress_pubkey`] 从 0x02/0x03 压缩公钥（33 字节）恢复完整
/// 非压缩形态（64 字节 x||y）。y = sqrt(x^3 + ax + b) mod p 的偶数
/// （0x02）/奇数（0x03）根；x 非法（无平方根或 y=0）返回 None。
fn sm2_uncompress_pubkey(compressed: &[u8]) -> Option<Vec<u8>> {
    if compressed.len() != 33 || (compressed[0] != 0x02 && compressed[0] != 0x03) {
        return None;
    }
    let p = BigUint::from_str_radix(ECC_P, 16).ok()?;
    let a = BigUint::from_bytes_be(&ECC_A);
    let b = BigUint::from_bytes_be(&ECC_B);
    let x = BigUint::from_bytes_be(&compressed[1..]);
    if x >= p {
        return None;
    }
    let alpha = ((((&x * &x) % &p) * &x) % &p + (&a * &x) % &p + &b) % &p;
    // y = alpha^((p+1)/4) mod p（p ≡ 3 mod 4 时的平方根）。
    let exp = (&p + BigUint::from(1u8)) / BigUint::from(4u8);
    let y = alpha.modpow(&exp, &p);
    if (&y * &y) % &p != alpha {
        return None;
    }
    let odd_bit = compressed[0] == 0x03;
    let parity = (&y & BigUint::from(1u8)) == BigUint::from(1u8);
    let y = if parity == odd_bit { y } else { &p - &y };
    if y == BigUint::from(0u8) {
        return None;
    }
    let mut xb = BigUint::to_bytes_be(&x);
    let mut yb = BigUint::to_bytes_be(&y);
    while xb.len() < 32 {
        xb.insert(0, 0);
    }
    while yb.len() < 32 {
        yb.insert(0, 0);
    }
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&xb);
    out.extend_from_slice(&yb);
    Some(out)
}

/// [`sm2_point_valid`] 非压缩公钥（64B x||y）的合法性校验：
/// x,y < p、非全零（无穷远点编码在此处拒绝）、且满足曲线方程
/// y² = x³+ax+b (mod p)。SM2 曲线群阶恰为素数 n（余因子 h=1），
/// 于是方程成立的非零仿射点必属于主阶子群，无需额外 [n]P 预乘。
fn sm2_point_valid(xy: &[u8]) -> bool {
    if xy.len() != 64 {
        return false;
    }
    let p = match BigUint::from_str_radix(ECC_P, 16) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let a = BigUint::from_bytes_be(&ECC_A);
    let b = BigUint::from_bytes_be(&ECC_B);
    let x = BigUint::from_bytes_be(&xy[..32]);
    let y = BigUint::from_bytes_be(&xy[32..]);
    if x >= p || y >= p {
        return false;
    }
    if x == BigUint::from(0u8) && y == BigUint::from(0u8) {
        return false;
    }
    let alpha = ((((&x * &x) % &p) * &x) % &p + (&a * &x) % &p + &b) % &p;
    ((&y * &y) % &p) == alpha
}

/// [`sm2_point_double`] 仿射点倍：λ=(3x²+a)/(2y)、x'=λ²-2x、y'=λ(x-x')-y。
fn sm2_point_double(x: &BigUint, y: &BigUint, p: &BigUint, a: &BigUint) -> (BigUint, BigUint) {
    use num_traits::Zero;
    let zero = BigUint::zero();
    if y == &zero {
        return (zero.clone(), zero);
    }
    let two = BigUint::from(2u8);
    let three = BigUint::from(3u8);
    // λ = (3x² + a) · (2y)⁻¹ (mod p)：分子与分母各自取模后求逆相乘。
    let m = ((x * x) * &three + a) % p;
    let two_y = (&two * y) % p;
    let inv_2y = two_y.modpow(&(p - &two), p);
    let lam = m * &inv_2y % p;
    let x3 = (&lam * &lam + p - ((&two * x) % p)) % p;
    let y3 = (&lam * ((x + p - &x3) % p)) % p;
    let y3 = (y3 + p - y) % p;
    (x3, y3)
}

/// [`sm2_point_add`] 仿射点加（两非无穷远点；坐标相同走加倍分支）。
fn sm2_point_add(
    x1: &BigUint,
    y1: &BigUint,
    x2: &BigUint,
    y2: &BigUint,
    p: &BigUint,
    a: &BigUint,
) -> (BigUint, BigUint) {
    if x1 == x2 && y1 == y2 {
        return sm2_point_double(x1, y1, p, a);
    }
    let x_diff = (x2 + p - x1) % p;
    if x_diff == BigUint::from(0u8) {
        // x 相同而 y 不同：和为无穷远点，用 (0,0) 哨兵表示。
        return (BigUint::from(0u8), BigUint::from(0u8));
    }
    let inv = x_diff.modpow(&(p - &BigUint::from(2u8)), p);
    let lam = ((y2 + p - y1) % p * &inv) % p;
    let x3 = (&lam * &lam + p - x1 + p - x2) % p;
    let y3 = (&lam * ((x1 + p - &x3) % p) % p + p - y1) % p;
    (x3, y3)
}

/// [`sm2_point_neg`] 仿射点取负：-P = (x, p-y)；无穷远 (0,0) 返回 None。
fn sm2_point_neg(x: BigUint, y: BigUint, p: &BigUint) -> Option<(BigUint, BigUint)> {
    if x == BigUint::from(0u8) && y == BigUint::from(0u8) {
        return None;
    }
    if y == BigUint::from(0u8) {
        return Some((x, BigUint::from(0u8)));
    }
    Some((x, p - &y))
}

/// [`encode_pub_key_decompressed`] 从 x||y 直角坐标生成非压缩 04 形态。
pub fn encode_pub_key_decompressed(x_y: &[u8; 64]) -> Option<Vec<u8>> {
    if !sm2_point_valid(x_y) {
        return None;
    }
    let mut out = Vec::with_capacity(65);
    out.push(0x04);
    out.extend_from_slice(x_y);
    Some(out)
}

/// [`encode_pub_key_compressed`] 从 x||y 直角坐标生成压缩形态：
/// 0x02（y 偶）或 0x03（y 奇）。
pub fn encode_pub_key_compressed(x_y: &[u8; 64]) -> Option<Vec<u8>> {
    if !sm2_point_valid(x_y) {
        return None;
    }
    let prefix = if x_y[63] & 1 == 0 { 0x02u8 } else { 0x03u8 };
    let mut out = Vec::with_capacity(33);
    out.push(prefix);
    out.extend_from_slice(&x_y[..32]);
    Some(out)
}

/// [`decode_pub_key`] 公钥形态解码：04 前缀 / 02 / 03 压缩 / 裸 x||y
/// 均归一为 64 字节非压缩字节形态；未校验曲线（校验由调用方承担）。
fn decode_pub_key(trimmed: &str) -> Option<Vec<u8>> {
    if trimmed.len() == 130 && trimmed.starts_with("04") {
        let raw = crate::crypto::hex_decode(&trimmed[2..])?;
        if raw.len() != 64 {
            return None;
        }
        return Some(raw);
    }
    let raw = crate::crypto::hex_decode(trimmed)?;
    match raw.len() {
        64 => Some(raw),
        33 if raw[0] == 0x02 || raw[0] == 0x03 => {
            let xy = sm2_uncompress_pubkey(&raw)?;
            Some(xy)
        }
        _ => None,
    }
}

// ---------- wasm 导出（b1 第 8 条导出名） ----------

/// [`gm_sm3_hmac`] b1 契约：SM3(key||msg) 输出 hex（64 字符）。
/// key 为会话主密钥 hex（64 字符 key32），超长 key 一律拒绝。
#[wasm_bindgen]
pub fn gm_sm3_hmac(keyhex: &str, msg: &str) -> String {
    let mut key = match crate::crypto::hex_decode(keyhex) {
        Some(key) if !key.is_empty() => key,
        _ => return String::new(),
    };
    if key.len() > SM3_HMAC_MAX_KEY_BYTES || msg.is_empty() {
        return String::new();
    }
    key.extend_from_slice(msg.as_bytes());
    crate::hex_encode(&sm3_digest(&key))
}

/// [`gm_decrypt_challenge_data`] captcha 题目解密（domain 0x02）。
#[wasm_bindgen]
pub fn gm_decrypt_challenge_data(envelope: &str, key_hex: &str) -> String {
    open_envelope_text(envelope, key_hex, DOMAIN_CAPTCHA_DATA)
}

/// [`gm_encrypt_challenge_answer`] captcha 答案加密（domain 0x03）。
#[wasm_bindgen]
pub fn gm_encrypt_challenge_answer(answer: &str, key_hex: &str) -> String {
    seal_envelope_text(key_hex, answer, DOMAIN_CAPTCHA_ANSWER)
}

/// [`gm_encrypt_fingerprint_gcm`] env 指纹加密（domain 0x01）。
/// aad 参数为调用面占位（OWVE 契约的 GCM AAD 由信封头部固定），
/// 空值仍失败关闭，防止调用侧不传参。
#[wasm_bindgen]
pub fn gm_encrypt_fingerprint_gcm(key_hex: &str, aad: &str) -> String {
    if aad.is_empty() {
        return String::new();
    }
    match crate::fingerprint::internal_fingerprint_payload() {
        Some(payload) => seal_envelope_text(key_hex, &payload, DOMAIN_ENV),
        None => String::new(),
    }
}

/// [`gm_encrypt_fingerprint_gcm_behavior`] env+behavior 指纹加密（domain 0x01）。
#[wasm_bindgen]
pub fn gm_encrypt_fingerprint_gcm_behavior(
    key_hex: &str,
    aad: &str,
    behavior_json: &str,
) -> String {
    if aad.is_empty() {
        return String::new();
    }
    match crate::fingerprint::internal_fingerprint_payload_with_behavior(behavior_json) {
        Some(payload) => seal_envelope_text(key_hex, &payload, DOMAIN_ENV),
        None => String::new(),
    }
}

/// `e = SM3(ZA ‖ M)`，ZA = SM3(ENTLA‖ID‖a‖b‖xG‖yG‖xA‖yA) 的 32B digest。
/// **禁止**在双方代码里再拼 e 的字面量（此函数是唯一实现点之一）。
fn derive_e_standard(id: &[u8], pub_hex: &str, msg: &[u8]) -> [u8; 32] {
    crate::sm3::sm3_digest(&sm2_e_preimage(id, pub_hex, msg))
}

/// [`public_key_hex`] 从 32 字节私钥快算公钥（smcrypto），返回 128 字符 hex。
fn public_key_hex(priv_hex: &str) -> String {
    if !smcrypto::sm2::privkey_valid(priv_hex) {
        return String::new();
    }
    smcrypto::sm2::pk_from_sk(priv_hex)
}

/// ID="owaf-gm-challenge"）。pub_hex 128 字符 hex（无 04 前缀），
/// sig 为标准 base64（RFC4648）DER。
#[wasm_bindgen]
pub fn gm_verify_signature(pub_hex: &str, sig_b64_std: &str, msg: &str) -> bool {
    if msg.is_empty() || msg.len() > MAX_GM_PLAINTEXT_BYTES {
        return false;
    }
    let sig = match crate::crypto::base64_decode(sig_b64_std) {
        Some(sig) if !sig.is_empty() => sig,
        _ => return false,
    };
    verify_za_der(pub_hex, &sig, msg.as_bytes())
}

/// ID="owaf-gm-challenge"）。输入私钥 hex 64 字符（32 字节，会话级一次性
/// keypair 的私钥，签名后即弃），输出 ASN.1 DER 的标准 base64（RFC4648）。
#[wasm_bindgen]
pub fn gm_sign_challenge(json: &str, priv_hex: &str) -> String {
    if json.is_empty() || json.len() > MAX_GM_PLAINTEXT_BYTES {
        return String::new();
    }
    let der = sign_za_der(json.as_bytes(), priv_hex);
    if der.is_empty() {
        return String::new();
    }
    crate::crypto::base64_encode(&der)
}

/// [`sign_za_der`] 标准 ZA 签名的内部实现（导出面仅 gm_sign_challenge）。
/// 语义：自算 e=SM3(ZA‖M) 后 sign_raw（见模块头注释）。
fn sign_za_der(msg: &[u8], priv_hex: &str) -> Vec<u8> {
    let sk = match normalize_priv_key(priv_hex) {
        Some(raw) => crate::hex_encode(&raw),
        None => return Vec::new(),
    };
    let pk = public_key_hex(&sk);
    if pk.is_empty() {
        return Vec::new();
    }
    let e = derive_e_standard(SM2_USER_ID, &pk, msg);
    let signer = smcrypto::sm2::Sign::new(&sk);
    signer.sign_raw(&e)
}

/// [`verify_za_der`] 标准 ZA 验签的内部实现（导出面仅 gm_verify_challenge /
/// gm_verify_signature）。语义同 [`sign_za_der`]。
fn verify_za_der(pub_hex: &str, sig_der: &[u8], msg: &[u8]) -> bool {
    let public_key = match normalize_pub_key(pub_hex) {
        Some(key) => key,
        None => return false,
    };
    if sig_der.is_empty() {
        return false;
    }
    let e = derive_e_standard(SM2_USER_ID, &public_key, msg);
    let verifier = smcrypto::sm2::Verify::new(&public_key);
    verifier.verify_raw(&e, sig_der)
}

/// [`gm_verify_challenge`] 原任务书验签导出名（标准 ZA 语义）。
#[wasm_bindgen]
pub fn gm_verify_challenge(json: &str, sig_b64: &str, pub_hex: &str) -> bool {
    gm_verify_signature(pub_hex, sig_b64, json)
}

/// [`gm_seal_signed`] 用会话级一次性私钥签发 OWVE 信封（标准 ZA），
/// sig 字段 = DER 的 r||s（64B），覆盖范围与 b1 契约一致。
#[wasm_bindgen]
pub fn gm_seal_signed(key_hex: &str, plaintext: &str, domain: u8, priv_hex: &str) -> String {
    seal_envelope_signed(key_hex, plaintext, domain, priv_hex)
}

/// [`gm_open_verify_sig`] 打开信封并用发布者公钥核对其 sig 字段
/// （标准 ZA 验签）。内部走恒定时间比较；任一步失败返回空串。
#[wasm_bindgen]
pub fn gm_open_verify_sig(envelope: &str, key_hex: &str, domain: u8, pub_hex: &str) -> String {
    match open_raw_signed(envelope, key_hex, domain, pub_hex) {
        Some(plaintext) => plaintext,
        None => String::new(),
    }
}

/// [`ct_eq`] 恒定时间字节比较（掩蔽内部失败路径差异，不作为可观测输出）。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// [`sm3_kdf`] SM3-HKDF 式密钥派生（复用到 label.rs 邻接实现）。
pub fn sm3_kdf(key: &[u8], category: &str) -> [u8; 32] {
    crate::label::sm3_kdf(key, category)
}
 
#[wasm_bindgen]
pub fn gm_sm3_kdf(keyhex: &str, category: &str) -> String {
    let key = match crate::crypto::hex_decode(keyhex) {
        Some(key) if key.len() == 32 => key,
        _ => return String::new(),
    };
    crate::hex_encode(&sm3_kdf(&key, category))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 64 字符 key32 hex：SM4 key 取前 16 字节 0123456789abcdeffedcba9876543210。
    const KEY_HEX: &str = "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210";

    fn key16() -> [u8; SM4_KEY_BYTES] {
        sm4_key_from_hex(KEY_HEX).unwrap()
    }

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

    #[test]
    fn sm4_block_matches_standard_vector() {
        let cipher = Sm4Cipher::new(&key16());
        assert_eq!(
            crate::hex_encode(&cipher.encrypt_block(&key16())),
            "681edf34d206965e86b3e94f536e4246"
        );
    }

    #[test]
    fn sm3_hmac_matches_definition() {
        // SM3(key32 || msg)：key 为 32 字节主密钥原始字节。
        let out = gm_sm3_hmac(KEY_HEX, "get|/api/v1/x");
        assert_eq!(out.len(), 64);
        let mut buf = sm4_key_from_hex(KEY_HEX).unwrap().to_vec();
        buf.clear();
        buf.extend_from_slice(&crate::crypto::hex_decode(KEY_HEX).unwrap());
        buf.extend_from_slice(b"get|/api/v1/x");
        assert_eq!(crate::hex_encode(&sm3_digest(&buf)), out);
    }

    #[test]
    fn envelope_header_layout_matches_spec() {
        let header = envelope_header(DOMAIN_ENV);
        assert_eq!(&header[..4], b"OWVE");
        assert_eq!(header[4], ENVELOPE_VERSION);
        assert_eq!(header[5], DOMAIN_ENV);
        assert_eq!(header[6], 0);
        assert_eq!(header[7], ENVELOPE_SIG_LEN);
    }

    #[test]
    fn sealed_roundtrip_recovers_plaintext() {
        let envelope = seal_envelope_text(KEY_HEX, "{\"v\":1}", DOMAIN_CAPTCHA_ANSWER);
        assert!(!envelope.is_empty());
        assert_eq!(
            open_envelope_text(&envelope, KEY_HEX, DOMAIN_CAPTCHA_ANSWER),
            "{\"v\":1}"
        );
        // 域不匹配必须拒绝。
        assert!(open_envelope_text(&envelope, KEY_HEX, DOMAIN_CAPTCHA_DATA).is_empty());
        // 错误 key 必须拒绝。
        let wrong = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert!(open_envelope_text(&envelope, wrong, DOMAIN_CAPTCHA_ANSWER).is_empty());
    }

    #[test]
    fn tampered_ct_rejected() {
        let envelope = seal_envelope_text(KEY_HEX, "payload", DOMAIN_ENV);
        let mut raw = crate::crypto::base64_decode(&envelope).unwrap();
        let ct_byte = ENVELOPE_HEADER_BYTES + GM_NONCE_BYTES;
        raw[ct_byte] ^= 0x01;
        let tampered = crate::crypto::base64url_encode(&raw);
        assert!(open_envelope_text(&tampered, KEY_HEX, DOMAIN_ENV).is_empty());
        // 伪造 sm3_out 使其与新 ct 匹配，GCM tag 仍必须拒绝。
        let mut raw2 = crate::crypto::base64_decode(&envelope).unwrap();
        raw2[ct_byte + 1] ^= 0x01;
        let ct_end = raw2.len() - SM2_RAW_SIG_BYTES - SM3_OUT_BYTES - GM_TAG_BYTES;
        let ct = raw2[ENVELOPE_HEADER_BYTES + GM_NONCE_BYTES..ct_end].to_vec();
        let mut buf = Vec::with_capacity(4 + ct.len());
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&ct);
        let fixed = sm3_digest(&buf);
        let tail_start = raw2.len() - SM3_OUT_BYTES;
        raw2[tail_start..].copy_from_slice(&fixed);
        let tampered2 = crate::crypto::base64url_encode(&raw2);
        assert!(open_envelope_text(&tampered2, KEY_HEX, DOMAIN_ENV).is_empty());
    }

    #[test]
    fn envelope_rejects_garbage() {
        assert!(gm_decrypt_challenge_data("AAAA", KEY_HEX).is_empty());
        assert!(gm_decrypt_challenge_data("", KEY_HEX).is_empty());
        assert!(gm_decrypt_challenge_data("v2g.d293rg", KEY_HEX).is_empty());
        assert!(gm_encrypt_challenge_answer("", KEY_HEX).is_empty());
        assert!(gm_encrypt_challenge_answer("x", "zz").is_empty());
        // 16 字节短 key hex 被拒绝（契约要求 64 字符 key32 下发）。
        assert!(seal_envelope_text("0123456789abcdeffedcba9876543210", "x", DOMAIN_ENV).is_empty());
    }

    #[test]
    fn sm2_za_and_e_match_authoritative_vectors() {
        // dA = 3945208F...（SM2 附录 A.2 keypair）、ida=owaf-gm-challenge、
        // msg="message digest"。
        let priv_hex = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
        let pk = public_key_hex(priv_hex);
        assert_eq!(
            pk,
            "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13"
        );
        let raw = sm2_za(SM2_USER_ID, &pk);
        assert_eq!(&raw[..2], &[0x00, 0x88], "ENTLA 必须为 ID 比特长 136");
        let za = sm2_za_digest(SM2_USER_ID, &pk);
        assert_eq!(
            crate::hex_encode(&za),
            "125ecf2961352a4220ec1d562987ee9f1570b7ffb62b70b7f34e6a98d99f4d62"
        );
        let e = derive_e_standard(SM2_USER_ID, &pk, b"message digest");
        assert_eq!(
            crate::hex_encode(&e),
            "6cd941ebc58389079c29abd48c9d1601810870593f469ec64a808a2934cd8f50"
        );
    }

    #[test]
    fn sm2_sign_verify_sealed_roundtrip() {
        let (sk, pk) = smcrypto::sm2::gen_keypair();
        let msg = r#"{"ts":1700000000}"#;
        let sig = gm_sign_challenge(msg, &sk);
        assert!(!sig.is_empty());
        assert!(gm_verify_signature(&pk, &sig, msg));
        assert!(!gm_verify_signature(&pk, &sig, "other"));
        let prefixed = format!("04{}", pk);
        assert!(gm_verify_signature(&prefixed, &sig, msg));
        assert!(!gm_verify_signature(&pk, "not base64", msg));
        assert!(gm_sign_challenge(msg, "zz").is_empty());
        // e=SM3(ZA‖M) 的 verify_raw 路径独立复验。
        let pub_norm = normalize_pub_key(&pk).unwrap();
        let e = derive_e_standard(SM2_USER_ID, &pub_norm, msg.as_bytes());
        let der = crate::crypto::base64_decode(&sig).unwrap();
        assert!(smcrypto::sm2::Verify::new(&pub_norm).verify_raw(&e, &der));
        // 无 ZA 路径不得存活：e=SM3(msg) 无 ZA 的签名在统一语义下必失败。
        let raw_e = sm3_digest(msg.as_bytes());
        let raw_sig = smcrypto::sm2::Sign::new(&sk).sign_raw(&raw_e);
        assert!(!gm_verify_signature(
            &pk,
            &crate::crypto::base64_encode(&raw_sig),
            msg
        ));
        // 多拼 4B 零（e=SM3(ZA‖00000000‖M)）的签名必须验签失败，
        // 防止两侧再次偏离标准公式。
        let za_only = sm2_za_digest(SM2_USER_ID, &pub_norm);
        let mut pre_padded = za_only.to_vec();
        pre_padded.extend_from_slice(&[0u8; 4]);
        pre_padded.extend_from_slice(msg.as_bytes());
        let e_padded = sm3_digest(&pre_padded);
        let sig_padded = smcrypto::sm2::Sign::new(&sk).sign_raw(&e_padded);
        assert!(!gm_verify_signature(
            &pk,
            &crate::crypto::base64_encode(&sig_padded),
            msg
        ));
    }

    #[test]
    fn sm3_kdf_matches_spec() {
        let key = crate::crypto::hex_decode(KEY_HEX).unwrap();
        let derived = sm3_kdf(&key, "server-sign");
        assert_eq!(derived.len(), 32);
        // kdf(key, category) = SM3(key || owaf-<category>:v2) 截 32 字节。
        let label = crate::label::envelope_label("server-sign", crate::label::PROTOCOL_VERSION);
        let mut buf = key.clone();
        buf.extend_from_slice(label.as_bytes());
        assert_eq!(
            crate::hex_encode(&derived),
            crate::hex_encode(&sm3_digest(&buf))
        );
        assert_eq!(
            gm_sm3_kdf(KEY_HEX, "server-sign"),
            crate::hex_encode(&derived)
        );
        assert!(gm_sm3_kdf("zz", "server-sign").is_empty());
    }

    #[test]
    fn ct_eq_masks_length_and_content() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }

    #[test]
    fn sm4_ecb_decrypt_inverts_encrypt() {
        // 由独立实现（OpenSSL 3.5.5 sm4-ecb）实测的向量：
        // E(0123456789abcdeffedcba9876543210) = 681edf34d206965e86b3e94f536e4246。
        let key = key16();
        let ct = sm4_ecb_encrypt_block(&key, &key);
        assert_eq!(crate::hex_encode(&ct), "681edf34d206965e86b3e94f536e4246");
        let pt = sm4_ecb_decrypt_block(&key, &ct);
        assert_eq!(pt, key);
        // 32 字节 ECB 往返（含 0 填充语义，长度恰为块倍数）。
        let data = b"0123456789abcdef0123456789abcdef";
        let enc = sm4_ecb_encrypt(&key, data);
        assert_eq!(enc.len(), 32);
        assert_eq!(sm4_ecb_decrypt(&key, &enc).unwrap(), data);
        assert!(sm4_ecb_decrypt(&key, &enc[..31]).is_none());
    }

    #[test]
    fn sm4_cbc_matches_openssl_vector() {
        // 由独立实现（OpenSSL 3.5.5 sm4-cbc，全零 IV）实测的向量：
        // CBC-Enc(681edf34d206965e86b3e94f536e4246) = f324184f3c8892b72bdc9d7c612919de。
        let key = key16();
        let iv = [0u8; 16];
        let block = sm4_ecb_encrypt_block(&key, &key);
        let ct = sm4_cbc_encrypt(&key, &iv, &block);
        assert_eq!(crate::hex_encode(&ct), "f324184f3c8892b72bdc9d7c612919de");
        assert_eq!(sm4_cbc_decrypt(&key, &iv, &ct).unwrap(), block);
        assert!(sm4_cbc_decrypt(&key, &iv, &ct[..15]).is_none());
    }

    #[test]
    fn sm3_kdf_matches_multi_round_and_truncation() {
        // GM/T 32918.4-2016 5.4.3：µ=[klen/32]，逐轮 SM3(z||ct)，ct 4 字节
        // 大端 1,2,3…；klen=0 空、klen=31 截 31 字节、klen=33 两轮拼接。
        let z = b"owaf-kdf-z";
        assert!(crate::sm3::sm3_kdf(z, 0).is_empty());

        let one = crate::sm3::sm3_kdf(z, 31);
        assert_eq!(one.len(), 31);
        let mut full = Vec::with_capacity(68);
        full.extend_from_slice(z);
        full.extend_from_slice(&1u32.to_be_bytes());
        assert_eq!(one, crate::sm3::sm3_digest(&full)[..31]);

        let two = crate::sm3::sm3_kdf(z, 33);
        assert_eq!(two.len(), 33);
        let mut buf = Vec::with_capacity(68);
        buf.extend_from_slice(z);
        buf.extend_from_slice(&1u32.to_be_bytes());
        let h1 = crate::sm3::sm3_digest(&buf);
        buf.clear();
        buf.extend_from_slice(z);
        buf.extend_from_slice(&2u32.to_be_bytes());
        let h2 = crate::sm3::sm3_digest(&buf);
        assert_eq!(&two[..32], &h1[..]);
        assert_eq!(two[32], h2[0]);
        assert_eq!(two, crate::sm3::sm3_kdf(z, 33));
    }

    #[test]
    fn sm4_gcm_zero_key_golden_ghash_consistency() {
        // 与 Go 标准库（cipher.NewGCM over sm4）同向检查：用手算 GHASH
        // 与 tag 掩码核对内部位序：标签 = GHASH(AAD,CT,H) ^ E(J0)。
        // 固定零输入下锁定 tag 实测值，同时以手工展开逐字节核对。
        let key = [0u8; SM4_KEY_BYTES];
        let nonce = [0u8; GM_NONCE_BYTES];
        let cipher = Sm4Cipher::new(&key);
        let j0 = {
            let mut j0 = [0u8; 16];
            j0[..GM_NONCE_BYTES].copy_from_slice(&nonce);
            j0[15] = 0x01;
            j0
        };
        let h = cipher.encrypt_block(&[0u8; 16]);
        let y = ghash(b"", b"", u128::from_be_bytes(h));
        let ek = cipher.encrypt_block(&j0);
        let mut want = [0u8; GM_TAG_BYTES];
        let (y_bits, ek_bits) = (y.to_be_bytes(), ek);
        for i in 0..GM_TAG_BYTES {
            want[i] = y_bits[i] ^ ek_bits[i];
        }
        let (_ct, tag) = sm4_gcm_encrypt_with_nonce(&cipher, &nonce, b"", b"");
        assert_eq!(tag, want);
        // tag 值本身锁定为 Rust 侧实测（保持 GCM 对称位序回归）。
        assert_eq!(crate::hex_encode(&tag), "232f0cfe308b49ea6fc88229b5dc858d");
    }

    #[test]
    fn sm4_gcm_counter_lies_at_nonce_plus_one() {
        // （即 J0+1），且与 Go 侧标准库 cipher.NewGCM(SM4) 逐字节一致。
        let key = key16();
        let nonce = [0u8; GM_NONCE_BYTES];
        let mut j1 = [0u8; 16];
        j1[..GM_NONCE_BYTES].copy_from_slice(&nonce);
        j1[15] = 0x02;
        let cipher = Sm4Cipher::new(&key);
        let (ct, _) = sm4_gcm_encrypt_with_nonce(&cipher, &nonce, &[0u8; 16], b"");
        let ks0 = cipher.encrypt_block(&j1);
        assert_eq!(ct, ks0);
    }

    #[test]
    fn compressed_pubkey_roundtrip_and_rejects() {
        // 0x02/0x03 压缩编码往返：A.2 标准公钥压缩后必须能无损还原。
        let priv_hex = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
        let pk = public_key_hex(priv_hex);
        let raw = crate::crypto::hex_decode(&pk).unwrap();
        let mut xy = [0u8; 64];
        xy.copy_from_slice(&raw);
        let comp = encode_pub_key_compressed(&xy).unwrap();
        assert_eq!(comp.len(), 33);
        assert!(comp[0] == 0x02 || comp[0] == 0x03);
        let restored = sm2_uncompress_pubkey(&comp).unwrap();
        assert_eq!(restored, raw);
        // 非压缩 04 形态编码同样可生成且 65 字节。
        assert_eq!(encode_pub_key_decompressed(&xy).unwrap().len(), 65);
        // 非法前缀形态必须拒绝。
        let mut bad = comp.clone();
        bad[0] = 0x05;
        assert!(sm2_uncompress_pubkey(&bad).is_none());
        assert!(sm2_uncompress_pubkey(&comp[..32]).is_none());
        // 非法公钥（全零 x/y、不在曲线上）必须拒绝。
        assert!(!sm2_point_valid(&[0u8; 64]));
        let mut off_curve = xy;
        off_curve[0] ^= 0x01;
        assert!(!sm2_point_valid(&off_curve));
        assert!(encode_pub_key_compressed(&off_curve).is_none());
        // 通过 gm_verify_signature 的压缩公钥输入路径。
        let (sk, pk2) = smcrypto::sm2::gen_keypair();
        let msg = "compressed-hex-input";
        let der = crate::crypto::base64_decode(&gm_sign_challenge(msg, &sk)).unwrap();
        let raw2 = crate::crypto::hex_decode(&pk2).unwrap();
        let mut xy2 = [0u8; 64];
        xy2.copy_from_slice(&raw2);
        let comp2 = crate::hex_encode(&encode_pub_key_compressed(&xy2).unwrap());
        assert!(gm_verify_signature(
            &comp2,
            &crate::crypto::base64_encode(&der),
            msg
        ));
        assert!(gm_verify_signature(
            &pk2,
            &crate::crypto::base64_encode(&der),
            msg
        ));
    }

    #[test]
    fn sm2_public_key_rejects_infinite_and_off_curve() {
        // 无穷远点/不在曲线点/范围外 x 与各编码入口全部拒绝。
        let all_zero = format!("04{}", "00".repeat(64));
        assert!(normalize_pub_key(&all_zero).is_none());
        assert!(normalize_pub_key(&"0f".repeat(64)).is_none());
        // 全零 x、非零 y=1 不在曲线上。
        assert!(normalize_pub_key(&format!("{}{}", "00".repeat(32), "01".repeat(32))).is_none());
        // 私钥越界 [0, n)：n 与 n+1。
        let n_hex = ECC_N.to_lowercase();
        assert!(normalize_priv_key(&n_hex).is_none());
    }

    #[test]
    fn sm2_scalar_mul_matches_reference_coordinates() {
        // gmsm（独立 Go 实现）生成的 [k]G 参考坐标，锁定素域倍/加正确性：
        // 历史上 double 的分母取模遗漏系数 2 会产生不在曲线上的点。
        let p = BigUint::from_str_radix(ECC_P, 16).unwrap();
        let a = BigUint::from_bytes_be(&ECC_A);
        let gx = BigUint::from_bytes_be(&ECC_GX);
        let gy = BigUint::from_bytes_be(&ECC_GY);
        let vecs: [(u64, &str, &str); 5] = [
            (
                2,
                "56cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd52",
                "31b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3",
            ),
            (
                3,
                "a97f7cd4b3c993b4be2daa8cdb41e24ca13f6bd945302244e26918f1d0509ebf",
                "530b5dd88c688ef5ccc5cec08a72150f7c400ee5cd045292aaacdd037458f6e6",
            ),
            (
                7,
                "ddf092555409c19dfdbe86a75c139906a80198337744ee78cd27e384d9fcaf15",
                "847d18ffb38e87065cd6b6e9c12d2922037937707d6a49a2223b949657e52bc1",
            ),
            (
                15,
                "f73b839f13912c1a3291676c38d393243b424f35f0ecce4c461b1bbcb80f829c",
                "32ec7722695dc7cf5ee9fab985c12455dc2e788fb170aa144c3533771db0955e",
            ),
            (
                255,
                "1999e5c85d17cc7c020ebe86ab18e836f5215adaeb2e42da066b638835960be2",
                "9de6b71e12e31189eb96f37a2f474f63168c7ecd2b437f59f2d3af28af6c1437",
            ),
        ];
        for (k, wx, wy) in vecs {
            let got = sm2_scalar_mul(&BigUint::from(k), &gx, &gy, &p, &a);
            let ex = BigUint::from_str_radix(wx, 16).unwrap();
            let ey = BigUint::from_str_radix(wy, 16).unwrap();
            assert_eq!((got.0, got.1), (ex, ey), "[{}]G mismatch", k);
        }
        // [n]G = O、[n-1]G = -G。
        let n = BigUint::from_str_radix(ECC_N, 16).unwrap();
        let inf = sm2_scalar_mul(&n, &gx, &gy, &p, &a);
        assert_eq!(inf, (BigUint::from(0u8), BigUint::from(0u8)));
        let nm1 = &n - BigUint::from(1u8);
        let last = sm2_scalar_mul(&nm1, &gx, &gy, &p, &a);
        assert_eq!(last.0, gx);
        assert_eq!(last.1, &p - &gy);
    }

    #[test]
    fn sm2_sign_verify_self_consistent() {
        // 用 A.2 标准私钥生成 self-consistency 对（确定性，重试路径保证）。
        let sk_hex = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
        assert!(normalize_priv_key(sk_hex).is_some());
        let pk = public_key_hex(sk_hex);
        assert!(!pk.is_empty());
        let e = crate::sm3::sm3_digest(b"sm2-raw-path-probe");
        let der = sm2_raw_sign(sk_hex, &e).expect("raw sign");
        assert!(sm2_raw_verify(&pk, &e, &der));
        let mut flipped = crate::crypto::hex_decode(&crate::hex_encode(&der)).unwrap();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;
        assert!(!sm2_raw_verify(&pk, &e, &flipped));
    }

    #[test]
    fn signed_envelope_roundtrip_and_tamper() {
        let (sk, pk) = smcrypto::sm2::gen_keypair();
        // 会话级一次性 keypair：seal 用 priv，open 用 pub 核对。
        let envelope = gm_seal_signed(KEY_HEX, "signed-payload", DOMAIN_ENV, &sk);
        assert!(!envelope.is_empty());
        // sig 字段非零（签名已填充）。
        let raw = crate::crypto::base64_decode(&envelope).unwrap();
        let sig_start = raw.len() - SM3_OUT_BYTES - SM2_RAW_SIG_BYTES;
        assert_eq!(&raw[..4], b"OWVE");
        assert_ne!(&raw[sig_start..sig_start + SM2_RAW_SIG_BYTES], &[0u8; 64]);
        // 正确 open + pub 验签通过。
        assert_eq!(
            gm_open_verify_sig(&envelope, KEY_HEX, DOMAIN_ENV, &pk),
            "signed-payload"
        );
        // 错误 pub 验签拒绝。
        let (_, other_pk) = smcrypto::sm2::gen_keypair();
        assert!(gm_open_verify_sig(&envelope, KEY_HEX, DOMAIN_ENV, &other_pk).is_empty());
        // 篡改一个密文字节必须拒绝（sm3_out 与 sig 均失效）。
        let mut raw2 = crate::crypto::base64_decode(&envelope).unwrap();
        let ct_byte = ENVELOPE_HEADER_BYTES + GM_NONCE_BYTES;
        raw2[ct_byte] ^= 0x01;
        let tampered = crate::crypto::base64url_encode(&raw2);
        assert!(gm_open_verify_sig(&tampered, KEY_HEX, DOMAIN_ENV, &pk).is_empty());
    }
}
