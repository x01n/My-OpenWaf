use aes_gcm::aes::cipher::{BlockCipherDecrypt, KeyInit as BlockKeyInit};
use aes_gcm::aes::{Aes256, Block};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use wasm_bindgen::prelude::*;

type HmacSha256 = Hmac<Sha256>;

const BASE64_URL_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const AES_KW_DEFAULT_IV: [u8; 8] = [0xA6; 8];

fn base64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let chunks = data.chunks(3);
    for chunk in chunks {
        let a = chunk[0] as u32;
        let b = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let c = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let t = (a << 16) | (b << 8) | c;
        out.push(BASE64_URL_CHARS[((t >> 18) & 63) as usize] as char);
        out.push(BASE64_URL_CHARS[((t >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(BASE64_URL_CHARS[((t >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(BASE64_URL_CHARS[(t & 63) as usize] as char);
        }
    }
    out
}

#[wasm_bindgen]
pub fn encrypt_env_data(json_data: &str, key_hex: &str) -> String {
    let key_bytes = hex_decode(key_hex);
    if key_bytes.len() != 32 {
        return String::new();
    }
    let cipher = match Aes256Gcm::new_from_slice(&key_bytes) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };

    let mut iv = [0u8; 12];
    getrandom::getrandom(&mut iv).unwrap_or(());
    let nonce = Nonce::from(iv);

    match cipher.encrypt(&nonce, json_data.as_bytes()) {
        Ok(ciphertext) => {
            let mut buf = Vec::with_capacity(12 + ciphertext.len());
            buf.extend_from_slice(&iv);
            buf.extend_from_slice(&ciphertext);
            base64url_encode(&buf)
        }
        Err(_) => String::new(),
    }
}

#[wasm_bindgen]
pub fn decrypt_dynamic_payload(data_b64: &str, iv_b64: &str, wrap_b64: &str, kek_b64: &str) -> Result<Vec<u8>, JsValue> {
    let data = base64_decode(data_b64).ok_or_else(|| JsValue::from_str("invalid data base64"))?;
    let iv = base64_decode(iv_b64).ok_or_else(|| JsValue::from_str("invalid iv base64"))?;
    let wrap = base64_decode(wrap_b64).ok_or_else(|| JsValue::from_str("invalid wrap base64"))?;
    let kek = base64_decode(kek_b64).ok_or_else(|| JsValue::from_str("invalid kek base64"))?;
    let cek = aes_key_unwrap_256(&kek, &wrap).ok_or_else(|| JsValue::from_str("AES-KW unwrap failed"))?;
    aes_gcm_decrypt_256(&cek, &iv, &data).ok_or_else(|| JsValue::from_str("AES-GCM decrypt failed"))
}

#[wasm_bindgen]
pub fn unwrap_dynamic_cek(wrap_b64: &str, kek_b64: &str) -> Result<Vec<u8>, JsValue> {
    let wrap = base64_decode(wrap_b64).ok_or_else(|| JsValue::from_str("invalid wrap base64"))?;
    let kek = base64_decode(kek_b64).ok_or_else(|| JsValue::from_str("invalid kek base64"))?;
    aes_key_unwrap_256(&kek, &wrap).ok_or_else(|| JsValue::from_str("AES-KW unwrap failed"))
}

#[wasm_bindgen]
pub fn decrypt_dynamic_with_cek(data_b64: &str, iv_b64: &str, cek: &[u8]) -> Result<Vec<u8>, JsValue> {
    let data = base64_decode(data_b64).ok_or_else(|| JsValue::from_str("invalid data base64"))?;
    let iv = base64_decode(iv_b64).ok_or_else(|| JsValue::from_str("invalid iv base64"))?;
    aes_gcm_decrypt_256(cek, &iv, &data).ok_or_else(|| JsValue::from_str("AES-GCM decrypt failed"))
}

#[wasm_bindgen]
pub fn hmac_sha256(key_hex: &str, message: &str) -> String {
    let key_bytes = hex_decode(key_hex);
    let mut mac = match HmacSha256::new_from_slice(&key_bytes) {
        Ok(m) => m,
        Err(_) => return String::new(),
    };
    mac.update(message.as_bytes());
    let result = mac.finalize().into_bytes();
    crate::hex_encode(&result)
}

#[wasm_bindgen]
pub fn sha256_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    crate::hex_encode(&result)
}

#[wasm_bindgen]
pub fn sha256_hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    crate::hex_encode(&result)
}

#[wasm_bindgen]
pub fn compute_canvas_hash(image_data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(image_data);
    let result = hasher.finalize();
    crate::hex_encode(&result[..16])
}

#[wasm_bindgen]
pub fn compute_audio_hash(samples: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(samples);
    let result = hasher.finalize();
    crate::hex_encode(&result[..16])
}

#[wasm_bindgen]
pub fn encode_and_encrypt_fingerprint(json_data: &str, key_hex: &str, hmac_key_hex: &str) -> String {
    let encrypted = encrypt_env_data(json_data, key_hex);
    if encrypted.is_empty() {
        return String::new();
    }
    let sig = hmac_sha256(hmac_key_hex, &encrypted);
    format!("{}|{}", encrypted, sig)
}

fn aes_gcm_decrypt_256(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if key.len() != 32 || iv.len() != 12 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher.decrypt(Nonce::from_slice(iv), data).ok()
}

fn aes_key_unwrap_256(kek: &[u8], wrapped: &[u8]) -> Option<Vec<u8>> {
    if kek.len() != 32 || wrapped.len() < 24 || wrapped.len() % 8 != 0 {
        return None;
    }
    let n = wrapped.len() / 8 - 1;
    let cipher = Aes256::new_from_slice(kek).ok()?;
    let mut a = [0u8; 8];
    a.copy_from_slice(&wrapped[..8]);
    let mut r = vec![[0u8; 8]; n];
    for i in 0..n {
        r[i].copy_from_slice(&wrapped[8 + i * 8..16 + i * 8]);
    }
    let mut buf = [0u8; 16];
    for j in (0..6).rev() {
        for i in (0..n).rev() {
            let t = (n * j + i + 1) as u64;
            let tb = t.to_be_bytes();
            for k in 0..8 {
                buf[k] = a[k] ^ tb[k];
            }
            buf[8..].copy_from_slice(&r[i]);
            let mut block = Block::from(buf);
            cipher.decrypt_block(&mut block);
            a.copy_from_slice(&block[..8]);
            r[i].copy_from_slice(&block[8..]);
        }
    }
    if a != AES_KW_DEFAULT_IV {
        return None;
    }
    let mut out = Vec::with_capacity(n * 8);
    for chunk in r {
        out.extend_from_slice(&chunk);
    }
    Some(out)
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut buf = [0u8; 4];
    let mut n = 0usize;
    for b in input.bytes() {
        if b == b'=' {
            break;
        }
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'\r' | b'\n' | b'\t' | b' ' => continue,
            _ => return None,
        };
        buf[n] = v;
        n += 1;
        if n == 4 {
            out.push((buf[0] << 2) | (buf[1] >> 4));
            out.push((buf[1] << 4) | (buf[2] >> 2));
            out.push((buf[2] << 6) | buf[3]);
            n = 0;
        }
    }
    if n == 1 {
        return None;
    }
    if n == 2 {
        out.push((buf[0] << 2) | (buf[1] >> 4));
    } else if n == 3 {
        out.push((buf[0] << 2) | (buf[1] >> 4));
        out.push((buf[1] << 4) | (buf[2] >> 2));
    }
    Some(out)
}

fn hex_decode(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();
    while let (Some(h), Some(l)) = (chars.next(), chars.next()) {
        let byte = hex_val(h) << 4 | hex_val(l);
        bytes.push(byte);
    }
    bytes
}

fn hex_val(c: char) -> u8 {
    match c {
        '0'..='9' => c as u8 - b'0',
        'a'..='f' => c as u8 - b'a' + 10,
        'A'..='F' => c as u8 - b'A' + 10,
        _ => 0,
    }
}
