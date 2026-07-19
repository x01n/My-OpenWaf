use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use wasm_bindgen::prelude::*;

type HmacSha256 = Hmac<Sha256>;

const BASE64_URL_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

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
