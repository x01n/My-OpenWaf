#![recursion_limit = "512"]

use wasm_bindgen::prelude::*;

mod crypto;
mod env;
mod fingerprint;
mod obfuscate;
mod vmp;

/**
 * solve_pow_batched performs only the deterministic proof-of-work calculation
 * in a Worker-safe WASM context. Browser environment collection is performed
 * by collect_and_encrypt_fingerprint on the main thread, where DOM APIs exist.
 */
#[wasm_bindgen]
pub fn solve_pow_batched(
    nonce: &str,
    difficulty: u32,
    program: &str,
    batch_size: u32,
    start_counter: u64,
) -> String {
    let context = match vmp::Context::parse(program) {
        Ok(context) => context,
        Err(err) => return format!(r#"{{"found":false,"error":"{}"}}"#, err.code()),
    };
    if difficulty > 64 {
        return r#"{"found":false,"error":"invalid_difficulty"}"#.to_string();
    }

    let mut counter = start_counter;
    let end = start_counter.saturating_add(batch_size as u64);
    while counter < end {
        if context.check_pow(nonce, counter, difficulty) {
            let hash = obfuscate::sha256_compute(format!("{}{}", nonce, counter).as_bytes());
            return format!(
                r#"{{"found":true,"counter":{},"hash":"{}"}}"#,
                counter,
                hex_encode(&hash),
            );
        }
        counter += 1;
    }

    format!(r#"{{"found":false,"next_counter":{}}}"#, counter)
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
    use super::solve_pow_batched;

    #[test]
    fn solves_with_go_raw_opcode_program() {
        let result = solve_pow_batched("nonce", 0, "1011121314", 1, 7);
        assert_eq!(
            result,
            r#"{"found":true,"counter":7,"hash":"e4f85dc8b6539ca709dd518a6fa0bca4b20bac8f2e77641d62a0d5b6f2b50685"}"#
        );
    }

    #[test]
    fn rejects_invalid_program_before_hashing() {
        let result = solve_pow_batched("nonce", 0, "1011151314", 1, 7);
        assert_eq!(result, r#"{"found":false,"error":"unknown_vm_opcode"}"#);
    }
}
