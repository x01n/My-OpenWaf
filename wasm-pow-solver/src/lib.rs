use sha2::{Sha256, Digest};
use wasm_bindgen::prelude::*;

mod vmp;
mod env;
mod integrity;
mod obfuscate;
mod crypto;
mod fingerprint;
#[wasm_bindgen]
pub fn solve_pow(nonce: &str, difficulty: u32, program: &str, env_data: &str, env_key: &str) -> String {
    let integrity_ok = integrity::self_check();
    let mut penalty: u32 = 0;
    if !integrity_ok {
        penalty += 30;
    }
    let js_env = decrypt_env_data(env_data, env_key);
    let js_env_score = evaluate_js_env(&js_env);
    penalty = penalty.saturating_add(js_env_score);
    let ctx = vmp::Context::new(program);
    let env_result = ctx.execute_env_check();
    let total_score = env_result.score.saturating_add(penalty);
    let cross_penalty = cross_validate_env(&env_result, &js_env);
    let total_score = total_score.saturating_add(cross_penalty);
    let score_throttle = compute_throttle(total_score);
    let throttle = score_throttle.max(env_result.throttle);
    let mut counter: u64 = 0;
    let hash_hex;
    let mut monitoring_score: u32 = 0;
    let monitor_interval: u64 = 512;
    let mut msg_buf = String::with_capacity(nonce.len() + 20);

    loop {
        msg_buf.clear();
        msg_buf.push_str(nonce);
        itoa_append(&mut msg_buf, counter);
        let hash_bytes = obfuscate::sha256_compute(msg_buf.as_bytes());

        if has_leading_zero_nibbles(&hash_bytes, difficulty) {
            hash_hex = hex_encode(&hash_bytes);
            break;
        }

        counter += 1;

        if counter % monitor_interval == 0 {
            let live_check = env::live_monitoring();
            if live_check > 0 {
                monitoring_score = monitoring_score.saturating_add(live_check);
            }
        }

        if throttle > 0 && counter % throttle == 0 {
            burn_cycles(throttle as u32 * 4);
        }

        if monitoring_score > 20 && counter % 256 == 0 {
            burn_cycles(monitoring_score * 8);
        }
    }
    let final_score = total_score.saturating_add(monitoring_score);
    let markers = env_result.markers_hex();
    let fp_hash = compute_fp_hash(&js_env);
    let sig = compute_result_sig_with_fp(nonce, counter, &hash_hex, final_score, &markers, &fp_hash);

    format!(
        r#"{{"counter":{},"hash":"{}","env_score":{},"markers":"{}","sig":"{}","fp_hash":"{}","nonce":"{}","difficulty":{}}}"#,
        counter, hash_hex, final_score, markers, sig, fp_hash, nonce, difficulty
    )
}
#[wasm_bindgen]
pub fn solve_pow_batched(nonce: &str, difficulty: u32, program: &str, batch_size: u32, start_counter: u64) -> String {
    let ctx = vmp::Context::new(program);
    let env_result = ctx.execute_env_check();
    let throttle = compute_throttle(env_result.score).max(env_result.throttle);

    let mut counter = start_counter;
    let end = start_counter.saturating_add(batch_size as u64);
    let mut msg_buf = String::with_capacity(nonce.len() + 20);

    while counter < end {
        msg_buf.clear();
        msg_buf.push_str(nonce);
        itoa_append(&mut msg_buf, counter);
        let hash_bytes = obfuscate::sha256_compute(msg_buf.as_bytes());

        if has_leading_zero_nibbles(&hash_bytes, difficulty) {
            let hash_hex = hex_encode(&hash_bytes);
            let sig = compute_result_sig(nonce, counter, &hash_hex, env_result.score, &env_result.markers_hex());
            return format!(
                r#"{{"found":true,"counter":{},"hash":"{}","env_score":{},"markers":"{}","sig":"{}"}}"#,
                counter, hash_hex, env_result.score, env_result.markers_hex(), sig
            );
        }

        counter += 1;

        if throttle > 0 && counter % throttle == 0 {
            burn_cycles(throttle as u32 * 4);
        }
    }

    format!(
        r#"{{"found":false,"next_counter":{},"env_score":{},"markers":"{}"}}"#,
        counter, env_result.score, env_result.markers_hex()
    )
}

#[wasm_bindgen]
pub fn verify_pow(nonce: &str, counter: u64, hash: &str, difficulty: u32) -> bool {
    let prefix = "0".repeat(difficulty as usize);
    if !hash.starts_with(&prefix) {
        return false;
    }
    let msg = format!("{}{}", nonce, counter);
    let computed = hex_encode(&obfuscate::sha256_compute(msg.as_bytes()));
    computed == hash
}

#[wasm_bindgen]
pub fn get_env_score(program: &str) -> String {
    let ctx = vmp::Context::new(program);
    let env_result = ctx.execute_env_check();
    let integrity_ok = integrity::self_check();
    let penalty = if integrity_ok { 0 } else { 30 };
    let total = env_result.score.saturating_add(penalty);
    format!(
        r#"{{"score":{},"markers":"{}","integrity":{}}}"#,
        total, env_result.markers_hex(), integrity_ok
    )
}


fn compute_throttle(score: u32) -> u64 {
    if score >= 80 {
        64
    } else if score >= 50 {
        128
    } else if score >= 30 {
        256
    } else if score > 10 {
        512
    } else {
        0
    }
}

fn compute_result_sig(nonce: &str, counter: u64, hash: &str, score: u32, markers: &str) -> String {
    let payload = format!("{}:{}:{}:{}:{}", nonce, counter, hash, score, markers);
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    hasher.update(integrity::COMPILE_SALT);
    let result = hasher.finalize();
    hex_encode(&result[..8])
}

fn compute_result_sig_with_fp(nonce: &str, counter: u64, hash: &str, score: u32, markers: &str, fp_hash: &str) -> String {
    let payload = format!("{}:{}:{}:{}:{}:{}", nonce, counter, hash, score, markers, fp_hash);
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    hasher.update(integrity::COMPILE_SALT);
    let result = hasher.finalize();
    hex_encode(&result[..8])
}

fn decrypt_env_data(env_data: &str, _env_key: &str) -> String {
    env_data.to_string()
}

fn evaluate_js_env(env_json: &str) -> u32 {
    if env_json.is_empty() {
        return 10; 
    }
    let mut score: u32 = 0;
    if env_json.contains("\"webdriver\":true") {
        score += 100;
    }
    if env_json.contains("\"phantom\":true") || env_json.contains("\"nightmare\":true") {
        score += 80;
    }
    if env_json.contains("\"selenium_sign\":true") || env_json.contains("\"chrome_cdc\":true") {
        score += 80;
    }
    if env_json.contains("\"headless_ua\":true") {
        score += 60;
    }
    if env_json.contains("\"webdriver_advanced\":true") {
        score += 70;
    }
    if env_json.contains("\"puppeteer_sign\":true") || env_json.contains("\"playwright_sign\":true") {
        score += 90;
    }
    if env_json.contains("\"devtools_open\":true") {
        score += 20;
    }
    if env_json.contains("\"ua_mismatch\":true") {
        score += 30;
    }
    if env_json.contains("\"navigator_proto\":false") {
        score += 25;
    }
    if env_json.contains("\"screen_consistency\":false") {
        score += 15;
    }
    if env_json.contains("\"timezone_consistency\":false") {
        score += 20;
    }
    if env_json.contains("\"math_consistency\":false") {
        score += 30;
    }
    if env_json.contains("\"hardware_concurrency\":0") || env_json.contains("\"hardware_concurrency\":1") {
        score += 15;
    }

    score
}

fn cross_validate_env(wasm_result: &vmp::EnvResult, js_env: &str) -> u32 {
    if js_env.is_empty() {
        return 0;
    }
    let mut penalty: u32 = 0;
    let wasm_webdriver = (wasm_result.score >= 100) || (wasm_result.markers_hex().contains("01"));
    let js_webdriver = js_env.contains("\"webdriver\":true");
    if wasm_webdriver && !js_webdriver {
        penalty += 40; 
    }
    if js_env.contains("\"canvas_hash\":\"\"") || js_env.contains("\"canvas_hash\":\"0\"") {
        penalty += 10;
    }

    penalty
}

fn compute_fp_hash(env_json: &str) -> String {
    if env_json.is_empty() {
        return "empty".to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(env_json.as_bytes());
    hasher.update(integrity::COMPILE_SALT);
    let result = hasher.finalize();
    hex_encode(&result[..8])
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    s
}

#[inline(never)]
fn burn_cycles(n: u32) {
    let mut x: u32 = 0xDEADBEEF;
    for _ in 0..n.min(65536) {
        x = x.wrapping_mul(1103515245).wrapping_add(12345);
        x ^= x >> 16;
    }
    std::hint::black_box(x);
}

#[inline(always)]
fn itoa_append(buf: &mut String, mut n: u64) {
    if n == 0 {
        buf.push('0');
        return;
    }
    let start = buf.len();
    while n > 0 {
        buf.push((b'0' + (n % 10) as u8) as char);
        n /= 10;
    }
    let bytes = unsafe { buf.as_bytes_mut() };
    bytes[start..].reverse();
}

#[inline(always)]
fn has_leading_zero_nibbles(hash: &[u8], difficulty: u32) -> bool {
    let full_bytes = (difficulty / 2) as usize;
    for i in 0..full_bytes {
        if hash[i] != 0 {
            return false;
        }
    }
    if difficulty % 2 == 1 {
        if hash[full_bytes] >> 4 != 0 {
            return false;
        }
    }
    true
}
