use wasm_bindgen::prelude::*;
pub const COMPILE_SALT: &[u8] = b"owaf_pow_v2_2026";
const MAGIC_A: u32 = 0x4F574146; // "OWAF"
const MAGIC_B: u32 = 0x504F5732; // "POW2"

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = eval)]
    fn js_eval(code: &str) -> JsValue;
}
pub fn self_check() -> bool {
    if !verify_magic() {
        return false;
    }
    if !verify_hash_consistency() {
        return false;
    }
    if !verify_runtime_env() {
        return false;
    }

    true
}
#[inline(never)]
fn verify_magic() -> bool {
    let a = compute_magic_a();
    let b = compute_magic_b();
    a == MAGIC_A && b == MAGIC_B
}

#[inline(never)]
fn compute_magic_a() -> u32 {
    let mut v: u32 = 0x4F;
    v = (v << 8) | 0x57;
    v = (v << 8) | 0x41;
    v = (v << 8) | 0x46;
    std::hint::black_box(v)
}

#[inline(never)]
fn compute_magic_b() -> u32 {
    let mut v: u32 = 0x50;
    v = (v << 8) | 0x4F;
    v = (v << 8) | 0x57;
    v = (v << 8) | 0x32;
    std::hint::black_box(v)
}
fn verify_hash_consistency() -> bool {
    let result = crate::obfuscate::sha256_raw(b"owaf_integrity_check");
    result[0] == 0x17 && result[1] == 0xd6 && result[2] == 0x8c && result[3] == 0xe3
}
fn verify_runtime_env() -> bool {
    let result = js_eval(
        r#"(function(){
        try{
            var w=WebAssembly;
            if(!w||!w.Module||!w.Instance)return false;
            if(w.Module.toString().indexOf('native code')<0)return false;
            if(typeof w.validate!=='function')return false;
            return true;
        }catch(e){return false}})()"#,
    );
    result.is_truthy()
}
