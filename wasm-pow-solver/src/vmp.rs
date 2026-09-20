use wasm_bindgen::prelude::*;

const MAX_PROGRAM_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpCode {
    Nop,
    LoadNonce,
    LoadCounter,
    Concat,
    Sha256,
    CheckPrefix,
}

impl OpCode {
    fn parse(byte: u8) -> Result<Self, ProgramError> {
        match byte {
            0x00 => Ok(Self::Nop),
            0x10 => Ok(Self::LoadNonce),
            0x11 => Ok(Self::LoadCounter),
            0x12 => Ok(Self::Concat),
            0x13 => Ok(Self::Sha256),
            0x14 => Ok(Self::CheckPrefix),
            _ => Err(ProgramError::UnknownOpcode),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProgramError {
    InvalidHex,
    OddHexLength,
    ProgramTooLarge,
    UnknownOpcode,
    InvalidOpcodeOrder,
}

impl ProgramError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidHex => "invalid_vm_hex",
            Self::OddHexLength => "odd_vm_hex_length",
            Self::ProgramTooLarge => "vm_program_too_large",
            Self::UnknownOpcode => "unknown_vm_opcode",
            Self::InvalidOpcodeOrder => "invalid_vm_opcode_order",
        }
    }
}

#[derive(Debug)]
pub(crate) struct Context {
    program: Vec<OpCode>,
}

pub(crate) struct EnvResult {
    pub(crate) score: u32,
    pub(crate) throttle: u64,
    markers: u32,
}

impl EnvResult {
    pub(crate) fn markers_hex(&self) -> String {
        format!("{:08x}", self.markers)
    }
}

impl Context {
    pub(crate) fn parse(program_hex: &str) -> Result<Self, ProgramError> {
        if program_hex.len() % 2 != 0 {
            return Err(ProgramError::OddHexLength);
        }
        if program_hex.len() / 2 > MAX_PROGRAM_BYTES {
            return Err(ProgramError::ProgramTooLarge);
        }

        let bytes = decode_hex(program_hex)?;
        let mut program = Vec::with_capacity(bytes.len());
        let mut expected = [
            OpCode::LoadNonce,
            OpCode::LoadCounter,
            OpCode::Concat,
            OpCode::Sha256,
            OpCode::CheckPrefix,
        ]
        .into_iter();
        let mut next = expected.next();

        for byte in bytes {
            let opcode = OpCode::parse(byte)?;
            if opcode != OpCode::Nop {
                if Some(opcode) != next {
                    return Err(ProgramError::InvalidOpcodeOrder);
                }
                next = expected.next();
            }
            program.push(opcode);
        }
        if next.is_some() {
            return Err(ProgramError::InvalidOpcodeOrder);
        }

        Ok(Self { program })
    }

    pub(crate) fn check_pow(&self, nonce: &str, counter: u64, difficulty: u32) -> bool {
        let mut loaded_nonce = None;
        let mut loaded_counter = None;
        let mut concatenated = None;
        let mut digest = None;

        for opcode in &self.program {
            match opcode {
                OpCode::Nop => {}
                OpCode::LoadNonce => loaded_nonce = Some(nonce),
                OpCode::LoadCounter => loaded_counter = Some(counter),
                OpCode::Concat => {
                    let (loaded_nonce, loaded_counter) = match (loaded_nonce, loaded_counter) {
                        (Some(loaded_nonce), Some(loaded_counter)) => {
                            (loaded_nonce, loaded_counter)
                        }
                        _ => return false,
                    };
                    concatenated = Some(format!("{}{}", loaded_nonce, loaded_counter));
                }
                OpCode::Sha256 => {
                    let input = match concatenated.as_deref() {
                        Some(input) => input,
                        None => return false,
                    };
                    digest = Some(crate::obfuscate::sha256_compute(input.as_bytes()));
                }
                OpCode::CheckPrefix => {
                    return digest
                        .as_ref()
                        .is_some_and(|value| has_leading_zero_nibbles(value, difficulty));
                }
            }
        }
        false
    }
}

pub(crate) fn collect_environment_check() -> EnvResult {
    let mut score = 0;
    let mut markers = 0;
    let mut throttle = 0;

    if detect_webdriver() {
        score += 100;
        markers |= 0x01;
        throttle = throttle.max(500);
    }
    if detect_devtools() {
        score += 30;
        markers |= 0x02;
        throttle = throttle.max(200);
    }
    if detect_automation() {
        score += 80;
        markers |= 0x04;
        throttle = throttle.max(400);
    }
    let timing = detect_timing_anomaly();
    if timing > 0 {
        score += timing;
        markers |= 0x08;
        throttle = throttle.max(100 * u64::from(timing));
    }
    if detect_stack_anomaly() {
        score += 20;
        markers |= 0x10;
        throttle = throttle.max(100);
    }
    if detect_memory_anomaly() {
        score += 15;
        markers |= 0x20;
    }
    if detect_canvas_anomaly() {
        score += 25;
        markers |= 0x40;
        throttle = throttle.max(150);
    }
    if detect_webgl_anomaly() {
        score += 20;
        markers |= 0x80;
    }
    if crate::env::fingerprint_hash().is_empty() {
        score += 15;
        markers |= 0x100;
    }
    if detect_prototype_tampering() {
        score += 40;
        markers |= 0x200;
        throttle = throttle.max(300);
    }

    EnvResult {
        score,
        throttle,
        markers,
    }
}

fn decode_hex(program_hex: &str) -> Result<Vec<u8>, ProgramError> {
    let mut bytes = Vec::with_capacity(program_hex.len() / 2);
    for pair in program_hex.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or(ProgramError::InvalidHex)?;
        let low = hex_nibble(pair[1]).ok_or(ProgramError::InvalidHex)?;
        bytes.push(high << 4 | low);
    }
    Ok(bytes)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn has_leading_zero_nibbles(hash: &[u8], difficulty: u32) -> bool {
    let full_bytes = (difficulty / 2) as usize;
    if full_bytes > hash.len() {
        return false;
    }
    if hash[..full_bytes].iter().any(|byte| *byte != 0) {
        return false;
    }
    difficulty % 2 == 0 || full_bytes < hash.len() && hash[full_bytes] >> 4 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_raw_opcode_program_with_nops() {
        let context = Context::parse("00100011001200130014").expect("Go raw opcode format");
        assert_eq!(context.program.len(), 10);
    }

    #[test]
    fn rejects_frames_and_non_raw_opcode_programs() {
        assert_eq!(
            Context::parse("564d504601c90005").unwrap_err(),
            ProgramError::UnknownOpcode
        );
        assert_eq!(
            Context::parse("1011121315").unwrap_err(),
            ProgramError::UnknownOpcode
        );
    }

    #[test]
    fn executes_raw_opcode_pow_semantics() {
        let context = Context::parse("0010110012130014").expect("raw PoW program");
        assert!(context.check_pow("nonce", 1, 1));
        assert!(!context.check_pow("nonce", 1, 64));
    }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["navigator"], js_name = webdriver, getter)]
    fn navigator_webdriver() -> bool;

    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn console_log(s: &str);
}

fn detect_webdriver() -> bool {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return true,
    };

    let nav = window.navigator();
    let webdriver =
        js_sys::Reflect::get(&nav, &JsValue::from_str("webdriver")).unwrap_or(JsValue::FALSE);
    if webdriver.is_truthy() {
        return true;
    }
    let doc = match window.document() {
        Some(d) => d,
        None => return true,
    };
    let driver_props = [
        "__webdriver_evaluate",
        "__selenium_evaluate",
        "__driver_evaluate",
    ];
    for prop in &driver_props {
        let val =
            js_sys::Reflect::get(&doc, &JsValue::from_str(prop)).unwrap_or(JsValue::UNDEFINED);
        if !val.is_undefined() {
            return true;
        }
    }

    false
}

fn detect_devtools() -> bool {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return false,
    };
    let perf = match window.performance() {
        Some(p) => p,
        None => return false,
    };

    let t1 = perf.now();
    let mut x: u64 = 0;
    for i in 0..10000u64 {
        x = x.wrapping_add(i.wrapping_mul(7));
    }
    std::hint::black_box(x);
    let t2 = perf.now();
    let elapsed = t2 - t1;
    elapsed > 50.0
}

fn detect_automation() -> bool {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return true,
    };
    let phantom_props = [
        "_phantom",
        "callPhantom",
        "__nightmare",
        "_selenium",
        "domAutomation",
        "domAutomationController",
    ];
    for prop in &phantom_props {
        let val =
            js_sys::Reflect::get(&window, &JsValue::from_str(prop)).unwrap_or(JsValue::UNDEFINED);
        if !val.is_undefined() {
            return true;
        }
    }
    let chrome =
        js_sys::Reflect::get(&window, &JsValue::from_str("chrome")).unwrap_or(JsValue::UNDEFINED);
    if !chrome.is_undefined() && !chrome.is_null() {
        let runtime = js_sys::Reflect::get(&chrome, &JsValue::from_str("runtime"))
            .unwrap_or(JsValue::UNDEFINED);
        if runtime.is_undefined() {
            return true;
        }
    }

    false
}

fn detect_timing_anomaly() -> u32 {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return 50,
    };
    let perf = match window.performance() {
        Some(p) => p,
        None => return 30,
    };
    let mut diffs = [0.0f64; 10];
    let mut prev = perf.now();
    for d in diffs.iter_mut() {
        let now = perf.now();
        *d = now - prev;
        prev = now;
    }
    let all_zero = diffs.iter().all(|&d| d == 0.0);
    let all_same = diffs.windows(2).all(|w| w[0] == w[1]);

    if all_zero {
        return 40;
    }
    if all_same && diffs[0] > 0.0 {
        return 25;
    }

    0
}

fn detect_stack_anomaly() -> bool {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return true,
    };
    let po = js_sys::Reflect::get(&window, &JsValue::from_str("PerformanceObserver"))
        .unwrap_or(JsValue::UNDEFINED);
    po.is_undefined()
}

fn detect_memory_anomaly() -> bool {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return true,
    };
    let nav = window.navigator();

    let mem = js_sys::Reflect::get(&nav, &JsValue::from_str("deviceMemory"))
        .unwrap_or(JsValue::UNDEFINED);
    if mem.is_undefined() {
        return false;
    }
    if let Some(val) = mem.as_f64() {
        return val <= 0.0;
    }
    false
}

fn detect_canvas_anomaly() -> bool {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return true,
    };
    let doc = match window.document() {
        Some(d) => d,
        None => return true,
    };
    let canvas = doc.create_element("canvas").ok();
    if canvas.is_none() {
        return true;
    }
    let canvas = canvas.unwrap();
    let ctx = js_sys::Reflect::get(&canvas, &JsValue::from_str("getContext"))
        .unwrap_or(JsValue::UNDEFINED);
    ctx.is_undefined() || ctx.is_null()
}

fn detect_webgl_anomaly() -> bool {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return true,
    };

    let webgl = js_sys::Reflect::get(&window, &JsValue::from_str("WebGLRenderingContext"))
        .unwrap_or(JsValue::UNDEFINED);
    webgl.is_undefined()
}

fn detect_prototype_tampering() -> bool {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return true,
    };
    let nav = window.navigator();
    let to_string =
        js_sys::Reflect::get(&nav, &JsValue::from_str("toString")).unwrap_or(JsValue::UNDEFINED);
    if !to_string.is_undefined() {
        let ts_str = js_sys::Function::from(to_string).to_string();
        let ts_val: String = ts_str.into();
        if !ts_val.contains("native code") {
            return true;
        }
    }
    let check = js_sys::eval(
        r#"(function(){
        try{
            var desc=Object.getOwnPropertyDescriptor(Navigator.prototype,'webdriver');
            if(desc&&desc.get&&desc.get.toString().indexOf('native code')<0)return true;
            var pn=Object.getOwnPropertyNames(navigator);
            if(pn.indexOf('webdriver')>=0){
                var d2=Object.getOwnPropertyDescriptor(navigator,'webdriver');
                if(d2&&typeof d2.get==='function')return true;
            }
            return false;
        }catch(e){return false}})()"#,
    );
    match check {
        Ok(v) => v.is_truthy(),
        Err(_) => false,
    }
}

fn hex_decode(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();
    while let (Some(h), Some(l)) = (chars.next(), chars.next()) {
        let byte = hex_char_to_u8(h) << 4 | hex_char_to_u8(l);
        bytes.push(byte);
    }
    bytes
}

fn hex_char_to_u8(c: char) -> u8 {
    match c {
        '0'..='9' => c as u8 - b'0',
        'a'..='f' => c as u8 - b'a' + 10,
        'A'..='F' => c as u8 - b'A' + 10,
        _ => 0,
    }
}

#[inline(never)]
fn burn_nop(n: u32) {
    let mut x: u32 = 0xCAFEBABE;
    for _ in 0..n {
        x = x.wrapping_mul(1103515245).wrapping_add(12345);
    }
    std::hint::black_box(x);
}
