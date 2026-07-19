#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OpCode {
    Nop = 0x00,
    CheckWebDriver = 0x10,
    CheckDevTools = 0x11,
    CheckAutomation = 0x12,
    CheckTiming = 0x13,
    CheckStack = 0x14,
    CheckMemory = 0x15,
    CheckCanvas = 0x16,
    CheckWebGL = 0x17,
    CheckFingerprint = 0x18,
    CheckPrototype = 0x19,
    Jump = 0x20,
    JumpIfFlag = 0x21,
    JumpIfNotFlag = 0x22,
    SetFlag = 0x23,
    ClearFlag = 0x24,
    JumpIfScore = 0x25,
    AddScore = 0x30,
    SetMarker = 0x31,
    SetThrottle = 0x32,
    MulScore = 0x33,
    ConditionalPenalty = 0x34,
    Shuffle = 0x40,
    FakeCheck = 0x41,
    Delay = 0x42,
    XorReg = 0x43,
    RotReg = 0x44,
    Halt = 0xFF,
}

impl OpCode {
    fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Nop,
            0x10 => Self::CheckWebDriver,
            0x11 => Self::CheckDevTools,
            0x12 => Self::CheckAutomation,
            0x13 => Self::CheckTiming,
            0x14 => Self::CheckStack,
            0x15 => Self::CheckMemory,
            0x16 => Self::CheckCanvas,
            0x17 => Self::CheckWebGL,
            0x18 => Self::CheckFingerprint,
            0x19 => Self::CheckPrototype,
            0x20 => Self::Jump,
            0x21 => Self::JumpIfFlag,
            0x22 => Self::JumpIfNotFlag,
            0x23 => Self::SetFlag,
            0x24 => Self::ClearFlag,
            0x25 => Self::JumpIfScore,
            0x30 => Self::AddScore,
            0x31 => Self::SetMarker,
            0x32 => Self::SetThrottle,
            0x33 => Self::MulScore,
            0x34 => Self::ConditionalPenalty,
            0x40 => Self::Shuffle,
            0x41 => Self::FakeCheck,
            0x42 => Self::Delay,
            0x43 => Self::XorReg,
            0x44 => Self::RotReg,
            0xFF => Self::Halt,
            _ => Self::Nop,
        }
    }
}

pub struct Context {
    bytecode: Vec<u8>,
}

pub struct EnvResult {
    pub score: u32,
    pub throttle: u64,
    markers: u32,
}

impl EnvResult {
    pub fn markers_hex(&self) -> String {
        format!("{:08x}", self.markers)
    }
}

impl Context {
    pub fn new(program_hex: &str) -> Self {
        let bytecode = hex_decode(program_hex);
        Context { bytecode }
    }
    pub fn execute_env_check(&self) -> EnvResult {
        let mut score: u32 = 0;
        let mut markers: u32 = 0;
        let mut throttle: u64 = 0;
        let mut pc = 0;
        let mut flags = [false; 16];
        let registers: [u32; 8] = [0; 8];
        let code = &self.bytecode;
        let max_steps = 1024; 
        let mut steps = 0;

        while pc < code.len() && steps < max_steps {
            steps += 1;
            let op = OpCode::from_byte(code[pc]);
            pc += 1;

            match op {
                OpCode::Nop => {}

                OpCode::CheckWebDriver => {
                    if detect_webdriver() {
                        score += 100;
                        markers |= 0x01;
                        throttle = throttle.max(500);
                    }
                }

                OpCode::CheckDevTools => {
                    if detect_devtools() {
                        score += 30;
                        markers |= 0x02;
                        throttle = throttle.max(200);
                    }
                }

                OpCode::CheckAutomation => {
                    if detect_automation() {
                        score += 80;
                        markers |= 0x04;
                        throttle = throttle.max(400);
                    }
                }

                OpCode::CheckTiming => {
                    let anomaly = detect_timing_anomaly();
                    if anomaly > 0 {
                        score += anomaly;
                        markers |= 0x08;
                        throttle = throttle.max(100 * anomaly as u64);
                    }
                }

                OpCode::CheckStack => {
                    if detect_stack_anomaly() {
                        score += 20;
                        markers |= 0x10;
                        throttle = throttle.max(100);
                    }
                }

                OpCode::CheckMemory => {
                    if detect_memory_anomaly() {
                        score += 15;
                        markers |= 0x20;
                    }
                }

                OpCode::CheckCanvas => {
                    if detect_canvas_anomaly() {
                        score += 25;
                        markers |= 0x40;
                        throttle = throttle.max(150);
                    }
                }

                OpCode::CheckWebGL => {
                    if detect_webgl_anomaly() {
                        score += 20;
                        markers |= 0x80;
                    }
                }

                OpCode::CheckFingerprint => {
                    let fp = crate::env::fingerprint_hash();
                    if fp.is_empty() {
                        score += 15;
                        markers |= 0x100;
                    }
                }

                OpCode::CheckPrototype => {
                    if detect_prototype_tampering() {
                        score += 40;
                        markers |= 0x200;
                        throttle = throttle.max(300);
                    }
                }

                OpCode::Jump => {
                    if pc < code.len() {
                        let offset = code[pc] as usize;
                        pc = offset.min(code.len());
                    }
                }

                OpCode::JumpIfFlag => {
                    if pc + 1 < code.len() {
                        let flag_idx = (code[pc] & 0x0F) as usize;
                        let target = code[pc + 1] as usize;
                        pc += 2;
                        if flags[flag_idx] {
                            pc = target.min(code.len());
                        }
                    } else {
                        pc = code.len();
                    }
                }

                OpCode::JumpIfNotFlag => {
                    if pc + 1 < code.len() {
                        let flag_idx = (code[pc] & 0x0F) as usize;
                        let target = code[pc + 1] as usize;
                        pc += 2;
                        if !flags[flag_idx] {
                            pc = target.min(code.len());
                        }
                    } else {
                        pc = code.len();
                    }
                }

                OpCode::SetFlag => {
                    if pc < code.len() {
                        let idx = (code[pc] & 0x0F) as usize;
                        flags[idx] = true;
                        pc += 1;
                    }
                }

                OpCode::ClearFlag => {
                    if pc < code.len() {
                        let idx = (code[pc] & 0x0F) as usize;
                        flags[idx] = false;
                        pc += 1;
                    }
                }

                OpCode::JumpIfScore => {
                    if pc + 2 < code.len() {
                        let threshold = code[pc] as u32;
                        let target = code[pc + 1] as usize;
                        pc += 2;
                        if score >= threshold {
                            pc = target.min(code.len());
                        }
                    } else {
                        pc = code.len();
                    }
                }

                OpCode::AddScore => {
                    if pc < code.len() {
                        score += code[pc] as u32;
                        pc += 1;
                    }
                }

                OpCode::SetMarker => {
                    if pc < code.len() {
                        markers |= 1u32 << (code[pc] & 0x1F);
                        pc += 1;
                    }
                }

                OpCode::SetThrottle => {
                    if pc + 1 < code.len() {
                        let val = u16::from_le_bytes([code[pc], code[pc + 1]]) as u64;
                        throttle = throttle.max(val);
                        pc += 2;
                    } else {
                        pc = code.len();
                    }
                }

                OpCode::MulScore => {
                    if pc < code.len() {
                        let factor = code[pc] as u32;
                        score = score.saturating_mul(factor);
                        pc += 1;
                    }
                }

                OpCode::ConditionalPenalty => {
                    if pc + 1 < code.len() {
                        let flag_idx = (code[pc] & 0x0F) as usize;
                        let penalty = code[pc + 1] as u32;
                        if flags[flag_idx] {
                            score = score.saturating_add(penalty);
                            throttle = throttle.max(penalty as u64 * 2);
                        }
                        pc += 2;
                    } else {
                        pc = code.len();
                    }
                }

                OpCode::Shuffle => {
                    if pc < code.len() {
                        let pair = code[pc];
                        let a = ((pair >> 4) & 0x07) as usize;
                        let b = (pair & 0x07) as usize;
                        std::hint::black_box(registers[a] ^ registers[b]);
                        pc += 1;
                    }
                }

                OpCode::FakeCheck => {
                    if pc < code.len() {
                        std::hint::black_box(code[pc]);
                        pc += 1;
                    }
                }

                OpCode::Delay => {
                    if pc < code.len() {
                        let n = code[pc] as u32 * 100;
                        burn_nop(n);
                        pc += 1;
                    }
                }

                OpCode::XorReg => {
                    if pc < code.len() {
                        let pair = code[pc];
                        let a = ((pair >> 4) & 0x07) as usize;
                        let b = (pair & 0x07) as usize;
                        let result = registers[a] ^ registers[b];
                        std::hint::black_box(result);
                        pc += 1;
                    }
                }

                OpCode::RotReg => {
                    if pc < code.len() {
                        let operand = code[pc];
                        let reg = (operand >> 4) as usize & 0x07;
                        let amount = (operand & 0x0F) as u32;
                        let result = registers[reg].rotate_left(amount);
                        std::hint::black_box(result);
                        pc += 1;
                    }
                }

                OpCode::Halt => break,
            }
        }

        EnvResult { score, markers, throttle }
    }
}


#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["navigator"], js_name = webdriver, getter)]
    fn navigator_webdriver() -> bool;

    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn console_log(s: &str);
}

use wasm_bindgen::prelude::*;

fn detect_webdriver() -> bool {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return true, 
    };

    let nav = window.navigator();
    let webdriver = js_sys::Reflect::get(&nav, &JsValue::from_str("webdriver"))
        .unwrap_or(JsValue::FALSE);
    if webdriver.is_truthy() {
        return true;
    }
    let doc = match window.document() {
        Some(d) => d,
        None => return true,
    };
    let driver_props = ["__webdriver_evaluate", "__selenium_evaluate", "__driver_evaluate"];
    for prop in &driver_props {
        let val = js_sys::Reflect::get(&doc, &JsValue::from_str(prop)).unwrap_or(JsValue::UNDEFINED);
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
    let phantom_props = ["_phantom", "callPhantom", "__nightmare", "_selenium", "domAutomation", "domAutomationController"];
    for prop in &phantom_props {
        let val = js_sys::Reflect::get(&window, &JsValue::from_str(prop)).unwrap_or(JsValue::UNDEFINED);
        if !val.is_undefined() {
            return true;
        }
    }
    let chrome = js_sys::Reflect::get(&window, &JsValue::from_str("chrome")).unwrap_or(JsValue::UNDEFINED);
    if !chrome.is_undefined() && !chrome.is_null() {
        let runtime = js_sys::Reflect::get(&chrome, &JsValue::from_str("runtime")).unwrap_or(JsValue::UNDEFINED);
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
    let to_string = js_sys::Reflect::get(&nav, &JsValue::from_str("toString"))
        .unwrap_or(JsValue::UNDEFINED);
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
