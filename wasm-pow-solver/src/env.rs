use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = eval)]
    fn js_eval(code: &str) -> JsValue;
}
pub fn perf_now() -> f64 {
    let window = web_sys::window().unwrap();
    let perf = window.performance().unwrap();
    perf.now()
}

pub fn live_monitoring() -> u32 {
    let mut score: u32 = 0;
    let t1 = perf_now();
    let mut x: u32 = 0xABCDEF01;
    for _ in 0..100 {
        x = x.wrapping_mul(1103515245).wrapping_add(12345);
    }
    std::hint::black_box(x);
    let elapsed = perf_now() - t1;

    if elapsed > 20.0 {
        score += 40;
    } else if elapsed > 5.0 {
        score += 15;
    }
    let debugger_check = js_eval(
        r#"(function(){var t=performance.now();debugger;return performance.now()-t>100})()"#,
    );
    if debugger_check.is_truthy() {
        score += 50;
    }

    score
}

pub fn fingerprint_hash() -> String {
    let result = js_eval(
        r#"(function(){
        var parts=[];
        parts.push(navigator.userAgent||'');
        parts.push(navigator.language||'');
        parts.push(String(screen.width)+'x'+String(screen.height));
        parts.push(String(navigator.hardwareConcurrency||0));
        parts.push(Intl.DateTimeFormat().resolvedOptions().timeZone||'');
        try{var c=document.createElement('canvas');var ctx=c.getContext('2d');
        ctx.textBaseline='top';ctx.font='14px Arial';ctx.fillText('owaf',2,2);
        parts.push(c.toDataURL().slice(-32))}catch(e){parts.push('no-canvas')}
        return parts.join('|')})()"#,
    );
    result.as_string().unwrap_or_default()
}
