use sha2::{Sha256, Digest};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = eval)]
    fn js_eval(code: &str) -> JsValue;
}

#[wasm_bindgen]
pub fn collect_fingerprint(key_hex: &str) -> String {
    let fp = gather_env_data();
    if key_hex.is_empty() {
        return fp;
    }
    crate::crypto::encrypt_env_data(&fp, key_hex)
}

#[wasm_bindgen]
pub fn collect_canvas_fingerprint() -> String {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return String::new(),
    };
    let document = match window.document() {
        Some(d) => d,
        None => return String::new(),
    };
    let canvas = match document.create_element("canvas") {
        Ok(el) => el,
        Err(_) => return String::new(),
    };
    let canvas: web_sys::HtmlCanvasElement = match canvas.dyn_into() {
        Ok(c) => c,
        Err(_) => return String::new(),
    };
    canvas.set_width(280);
    canvas.set_height(60);

    let ctx = match canvas.get_context("2d") {
        Ok(Some(ctx)) => ctx,
        _ => return String::new(),
    };
    let ctx: web_sys::CanvasRenderingContext2d = match ctx.dyn_into() {
        Ok(c) => c,
        Err(_) => return String::new(),
    };

    ctx.set_fill_style_str("rgb(102,204,0)");
    ctx.set_font("18px Arial");
    ctx.set_text_baseline("top");
    let _ = ctx.fill_text("OWAF fp v1.0", 2.0, 2.0);
    ctx.set_fill_style_str("rgba(100,200,50,0.7)");
    ctx.fill_rect(50.0, 10.0, 100.0, 40.0);
    ctx.set_fill_style_str("rgb(50,100,150)");
    ctx.begin_path();
    let _ = ctx.arc(150.0, 30.0, 20.0, 0.0, std::f64::consts::PI * 2.0);
    ctx.fill();

    let data_url = match canvas.to_data_url() {
        Ok(d) => d,
        Err(_) => return String::new(),
    };

    let mut hasher = Sha256::new();
    hasher.update(data_url.as_bytes());
    let result = hasher.finalize();
    crate::hex_encode(&result)
}

#[wasm_bindgen]
pub fn collect_webgl_fingerprint() -> String {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return String::new(),
    };
    let document = match window.document() {
        Some(d) => d,
        None => return String::new(),
    };
    let canvas = match document.create_element("canvas") {
        Ok(el) => el,
        Err(_) => return String::new(),
    };
    let canvas: web_sys::HtmlCanvasElement = match canvas.dyn_into() {
        Ok(c) => c,
        Err(_) => return String::new(),
    };

    let gl = match canvas.get_context("webgl") {
        Ok(Some(ctx)) => ctx,
        _ => return String::new(),
    };
    let gl: web_sys::WebGlRenderingContext = match gl.dyn_into() {
        Ok(g) => g,
        Err(_) => return String::new(),
    };

    let vendor = gl.get_parameter(web_sys::WebGlRenderingContext::VENDOR)
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default();
    let renderer = gl.get_parameter(web_sys::WebGlRenderingContext::RENDERER)
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default();

    let debug_ext = gl.get_extension("WEBGL_debug_renderer_info").ok().flatten();
    let (unmasked_vendor, unmasked_renderer) = if debug_ext.is_some() {
        let uv = gl.get_parameter(0x9245) // UNMASKED_VENDOR_WEBGL
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default();
        let ur = gl.get_parameter(0x9246) // UNMASKED_RENDERER_WEBGL
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default();
        (uv, ur)
    } else {
        (String::new(), String::new())
    };

    let combined = format!("{}|{}|{}|{}", vendor, renderer, unmasked_vendor, unmasked_renderer);
    let mut hasher = Sha256::new();
    hasher.update(combined.as_bytes());
    let result = hasher.finalize();
    crate::hex_encode(&result)
}

fn gather_env_data() -> String {
    let result = js_eval(
        r#"(function(){
var fp={};
try{fp.webdriver=!!navigator.webdriver}catch(e){fp.webdriver=false}
try{fp.chrome_present=!!window.chrome}catch(e){fp.chrome_present=false}
try{fp.plugins_count=navigator.plugins?navigator.plugins.length:0}catch(e){fp.plugins_count=0}
try{fp.languages=navigator.languages?navigator.languages.join(','):navigator.language||''}catch(e){fp.languages=''}
try{fp.screen_width=screen.width;fp.screen_height=screen.height}catch(e){fp.screen_width=0;fp.screen_height=0}
try{fp.timezone_offset=new Date().getTimezoneOffset()}catch(e){fp.timezone_offset=0}
try{fp.touch_support='ontouchstart' in window||navigator.maxTouchPoints>0}catch(e){fp.touch_support=false}
try{fp.hardware_concurrency=navigator.hardwareConcurrency||0}catch(e){fp.hardware_concurrency=0}
try{fp.color_depth=screen.colorDepth||0}catch(e){fp.color_depth=0}
try{fp.pixel_ratio=window.devicePixelRatio||0}catch(e){fp.pixel_ratio=0}
try{fp.session_storage=!!window.sessionStorage}catch(e){fp.session_storage=false}
try{fp.indexed_db=!!window.indexedDB}catch(e){fp.indexed_db=false}
try{fp.cookie_enabled=!!navigator.cookieEnabled}catch(e){fp.cookie_enabled=false}
try{fp.platform=navigator.platform||''}catch(e){fp.platform=''}
try{fp.max_touch_points=navigator.maxTouchPoints||0}catch(e){fp.max_touch_points=0}
try{fp.do_not_track=navigator.doNotTrack||''}catch(e){fp.do_not_track=''}
try{fp.device_memory=navigator.deviceMemory||0}catch(e){fp.device_memory=0}
try{fp.pdf_viewer=!!navigator.pdfViewerEnabled}catch(e){fp.pdf_viewer=false}
try{fp.web_assembly=typeof WebAssembly!=='undefined'}catch(e){fp.web_assembly=false}
try{fp.service_worker='serviceWorker' in navigator}catch(e){fp.service_worker=false}
try{
var wda=false;
if(navigator.webdriver)wda=true;
if(!wda){try{var ks=['__webdriver_evaluate','__selenium_evaluate','__fxdriver_evaluate','__driver_unwrapped','__webdriver_unwrapped','__driver_evaluate','__selenium_unwrapped','__fxdriver_unwrapped','_Selenium_IDE_Recorder','_selenium','calledSelenium','_WEBDRIVER_ELEM_CACHE','ChromeDriverw'];for(var i=0;i<ks.length;i++){if(window[ks[i]]!==undefined){wda=true;break}}}catch(e2){}}
fp.webdriver_advanced=wda;
}catch(e){fp.webdriver_advanced=false}
try{fp.phantom=!!(window.callPhantom||window._phantom)}catch(e){fp.phantom=false}
try{fp.nightmare=!!window.__nightmare}catch(e){fp.nightmare=false}
try{fp.puppeteer_sign=!!(window.__pptr_tmp_binding||window.__puppeteer_evaluation_script__)}catch(e){fp.puppeteer_sign=false}
try{fp.playwright_sign=!!(window.__playwright||window.__pw_manual||window._playwrightInstance)}catch(e){fp.playwright_sign=false}
try{fp.electron_sign=!!(window.process&&window.process.versions&&window.process.versions.electron)}catch(e){fp.electron_sign=false}
try{fp.cypress_sign=!!(window.Cypress||window.__cypress)}catch(e){fp.cypress_sign=false}
return JSON.stringify(fp)})()
"#,
    );
    result.as_string().unwrap_or_else(|| "{}".to_string())
}
