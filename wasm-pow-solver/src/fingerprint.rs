use js_sys::Reflect;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;



const MAX_FINGERPRINT_BYTES: usize = 64 * 1024;

/**
 * collect_fingerprint assembles and serializes browser observations in Rust.
 * JavaScript only transports browser API reads through wasm-bindgen; it does
 * not define fields, classify signals, hash data, or encrypt the result.
 */
#[wasm_bindgen]
pub fn collect_fingerprint() -> String {
    collect_fingerprint_json()
}

/**
 * collect_and_encrypt_fingerprint creates the canonical v1 envelope in WASM.
 */
#[wasm_bindgen]
pub fn collect_and_encrypt_fingerprint(key_hex: &str, aad: &str) -> String {
    let fingerprint = collect_fingerprint_json();
    if fingerprint.is_empty() {
        return String::new();
    }
    crate::crypto::encrypt_env_data_with_aad(&fingerprint, key_hex, aad)
}

/**
 * collect_canvas_fingerprint computes the Canvas SHA-256 digest in WASM.
 */
#[wasm_bindgen]
pub fn collect_canvas_fingerprint() -> String {
    let window = match web_sys::window() {
        Some(window) => window,
        None => return String::new(),
    };
    let document = match window.document() {
        Some(document) => document,
        None => return String::new(),
    };
    let canvas = match document.create_element("canvas") {
        Ok(element) => match element.dyn_into::<web_sys::HtmlCanvasElement>() {
            Ok(canvas) => canvas,
            Err(_) => return String::new(),
        },
        Err(_) => return String::new(),
    };
    canvas.set_width(280);
    canvas.set_height(60);
    let context = match canvas.get_context("2d") {
        Ok(Some(context)) => match context.dyn_into::<web_sys::CanvasRenderingContext2d>() {
            Ok(context) => context,
            Err(_) => return String::new(),
        },
        _ => return String::new(),
    };
    context.set_fill_style_str("rgb(102,204,0)");
    context.set_font("18px Arial");
    context.set_text_baseline("top");
    let _ = context.fill_text("OWAF fp v1.0", 2.0, 2.0);
    context.set_fill_style_str("rgba(100,200,50,0.7)");
    context.fill_rect(50.0, 10.0, 100.0, 40.0);
    context.set_fill_style_str("rgb(50,100,150)");
    context.begin_path();
    let _ = context.arc(150.0, 30.0, 20.0, 0.0, std::f64::consts::PI * 2.0);
    context.fill();
    match canvas.to_data_url() {
        Ok(value) => sha256_hex(value.as_bytes()),
        Err(_) => String::new(),
    }
}

/**
 * collect_webgl_fingerprint computes a WebGL digest in WASM from raw API values.
 */
#[wasm_bindgen]
pub fn collect_webgl_fingerprint() -> String {
    let (vendor, renderer) = collect_webgl_values();
    if vendor.is_empty() && renderer.is_empty() {
        return String::new();
    }
    sha256_hex(format!("{}|{}", vendor, renderer).as_bytes())
}

pub(crate) fn collect_fingerprint_json() -> String {
    let window = match web_sys::window() {
        Some(window) => window,
        None => return String::new(),
    };
    let document = match window.document() {
        Some(document) => document,
        None => return String::new(),
    };
    let window_value = JsValue::from(window.clone());
    let document_value = JsValue::from(document);
    let navigator_value = JsValue::from(window.navigator());
    let screen_value = property(&window_value, "screen").unwrap_or(JsValue::UNDEFINED);
    let (webgl_vendor, webgl_renderer) = collect_webgl_values();

    let webdriver = bool_property(&navigator_value, "webdriver");
    let phantom = has_any_property(&window_value, &["callPhantom", "_phantom"]);
    let nightmare = has_property(&window_value, "__nightmare");
    let selenium_sign = has_any_property(
        &window_value,
        &[
            "__selenium_unwrapped",
            "__webdriver_evaluate",
            "__fxdriver_unwrapped",
        ],
    ) || has_property(&document_value, "__selenium_unwrapped");
    let chrome_cdc = has_any_property(
        &window_value,
        &[
            "cdc_adoQpoasnfa76pfcZLmcfl_Array",
            "cdc_adoQpoasnfa76pfcZLmcfl_Promise",
            "__cdp_runtime",
        ],
    );
    let puppeteer_sign = has_any_property(
        &window_value,
        &["__pptr_tmp_binding", "__puppeteer_evaluation_script__"],
    );
    let playwright_sign = has_any_property(
        &window_value,
        &["__playwright", "__pw_manual", "_playwrightInstance"],
    );
    let cypress_sign = has_any_property(&window_value, &["Cypress", "__cypress"]);
    let automation_sign = if webdriver {
        "webdriver"
    } else if phantom {
        "phantom"
    } else if nightmare {
        "nightmare"
    } else if selenium_sign {
        "selenium"
    } else {
        ""
    };

    let fingerprint = json!({
        "webdriver": webdriver,
        "chrome_present": has_property(&window_value, "chrome"),
        "plugins_count": array_length(&navigator_value, "plugins"),
        "languages": languages_value(&navigator_value),
        "devtools_open": false,
        "canvas_hash": collect_canvas_fingerprint(),
        "webgl_renderer": webgl_renderer,
        "screen_width": number_property(&screen_value, "width") as i64,
        "screen_height": number_property(&screen_value, "height") as i64,
        "timezone_offset": 0_i64,
        "touch_support": number_property(&navigator_value, "maxTouchPoints") > 0.0,
        "hardware_concurrency": number_property(&navigator_value, "hardwareConcurrency"),
        "color_depth": number_property(&screen_value, "colorDepth"),
        "pixel_ratio": window.device_pixel_ratio(),
        "audio_hash": "",
        "font_count": 0_i64,
        "session_storage": window.session_storage().ok().flatten().is_some(),
        "indexed_db": has_property(&window_value, "indexedDB"),
        "pdf_viewer": bool_property(&navigator_value, "pdfViewerEnabled"),
        "do_not_track": string_property(&navigator_value, "doNotTrack"),
        "max_touch_points": number_property(&navigator_value, "maxTouchPoints"),
        "connection_type": "",
        "devtools_timing": 0_i64,
        "platform": string_property(&navigator_value, "platform"),
        "cookie_enabled": bool_property(&navigator_value, "cookieEnabled"),
        "device_memory": number_property(&navigator_value, "deviceMemory"),
        "user_agent": string_property(&navigator_value, "userAgent"),
        "vendor": string_property(&navigator_value, "vendor"),
        "product": string_property(&navigator_value, "product"),
        "app_version": string_property(&navigator_value, "appVersion"),
        "language": string_property(&navigator_value, "language"),
        "viewport_width": number_property(&window_value, "innerWidth"),
        "viewport_height": number_property(&window_value, "innerHeight"),
        "outer_width": number_property(&window_value, "outerWidth"),
        "outer_height": number_property(&window_value, "outerHeight"),
        "inner_width": number_property(&window_value, "innerWidth"),
        "inner_height": number_property(&window_value, "innerHeight"),
        "screen_x": number_property(&window_value, "screenX"),
        "screen_y": number_property(&window_value, "screenY"),
        "notification_api": has_property(&window_value, "Notification"),
        "push_api": has_property(&window_value, "PushManager"),
        "clipboard_api": has_property(&navigator_value, "clipboard"),
        "geolocation_api": has_property(&navigator_value, "geolocation"),
        "webrtc_api": has_property(&window_value, "RTCPeerConnection"),
        "fetch_api": has_property(&window_value, "fetch"),
        "websocket_api": has_property(&window_value, "WebSocket"),
        "crypto_api": has_property(&window_value, "crypto"),
        "battery_api": has_property(&navigator_value, "getBattery"),
        "gamepad_api": has_property(&navigator_value, "getGamepads"),
        "vibrate_api": has_property(&navigator_value, "vibrate"),
        "automation_sign": automation_sign,
        "phantom": phantom,
        "nightmare": nightmare,
        "selenium_sign": selenium_sign,
        "headless_ua": string_property(&navigator_value, "userAgent").contains("HeadlessChrome"),
        "chrome_cdc": chrome_cdc,
        "perm_notif": "",
        "user_agent_data": json_property(&navigator_value, "userAgentData"),
        "browser_brand": "",
        "browser_version": "",
        "is_mobile": false,
        "ua_mismatch": false,
        "navigator_proto": true,
        "webgl_vendor": webgl_vendor,
        "canvas_to_blob": true,
        "webgl2_support": has_property(&window_value, "WebGL2RenderingContext"),
        "svg_support": has_property(&window_value, "SVGElement"),
        "media_devices": has_property(&navigator_value, "mediaDevices"),
        "speech_synthesis": has_property(&window_value, "speechSynthesis"),
        "service_worker": has_property(&navigator_value, "serviceWorker"),
        "cache_api": has_property(&window_value, "caches"),
        "web_assembly": has_property(&window_value, "WebAssembly"),
        "shared_worker": has_property(&window_value, "SharedWorker"),
        "broadcast_channel": has_property(&window_value, "BroadcastChannel"),
        "performance_observer": has_property(&window_value, "PerformanceObserver"),
        "performance_mark": has_property(&window_value, "performance"),
        "timing_api_depth": 0_i64,
        "permission_api": has_property(&navigator_value, "permissions"),
        "credential_api": has_property(&navigator_value, "credentials"),
        "csp_violation": false,
        "webdriver_advanced": webdriver || selenium_sign,
        "cdp_runtime": chrome_cdc || has_property(&window_value, "Runtime"),
        "puppeteer_sign": puppeteer_sign,
        "playwright_sign": playwright_sign,
        "electron_sign": has_property(&window_value, "process"),
        "cypress_sign": cypress_sign,
        "screen_consistency": true,
        "timezone_consistency": true,
        "language_consistency": true,
        "math_consistency": true,
        "css_supports_check": has_property(&window_value, "CSS"),
        "intersection_observer": has_property(&window_value, "IntersectionObserver"),
        "mutation_observer": has_property(&window_value, "MutationObserver"),
        "resize_observer": has_property(&window_value, "ResizeObserver"),
        "history_api": has_property(&window_value, "history")
    });
    canonical_json(fingerprint)
}

fn collect_webgl_values() -> (String, String) {
    let window = match web_sys::window() {
        Some(window) => window,
        None => return (String::new(), String::new()),
    };
    let document = match window.document() {
        Some(document) => document,
        None => return (String::new(), String::new()),
    };
    let canvas = match document.create_element("canvas") {
        Ok(element) => match element.dyn_into::<web_sys::HtmlCanvasElement>() {
            Ok(canvas) => canvas,
            Err(_) => return (String::new(), String::new()),
        },
        Err(_) => return (String::new(), String::new()),
    };
    let gl = match canvas.get_context("webgl") {
        Ok(Some(context)) => match context.dyn_into::<web_sys::WebGlRenderingContext>() {
            Ok(context) => context,
            Err(_) => return (String::new(), String::new()),
        },
        _ => return (String::new(), String::new()),
    };
    let vendor = gl
        .get_parameter(web_sys::WebGlRenderingContext::VENDOR)
        .ok()
        .and_then(|value| value.as_string())
        .unwrap_or_default();
    let renderer = gl
        .get_parameter(web_sys::WebGlRenderingContext::RENDERER)
        .ok()
        .and_then(|value| value.as_string())
        .unwrap_or_default();
    (vendor, renderer)
}

fn property(target: &JsValue, key: &str) -> Option<JsValue> {
    Reflect::get(target, &JsValue::from_str(key))
        .ok()
        .filter(|value| !value.is_null() && !value.is_undefined())
}

fn has_property(target: &JsValue, key: &str) -> bool {
    property(target, key).is_some()
}

fn has_any_property(target: &JsValue, keys: &[&str]) -> bool {
    keys.iter().any(|key| has_property(target, key))
}

fn bool_property(target: &JsValue, key: &str) -> bool {
    property(target, key)
        .map(|value| value.is_truthy())
        .unwrap_or(false)
}

fn number_property(target: &JsValue, key: &str) -> f64 {
    property(target, key)
        .and_then(|value| value.as_f64())
        .unwrap_or(0.0)
}

fn string_property(target: &JsValue, key: &str) -> String {
    property(target, key)
        .and_then(|value| value.as_string())
        .unwrap_or_default()
}

fn array_length(target: &JsValue, key: &str) -> usize {
    property(target, key)
        .and_then(|value| property(&value, "length"))
        .and_then(|value| value.as_f64())
        .unwrap_or(0.0) as usize
}

fn languages_value(navigator: &JsValue) -> String {
    let languages = match property(navigator, "languages") {
        Some(languages) => languages,
        None => return string_property(navigator, "language"),
    };
    let length = property(&languages, "length")
        .and_then(|value| value.as_f64())
        .unwrap_or(0.0) as usize;
    let mut values = Vec::new();
    for index in 0..length.min(32) {
        if let Ok(value) = Reflect::get(&languages, &JsValue::from_f64(index as f64)) {
            if let Some(value) = value.as_string() {
                values.push(value);
            }
        }
    }
    values.join(",")
}

fn json_property(target: &JsValue, key: &str) -> String {
    property(target, key)
        .and_then(|value| js_sys::JSON::stringify(&value).ok())
        .and_then(|value| value.as_string())
        .unwrap_or_default()
}

fn canonical_json(value: Value) -> String {
    let output = value.to_string();
    if output.len() > MAX_FINGERPRINT_BYTES {
        String::new()
    } else {
        output
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    crate::hex_encode(&hasher.finalize())
}
