package challenge

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
)

const (
	// EnvFingerprintProtocolVersion 是环境指纹 AES-256-GCM 密文封装的唯一协议版本。
	EnvFingerprintProtocolVersion = "v1"
	envSessionKeySize             = 32
	envNonceSize                  = 12
	envCiphertextPrefix           = EnvFingerprintProtocolVersion + "."
)

/**
 * EnvFingerprint 表示通过 JavaScript 收集的客户端环境指纹数据。
 * 涵盖浏览器 API、渲染/图形、媒体/音频、存储/API、性能/计时、
 * 权限/安全、自动化检测、环境一致性、DOM/CSS 等多维度检测点。
 */
type EnvFingerprint struct {
	WebDriver            bool    `json:"webdriver"`
	ChromePresent        bool    `json:"chrome_present"`
	PluginsCount         int     `json:"plugins_count"`
	Languages            string  `json:"languages"`
	DevtoolsOpen         bool    `json:"devtools_open"`
	CanvasHash           string  `json:"canvas_hash"`
	WebGLRenderer        string  `json:"webgl_renderer"`
	ScreenWidth          int     `json:"screen_width"`
	ScreenHeight         int     `json:"screen_height"`
	TimezoneOffset       int     `json:"timezone_offset"`
	TouchSupport         bool    `json:"touch_support"`
	HardwareConcur       int     `json:"hardware_concurrency"`
	ColorDepth           int     `json:"color_depth"`
	PixelRatio           float64 `json:"pixel_ratio"`
	AudioHash            string  `json:"audio_hash"`
	FontCount            int     `json:"font_count"`
	SessionStorage       bool    `json:"session_storage"`
	IndexedDB            bool    `json:"indexed_db"`
	PDFViewer            bool    `json:"pdf_viewer"`
	DoNotTrack           string  `json:"do_not_track"`
	MaxTouchPoints       int     `json:"max_touch_points"`
	ConnectionType       string  `json:"connection_type"`
	DevtoolsTiming       float64 `json:"devtools_timing"`
	PlatformStr          string  `json:"platform"`
	CookieEnabled        bool    `json:"cookie_enabled"`
	MemoryGB             float64 `json:"device_memory"`
	UserAgent            string  `json:"user_agent"`
	Vendor               string  `json:"vendor"`
	Product              string  `json:"product"`
	AppVersion           string  `json:"app_version"`
	Language             string  `json:"language"`
	ViewportWidth        int     `json:"viewport_width"`
	ViewportHeight       int     `json:"viewport_height"`
	OuterWidth           int     `json:"outer_width"`
	OuterHeight          int     `json:"outer_height"`
	InnerWidth           int     `json:"inner_width"`
	InnerHeight          int     `json:"inner_height"`
	ScreenX              int     `json:"screen_x"`
	ScreenY              int     `json:"screen_y"`
	NotificationAPI      bool    `json:"notification_api"`
	PushAPI              bool    `json:"push_api"`
	ClipboardAPI         bool    `json:"clipboard_api"`
	GeolocationAPI       bool    `json:"geolocation_api"`
	WebRTCAPI            bool    `json:"webrtc_api"`
	FetchAPI             bool    `json:"fetch_api"`
	WebSocketAPI         bool    `json:"websocket_api"`
	CryptoAPI            bool    `json:"crypto_api"`
	BatteryAPI           bool    `json:"battery_api"`
	GamepadAPI           bool    `json:"gamepad_api"`
	VibrateAPI           bool    `json:"vibrate_api"`
	AutomationSign       string  `json:"automation_sign"`
	Phantom              bool    `json:"phantom"`
	Nightmare            bool    `json:"nightmare"`
	SeleniumSign         bool    `json:"selenium_sign"`
	HeadlessUA           bool    `json:"headless_ua"`
	ChromeCDC            bool    `json:"chrome_cdc"`
	PermNotif            string  `json:"perm_notif"`
	UserAgentData        string  `json:"user_agent_data"`       // navigator.userAgentData JSON 序列化
	BrowserBrand         string  `json:"browser_brand"`         // 从 userAgentData 中提取的主要品牌
	BrowserVersion       string  `json:"browser_version"`       // 从 userAgentData 中提取的版本号
	IsMobile             bool    `json:"is_mobile"`             // navigator.userAgentData.mobile
	UAMismatch           bool    `json:"ua_mismatch"`           // user-agent 字符串与 userAgentData brands 不匹配
	NavigatorProto       bool    `json:"navigator_proto"`       // navigator 原型链是否标准
	WebGLVendor          string  `json:"webgl_vendor"`          // WEBGL_debug_renderer_info UNMASKED_VENDOR
	CanvasToBlob         bool    `json:"canvas_to_blob"`        // canvas.toBlob 是否可用
	WebGL2Support        bool    `json:"webgl2_support"`        // WebGL2RenderingContext 是否可用
	SVGSupport           bool    `json:"svg_support"`           // SVGElement 是否可用
	MediaDevices         bool    `json:"media_devices"`         // navigator.mediaDevices 是否可用
	SpeechSynthesis      bool    `json:"speech_synthesis"`      // window.speechSynthesis 是否可用
	ServiceWorker        bool    `json:"service_worker"`        // navigator.serviceWorker 是否可用
	CacheAPI             bool    `json:"cache_api"`             // window.caches 是否可用
	WebAssembly          bool    `json:"web_assembly"`          // WebAssembly 是否可用
	SharedWorker         bool    `json:"shared_worker"`         // SharedWorker 是否可用
	BroadcastChannel     bool    `json:"broadcast_channel"`     // BroadcastChannel 是否可用
	PerformanceObserver  bool    `json:"performance_observer"`  // PerformanceObserver 是否可用
	PerformanceMark      bool    `json:"performance_mark"`      // performance.mark 是否可用
	TimingAPIDepth       int     `json:"timing_api_depth"`      // performance.getEntries 条目数量
	PermissionAPI        bool    `json:"permission_api"`        // navigator.permissions 是否可用
	CredentialAPI        bool    `json:"credential_api"`        // navigator.credentials 是否可用
	CSPViolation         bool    `json:"csp_violation"`         // 指纹采集过程中是否发生 CSP 违规
	WebDriverAdvanced    bool    `json:"webdriver_advanced"`    // 多重 webdriver 指标检测
	CDPRuntime           bool    `json:"cdp_runtime"`           // Chrome DevTools Protocol Runtime.evaluate 痕迹
	PuppeteerSign        bool    `json:"puppeteer_sign"`        // Puppeteer 特有痕迹
	PlaywrightSign       bool    `json:"playwright_sign"`       // Playwright 特有痕迹
	ElectronSign         bool    `json:"electron_sign"`         // 是否运行在 Electron 中
	CypressSign          bool    `json:"cypress_sign"`          // Cypress 测试框架痕迹
	ScreenConsistency    bool    `json:"screen_consistency"`    // screen 属性与 window.screen 一致性
	TimezoneConsistency  bool    `json:"timezone_consistency"`  // Intl 时区与 getTimezoneOffset 一致性
	LanguageConsistency  bool    `json:"language_consistency"`  // navigator.language 与 Intl 区域设置一致性
	MathConsistency      bool    `json:"math_consistency"`      // Math 函数特定值跨次一致性
	CSSSupportsCheck     bool    `json:"css_supports_check"`    // CSS.supports 是否可用
	IntersectionObserver bool    `json:"intersection_observer"` // IntersectionObserver 是否可用
	MutationObserver     bool    `json:"mutation_observer"`     // MutationObserver 是否可用
	ResizeObserver       bool    `json:"resize_observer"`       // ResizeObserver 是否可用
	HistoryAPI           bool    `json:"history_api"`           // history.pushState 是否可用
}

/**
 * EnvCheckResult 保存环境指纹验证的结果。
 */
type EnvCheckResult struct {
	Score   int      `json:"score"`   // 0-100，越高越可疑
	Reasons []string `json:"reasons"` // 每个评分贡献的说明
	Pass    bool     `json:"pass"`    // score <= threshold 时为 true
}

/**
 * ValidateEnvFingerprint 分析环境指纹并返回风险评分。
 * 评分 > 50 表示可疑（机器人/自动化）。
 */
func ValidateEnvFingerprint(fp *EnvFingerprint) EnvCheckResult {
	if fp == nil {
		return EnvCheckResult{Score: 100, Reasons: []string{"no fingerprint data"}, Pass: false}
	}

	score := 0
	var reasons []string

	if fp.WebDriver {
		return EnvCheckResult{Score: 100, Reasons: []string{"webdriver=true: automated browser detected"}, Pass: false}
	}

	if fp.AutomationSign != "" {
		return EnvCheckResult{Score: 100, Reasons: []string{"client-side automation detected: " + fp.AutomationSign}, Pass: false}
	}

	if fp.Phantom || fp.Nightmare || fp.SeleniumSign || fp.ChromeCDC {
		return EnvCheckResult{Score: 100, Reasons: []string{"automation framework signatures detected"}, Pass: false}
	}

	if fp.HeadlessUA {
		return EnvCheckResult{Score: 100, Reasons: []string{"HeadlessChrome user-agent detected"}, Pass: false}
	}

	if fp.WebDriverAdvanced {
		return EnvCheckResult{Score: 100, Reasons: []string{"advanced webdriver indicators detected"}, Pass: false}
	}

	if fp.PuppeteerSign {
		return EnvCheckResult{Score: 100, Reasons: []string{"puppeteer automation signatures detected"}, Pass: false}
	}

	if fp.PlaywrightSign {
		return EnvCheckResult{Score: 100, Reasons: []string{"playwright automation signatures detected"}, Pass: false}
	}

	if fp.CypressSign {
		return EnvCheckResult{Score: 100, Reasons: []string{"cypress testing framework detected"}, Pass: false}
	}

	if fp.DevtoolsOpen {
		score += 30
		reasons = append(reasons, "devtools open (+30)")
	}

	if fp.DevtoolsTiming > 100 {
		score += 20
		reasons = append(reasons, "devtools timing anomaly (+20)")
	}

	if fp.CDPRuntime {
		score += 25
		reasons = append(reasons, "Chrome DevTools Protocol runtime detected (+25)")
	}

	if fp.ElectronSign {
		score += 15
		reasons = append(reasons, "Electron environment detected (+15)")
	}

	if !fp.ChromePresent {
		score += 10
		reasons = append(reasons, "chrome object missing (+10)")
	}

	if fp.PluginsCount == 0 {
		score += 15
		reasons = append(reasons, "zero plugins (+15)")
	} else if fp.PluginsCount < 2 {
		score += 5
		reasons = append(reasons, "very few plugins (+5)")
	}

	if fp.Languages == "" || fp.Languages == "undefined" {
		score += 10
		reasons = append(reasons, "no language preference (+10)")
	}

	if fp.CanvasHash == "" || fp.CanvasHash == "0" {
		score += 10
		reasons = append(reasons, "empty canvas hash (+10)")
	}

	if fp.WebGLRenderer == "" {
		score += 10
		reasons = append(reasons, "no WebGL renderer (+10)")
	} else if isSuspiciousRenderer(fp.WebGLRenderer) {
		score += 15
		reasons = append(reasons, "suspicious WebGL renderer (+15)")
	}

	if fp.ScreenWidth == 0 || fp.ScreenHeight == 0 {
		score += 10
		reasons = append(reasons, "zero screen dimensions (+10)")
	}

	if fp.HardwareConcur <= 1 {
		score += 5
		reasons = append(reasons, "low hardware concurrency (+5)")
	}

	if fp.UAMismatch {
		score += 20
		reasons = append(reasons, "user-agent string mismatches userAgentData brands (+20)")
	}

	if !fp.ScreenConsistency {
		score += 15
		reasons = append(reasons, "screen property inconsistency (+15)")
	}

	if !fp.TimezoneConsistency {
		score += 12
		reasons = append(reasons, "timezone inconsistency between Intl and getTimezoneOffset (+12)")
	}

	if !fp.LanguageConsistency {
		score += 10
		reasons = append(reasons, "language inconsistency between navigator and Intl (+10)")
	}

	if !fp.MathConsistency {
		score += 20
		reasons = append(reasons, "Math function output tampered (+20)")
	}

	if fp.ColorDepth == 0 {
		score += 8
		reasons = append(reasons, "zero color depth (+8)")
	}

	if fp.PixelRatio == 0 {
		score += 8
		reasons = append(reasons, "zero pixel ratio (+8)")
	}

	if fp.AudioHash == "" {
		score += 5
		reasons = append(reasons, "no audio fingerprint (+5)")
	}

	if !fp.SessionStorage {
		score += 8
		reasons = append(reasons, "sessionStorage unavailable (+8)")
	}

	if !fp.IndexedDB {
		score += 8
		reasons = append(reasons, "indexedDB unavailable (+8)")
	}

	if !fp.CookieEnabled {
		score += 10
		reasons = append(reasons, "cookies disabled (+10)")
	}

	if fp.TouchSupport && fp.MaxTouchPoints == 0 {
		score += 8
		reasons = append(reasons, "touch support inconsistency (+8)")
	}

	if fp.PlatformStr == "" {
		score += 5
		reasons = append(reasons, "empty platform string (+5)")
	}

	if fp.FontCount == 0 {
		score += 5
		reasons = append(reasons, "zero detectable fonts (+5)")
	}

	if !fp.WebAssembly {
		score += 8
		reasons = append(reasons, "WebAssembly unavailable (+8)")
	}

	if !fp.ServiceWorker {
		score += 5
		reasons = append(reasons, "ServiceWorker unavailable (+5)")
	}

	if !fp.MediaDevices {
		score += 5
		reasons = append(reasons, "MediaDevices unavailable (+5)")
	}

	if !fp.IntersectionObserver && !fp.MutationObserver && !fp.ResizeObserver {
		score += 10
		reasons = append(reasons, "all observers missing (Intersection+Mutation+Resize) (+10)")
	}

	if !fp.WebGL2Support && fp.WebGLRenderer == "" {
		score += 12
		reasons = append(reasons, "no WebGL2 support and no WebGL renderer (+12)")
	}

	if score > 100 {
		score = 100
	}

	return EnvCheckResult{
		Score:   score,
		Reasons: reasons,
		Pass:    score <= 50,
	}
}

/**
 * ParseEnvFingerprint 将 JSON 字符串解析为 EnvFingerprint。
 */
func ParseEnvFingerprint(data string) *EnvFingerprint {
	if data == "" {
		return nil
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &values); err != nil {
		return nil
	}
	typeOfFingerprint := reflect.TypeOf(EnvFingerprint{})
	for i := 0; i < typeOfFingerprint.NumField(); i++ {
		field := typeOfFingerprint.Field(i)
		if field.Type.Kind() != reflect.Int {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		raw, ok := values[name]
		if !ok {
			continue
		}
		value, err := parseJSONInteger(raw, field.Type.Bits())
		if err != nil {
			return nil
		}
		values[name] = json.RawMessage(strconv.FormatInt(value, 10))
	}
	var fp EnvFingerprint
	normalized, err := json.Marshal(values)
	if err != nil || json.Unmarshal(normalized, &fp) != nil {
		return nil
	}
	return &fp
}

// parseJSONInteger 接受 JSON 整数以及数值上等价的浮点表示，例如 24.0。
// 非整数、字符串、布尔值、null 和超出 int 范围的值都会被拒绝。
func parseJSONInteger(raw []byte, bits int) (int64, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return 0, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return 0, fmt.Errorf("trailing JSON value")
		}
		return 0, err
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, fmt.Errorf("not a JSON number")
	}
	if integer, err := strconv.ParseInt(string(number), 10, bits); err == nil {
		return integer, nil
	}
	floatValue, err := strconv.ParseFloat(string(number), 64)
	if err != nil || math.IsNaN(floatValue) || math.IsInf(floatValue, 0) || math.Trunc(floatValue) != floatValue {
		return 0, fmt.Errorf("not an integer")
	}
	if bits == 32 && (floatValue < math.MinInt32 || floatValue > math.MaxInt32) {
		return 0, fmt.Errorf("integer out of range")
	}
	if bits == 64 && (floatValue < -float64(math.MaxInt64) || floatValue >= float64(math.MaxInt64)) {
		return 0, fmt.Errorf("integer out of range")
	}
	return int64(floatValue), nil
}

/**
 * DecryptEnvFingerprint 使用会话绑定密钥解密加密的环境指纹。
 */
/**
 * DecryptEnvFingerprintWithAAD verifies the versioned WASM envelope before
 * parsing it. AAD binds the ciphertext to its server-issued challenge scope.
 */
func DecryptEnvFingerprintWithAAD(encrypted string, sessionKey []byte, aad string) *EnvFingerprint {
	if !strings.HasPrefix(encrypted, envCiphertextPrefix) || len(sessionKey) != envSessionKeySize || aad == "" {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encrypted, envCiphertextPrefix))
	if err != nil {
		return nil
	}
	plaintext, err := envDecrypt(raw, sessionKey, []byte(aad))
	if err != nil || len(plaintext) == 0 || len(plaintext) > 64*1024 {
		return nil
	}
	return ParseEnvFingerprint(string(plaintext))
}

/**
 * GenerateEnvSessionKey 创建一个 32 字节的随机 AES-256-GCM 会话密钥。
 */
func GenerateEnvSessionKey() []byte {
	key := make([]byte, envSessionKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil
	}
	return key
}

/**
 * EnvSessionKeyHex 返回十六进制编码的会话密钥，用于嵌入 JS。
 */
func EnvSessionKeyHex(key []byte) string {
	if len(key) != envSessionKeySize {
		return ""
	}
	return hex.EncodeToString(key)
}

// EnvSessionKeyFromChallengeToken 将 HMAC-SHA256 挑战令牌解码为 AES-256-GCM 密钥。
func EnvSessionKeyFromChallengeToken(token string) []byte {
	key, err := hex.DecodeString(token)
	if err != nil || len(key) != envSessionKeySize {
		return nil
	}
	return key
}

func envDecrypt(ciphertext, key, aad []byte) ([]byte, error) {
	if len(key) != envSessionKeySize {
		return nil, fmt.Errorf("invalid session key length")
	}
	if len(aad) == 0 || len(aad) > 512 {
		return nil, fmt.Errorf("invalid environment AAD")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if gcm.NonceSize() != envNonceSize || len(ciphertext) < envNonceSize+gcm.Overhead() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:envNonceSize], ciphertext[envNonceSize:]
	return gcm.Open(nil, nonce, ct, aad)
}

func isSuspiciousRenderer(renderer string) bool {
	suspicious := []string{
		"SwiftShader",
		"llvmpipe",
		"softpipe",
		"VirtualBox",
		"VMware",
		"Mesa",
		"Google SwiftShader",
	}
	for _, s := range suspicious {
		if envContainsCI(renderer, s) {
			return true
		}
	}
	return false
}

func envContainsCI(s, substr string) bool {
	sl := len(substr)
	if sl == 0 {
		return true
	}
	if len(s) < sl {
		return false
	}
	for i := 0; i <= len(s)-sl; i++ {
		match := true
		for j := 0; j < sl; j++ {
			a, b := s[i+j], substr[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

/**
 * EnvFingerprintAAD creates the authenticated-data binding for a fingerprint
 * envelope. The session/token remains the server authorization root; this
 * binding rejects cross-scope and cross-site ciphertext replay.
 */
func EnvFingerprintAAD(scope, sessionID string, binding ChallengeSessionBinding) string {
	binding = binding.normalized()
	return fmt.Sprintf("owaf-env:%s|%s|%d|%s|%s", EnvFingerprintProtocolVersion, scope, binding.SiteID, binding.Host, binding.Bind) + "|" + sessionID
}

/**
 * EnvCheckJSEncrypted returns a loader which only initializes WASM and carries
 * its opaque encrypted result. Fingerprint collection, canonical JSON encoding,
 * hashing, and AES-256-GCM encryption execute in Rust WASM.
 */
func EnvCheckJSEncrypted(keyHex, aad string) string {
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != envSessionKeySize || aad == "" {
		return ""
	}
	return fmt.Sprintf(envCheckJSTemplate, strconv.Quote(keyHex), strconv.Quote(aad))
}

/**
 * EnvCheckJSPlain emits a non-authorizing WASM collector. It is retained only
 * for BrowserSign telemetry, whose headers cannot establish client identity.
 */
func EnvCheckJSPlain() string {
	return `(function(){
function reportEnvError(err){window.__owaf_env_error=(err&&err.message)||String(err||"environment WASM initialization failed")}
function loadWasm(){
 var cspNonce=(document.currentScript&&document.currentScript.nonce)||"";
 if(window.__owaf_wasm_ready)return window.__owaf_wasm_ready;
 window.__owaf_wasm_ready=new Promise(function(resolve,reject){
  if(typeof WebAssembly==="undefined"){reject(new Error("WebAssembly is unavailable"));return}
  function initialize(){wasm_bindgen({module_or_path:"/__owaf/pow.wasm"}).then(resolve).catch(reject)}
  if(typeof wasm_bindgen!=="undefined"){initialize();return}
  var script=document.createElement("script");script.src="/__owaf/pow_glue.js";if(cspNonce)script.nonce=cspNonce;script.async=true;script.onload=initialize;script.onerror=function(){reject(new Error("WASM glue load failed"))};(document.head||document.documentElement).appendChild(script);
 });
 return window.__owaf_wasm_ready;
}
window.__owaf_env_ready=loadWasm().then(function(){var value=wasm_bindgen.collect_fingerprint();if(!value)throw new Error("WASM fingerprint collection failed");window.__owaf_env=value;return value}).catch(function(err){reportEnvError(err);return ""});
})();`
}

const envCheckJSTemplate = `(function(){
var keyHex=%s,aad=%s,cspNonce=(document.currentScript&&document.currentScript.nonce)||"";
function reportEnvError(err){
  var msg=(err&&err.message)||String(err||"environment WASM initialization failed");
  window.__owaf_env_encrypted="";
  window.__owaf_env_error=msg;
  if(typeof window.__owaf_env_error_callback==="function"){window.__owaf_env_error_callback(msg)}
}
function loadWasm(){
  if(window.__owaf_wasm_ready)return window.__owaf_wasm_ready;
  window.__owaf_wasm_ready=new Promise(function(resolve,reject){
    if(typeof WebAssembly==="undefined"){reject(new Error("WebAssembly is unavailable"));return}
    function initialize(){
      wasm_bindgen({module_or_path:"/__owaf/pow.wasm"}).then(resolve).catch(reject)
    }
    if(typeof wasm_bindgen!=="undefined"){initialize();return}
    var script=document.createElement("script");
    script.src="/__owaf/pow_glue.js";
    if(cspNonce)script.nonce=cspNonce;
    script.async=true;
    script.onload=initialize;
    script.onerror=function(){reject(new Error("WASM glue load failed"))};
    (document.head||document.documentElement).appendChild(script);
  });
  return window.__owaf_wasm_ready;
}
window.__owaf_env_required=true;
window.__owaf_env_ready=loadWasm().then(function(){
  var encrypted=wasm_bindgen.collect_and_encrypt_fingerprint(keyHex,aad);
  if(!encrypted)throw new Error("WASM fingerprint envelope failed");
  window.__owaf_env_encrypted=encrypted;
  return encrypted;
}).catch(function(err){reportEnvError(err);return ""});
})();`
