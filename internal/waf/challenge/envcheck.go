package challenge

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

/**
 * EnvFingerprint 表示通过 JavaScript 收集的客户端环境指纹数据。
 * 涵盖浏览器 API、渲染/图形、媒体/音频、存储/API、性能/计时、
 * 权限/安全、自动化检测、环境一致性、DOM/CSS 等多维度检测点。
 */
type EnvFingerprint struct {
	// ── 基础浏览器属性 ──
	WebDriver      bool    `json:"webdriver"`
	ChromePresent  bool    `json:"chrome_present"`
	PluginsCount   int     `json:"plugins_count"`
	Languages      string  `json:"languages"`
	DevtoolsOpen   bool    `json:"devtools_open"`
	CanvasHash     string  `json:"canvas_hash"`
	WebGLRenderer  string  `json:"webgl_renderer"`
	ScreenWidth    int     `json:"screen_width"`
	ScreenHeight   int     `json:"screen_height"`
	TimezoneOffset int     `json:"timezone_offset"`
	TouchSupport   bool    `json:"touch_support"`
	HardwareConcur int     `json:"hardware_concurrency"`
	ColorDepth     int     `json:"color_depth"`
	PixelRatio     float64 `json:"pixel_ratio"`
	AudioHash      string  `json:"audio_hash"`
	FontCount      int     `json:"font_count"`
	SessionStorage bool    `json:"session_storage"`
	IndexedDB      bool    `json:"indexed_db"`
	PDFViewer      bool    `json:"pdf_viewer"`
	DoNotTrack     string  `json:"do_not_track"`
	MaxTouchPoints int     `json:"max_touch_points"`
	ConnectionType string  `json:"connection_type"`
	DevtoolsTiming float64 `json:"devtools_timing"`
	PlatformStr    string  `json:"platform"`
	CookieEnabled  bool    `json:"cookie_enabled"`
	MemoryGB       float64 `json:"device_memory"`

	// ── 自动化检测信号（原有） ──
	AutomationSign string `json:"automation_sign"`
	Phantom        bool   `json:"phantom"`
	Nightmare      bool   `json:"nightmare"`
	SeleniumSign   bool   `json:"selenium_sign"`
	HeadlessUA     bool   `json:"headless_ua"`
	ChromeCDC      bool   `json:"chrome_cdc"`
	PermNotif      string `json:"perm_notif"`

	// ── Navigator/Browser API（CH-UA 客户端提示） ──
	UserAgentData  string `json:"user_agent_data"` // navigator.userAgentData JSON 序列化
	BrowserBrand   string `json:"browser_brand"`   // 从 userAgentData 中提取的主要品牌
	BrowserVersion string `json:"browser_version"` // 从 userAgentData 中提取的版本号
	IsMobile       bool   `json:"is_mobile"`       // navigator.userAgentData.mobile
	UAMismatch     bool   `json:"ua_mismatch"`     // user-agent 字符串与 userAgentData brands 不匹配
	NavigatorProto bool   `json:"navigator_proto"` // navigator 原型链是否标准

	// ── 渲染/图形 ──
	WebGLVendor   string `json:"webgl_vendor"`   // WEBGL_debug_renderer_info UNMASKED_VENDOR
	CanvasToBlob  bool   `json:"canvas_to_blob"` // canvas.toBlob 是否可用
	WebGL2Support bool   `json:"webgl2_support"` // WebGL2RenderingContext 是否可用
	SVGSupport    bool   `json:"svg_support"`    // SVGElement 是否可用

	// ── 媒体/音频 ──
	MediaDevices    bool `json:"media_devices"`    // navigator.mediaDevices 是否可用
	SpeechSynthesis bool `json:"speech_synthesis"` // window.speechSynthesis 是否可用

	// ── 存储/API ──
	ServiceWorker    bool `json:"service_worker"`    // navigator.serviceWorker 是否可用
	CacheAPI         bool `json:"cache_api"`         // window.caches 是否可用
	WebAssembly      bool `json:"web_assembly"`      // WebAssembly 是否可用
	SharedWorker     bool `json:"shared_worker"`     // SharedWorker 是否可用
	BroadcastChannel bool `json:"broadcast_channel"` // BroadcastChannel 是否可用

	// ── 性能/计时 ──
	PerformanceObserver bool `json:"performance_observer"` // PerformanceObserver 是否可用
	PerformanceMark     bool `json:"performance_mark"`     // performance.mark 是否可用
	TimingAPIDepth      int  `json:"timing_api_depth"`     // performance.getEntries 条目数量

	// ── 权限/安全 ──
	PermissionAPI bool `json:"permission_api"` // navigator.permissions 是否可用
	CredentialAPI bool `json:"credential_api"` // navigator.credentials 是否可用
	CSPViolation  bool `json:"csp_violation"`  // 指纹采集过程中是否发生 CSP 违规

	// ── 高级自动化检测 ──
	WebDriverAdvanced bool `json:"webdriver_advanced"` // 多重 webdriver 指标检测
	CDPRuntime        bool `json:"cdp_runtime"`        // Chrome DevTools Protocol Runtime.evaluate 痕迹
	PuppeteerSign     bool `json:"puppeteer_sign"`     // Puppeteer 特有痕迹
	PlaywrightSign    bool `json:"playwright_sign"`    // Playwright 特有痕迹
	ElectronSign      bool `json:"electron_sign"`      // 是否运行在 Electron 中
	CypressSign       bool `json:"cypress_sign"`       // Cypress 测试框架痕迹

	// ── 环境一致性 ──
	ScreenConsistency   bool `json:"screen_consistency"`   // screen 属性与 window.screen 一致性
	TimezoneConsistency bool `json:"timezone_consistency"` // Intl 时区与 getTimezoneOffset 一致性
	LanguageConsistency bool `json:"language_consistency"` // navigator.language 与 Intl 区域设置一致性
	MathConsistency     bool `json:"math_consistency"`     // Math 函数特定值跨次一致性

	// ── DOM/CSS ──
	CSSSupportsCheck     bool `json:"css_supports_check"`    // CSS.supports 是否可用
	IntersectionObserver bool `json:"intersection_observer"` // IntersectionObserver 是否可用
	MutationObserver     bool `json:"mutation_observer"`     // MutationObserver 是否可用
	ResizeObserver       bool `json:"resize_observer"`       // ResizeObserver 是否可用
	HistoryAPI           bool `json:"history_api"`           // history.pushState 是否可用
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

	// ── 即时失败信号（确定性自动化指标） ──

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

	// ── 高级自动化检测（即时失败） ──

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

	// ── DevTools 信号 ──

	if fp.DevtoolsOpen {
		score += 30
		reasons = append(reasons, "devtools open (+30)")
	}

	if fp.DevtoolsTiming > 100 {
		score += 20
		reasons = append(reasons, "devtools timing anomaly (+20)")
	}

	// ── CDP / Electron 信号 ──

	if fp.CDPRuntime {
		score += 25
		reasons = append(reasons, "Chrome DevTools Protocol runtime detected (+25)")
	}

	if fp.ElectronSign {
		score += 15
		reasons = append(reasons, "Electron environment detected (+15)")
	}

	// ── 强信号 ──

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

	// ── UA 一致性信号 ──

	if fp.UAMismatch {
		score += 20
		reasons = append(reasons, "user-agent string mismatches userAgentData brands (+20)")
	}

	// ── 环境一致性信号 ──

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

	// ── 增强的基础信号 ──

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

	// ── 存储/API 信号 ──

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

	// ── Observer 组合信号 ──

	if !fp.IntersectionObserver && !fp.MutationObserver && !fp.ResizeObserver {
		score += 10
		reasons = append(reasons, "all observers missing (Intersection+Mutation+Resize) (+10)")
	}

	// ── WebGL2 + WebGL Renderer 组合信号 ──

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
	var fp EnvFingerprint
	if err := json.Unmarshal([]byte(data), &fp); err != nil {
		return nil
	}
	return &fp
}

/**
 * DecryptEnvFingerprint 使用会话绑定密钥解密加密的环境指纹。
 */
func DecryptEnvFingerprint(encrypted string, sessionKey []byte) *EnvFingerprint {
	if encrypted == "" || len(sessionKey) == 0 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil {
		return ParseEnvFingerprint(encrypted)
	}
	plaintext, err := envDecrypt(raw, sessionKey)
	if err != nil {
		return ParseEnvFingerprint(encrypted)
	}
	var fp EnvFingerprint
	if json.Unmarshal(plaintext, &fp) != nil {
		return nil
	}
	return &fp
}

/**
 * GenerateEnvSessionKey 创建一个 16 字节的随机密钥用于环境指纹加密。
 */
func GenerateEnvSessionKey() []byte {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b
}

/**
 * EnvSessionKeyHex 返回十六进制编码的会话密钥，用于嵌入 JS。
 */
func EnvSessionKeyHex(key []byte) string {
	return hex.EncodeToString(key)
}

func envDecrypt(ciphertext, key []byte) ([]byte, error) {
	h := sha256.Sum256(key)
	block, err := aes.NewCipher(h[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns+1 {
		return nil, fmt.Errorf("too short")
	}
	nonce, ct := ciphertext[:ns], ciphertext[ns:]
	return gcm.Open(nil, nonce, ct, nil)
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
 * EnvCheckJS 返回收集环境指纹数据的 JavaScript 代码（明文模式）。
 */
func EnvCheckJS() string {
	return envCheckJSWithKey("")
}

/**
 * EnvCheckJSEncrypted 返回使用给定十六进制密钥加密的环境采集 JS。
 */
func EnvCheckJSEncrypted(keyHex string) string {
	return envCheckJSWithKey(keyHex)
}

func envCheckJSWithKey(keyHex string) string {
	if keyHex == "" {
		return envCheckJSPlain()
	}
	js := fmt.Sprintf(envCheckJSTemplate, keyHex)
	fpVar := "_" + hex.EncodeToString(func() []byte { b := make([]byte, 3); rand.Read(b); return b }())
	rawVar := "_" + hex.EncodeToString(func() []byte { b := make([]byte, 3); rand.Read(b); return b }())
	khVar := "_" + hex.EncodeToString(func() []byte { b := make([]byte, 3); rand.Read(b); return b }())
	r := strings.NewReplacer(
		"var fp=", "var "+fpVar+"=",
		"fp.", fpVar+".",
		"(fp)", "("+fpVar+")",
		"=fp;", "="+fpVar+";",
		"(fp,", "("+fpVar+",",
		"var raw=", "var "+rawVar+"=",
		"(raw,", "("+rawVar+",",
		"(raw)", "("+rawVar+")",
		"var keyHex=", "var "+khVar+"=",
		"if(keyHex", "if("+khVar,
		",keyHex)", ","+khVar+")",
	)
	return r.Replace(js)
}

const envCheckJSTemplate = `
(function(){
var fp={};
try{fp.webdriver=!!navigator.webdriver}catch(e){fp.webdriver=false}
try{fp.chrome_present=!!window.chrome}catch(e){fp.chrome_present=false}
try{fp.plugins_count=navigator.plugins?navigator.plugins.length:0}catch(e){fp.plugins_count=0}
try{fp.languages=navigator.languages?navigator.languages.join(','):navigator.language||''}catch(e){fp.languages=''}
try{fp.platform=navigator.platform||''}catch(e){fp.platform=''}
try{fp.cookie_enabled=!!navigator.cookieEnabled}catch(e){fp.cookie_enabled=false}
try{fp.do_not_track=navigator.doNotTrack||''}catch(e){fp.do_not_track=''}
try{fp.pdf_viewer=!!navigator.pdfViewerEnabled}catch(e){fp.pdf_viewer=false}
try{fp.device_memory=navigator.deviceMemory||0}catch(e){fp.device_memory=0}
try{fp.max_touch_points=navigator.maxTouchPoints||0}catch(e){fp.max_touch_points=0}
try{fp.color_depth=screen.colorDepth||0}catch(e){fp.color_depth=0}
try{fp.pixel_ratio=window.devicePixelRatio||0}catch(e){fp.pixel_ratio=0}
try{fp.screen_width=screen.width;fp.screen_height=screen.height}catch(e){fp.screen_width=0;fp.screen_height=0}
try{fp.timezone_offset=new Date().getTimezoneOffset()}catch(e){fp.timezone_offset=0}
try{fp.touch_support='ontouchstart' in window||navigator.maxTouchPoints>0}catch(e){fp.touch_support=false}
try{fp.hardware_concurrency=navigator.hardwareConcurrency||0}catch(e){fp.hardware_concurrency=0}
try{fp.session_storage=!!window.sessionStorage}catch(e){fp.session_storage=false}
try{fp.indexed_db=!!window.indexedDB}catch(e){fp.indexed_db=false}
try{var c=navigator.connection||navigator.mozConnection;fp.connection_type=c?c.effectiveType||'':''}catch(e){fp.connection_type=''}
try{
var c=document.createElement('canvas');c.width=200;c.height=50;
var ctx=c.getContext('2d');
ctx.textBaseline='top';ctx.font='14px Arial';ctx.fillText('WAF-FP-2026',2,2);
ctx.font='12px monospace';ctx.fillText('abcdefg',60,20);
var d=c.toDataURL();var h=0;
for(var i=0;i<d.length;i++){h=((h<<5)-h)+d.charCodeAt(i);h|=0}
fp.canvas_hash=h.toString();
}catch(e){fp.canvas_hash=''}
try{
var gl=document.createElement('canvas').getContext('webgl');
if(gl){var di=gl.getExtension('WEBGL_debug_renderer_info');
fp.webgl_renderer=di?gl.getParameter(di.UNMASKED_RENDERER_WEBGL):gl.getParameter(gl.RENDERER);
fp.webgl_vendor=di?gl.getParameter(di.UNMASKED_VENDOR_WEBGL):gl.getParameter(gl.VENDOR)}
else{fp.webgl_renderer='';fp.webgl_vendor=''}
}catch(e){fp.webgl_renderer='';fp.webgl_vendor=''}
try{
var actx=new(window.AudioContext||window.webkitAudioContext)();
var osc=actx.createOscillator();var an=actx.createAnalyser();
var gain=actx.createGain();gain.gain.value=0;
osc.connect(an);an.connect(gain);gain.connect(actx.destination);
osc.start(0);var buf=new Float32Array(an.frequencyBinCount);
an.getFloatFrequencyData(buf);osc.stop();actx.close();
var ah=0;for(var i=0;i<buf.length;i++){ah=((ah<<5)-ah)+Math.round(buf[i]*100);ah|=0}
fp.audio_hash=ah.toString();
}catch(e){fp.audio_hash=''}
try{
var testFonts=['monospace','serif','sans-serif','Arial','Courier New','Georgia','Times New Roman','Verdana','Trebuchet MS','Palatino','Impact','Comic Sans MS','Lucida Console'];
var baseFonts=['monospace','sans-serif','serif'];
var testStr='mmmmmmmmmmlli';var testSize='72px';
var cEl=document.createElement('span');cEl.style.position='absolute';cEl.style.left='-9999px';
cEl.style.fontSize=testSize;cEl.textContent=testStr;document.body.appendChild(cEl);
var baseW={};for(var i=0;i<baseFonts.length;i++){cEl.style.fontFamily=baseFonts[i];baseW[baseFonts[i]]=cEl.offsetWidth}
var fc=0;for(var i=0;i<testFonts.length;i++){for(var j=0;j<baseFonts.length;j++){cEl.style.fontFamily='"'+testFonts[i]+'",'+baseFonts[j];if(cEl.offsetWidth!==baseW[baseFonts[j]]){fc++;break}}}
document.body.removeChild(cEl);fp.font_count=fc;
}catch(e){fp.font_count=0}
try{
var devT=0;var el=new Image();Object.defineProperty(el,'id',{get:function(){devT++}});
console.log(el);console.clear();
fp.devtools_open=devT>0;
var t1=performance.now();for(var x=0;x<100;x++){console.log(x)}console.clear();
fp.devtools_timing=performance.now()-t1;
}catch(e){fp.devtools_open=false;fp.devtools_timing=0}
try{fp.phantom=!!(window.callPhantom||window._phantom)}catch(e){fp.phantom=false}
try{fp.nightmare=!!window.__nightmare}catch(e){fp.nightmare=false}
try{fp.selenium_sign=!!(window.__selenium_unwrapped||window.__webdriver_evaluate||document.__selenium_unwrapped||window.__fxdriver_unwrapped)}catch(e){fp.selenium_sign=false}
try{fp.headless_ua=navigator.userAgent.indexOf('HeadlessChrome')!==-1}catch(e){fp.headless_ua=false}
try{var cdcFound=false;for(var k in document){if(k.match(/^cdc_/)||k.match(/^\$cdc_/)){cdcFound=true;break}}fp.chrome_cdc=cdcFound}catch(e){fp.chrome_cdc=false}
try{fp.perm_notif=typeof Notification!=='undefined'?Notification.permission:''}catch(e){fp.perm_notif=''}
try{fp.automation_sign='';if(navigator.webdriver)fp.automation_sign='webdriver';else if(window.__nightmare)fp.automation_sign='nightmare';else if(window.callPhantom||window._phantom)fp.automation_sign='phantom';else if(window.__selenium_unwrapped||document.__selenium_unwrapped)fp.automation_sign='selenium'}catch(e){}
try{
if(navigator.userAgentData){
var ua=navigator.userAgentData;
fp.is_mobile=!!ua.mobile;
var brands=ua.brands||[];
fp.user_agent_data=JSON.stringify({brands:brands,mobile:ua.mobile,platform:ua.platform||''});
var primary='';var ver='';
for(var i=0;i<brands.length;i++){var b=brands[i];if(b.brand&&b.brand.indexOf('Not')===0)continue;if(b.brand&&b.brand.indexOf('Chromium')!==-1)continue;primary=b.brand;ver=b.version;break}
if(!primary&&brands.length>0){for(var i=0;i<brands.length;i++){if(brands[i].brand&&brands[i].brand.indexOf('Chromium')!==-1){primary=brands[i].brand;ver=brands[i].version;break}}}
fp.browser_brand=primary||'';fp.browser_version=ver||'';
var uaStr=navigator.userAgent||'';
var mismatch=true;
for(var i=0;i<brands.length;i++){if(brands[i].brand&&uaStr.indexOf(brands[i].brand)!==-1){mismatch=false;break}}
if(uaStr.indexOf('Chrome')!==-1){for(var i=0;i<brands.length;i++){if(brands[i].brand&&(brands[i].brand.indexOf('Chrom')!==-1||brands[i].brand.indexOf('Google')!==-1)){mismatch=false;break}}}
fp.ua_mismatch=mismatch;
}else{fp.user_agent_data='';fp.browser_brand='';fp.browser_version='';fp.is_mobile=false;fp.ua_mismatch=false}
}catch(e){fp.user_agent_data='';fp.browser_brand='';fp.browser_version='';fp.is_mobile=false;fp.ua_mismatch=false}
try{
var np=Object.getPrototypeOf(navigator);
fp.navigator_proto=np===Navigator.prototype;
}catch(e){fp.navigator_proto=true}
try{
var tc=document.createElement('canvas');
fp.canvas_to_blob=typeof tc.toBlob==='function';
}catch(e){fp.canvas_to_blob=false}
try{fp.webgl2_support=typeof WebGL2RenderingContext!=='undefined'}catch(e){fp.webgl2_support=false}
try{fp.svg_support=typeof SVGElement!=='undefined'}catch(e){fp.svg_support=false}
try{fp.media_devices=!!(navigator.mediaDevices)}catch(e){fp.media_devices=false}
try{fp.speech_synthesis=!!window.speechSynthesis}catch(e){fp.speech_synthesis=false}
try{fp.service_worker=!!navigator.serviceWorker}catch(e){fp.service_worker=false}
try{fp.cache_api=!!window.caches}catch(e){fp.cache_api=false}
try{fp.web_assembly=typeof WebAssembly!=='undefined'}catch(e){fp.web_assembly=false}
try{fp.shared_worker=typeof SharedWorker!=='undefined'}catch(e){fp.shared_worker=false}
try{fp.broadcast_channel=typeof BroadcastChannel!=='undefined'}catch(e){fp.broadcast_channel=false}
try{fp.performance_observer=typeof PerformanceObserver!=='undefined'}catch(e){fp.performance_observer=false}
try{fp.performance_mark=!!(performance&&typeof performance.mark==='function')}catch(e){fp.performance_mark=false}
try{fp.timing_api_depth=(performance&&typeof performance.getEntries==='function')?performance.getEntries().length:0}catch(e){fp.timing_api_depth=0}
try{fp.permission_api=!!(navigator.permissions)}catch(e){fp.permission_api=false}
try{fp.credential_api=!!(navigator.credentials)}catch(e){fp.credential_api=false}
try{
var cspV=false;
document.addEventListener('securitypolicyviolation',function(){cspV=true},{once:true});
fp.csp_violation=cspV;
}catch(e){fp.csp_violation=false}
try{
var wda=false;
if(navigator.webdriver)wda=true;
if(!wda){try{if(Object.getOwnPropertyDescriptor(Navigator.prototype,'webdriver')){var desc=Object.getOwnPropertyDescriptor(Navigator.prototype,'webdriver');if(desc&&desc.get&&desc.get.toString().indexOf('native code')===-1)wda=true}}catch(e2){}}
if(!wda&&window.chrome){try{if(window.chrome.runtime&&window.chrome.runtime.id===undefined&&window.chrome.app===undefined)wda=true}catch(e2){}}
if(!wda){try{if(document.documentElement.getAttribute('webdriver')!==null)wda=true}catch(e2){}}
if(!wda){try{var ks=['__webdriver_evaluate','__selenium_evaluate','__fxdriver_evaluate','__driver_unwrapped','__webdriver_unwrapped','__driver_evaluate','__selenium_unwrapped','__fxdriver_unwrapped','_Selenium_IDE_Recorder','_selenium','calledSelenium','_WEBDRIVER_ELEM_CACHE','ChromeDriverw','driver-hierarchical-name'];for(var i=0;i<ks.length;i++){if(window[ks[i]]!==undefined){wda=true;break}}}catch(e2){}}
fp.webdriver_advanced=wda;
}catch(e){fp.webdriver_advanced=false}
try{
var cdp=false;
if(window.Runtime&&typeof window.Runtime.evaluate==='function')cdp=true;
if(!cdp){try{if(window.__cdp_runtime||window.cdc_adoQpoasnfa76pfcZLmcfl_Array||window.cdc_adoQpoasnfa76pfcZLmcfl_Promise)cdp=true}catch(e2){}}
if(!cdp){try{var perfE=performance.getEntries();for(var i=0;i<perfE.length;i++){if(perfE[i].name&&perfE[i].name.indexOf('devtools')!==-1){cdp=true;break}}}catch(e2){}}
fp.cdp_runtime=cdp;
}catch(e){fp.cdp_runtime=false}
try{
var pp=false;
if(window.__pptr_tmp_binding||window.__puppeteer_evaluation_script__)pp=true;
if(!pp){try{if(navigator.webdriver&&window.chrome&&!window.chrome.app)pp=true}catch(e2){}}
fp.puppeteer_sign=pp;
}catch(e){fp.puppeteer_sign=false}
try{
var pw=false;
if(window.__playwright||window.__pw_manual)pw=true;
if(!pw){try{if(window._playwrightInstance||document.__playwright_target__)pw=true}catch(e2){}}
fp.playwright_sign=pw;
}catch(e){fp.playwright_sign=false}
try{
fp.electron_sign=!!(window.process&&window.process.versions&&window.process.versions.electron);
}catch(e){fp.electron_sign=false}
try{
fp.cypress_sign=!!(window.Cypress||window.__cypress);
}catch(e){fp.cypress_sign=false}
try{
var sw=screen.width;var sh=screen.height;
var ww=window.screen.width;var wh=window.screen.height;
fp.screen_consistency=(sw===ww&&sh===wh);
}catch(e){fp.screen_consistency=true}
try{
var intlTz='';
try{intlTz=Intl.DateTimeFormat().resolvedOptions().timeZone}catch(e2){}
var jsOff=new Date().getTimezoneOffset();
var consistent=true;
if(intlTz){
var d=new Date();var fmt=new Intl.DateTimeFormat('en-US',{timeZone:intlTz,timeZoneName:'shortOffset'});
var parts=fmt.formatToParts(d);var offStr='';
for(var i=0;i<parts.length;i++){if(parts[i].type==='timeZoneName'){offStr=parts[i].value;break}}
if(offStr){
var m=offStr.match(/GMT([+-]?)(\d+)(?::(\d+))?/);
if(m){var sign=m[1]==='-'?1:-1;var hrs=parseInt(m[2],10);var mins=parseInt(m[3]||'0',10);var intlOff=sign*(hrs*60+mins);if(Math.abs(intlOff-jsOff)>60)consistent=false}
}}
fp.timezone_consistency=consistent;
}catch(e){fp.timezone_consistency=true}
try{
var navLang=(navigator.language||'').split('-')[0].toLowerCase();
var intlLang='';
try{intlLang=Intl.DateTimeFormat().resolvedOptions().locale.split('-')[0].toLowerCase()}catch(e2){}
fp.language_consistency=(!navLang||!intlLang||navLang===intlLang);
}catch(e){fp.language_consistency=true}
try{
var t1=Math.tan(-1e300);var c1=Math.cos(21*Math.LN2);var t2=Math.tan(-1e300);var c2=Math.cos(21*Math.LN2);
fp.math_consistency=(t1===t2&&c1===c2&&isFinite(c1));
}catch(e){fp.math_consistency=true}
try{fp.css_supports_check=typeof CSS!=='undefined'&&typeof CSS.supports==='function'}catch(e){fp.css_supports_check=false}
try{fp.intersection_observer=typeof IntersectionObserver!=='undefined'}catch(e){fp.intersection_observer=false}
try{fp.mutation_observer=typeof MutationObserver!=='undefined'}catch(e){fp.mutation_observer=false}
try{fp.resize_observer=typeof ResizeObserver!=='undefined'}catch(e){fp.resize_observer=false}
try{fp.history_api=!!(window.history&&typeof window.history.pushState==='function')}catch(e){fp.history_api=false}
window.__owaf_env=fp;
var raw=JSON.stringify(fp);
var keyHex="%s";
if(keyHex&&typeof wasm_bindgen!=='undefined'&&typeof wasm_bindgen.encrypt_env_data==='function'){
window.__owaf_env_encrypted=wasm_bindgen.encrypt_env_data(raw,keyHex);
}else if(keyHex&&window.crypto&&window.crypto.subtle){
var keyBytes=new Uint8Array(keyHex.length/2);
for(var i=0;i<keyHex.length;i+=2)keyBytes[i/2]=parseInt(keyHex.substr(i,2),16);
crypto.subtle.importKey('raw',keyBytes,{name:'AES-GCM'},false,['encrypt']).then(function(key){
var iv=crypto.getRandomValues(new Uint8Array(12));
var enc=new TextEncoder();
return crypto.subtle.encrypt({name:'AES-GCM',iv:iv},key,enc.encode(raw)).then(function(ct){
var buf=new Uint8Array(iv.length+ct.byteLength);
buf.set(iv);buf.set(new Uint8Array(ct),iv.length);
var b64='';var bytes=buf;
for(var i=0;i<bytes.length;i+=3){
var a=bytes[i],b=bytes[i+1]||0,c2=bytes[i+2]||0;
var t=(a<<16)|(b<<8)|c2;
var chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
b64+=chars[(t>>18)&63]+chars[(t>>12)&63];
if(i+1<bytes.length)b64+=chars[(t>>6)&63];
if(i+2<bytes.length)b64+=chars[t&63];
}
window.__owaf_env_encrypted=b64;
});
}).catch(function(){window.__owaf_env_encrypted='';});
}else{window.__owaf_env_encrypted='';}
})();`

func envCheckJSPlain() string {
	return `
(function(){
var fp={};
try{fp.webdriver=!!navigator.webdriver}catch(e){fp.webdriver=false}
try{fp.chrome_present=!!window.chrome}catch(e){fp.chrome_present=false}
try{fp.plugins_count=navigator.plugins?navigator.plugins.length:0}catch(e){fp.plugins_count=0}
try{fp.languages=navigator.languages?navigator.languages.join(','):navigator.language||''}catch(e){fp.languages=''}
try{fp.devtools_open=false;fp.devtools_timing=0}catch(e){}
try{fp.color_depth=screen.colorDepth||0}catch(e){fp.color_depth=0}
try{fp.pixel_ratio=window.devicePixelRatio||0}catch(e){fp.pixel_ratio=0}
try{fp.screen_width=screen.width;fp.screen_height=screen.height}catch(e){fp.screen_width=0;fp.screen_height=0}
try{fp.timezone_offset=new Date().getTimezoneOffset()}catch(e){fp.timezone_offset=0}
try{fp.touch_support='ontouchstart' in window||navigator.maxTouchPoints>0}catch(e){fp.touch_support=false}
try{fp.hardware_concurrency=navigator.hardwareConcurrency||0}catch(e){fp.hardware_concurrency=0}
try{fp.canvas_hash='';fp.webgl_renderer='';fp.audio_hash='';fp.font_count=0}catch(e){}
try{fp.session_storage=!!window.sessionStorage}catch(e){fp.session_storage=false}
try{fp.indexed_db=!!window.indexedDB}catch(e){fp.indexed_db=false}
try{fp.cookie_enabled=!!navigator.cookieEnabled}catch(e){fp.cookie_enabled=false}
try{fp.platform=navigator.platform||''}catch(e){fp.platform=''}
try{fp.max_touch_points=navigator.maxTouchPoints||0}catch(e){fp.max_touch_points=0}
try{fp.webgl_vendor='';fp.canvas_to_blob=false;fp.webgl2_support=false;fp.svg_support=false}catch(e){}
try{fp.user_agent_data='';fp.browser_brand='';fp.browser_version='';fp.is_mobile=false;fp.ua_mismatch=false;fp.navigator_proto=true}catch(e){}
try{fp.media_devices=false;fp.speech_synthesis=false}catch(e){}
try{fp.service_worker=false;fp.cache_api=false;fp.web_assembly=typeof WebAssembly!=='undefined';fp.shared_worker=false;fp.broadcast_channel=false}catch(e){}
try{fp.performance_observer=false;fp.performance_mark=false;fp.timing_api_depth=0}catch(e){}
try{fp.permission_api=false;fp.credential_api=false;fp.csp_violation=false}catch(e){}
try{fp.webdriver_advanced=false;fp.cdp_runtime=false;fp.puppeteer_sign=false;fp.playwright_sign=false;fp.electron_sign=false;fp.cypress_sign=false}catch(e){}
try{fp.screen_consistency=true;fp.timezone_consistency=true;fp.language_consistency=true;fp.math_consistency=true}catch(e){}
try{fp.css_supports_check=false;fp.intersection_observer=false;fp.mutation_observer=false;fp.resize_observer=false;fp.history_api=false}catch(e){}
window.__owaf_env=fp;
window.__owaf_env_encrypted=JSON.stringify(fp);
})();`
}
