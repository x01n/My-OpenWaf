package waf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// EnvFingerprint represents the client environment data collected via JavaScript.
type EnvFingerprint struct {
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
	// Automation detection signals
	AutomationSign string `json:"automation_sign"` // non-empty if automation detected client-side
	Phantom        bool   `json:"phantom"`         // window.callPhantom or window._phantom
	Nightmare      bool   `json:"nightmare"`       // window.__nightmare
	SeleniumSign   bool   `json:"selenium_sign"`   // __selenium_unwrapped etc.
	HeadlessUA     bool   `json:"headless_ua"`     // HeadlessChrome in UA
	ChromeCDC      bool   `json:"chrome_cdc"`      // cdc_ property on document (chromedriver)
	PermNotif      string `json:"perm_notif"`      // Notification.permission
}

// EnvCheckResult holds the validation outcome.
type EnvCheckResult struct {
	Score   int      `json:"score"`   // 0-100, higher = more suspicious
	Reasons []string `json:"reasons"` // explanation of each score contribution
	Pass    bool     `json:"pass"`    // true if score <= threshold
}

// ValidateEnvFingerprint analyzes the environment fingerprint and returns a risk score.
// Score > 50 is considered suspicious (bot/automation).
func ValidateEnvFingerprint(fp *EnvFingerprint) EnvCheckResult {
	if fp == nil {
		return EnvCheckResult{Score: 100, Reasons: []string{"no fingerprint data"}, Pass: false}
	}

	score := 0
	var reasons []string

	// ── Instant-fail signals (definitive automation indicators) ──

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

	if fp.DevtoolsOpen {
		score += 30
		reasons = append(reasons, "devtools open (+30)")
	}

	if fp.DevtoolsTiming > 100 {
		score += 20
		reasons = append(reasons, "devtools timing anomaly (+20)")
	}

	// ── Strong signals ──

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

	// ── New enhanced signals ──

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

	// Touch support inconsistency: claims touch but max_touch_points is 0
	if fp.TouchSupport && fp.MaxTouchPoints == 0 {
		score += 8
		reasons = append(reasons, "touch support inconsistency (+8)")
	}

	// No platform string is suspicious
	if fp.PlatformStr == "" {
		score += 5
		reasons = append(reasons, "empty platform string (+5)")
	}

	// Font count: real browsers usually have 10+ fonts detectable
	if fp.FontCount == 0 {
		score += 5
		reasons = append(reasons, "zero detectable fonts (+5)")
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

// ParseEnvFingerprint parses a JSON string into an EnvFingerprint.
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

// DecryptEnvFingerprint decrypts an encrypted env fingerprint using the session-bound key.
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

// GenerateEnvSessionKey creates a random 16-byte key for env fingerprint encryption.
func GenerateEnvSessionKey() []byte {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b
}

// EnvSessionKeyHex returns the hex-encoded session key for embedding in JS.
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

// EnvCheckJS returns JavaScript code that collects environment fingerprint data (plain mode).
func EnvCheckJS() string {
	return envCheckJSWithKey("")
}

// EnvCheckJSEncrypted returns the env collection JS with encryption using the given hex key.
func EnvCheckJSEncrypted(keyHex string) string {
	return envCheckJSWithKey(keyHex)
}

func envCheckJSWithKey(keyHex string) string {
	if keyHex == "" {
		return envCheckJSPlain()
	}
	return fmt.Sprintf(`
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
fp.webgl_renderer=di?gl.getParameter(di.UNMASKED_RENDERER_WEBGL):gl.getParameter(gl.RENDERER)}
else{fp.webgl_renderer=''}
}catch(e){fp.webgl_renderer=''}
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
window.__owaf_env=fp;
var raw=JSON.stringify(fp);
var keyHex="%s";
if(keyHex&&window.crypto&&window.crypto.subtle){
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
})();`, keyHex)
}

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
window.__owaf_env=fp;
window.__owaf_env_encrypted=JSON.stringify(fp);
})();`
}
