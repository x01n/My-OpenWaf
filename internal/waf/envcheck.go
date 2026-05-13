package waf

import (
	"encoding/json"
)

// EnvFingerprint represents the client environment data collected via JavaScript.
type EnvFingerprint struct {
	WebDriver      bool   `json:"webdriver"`
	ChromePresent  bool   `json:"chrome_present"`
	PluginsCount   int    `json:"plugins_count"`
	Languages      string `json:"languages"`
	DevtoolsOpen   bool   `json:"devtools_open"`
	CanvasHash     string `json:"canvas_hash"`
	WebGLRenderer  string `json:"webgl_renderer"`
	ScreenWidth    int    `json:"screen_width"`
	ScreenHeight   int    `json:"screen_height"`
	TimezoneOffset int    `json:"timezone_offset"`
	TouchSupport   bool   `json:"touch_support"`
	HardwareConcur int    `json:"hardware_concurrency"`
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

	// WebDriver detection (strongest signal)
	if fp.WebDriver {
		score += 40
		reasons = append(reasons, "webdriver detected (+40)")
	}

	// Chrome object missing in Chrome browser
	if !fp.ChromePresent {
		score += 10
		reasons = append(reasons, "chrome object missing (+10)")
	}

	// Very few or no plugins (headless browsers typically have 0)
	if fp.PluginsCount == 0 {
		score += 15
		reasons = append(reasons, "zero plugins (+15)")
	} else if fp.PluginsCount < 2 {
		score += 5
		reasons = append(reasons, "very few plugins (+5)")
	}

	// No language preference
	if fp.Languages == "" || fp.Languages == "undefined" {
		score += 10
		reasons = append(reasons, "no language preference (+10)")
	}

	// DevTools open (suspicious for automated interaction)
	if fp.DevtoolsOpen {
		score += 5
		reasons = append(reasons, "devtools open (+5)")
	}

	// Empty canvas hash (headless/blocked)
	if fp.CanvasHash == "" || fp.CanvasHash == "0" {
		score += 10
		reasons = append(reasons, "empty canvas hash (+10)")
	}

	// Suspicious WebGL renderer strings
	if fp.WebGLRenderer == "" {
		score += 10
		reasons = append(reasons, "no WebGL renderer (+10)")
	} else if isSuspiciousRenderer(fp.WebGLRenderer) {
		score += 15
		reasons = append(reasons, "suspicious WebGL renderer (+15)")
	}

	// Unrealistic screen size
	if fp.ScreenWidth == 0 || fp.ScreenHeight == 0 {
		score += 10
		reasons = append(reasons, "zero screen dimensions (+10)")
	}

	// Low hardware concurrency (VMs/containers often have 1-2)
	if fp.HardwareConcur <= 1 {
		score += 5
		reasons = append(reasons, "low hardware concurrency (+5)")
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

// isSuspiciousRenderer checks for known bot/headless renderer strings.
func isSuspiciousRenderer(renderer string) bool {
	suspicious := []string{
		"SwiftShader",
		"llvmpipe",
		"softpipe",
		"VirtualBox",
		"VMware",
		"Mesa",
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

// EnvCheckJS returns JavaScript code that collects environment fingerprint data
// and stores it in a hidden form field or global variable.
func EnvCheckJS() string {
	return `
(function(){
var fp={};
try{fp.webdriver=!!navigator.webdriver}catch(e){fp.webdriver=false}
try{fp.chrome_present=!!window.chrome}catch(e){fp.chrome_present=false}
try{fp.plugins_count=navigator.plugins?navigator.plugins.length:0}catch(e){fp.plugins_count=0}
try{fp.languages=navigator.languages?navigator.languages.join(','):navigator.language||''}catch(e){fp.languages=''}
try{
var t1=performance.now();debugger;var t2=performance.now();
fp.devtools_open=(t2-t1)>100;
}catch(e){fp.devtools_open=false}
try{
var c=document.createElement('canvas');c.width=200;c.height=50;
var ctx=c.getContext('2d');
ctx.textBaseline='top';ctx.font='14px Arial';ctx.fillText('WAF-FP-2026',2,2);
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
try{fp.screen_width=screen.width;fp.screen_height=screen.height}catch(e){fp.screen_width=0;fp.screen_height=0}
try{fp.timezone_offset=new Date().getTimezoneOffset()}catch(e){fp.timezone_offset=0}
try{fp.touch_support='ontouchstart' in window||navigator.maxTouchPoints>0}catch(e){fp.touch_support=false}
try{fp.hardware_concurrency=navigator.hardwareConcurrency||0}catch(e){fp.hardware_concurrency=0}
window.__owaf_env=fp;
window.__envFingerprint=JSON.stringify(fp);
var input=document.getElementById('__waf_env_fp');
if(input)input.value=window.__envFingerprint;
})();`
}
