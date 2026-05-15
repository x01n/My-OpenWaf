package waf

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	goredis "github.com/redis/go-redis/v9"
)

// ShieldSession stores the server-side state for a pending shield challenge.
type ShieldSession struct {
	ID          string    `json:"id"`
	Nonce       string    `json:"nonce"`
	Difficulty  int       `json:"difficulty"`
	OriginalURL string    `json:"original_url"`
	EnvKey      []byte    `json:"env_key"` // AES key for env fingerprint encryption
	CreatedAt   time.Time `json:"created_at"`
}

// ShieldManager orchestrates 5-second shield challenges (PoW + env fingerprint).
// Cloudflare-style: user clicks verify → PoW runs in background → auto-submit on success.
type ShieldManager struct {
	captcha    *CaptchaManager
	redis      *goredis.Client
	difficulty int
	prefix     string
	mu         sync.RWMutex
	sessions   map[string]*ShieldSession
}

// NewShieldManager creates a new ShieldManager.
func NewShieldManager(captcha *CaptchaManager, redis *goredis.Client, difficulty int) *ShieldManager {
	if difficulty <= 0 {
		difficulty = 4
	}
	sm := &ShieldManager{
		captcha:    captcha,
		redis:      redis,
		difficulty: difficulty,
		prefix:     "owaf:shield:",
		sessions:   make(map[string]*ShieldSession),
	}
	go sm.cleanupLoop()
	return sm
}

func (sm *ShieldManager) SetDifficulty(difficulty int) {
	if difficulty <= 0 {
		difficulty = 4
	}
	sm.mu.Lock()
	sm.difficulty = difficulty
	sm.mu.Unlock()
}

func (sm *ShieldManager) difficultyValue() int {
	sm.mu.RLock()
	difficulty := sm.difficulty
	sm.mu.RUnlock()
	if difficulty <= 0 {
		return 4
	}
	return difficulty
}

// GenerateChallenge creates a new shield challenge session (no captcha needed).
func (sm *ShieldManager) GenerateChallenge(originalURL string) (*ShieldSession, error) {
	nonce := GeneratePoWNonce()
	sessionID := shieldGenSessionID()
	envKey := GenerateEnvSessionKey()
	session := &ShieldSession{
		ID:          sessionID,
		Nonce:       nonce,
		Difficulty:  sm.difficultyValue(),
		OriginalURL: originalURL,
		EnvKey:      envKey,
		CreatedAt:   time.Now(),
	}
	sm.saveShieldSession(session)
	return session, nil
}

// VerifyChallenge checks PoW + env fingerprint.
func (sm *ShieldManager) VerifyChallenge(sessionID, captchaAnswer string, powCounter int64, powHash, envFPJSON string) (bool, string) {
	session := sm.loadShieldSession(sessionID)
	if session == nil {
		return false, ""
	}
	sm.deleteShieldSession(sessionID)
	// PoW verification is the primary challenge.
	if !VerifyPoW(session.Nonce, powCounter, powHash, session.Difficulty) {
		return false, session.OriginalURL
	}
	// Env fingerprint: decrypt using session-bound key then validate.
	if envFPJSON != "" {
		var fp *EnvFingerprint
		if len(session.EnvKey) > 0 {
			fp = DecryptEnvFingerprint(envFPJSON, session.EnvKey)
		} else {
			fp = ParseEnvFingerprint(envFPJSON)
		}
		if fp != nil {
			result := ValidateEnvFingerprint(fp)
			if !result.Pass {
				return false, session.OriginalURL
			}
		}
	}
	return true, session.OriginalURL
}

// WriteShieldChallengeResponse renders the Cloudflare-style shield HTML page.
func (sm *ShieldManager) WriteShieldChallengeResponse(c *app.RequestContext, reqID, originalURL string, statusCode int) {
	prepareChallengeResponseHeaders(c, reqID, "shield_challenge")
	session, err := sm.GenerateChallenge(originalURL)
	if err != nil {
		c.String(500, "shield challenge generation failed")
		return
	}
	powScript := GeneratePoWWASMScript(session.Difficulty, session.Nonce)
	envJS := EnvCheckJSEncrypted(EnvSessionKeyHex(session.EnvKey))

	html := fmt.Sprintf(shieldPageHTML, session.ID, envJS, powScript)
	c.Data(statusCode, "text/html; charset=utf-8", []byte(html))
}

const shieldPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,"Helvetica Neue",sans-serif;background:linear-gradient(160deg,#f0fdfa 0%%,#f8fafc 40%%,#f1f5f9 100%%);display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:16px;box-shadow:0 4px 32px rgba(0,0,0,.08),0 1px 4px rgba(0,0,0,.04);padding:48px 40px;max-width:440px;width:92%%;text-align:center}
.shield-icon{font-size:48px;margin-bottom:16px;line-height:1.2}
h1{font-size:1.15rem;font-weight:600;color:#334155;margin-bottom:4px}
.sub{color:#64748b;font-size:.875rem;margin-bottom:8px}
.divider{width:48px;height:3px;background:#14b8a6;border-radius:2px;margin:16px auto 24px}
.cb-wrap{display:flex;align-items:center;gap:14px;padding:18px 20px;border:2px solid #e2e8f0;border-radius:12px;margin-bottom:20px;cursor:pointer;transition:border-color .2s,background .2s;user-select:none}
.cb-wrap:hover{border-color:#14b8a6;background:#f0fdfa}
.cb-wrap.checking{border-color:#14b8a6;background:#f0fdfa;cursor:default}
.cb-wrap.done{border-color:#22c55e;background:#f0fdf4}
.cb-wrap.fail{border-color:#ef4444;background:#fef2f2}
.cb{width:24px;height:24px;border:2px solid #cbd5e1;border-radius:6px;display:flex;align-items:center;justify-content:center;transition:all .3s;flex-shrink:0}
.cb-wrap.checking .cb{border-color:#14b8a6;animation:spin 1s linear infinite}
.cb-wrap.done .cb{border-color:#22c55e;background:#22c55e}
.cb-wrap.fail .cb{border-color:#ef4444;background:#ef4444}
@keyframes spin{from{transform:rotate(0)}to{transform:rotate(360deg)}}
.cb svg{width:14px;height:14px;opacity:0;transition:opacity .2s}
.cb-wrap.done .cb svg{opacity:1}
.cb-label{font-size:.95rem;color:#334155;font-weight:500}
.cb-wrap.checking .cb-label{color:#0d9488}
.cb-wrap.done .cb-label{color:#16a34a}
.cb-wrap.fail .cb-label{color:#ef4444}
.status{color:#64748b;font-size:.8rem;margin-top:12px;min-height:1.2em}
.footer{margin-top:24px;padding-top:14px;border-top:1px solid #f1f5f9;font-size:.7rem;color:#94a3b8}
.spinner{width:18px;height:18px;border:2px solid #14b8a6;border-top-color:transparent;border-radius:50%%;animation:spin .8s linear infinite;display:none}
.cb-wrap.checking .spinner{display:block}
.cb-wrap.checking .cb-box{display:none}
.retry{display:none;margin-top:12px;padding:10px 20px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;font-size:.85rem;color:#334155;cursor:pointer}
.retry:hover{background:#f0fdfa;border-color:#14b8a6}
</style>
</head>
<body>
<div class="card">
<div class="shield-icon">&#128737;</div>
<h1>Checking your browser / 正在验证您的浏览器</h1>
<p class="sub">This process is automatic. Please wait...</p>
<p class="sub">此过程自动完成，请稍候...</p>
<div class="divider"></div>
<div class="cb-wrap" id="cbw">
<div class="cb" id="cb"><span class="cb-box">&#9744;</span><span class="spinner"></span><svg viewBox="0 0 14 14" fill="none"><path d="M2 7l3.5 3.5L12 4" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
<span class="cb-label" id="cbl">Verify you are human / 验证您是真人</span>
</div>
<p class="status" id="st"></p>
<button class="retry" id="retry" onclick="location.reload()">Retry / 重试</button>
<div class="footer">Protected by My-OpenWAF</div>
</div>
<script>
(function(){
var sid="%s",pc=0,ph="",env="",solving=false,solved=false;
%s
var cbw=document.getElementById('cbw'),cbl=document.getElementById('cbl'),st=document.getElementById('st'),retry=document.getElementById('retry');

function detectDevTools(){
var w=window.outerWidth-window.innerWidth>160;
var h=window.outerHeight-window.innerHeight>160;
if(w||h)return true;
var dt=false;
try{var el=new Image();Object.defineProperty(el,'id',{get:function(){dt=true}});console.log(el);console.clear()}catch(e){}
if(dt)return true;
if(window.__owaf_env&&window.__owaf_env.devtools_open)return true;
if(window.__owaf_env&&window.__owaf_env.devtools_timing>50)return true;
return false;
}

function detectAutomation(){
if(navigator.webdriver)return 'webdriver';
if(!window.chrome&&/Chrome/.test(navigator.userAgent))return 'chrome_mismatch';
if(window.__nightmare)return 'nightmare';
if(window.callPhantom||window._phantom)return 'phantomjs';
if(window.__selenium_unwrapped||window.__webdriver_evaluate||document.__selenium_unwrapped)return 'selenium';
if(navigator.plugins&&navigator.plugins.length===0&&navigator.userAgent.indexOf('HeadlessChrome')!==-1)return 'headless';
return null;
}

function blockEnv(msg){
solving=false;solved=true;
cbw.className='cb-wrap fail';
cbl.textContent='Environment error / 环境异常';
st.textContent=msg;
retry.style.display='inline-block';
}

// Continuous environment monitoring — check every 2 seconds during solving.
var envMonitor=setInterval(function(){
if(solved)return clearInterval(envMonitor);
if(detectDevTools()){
clearInterval(envMonitor);
blockEnv('Developer tools detected. Please close DevTools and refresh. / 检测到开发者工具，请关闭后刷新页面。');
}
},2000);

// Auto-start verification after page loads (Cloudflare-style).
// Wait a short delay for env fingerprint collection to complete.
setTimeout(function(){
if(solving||solved)return;
var autoReason=detectAutomation();
if(autoReason){blockEnv('Automated browser detected ('+autoReason+'). / 检测到自动化浏览器环境。');return;}
if(detectDevTools()){blockEnv('Developer tools detected. Please close DevTools and refresh. / 检测到开发者工具，请关闭后刷新页面。');return;}
startVerify();
},800);

// Also allow manual click to restart if auto-start didn't trigger
cbw.addEventListener('click',function(){
if(solving||solved)return;
var autoReason=detectAutomation();
if(autoReason){blockEnv('Automated browser detected ('+autoReason+'). / 检测到自动化浏览器环境。');return;}
if(detectDevTools()){blockEnv('Developer tools detected. Please close DevTools and refresh. / 检测到开发者工具，请关闭后刷新页面。');return;}
startVerify();
});

function startVerify(){
solving=true;
cbw.className='cb-wrap checking';
cbl.textContent='Verifying... / 验证中...';
st.textContent='Computing challenge...';
setTimeout(function(){if(window.__owaf_env_encrypted)env=window.__owaf_env_encrypted},300);
%s
}

window.__owaf_pow_callback=function(c,h){
// Final env check before submitting
if(detectDevTools()){
blockEnv('Developer tools opened during verification. / 验证过程中检测到开发者工具。');
return;
}
var autoReason=detectAutomation();
if(autoReason){blockEnv('Automated browser detected ('+autoReason+'). / 检测到自动化浏览器环境。');return;}
pc=c;ph=h;solved=true;
clearInterval(envMonitor);
cbw.className='cb-wrap done';
cbl.textContent='Verified / 验证通过';
st.textContent='Redirecting...';
setTimeout(function(){if(window.__owaf_env_encrypted)env=window.__owaf_env_encrypted;submitResult()},200);
};

window.__owaf_pow_error=function(msg){
solved=true;
cbw.className='cb-wrap fail';
cbl.textContent='Verification failed / 验证失败';
st.textContent='Error: '+(msg||'unknown');
retry.style.display='inline-block';
};

setTimeout(function(){
if(!solved&&solving){
solved=true;
cbw.className='cb-wrap fail';
cbl.textContent='Timeout / 超时';
st.textContent='Verification took too long. Please retry.';
retry.style.display='inline-block';
}
},30000);

function submitResult(){
if(!env&&window.__owaf_env_encrypted)env=window.__owaf_env_encrypted;
var f=document.createElement('form');f.method='POST';f.action='/__owaf/shield/verify';
var d={'__waf_shield_session':sid,'__waf_captcha_answer':'','__waf_pow_counter':String(pc),'__waf_pow_hash':ph,'__waf_env_fp':env};
for(var k in d){var i=document.createElement('input');i.type='hidden';i.name=k;i.value=d[k];f.appendChild(i)}
document.body.appendChild(f);f.submit();
}
})();
</script>
</body>
</html>`

func (sm *ShieldManager) saveShieldSession(s *ShieldSession) {
	if sm.redis != nil {
		data, _ := json.Marshal(s)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if sm.redis.Set(ctx, sm.prefix+s.ID, data, 5*time.Minute).Err() == nil {
			return
		}
	}
	sm.mu.Lock()
	sm.sessions[s.ID] = s
	sm.mu.Unlock()
}

func (sm *ShieldManager) loadShieldSession(id string) *ShieldSession {
	if sm.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		data, err := sm.redis.Get(ctx, sm.prefix+id).Bytes()
		if err == nil {
			var s ShieldSession
			if json.Unmarshal(data, &s) == nil {
				return &s
			}
		}
	}
	sm.mu.RLock()
	s := sm.sessions[id]
	sm.mu.RUnlock()
	return s
}

func (sm *ShieldManager) deleteShieldSession(id string) {
	if sm.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		sm.redis.Del(ctx, sm.prefix+id)
	}
	sm.mu.Lock()
	delete(sm.sessions, id)
	sm.mu.Unlock()
}

func (sm *ShieldManager) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		sm.mu.Lock()
		now := time.Now()
		for id, s := range sm.sessions {
			if now.Sub(s.CreatedAt) > 5*time.Minute {
				delete(sm.sessions, id)
			}
		}
		sm.mu.Unlock()
	}
}

func shieldGenSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
