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
	CaptchaID   string    `json:"captcha_id"`
	OriginalURL string    `json:"original_url"`
	CreatedAt   time.Time `json:"created_at"`
}

// ShieldManager orchestrates 5-second shield challenges (CAPTCHA + PoW + env fingerprint).
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

// GenerateChallenge creates a new shield challenge session.
func (sm *ShieldManager) GenerateChallenge(originalURL string) (*ShieldSession, *CaptchaChallenge, error) {
	captchaChallenge, err := sm.captcha.Generate(CaptchaTypeMath)
	if err != nil {
		return nil, nil, err
	}
	nonce := GeneratePoWNonce()
	sessionID := shieldGenSessionID()
	session := &ShieldSession{
		ID:          sessionID,
		Nonce:       nonce,
		Difficulty:  sm.difficulty,
		CaptchaID:   captchaChallenge.SessionID,
		OriginalURL: originalURL,
		CreatedAt:   time.Now(),
	}
	sm.saveShieldSession(session)
	return session, captchaChallenge, nil
}

// VerifyChallenge checks all three components (captcha + PoW + env).
func (sm *ShieldManager) VerifyChallenge(sessionID, captchaAnswer string, powCounter int64, powHash, envFPJSON string) (bool, string) {
	session := sm.loadShieldSession(sessionID)
	if session == nil {
		return false, ""
	}
	sm.deleteShieldSession(sessionID)
	if !sm.captcha.Verify(session.CaptchaID, captchaAnswer) {
		return false, session.OriginalURL
	}
	if !VerifyPoW(session.Nonce, powCounter, powHash, session.Difficulty) {
		return false, session.OriginalURL
	}
	if envFPJSON != "" {
		var fp EnvFingerprint
		if err := json.Unmarshal([]byte(envFPJSON), &fp); err == nil {
			result := ValidateEnvFingerprint(&fp)
			if !result.Pass {
				return false, session.OriginalURL
			}
		}
	}
	return true, session.OriginalURL
}

// WriteShieldChallengeResponse renders the 5-second shield HTML page.
func (sm *ShieldManager) WriteShieldChallengeResponse(c *app.RequestContext, reqID, originalURL string) {
	session, captchaChallenge, err := sm.GenerateChallenge(originalURL)
	if err != nil {
		c.String(500, "shield challenge generation failed")
		return
	}
	powScript := GeneratePoWScript(session.Difficulty, session.Nonce)
	envJS := EnvCheckJS()

	html := fmt.Sprintf(shieldPageHTML, captchaChallenge.MasterImg, captchaChallenge.Prompt, session.ID, envJS, powScript)
	c.Data(403, "text/html; charset=utf-8", []byte(html))
}

const shieldPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.sc{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.1);padding:40px;max-width:420px;width:90%%;text-align:center}
.si{font-size:48px;margin-bottom:16px}
h1{font-size:20px;color:#1a1a2e;margin-bottom:8px}
.sub{color:#666;font-size:14px;margin-bottom:24px}
.ca{margin:20px 0}.ca img{max-width:100%%;border-radius:8px;border:1px solid #e0e0e0}
.ci{width:100%%;padding:12px;border:2px solid #e0e0e0;border-radius:8px;font-size:16px;margin-top:12px;outline:none}
.ci:focus{border-color:#4a90d9}
.pb{width:100%%;height:4px;background:#e0e0e0;border-radius:2px;margin:20px 0;overflow:hidden}
.pf{height:100%%;background:linear-gradient(90deg,#4a90d9,#7c3aed);width:0%%;transition:width .3s}
.st{color:#666;font-size:13px;margin-top:12px}
.sb{width:100%%;padding:12px;background:#4a90d9;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer;margin-top:16px}
.sb:hover{background:#357abd}.sb:disabled{background:#ccc;cursor:not-allowed}
</style>
</head>
<body>
<div class="sc">
<div class="si">&#128737;</div>
<h1>Verifying your connection</h1>
<p class="sub">Please complete the security check to continue</p>
<div class="ca"><img src="%s" alt="CAPTCHA"><input type="text" class="ci" id="ca" placeholder="%s" autocomplete="off"></div>
<div class="pb"><div class="pf" id="pg"></div></div>
<p class="st" id="st">Waiting for input...</p>
<button class="sb" id="btn" disabled>Verify</button>
</div>
<script>
(function(){
var sid="%s",pd=false,pc=0,ph="",env="";
%s
setTimeout(function(){if(window.__owaf_env)env=JSON.stringify(window.__owaf_env)},500);
var pg=document.getElementById('pg'),st=document.getElementById('st'),btn=document.getElementById('btn'),inp=document.getElementById('ca');
st.textContent='Computing proof of work...';pg.style.width='10%%';
%s
window.__owaf_pow_callback=function(c,h){pd=true;pc=c;ph=h;pg.style.width='80%%';st.textContent='PoW done. Enter answer.';chk()};
inp.addEventListener('input',function(){chk()});
function chk(){if(pd&&inp.value.trim()!==''){btn.disabled=false;pg.style.width='100%%';st.textContent='Ready'}}
btn.addEventListener('click',function(){
btn.disabled=true;st.textContent='Submitting...';
if(!env&&window.__owaf_env)env=JSON.stringify(window.__owaf_env);
var f=document.createElement('form');f.method='POST';f.action='/__owaf/shield/verify';
var d={'__waf_shield_session':sid,'__waf_captcha_answer':inp.value.trim(),'__waf_pow_counter':String(pc),'__waf_pow_hash':ph,'__waf_env_fp':env};
for(var k in d){var i=document.createElement('input');i.type='hidden';i.name=k;i.value=d[k];f.appendChild(i)}
document.body.appendChild(f);f.submit()});
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
