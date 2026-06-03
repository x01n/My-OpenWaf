package challenge

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// ChainStepType defines the type of a chain challenge step.
type ChainStepType string

const (
	ChainStepEnv     ChainStepType = "env"
	ChainStepPoW     ChainStepType = "pow"
	ChainStepCaptcha ChainStepType = "captcha"
)

// ChainStepConfig defines one step in the chain challenge pipeline.
type ChainStepConfig struct {
	Type        ChainStepType `json:"type"`
	Condition   string        `json:"condition,omitempty"`
	CaptchaType CaptchaType   `json:"captcha_type,omitempty"`
}

// ChainState is the server-side state for an ongoing chain challenge.
type ChainSessionInfo struct {
	ID          string `json:"id"`
	CurrentStep int    `json:"current_step"`
	StepCount   int    `json:"step_count"`
	OriginalURL string `json:"original_url"`
	CreatedAt   string `json:"started_at"`
}

type ChainState struct {
	SessionID   string            `json:"session_id"`
	CurrentStep int               `json:"current_step"`
	Steps       []ChainStepConfig `json:"steps"`
	Scores      map[string]int    `json:"scores"`
	EnvScore    int               `json:"env_score"`
	OriginalURL string            `json:"original_url"`
	Nonce       string            `json:"nonce"`
	CaptchaID   string            `json:"captcha_id"`
	CreatedAt   time.Time         `json:"created_at"`
}

// ChainChallengeManager manages multi-step chain challenges with a state machine.
type ChainChallengeManager struct {
	captcha    *CaptchaManager
	redis      *goredis.Client
	prefix     string
	difficulty int
	steps      []ChainStepConfig
	mu         sync.RWMutex
	states     map[string]*ChainState
}

// NewChainChallengeManager creates a new ChainChallengeManager with default steps.
func NewChainChallengeManager(captcha *CaptchaManager, redis *goredis.Client) *ChainChallengeManager {
	return &ChainChallengeManager{
		captcha:    captcha,
		redis:      redis,
		prefix:     "owaf:chain:",
		difficulty: 4,
		steps:      defaultChainSteps(),
		states:     make(map[string]*ChainState),
	}
}

func defaultChainSteps() []ChainStepConfig {
	return []ChainStepConfig{
		{Type: ChainStepEnv, Condition: "all"},
		{Type: ChainStepPoW, Condition: "all"},
		{Type: ChainStepCaptcha, Condition: "env_score>30"},
	}
}

func normalizeChainSteps(steps []ChainStepConfig) []ChainStepConfig {
	out := make([]ChainStepConfig, 0, len(steps))
	for _, step := range steps {
		switch step.Type {
		case ChainStepEnv, ChainStepPoW:
			step.CaptchaType = ""
			out = append(out, step)
		case ChainStepCaptcha:
			step.CaptchaType = normalizeChainCaptchaType(step.CaptchaType)
			out = append(out, step)
		}
	}
	if len(out) == 0 {
		return defaultChainSteps()
	}
	return out
}

func normalizeChainCaptchaType(t CaptchaType) CaptchaType {
	switch t {
	case CaptchaTypeMath, CaptchaTypeClick, CaptchaTypeSlide, CaptchaTypeRotate:
		return t
	default:
		return CaptchaTypeMath
	}
}

func (cm *ChainChallengeManager) Reconfigure(steps []ChainStepConfig, difficulty int) {
	if difficulty <= 0 {
		difficulty = 4
	}
	cm.mu.Lock()
	cm.steps = normalizeChainSteps(steps)
	cm.difficulty = difficulty
	cm.mu.Unlock()
}

func (cm *ChainChallengeManager) configuredSteps() []ChainStepConfig {
	cm.mu.RLock()
	steps := append([]ChainStepConfig(nil), cm.steps...)
	cm.mu.RUnlock()
	return normalizeChainSteps(steps)
}

func (cm *ChainChallengeManager) difficultyValue() int {
	cm.mu.RLock()
	difficulty := cm.difficulty
	cm.mu.RUnlock()
	if difficulty <= 0 {
		return 4
	}
	return difficulty
}

// StartChain begins a new chain challenge and returns the session ID and HTML for the first step.
func (cm *ChainChallengeManager) StartChain(originalURL string) (string, string) {
	sid := chainGenID()
	state := &ChainState{
		SessionID:   sid,
		CurrentStep: 0,
		Steps:       cm.configuredSteps(),
		Scores:      make(map[string]int),
		OriginalURL: originalURL,
		Nonce:       GeneratePoWNonce(),
		CreatedAt:   time.Now(),
	}
	cm.saveChainState(state)
	return sid, cm.renderStepHTML(state)
}

// ProcessStep handles a step submission and returns (passed, redirectURL, nextHTML).
func (cm *ChainChallengeManager) ProcessStep(sessionID string, formData map[string]string) (bool, string, string) {
	state := cm.loadChainState(sessionID)
	if state == nil {
		return false, "", ""
	}
	if state.CurrentStep >= len(state.Steps) {
		cm.deleteChainState(sessionID)
		return true, state.OriginalURL, ""
	}
	step := state.Steps[state.CurrentStep]
	switch step.Type {
	case ChainStepEnv:
		envFP := formData["env_fp"]
		if envFP != "" {
			var fp EnvFingerprint
			if err := json.Unmarshal([]byte(envFP), &fp); err == nil {
				result := ValidateEnvFingerprint(&fp)
				state.EnvScore = result.Score
				state.Scores["env"] = result.Score
			}
		}
	case ChainStepPoW:
		hash := formData["pow_hash"]
		counterStr := formData["pow_counter"]
		var counter int64
		fmt.Sscanf(counterStr, "%d", &counter)
		if !VerifyPoW(state.Nonce, counter, hash, cm.difficultyValue()) {
			state.Nonce = GeneratePoWNonce()
			cm.saveChainState(state)
			return false, "", cm.renderStepHTML(state)
		}
		state.Scores["pow"] = 0
	case ChainStepCaptcha:
		answer := formData["captcha_answer"]
		if state.CaptchaID == "" || !cm.captcha.VerifyAdvanced(state.CaptchaID, answer) {
			ch, _ := cm.captcha.Generate(normalizeChainCaptchaType(step.CaptchaType))
			if ch != nil {
				state.CaptchaID = ch.SessionID
			}
			cm.saveChainState(state)
			return false, "", cm.renderStepHTML(state)
		}
		state.Scores["captcha"] = 0
	}
	state.CurrentStep++
	for state.CurrentStep < len(state.Steps) {
		ns := state.Steps[state.CurrentStep]
		if cm.shouldRunStep(ns, state) {
			break
		}
		state.CurrentStep++
	}
	if state.CurrentStep >= len(state.Steps) {
		cm.deleteChainState(sessionID)
		return true, state.OriginalURL, ""
	}
	ns := state.Steps[state.CurrentStep]
	if ns.Type == ChainStepPoW {
		state.Nonce = GeneratePoWNonce()
	} else if ns.Type == ChainStepCaptcha {
		ch, _ := cm.captcha.Generate(normalizeChainCaptchaType(ns.CaptchaType))
		if ch != nil {
			state.CaptchaID = ch.SessionID
		}
	}
	cm.saveChainState(state)
	return false, "", cm.renderStepHTML(state)
}

func (cm *ChainChallengeManager) shouldRunStep(step ChainStepConfig, state *ChainState) bool {
	cond := step.Condition
	if cond == "" || cond == "all" {
		return true
	}
	var threshold int
	if n, _ := fmt.Sscanf(cond, "env_score>%d", &threshold); n == 1 {
		return state.EnvScore > threshold
	}
	if n, _ := fmt.Sscanf(cond, "env_score<%d", &threshold); n == 1 {
		return state.EnvScore < threshold
	}
	if n, _ := fmt.Sscanf(cond, "score>%d", &threshold); n == 1 {
		total := 0
		for _, s := range state.Scores {
			total += s
		}
		return total > threshold
	}
	return true
}

func (cm *ChainChallengeManager) renderStepHTML(state *ChainState) string {
	if state.CurrentStep >= len(state.Steps) {
		return ""
	}
	step := state.Steps[state.CurrentStep]
	stepNum := state.CurrentStep + 1
	total := len(state.Steps)

	dots := ""
	for i := 0; i < total; i++ {
		cls := "sd"
		if i < state.CurrentStep {
			cls += " done"
		} else if i == state.CurrentStep {
			cls += " active"
		}
		dots += fmt.Sprintf(`<div class="%s"></div>`, cls)
	}

	header := fmt.Sprintf(chainHdrHTML, stepNum, total)
	var body string
	switch step.Type {
	case ChainStepEnv:
		body = fmt.Sprintf(chainEnvHTML, stepNum, total, dots, EnvCheckJS(), state.SessionID)
	case ChainStepPoW:
		body = fmt.Sprintf(chainPowHTML, stepNum, total, dots, GeneratePoWScript(cm.difficultyValue(), state.Nonce), state.SessionID)
	case ChainStepCaptcha:
		captchaBlock := ""
		ch, _ := cm.captcha.Generate(normalizeChainCaptchaType(step.CaptchaType))
		if ch != nil {
			state.CaptchaID = ch.SessionID
			cm.saveChainState(state)
			captchaBlock = renderChainCaptchaHTML(ch)
		}
		body = fmt.Sprintf(chainCapHTML, stepNum, total, dots, captchaBlock, state.SessionID)
	}
	return header + body + "</div></body></html>"
}

func renderChainCaptchaHTML(ch *CaptchaChallenge) string {
	if ch == nil {
		return `<input type="text" class="ci" id="ans" autocomplete="off">`
	}
	switch CaptchaType(ch.Type) {
	case CaptchaTypeClick:
		return fmt.Sprintf(`<input type="hidden" id="cap-type" value="%s"><div class="img-wrap"><img id="cap-img" src="%s" alt="CAPTCHA"></div><img class="thumb" src="%s" alt="target"><input type="hidden" class="ci" id="ans"><button type="button" class="mini" id="clear-clicks">Clear clicks / 清空点击</button>`, ch.Type, ch.MasterImg, ch.ThumbImg)
	case CaptchaTypeSlide:
		return fmt.Sprintf(`<input type="hidden" id="cap-type" value="%s"><img src="%s" alt="CAPTCHA"><img id="slide-thumb" class="thumb slide-thumb" src="%s" alt="slider"><input type="hidden" class="ci" id="ans"><input type="range" min="0" max="%d" value="0" id="slide-range">`, ch.Type, ch.MasterImg, ch.ThumbImg, firstPositiveInt(ch.Width, 360))
	case CaptchaTypeRotate:
		return fmt.Sprintf(`<input type="hidden" id="cap-type" value="%s"><img id="cap-img" src="%s" alt="CAPTCHA"><img class="thumb" src="%s" alt="target"><input type="hidden" class="ci" id="ans"><input type="range" min="0" max="360" value="0" id="rotate-range">`, ch.Type, ch.MasterImg, ch.ThumbImg)
	default:
		return fmt.Sprintf(`<input type="hidden" id="cap-type" value="%s"><img src="%s" alt="CAPTCHA"><input type="text" class="ci" id="ans" placeholder="%s" autocomplete="off">`, ch.Type, ch.MasterImg, ch.Prompt)
	}
}

const chainHdrHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Verification - Step %d/%d</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,"Helvetica Neue",sans-serif;background:linear-gradient(160deg,#f0fdfa 0%%,#f8fafc 40%%,#f1f5f9 100%%);display:flex;justify-content:center;align-items:center;min-height:100vh}
.ct{background:#fff;border-radius:16px;box-shadow:0 4px 32px rgba(0,0,0,.08),0 1px 4px rgba(0,0,0,.04);padding:48px 40px;max-width:460px;width:92%%;text-align:center}
.chain-icon{font-size:42px;margin-bottom:10px;line-height:1.2}
h1{font-size:1.1rem;font-weight:600;color:#334155;margin-bottom:4px}
.si{color:#64748b;font-size:.8rem;margin-bottom:16px}
.divider{width:48px;height:3px;background:#14b8a6;border-radius:2px;margin:0 auto 20px}
.ps{display:flex;justify-content:center;gap:6px;margin-bottom:24px}
.sd{width:12px;height:12px;border-radius:50%%;background:#e2e8f0;transition:all .3s;border:2px solid transparent}
.sd.active{background:#14b8a6;border-color:#0d9488;box-shadow:0 0 0 3px rgba(20,184,166,.15)}
.sd.done{background:#22c55e;border-color:#16a34a}
.st{color:#64748b;font-size:.8rem;margin-top:16px;min-height:1.2em}
.ci{width:100%%;padding:14px 16px;border:2px solid #e2e8f0;border-radius:10px;font-size:1rem;margin-top:14px;outline:none;transition:border-color .2s,box-shadow .2s;background:#f8fafc}
.ci:focus{border-color:#14b8a6;box-shadow:0 0 0 3px rgba(20,184,166,.12);background:#fff}
.btn{width:100%%;padding:14px;background:linear-gradient(135deg,#14b8a6,#0d9488);color:#fff;border:none;border-radius:10px;font-size:1rem;font-weight:500;cursor:pointer;margin-top:16px;transition:opacity .2s,transform .1s}
.btn:hover{opacity:.92}.btn:active{transform:scale(.98)}
.btn:disabled{background:#cbd5e1;cursor:not-allowed;opacity:.7}
.captcha-box{background:#f8fafc;border-radius:12px;padding:16px;border:1px solid #e2e8f0}
.captcha-box img{max-width:100%%;border-radius:8px;display:block;margin:0 auto}
.img-wrap{position:relative;width:fit-content;margin:0 auto}.dot{position:absolute;transform:translate(-50%%,-50%%);border-radius:999px;background:#14b8a6;color:#fff;font-size:10px;font-weight:700;padding:2px 6px;box-shadow:0 2px 8px rgba(15,118,110,.35)}.mini{border:1px solid #cbd5e1;background:#fff;border-radius:8px;padding:7px 10px;color:#64748b;cursor:pointer}.thumb{max-height:84px;object-fit:contain}.slide-thumb{background:#e2e8f0;padding:6px;transition:transform .12s}input[type=range]{width:100%%;accent-color:#14b8a6}
img{max-width:100%%;border-radius:8px;margin:12px 0}
.pb{width:100%%;height:6px;background:#e2e8f0;border-radius:3px;margin:20px 0;overflow:hidden}
.pf{height:100%%;background:linear-gradient(90deg,#14b8a6,#0d9488);width:10%%;transition:width .4s ease;border-radius:3px}
.footer{margin-top:24px;padding-top:14px;border-top:1px solid #f1f5f9;font-size:.7rem;color:#94a3b8}
</style></head><body><div class="ct">`

const chainEnvHTML = `<div class="chain-icon">&#128270;</div>
<h1>Environment Check / 环境检测</h1>
<p class="si">Step %d of %d</p><div class="divider"></div><div class="ps">%s</div>
<p class="st" id="st">Collecting browser information... / 正在收集浏览器信息...</p>
<div class="footer">Protected by My-OpenWAF</div>
<script>
%s
setTimeout(function(){
var d=window.__owaf_env?JSON.stringify(window.__owaf_env):'{}';
var f=document.createElement('form');f.method='POST';f.action='/__owaf/chain/verify';
var fl={'__waf_chain_session':'%s','__waf_chain_step':'env','__waf_env_fp':d};
for(var k in fl){var i=document.createElement('input');i.type='hidden';i.name=k;i.value=fl[k];f.appendChild(i)}
document.body.appendChild(f);f.submit()},1500);
</script>`

const chainPowHTML = `<div class="chain-icon">&#9881;</div>
<h1>Proof of Work / 工作量证明</h1>
<p class="si">Step %d of %d</p><div class="divider"></div><div class="ps">%s</div>
<div class="pb"><div class="pf" id="pg"></div></div>
<p class="st" id="st">Computing... / 正在计算...</p>
<div class="footer">Protected by My-OpenWAF</div>
<script>
%s
window.__owaf_pow_callback=function(c,h){
document.getElementById('pg').style.width='100%%';
document.getElementById('st').textContent='Complete! / 完成！';
var f=document.createElement('form');f.method='POST';f.action='/__owaf/chain/verify';
var fl={'__waf_chain_session':'%s','__waf_chain_step':'pow','__waf_pow_counter':String(c),'__waf_pow_hash':h};
for(var k in fl){var i=document.createElement('input');i.type='hidden';i.name=k;i.value=fl[k];f.appendChild(i)}
document.body.appendChild(f);f.submit()};
</script>`

const chainCapHTML = `<div class="chain-icon">&#128274;</div>
<h1>CAPTCHA Verification / 验证码验证</h1>
<p class="si">Step %d of %d</p><div class="divider"></div><div class="ps">%s</div>
<div class="captcha-box">%s</div>
<button class="btn" onclick="go()">Submit / 提交</button>
<div class="footer">Protected by My-OpenWAF</div>
<script>
(function(){
var type=(document.getElementById('cap-type')||{}).value||'math';
var answer=document.getElementById('ans');
var img=document.getElementById('cap-img');
if(type==='click'&&img){
  var points=[];
  img.addEventListener('click',function(e){var r=img.getBoundingClientRect();var x=Math.round(((e.clientX-r.left)/r.width)*(img.naturalWidth||r.width));var y=Math.round(((e.clientY-r.top)/r.height)*(img.naturalHeight||r.height));points.push({x:x,y:y});answer.value=JSON.stringify(points);var d=document.createElement('span');d.className='dot';d.textContent=String(points.length);d.style.left=((x/(img.naturalWidth||r.width))*100)+'%%';d.style.top=((y/(img.naturalHeight||r.height))*100)+'%%';img.parentNode.appendChild(d);});
  var clear=document.getElementById('clear-clicks');if(clear){clear.addEventListener('click',function(){points=[];answer.value='';document.querySelectorAll('.dot').forEach(function(n){n.remove();});});}
}
var slide=document.getElementById('slide-range');var thumb=document.getElementById('slide-thumb');
if(type==='slide'&&slide){slide.addEventListener('input',function(){answer.value=JSON.stringify({x:Number(slide.value)});if(thumb){thumb.style.transform='translateX('+slide.value+'px)';}});}
var rotate=document.getElementById('rotate-range');
if(type==='rotate'&&rotate&&img){rotate.addEventListener('input',function(){answer.value=JSON.stringify({angle:Number(rotate.value)});img.style.transform='rotate('+rotate.value+'deg)';});}
})();
function go(){var a=document.getElementById('ans').value.trim();if(!a)return;
var f=document.createElement('form');f.method='POST';f.action='/__owaf/chain/verify';
var fl={'__waf_chain_session':'%s','__waf_chain_step':'captcha','__waf_captcha_answer':a};
for(var k in fl){var i=document.createElement('input');i.type='hidden';i.name=k;i.value=fl[k];f.appendChild(i)}
document.body.appendChild(f);f.submit()}
document.getElementById('ans').addEventListener('keypress',function(e){if(e.key==='Enter')go()});
</script>`

func chainGenID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (cm *ChainChallengeManager) ListSessions() []ChainSessionInfo {
	if cm == nil {
		return nil
	}
	if cm.redis != nil {
		return cm.listRedisSessions()
	}
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	sessions := make([]ChainSessionInfo, 0, len(cm.states))
	for _, state := range cm.states {
		sessions = append(sessions, chainSessionInfoFromState(state))
	}
	return sessions
}

func (cm *ChainChallengeManager) DeleteSession(id string) bool {
	if cm == nil || strings.TrimSpace(id) == "" {
		return false
	}
	if cm.loadChainState(id) == nil {
		return false
	}
	cm.deleteChainState(id)
	return true
}

func (cm *ChainChallengeManager) listRedisSessions() []ChainSessionInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	iter := cm.redis.Scan(ctx, 0, cm.prefix+"*", 100).Iterator()
	sessions := make([]ChainSessionInfo, 0)
	for iter.Next(ctx) {
		data, err := cm.redis.Get(ctx, iter.Val()).Bytes()
		if err != nil {
			continue
		}
		var state ChainState
		if json.Unmarshal(data, &state) != nil {
			continue
		}
		sessions = append(sessions, chainSessionInfoFromState(&state))
	}
	return sessions
}

func chainSessionInfoFromState(state *ChainState) ChainSessionInfo {
	if state == nil {
		return ChainSessionInfo{}
	}
	return ChainSessionInfo{
		ID:          state.SessionID,
		CurrentStep: state.CurrentStep,
		StepCount:   len(state.Steps),
		OriginalURL: state.OriginalURL,
		CreatedAt:   state.CreatedAt.Format(time.RFC3339),
	}
}

func (cm *ChainChallengeManager) saveChainState(state *ChainState) {
	if cm.redis != nil {
		data, _ := json.Marshal(state)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if cm.redis.Set(ctx, cm.prefix+state.SessionID, data, 10*time.Minute).Err() == nil {
			return
		}
	}
	cm.mu.Lock()
	cm.states[state.SessionID] = state
	cm.mu.Unlock()
}

func (cm *ChainChallengeManager) loadChainState(id string) *ChainState {
	if cm.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		data, err := cm.redis.Get(ctx, cm.prefix+id).Bytes()
		if err == nil {
			var s ChainState
			if json.Unmarshal(data, &s) == nil {
				return &s
			}
		}
	}
	cm.mu.RLock()
	s := cm.states[id]
	cm.mu.RUnlock()
	return s
}

func (cm *ChainChallengeManager) deleteChainState(id string) {
	if cm.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cm.redis.Del(ctx, cm.prefix+id)
	}
	cm.mu.Lock()
	delete(cm.states, id)
	cm.mu.Unlock()
}
