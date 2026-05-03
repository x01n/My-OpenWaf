package waf

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	Type      ChainStepType `json:"type"`
	Condition string        `json:"condition,omitempty"`
}

// ChainState is the server-side state for an ongoing chain challenge.
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
		case ChainStepEnv, ChainStepPoW, ChainStepCaptcha:
			out = append(out, step)
		}
	}
	if len(out) == 0 {
		return defaultChainSteps()
	}
	return out
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
		if state.CaptchaID == "" || !cm.captcha.Verify(state.CaptchaID, answer) {
			ch, _ := cm.captcha.Generate(CaptchaTypeMath)
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
		ch, _ := cm.captcha.Generate(CaptchaTypeMath)
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
		ch, _ := cm.captcha.Generate(CaptchaTypeMath)
		if ch != nil {
			state.CaptchaID = ch.SessionID
			cm.saveChainState(state)
			captchaBlock = fmt.Sprintf(`<img src="%s" alt="CAPTCHA"><input type="text" class="ci" id="ans" placeholder="%s" autocomplete="off">`, ch.MasterImg, ch.Prompt)
		}
		body = fmt.Sprintf(chainCapHTML, stepNum, total, dots, captchaBlock, state.SessionID)
	}
	return header + body + "</div></body></html>"
}

const chainHdrHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security - Step %d/%d</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.ct{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.1);padding:40px;max-width:420px;width:90%%;text-align:center}
h1{font-size:18px;color:#1a1a2e;margin-bottom:8px}
.si{color:#666;font-size:13px;margin-bottom:20px}
.ps{display:flex;justify-content:center;gap:8px;margin-bottom:24px}
.sd{width:10px;height:10px;border-radius:50%%;background:#e0e0e0}
.sd.active{background:#4a90d9}.sd.done{background:#27ae60}
.st{color:#666;font-size:13px;margin-top:16px}
.ci{width:100%%;padding:12px;border:2px solid #e0e0e0;border-radius:8px;font-size:16px;margin-top:12px;outline:none}
.ci:focus{border-color:#4a90d9}
.btn{width:100%%;padding:12px;background:#4a90d9;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer;margin-top:16px}
.btn:disabled{background:#ccc;cursor:not-allowed}
img{max-width:100%%;border-radius:8px;margin:12px 0}
.pb{width:100%%;height:4px;background:#e0e0e0;border-radius:2px;margin:20px 0;overflow:hidden}
.pf{height:100%%;background:linear-gradient(90deg,#4a90d9,#7c3aed);width:10%%;transition:width .3s}
</style></head><body><div class="ct">`

const chainEnvHTML = `<h1>Environment Check</h1>
<p class="si">Step %d of %d</p><div class="ps">%s</div>
<p class="st" id="st">Collecting browser info...</p>
<script>
%s
setTimeout(function(){
var d=window.__owaf_env?JSON.stringify(window.__owaf_env):'{}';
var f=document.createElement('form');f.method='POST';f.action='/__owaf/chain/verify';
var fl={'__waf_chain_session':'%s','__waf_chain_step':'env','__waf_env_fp':d};
for(var k in fl){var i=document.createElement('input');i.type='hidden';i.name=k;i.value=fl[k];f.appendChild(i)}
document.body.appendChild(f);f.submit()},1500);
</script>`

const chainPowHTML = `<h1>Proof of Work</h1>
<p class="si">Step %d of %d</p><div class="ps">%s</div>
<div class="pb"><div class="pf" id="pg"></div></div>
<p class="st" id="st">Computing...</p>
<script>
%s
window.__owaf_pow_callback=function(c,h){
document.getElementById('pg').style.width='100%%';
document.getElementById('st').textContent='Done!';
var f=document.createElement('form');f.method='POST';f.action='/__owaf/chain/verify';
var fl={'__waf_chain_session':'%s','__waf_chain_step':'pow','__waf_pow_counter':String(c),'__waf_pow_hash':h};
for(var k in fl){var i=document.createElement('input');i.type='hidden';i.name=k;i.value=fl[k];f.appendChild(i)}
document.body.appendChild(f);f.submit()};
</script>`

const chainCapHTML = `<h1>CAPTCHA Verification</h1>
<p class="si">Step %d of %d</p><div class="ps">%s</div>
%s
<button class="btn" onclick="go()">Submit</button>
<script>
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
