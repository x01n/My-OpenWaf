package challenge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	goredis "github.com/redis/go-redis/v9"
)

// ShieldConfig 定义 5s 盾的高级配置。
type ShieldConfig struct {
	Difficulty           int  `json:"difficulty"`             // PoW 难度（前导零数量）
	TimeoutSecs          int  `json:"timeout_secs"`           // 验证超时时间（秒）
	AutoStartDelay       int  `json:"auto_start_delay"`       // 自动启动延迟（毫秒）
	MaxRetries           int  `json:"max_retries"`            // 最大重试次数
	EnvStrictness        int  `json:"env_strictness"`         // 环境检测严格度 (0=宽松, 1=标准, 2=严格)
	RequireHTTP2         bool `json:"require_http2"`          // 要求客户端支持 HTTP/2
	RequireHTTP3         bool `json:"require_http3"`          // 要求客户端支持 HTTP/3 (QUIC)
	AllowHTTP1           bool `json:"allow_http1"`            // 是否允许 HTTP/1.x
	EnableJSChallenge    bool `json:"enable_js_challenge"`    // 启用 JS 挑战验证
	EnableEnvCheck       bool `json:"enable_env_check"`       // 启用环境指纹检测
	EnableDevToolsDetect bool `json:"enable_devtools_detect"` // 启用开发者工具检测
	EnableBehaviorCheck  bool `json:"enable_behavior_check"`  // 启用行为心率采样（随环境指纹评分）
}

// DefaultShieldConfig 返回默认的 Shield 配置。
func DefaultShieldConfig() ShieldConfig {
	return ShieldConfig{
		Difficulty:           4,
		TimeoutSecs:          30,
		AutoStartDelay:       800,
		MaxRetries:           3,
		EnvStrictness:        1,
		RequireHTTP2:         false,
		RequireHTTP3:         false,
		AllowHTTP1:           true,
		EnableJSChallenge:    true,
		EnableEnvCheck:       true,
		EnableDevToolsDetect: true,
		EnableBehaviorCheck:  false,
	}
}

func shieldProtocolValue(raw string) string {
	protocol := normalizeShieldProtocol(raw)
	if protocol == "" {
		return "http/1.1"
	}
	return protocol
}

func normalizeShieldProtocol(raw string) string {
	protocol := strings.ToLower(strings.TrimSpace(raw))
	switch protocol {
	case "http/2.0", "h2":
		return "h2"
	case "http/3.0", "h3":
		return "h3"
	case "http/1.0", "http/1.1", "http", "https":
		return "http/1.1"
	default:
		return ""
	}
}

func shieldProtocolAllowed(cfg ShieldConfig, requestProtocol string) bool {
	protocol := shieldProtocolValue(requestProtocol)
	if cfg.RequireHTTP2 && cfg.RequireHTTP3 {
		if protocol != "h2" && protocol != "h3" {
			return false
		}
	} else if cfg.RequireHTTP2 {
		if protocol != "h2" {
			return false
		}
	} else if cfg.RequireHTTP3 {
		if protocol != "h3" {
			return false
		}
	}
	if !cfg.AllowHTTP1 && protocol == "http/1.1" {
		return false
	}
	return true
}

// ShieldSession stores the server-side state for a pending shield challenge.
type ShieldSession struct {
	ChallengeSessionBinding
	ID                   string    `json:"id"`
	Nonce                string    `json:"nonce"`
	Difficulty           int       `json:"difficulty"`
	TimeoutSecs          int       `json:"timeout_secs"`
	EnvStrictness        int       `json:"env_strictness"`
	EnableEnvCheck       bool      `json:"enable_env_check"`
	EnableBehaviorCheck  bool      `json:"enable_behavior_check"`
	EnvConfigFrozen      bool      `json:"env_config_frozen"`
	RequireHTTP2         bool      `json:"require_http2"`
	RequireHTTP3         bool      `json:"require_http3"`
	AllowHTTP1           bool      `json:"allow_http1"`
	ProtocolConfigFrozen bool      `json:"protocol_config_frozen"`
	OriginalURL          string    `json:"original_url"`
	RequestProtocol      string    `json:"request_protocol"`
	EnvKey               []byte    `json:"env_key"`   // 32-byte session master key (first 16 bytes feed SM4-GCM)
	ClientIP             string    `json:"client_ip"` // 签发请求的客户端 IP（方案 B：只读评分源）
	CreatedAt            time.Time `json:"created_at"`
}

func (s *ShieldSession) sessionTTL() time.Duration {
	if s.TimeoutSecs > 0 {
		return time.Duration(s.TimeoutSecs) * time.Second
	}
	// 强制化语义：缺超时字段的会话按立即过期处置（签发侧恒写 TimeoutSecs>0）。
	return 0
}

func (s *ShieldSession) expiredAt(now time.Time) bool {
	return now.Sub(s.CreatedAt) >= s.sessionTTL()
}

func (s *ShieldSession) hasFrozenConfig() bool {
	if s == nil || !s.EnvConfigFrozen || !s.ProtocolConfigFrozen {
		return false
	}
	if s.EnvStrictness < 0 || s.EnvStrictness > 2 {
		return false
	}
	if normalizeShieldProtocol(s.RequestProtocol) == "" {
		return false
	}
	return !s.EnableEnvCheck || len(s.EnvKey) == envSessionKeySize
}

func decodeShieldSession(data []byte) *ShieldSession {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return nil
	}
	for _, field := range []string{
		"env_strictness",
		"enable_env_check",
		"enable_behavior_check",
		"env_config_frozen",
		"require_http2",
		"require_http3",
		"allow_http1",
		"protocol_config_frozen",
		"request_protocol",
	} {
		raw, ok := fields[field]
		if !ok || string(raw) == "null" {
			return nil
		}
	}
	var session ShieldSession
	if json.Unmarshal(data, &session) != nil || !session.hasFrozenConfig() {
		return nil
	}
	return &session
}

// ShieldManager orchestrates 5-second shield challenges (PoW + env fingerprint).
// Cloudflare-style: user clicks verify -> PoW runs in background -> auto-submit on success.
type ShieldManager struct {
	captcha   *CaptchaManager
	redis     *goredis.Client
	config    ShieldConfig
	prefix    string
	ipHistory func(ip string) (violations int64, banned bool)
	geoAttr   func(ip string) (geoScore int, geoReasons []string)
	done      chan struct{}
	once      sync.Once
	mu        sync.RWMutex
	sessions  map[string]*ShieldSession
}

// NewShieldManager creates a new ShieldManager.
func NewShieldManager(captcha *CaptchaManager, redis *goredis.Client, difficulty int) *ShieldManager {
	cfg := DefaultShieldConfig()
	if difficulty > 0 {
		cfg.Difficulty = ClampPoWDifficulty(difficulty)
	}
	sm := &ShieldManager{
		captcha:  captcha,
		redis:    redis,
		config:   cfg,
		prefix:   "owaf:shield:",
		done:     make(chan struct{}),
		sessions: make(map[string]*ShieldSession),
	}
	go sm.cleanupLoop()
	return sm
}

func (sm *ShieldManager) Close() {
	sm.once.Do(func() { close(sm.done) })
}

func (sm *ShieldManager) SetIPHistory(fn func(ip string) (violations int64, banned bool)) {
	if sm == nil {
		return
	}
	sm.mu.Lock()
	sm.ipHistory = fn
	sm.mu.Unlock()
}

func (sm *ShieldManager) ipHistoryLookup() func(ip string) (violations int64, banned bool) {
	if sm == nil {
		return nil
	}
	sm.mu.RLock()
	fn := sm.ipHistory
	sm.mu.RUnlock()
	return fn
}

func (sm *ShieldManager) SetGeoAttr(fn func(ip string) (geoScore int, geoReasons []string)) {
	if sm == nil {
		return
	}
	sm.mu.Lock()
	sm.geoAttr = fn
	sm.mu.Unlock()
}

func (sm *ShieldManager) geoAttrLookup() func(ip string) (geoScore int, geoReasons []string) {
	if sm == nil {
		return nil
	}
	sm.mu.RLock()
	fn := sm.geoAttr
	sm.mu.RUnlock()
	return fn
}

func (sm *ShieldManager) redisClient() *goredis.Client {
	if sm == nil {
		return nil
	}
	sm.mu.RLock()
	client := sm.redis
	sm.mu.RUnlock()
	return client
}

func (sm *ShieldManager) SetRedis(redis *goredis.Client) {
	if sm == nil {
		return
	}
	sm.mu.Lock()
	sm.redis = redis
	sm.mu.Unlock()
}

// SetConfig 更新 Shield 配置。
// 难度会被钳制到 VerifyPoW 支持的区间，否则超出上限的配置会让挑战永远无法通过。
func (sm *ShieldManager) SetConfig(cfg ShieldConfig) {
	if cfg.Difficulty <= 0 {
		cfg.Difficulty = 4
	}
	cfg.Difficulty = ClampPoWDifficulty(cfg.Difficulty)
	if cfg.TimeoutSecs <= 0 {
		cfg.TimeoutSecs = 30
	}
	if cfg.AutoStartDelay <= 0 {
		cfg.AutoStartDelay = 800
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.EnvStrictness < 0 || cfg.EnvStrictness > 2 {
		cfg.EnvStrictness = 1
	}
	sm.mu.Lock()
	sm.config = cfg
	sm.mu.Unlock()
}

func (sm *ShieldManager) difficultyValue() int {
	sm.mu.RLock()
	difficulty := sm.config.Difficulty
	sm.mu.RUnlock()
	if difficulty <= 0 {
		return 4
	}
	return ClampPoWDifficulty(difficulty)
}

// Config 返回当前配置的副本。
func (sm *ShieldManager) Config() ShieldConfig {
	sm.mu.RLock()
	cfg := sm.config
	sm.mu.RUnlock()
	return cfg
}

func (sm *ShieldManager) shieldPageConfig(session *ShieldSession) ShieldConfig {
	cfg := sm.Config()
	cfg.TimeoutSecs = int(session.sessionTTL() / time.Second)
	cfg.EnvStrictness = session.EnvStrictness
	cfg.EnableEnvCheck = session.EnableEnvCheck
	cfg.EnableBehaviorCheck = session.EnableBehaviorCheck
	cfg.RequireHTTP2 = session.RequireHTTP2
	cfg.RequireHTTP3 = session.RequireHTTP3
	cfg.AllowHTTP1 = session.AllowHTTP1
	return cfg
}

// GenerateChallenge creates a new shield challenge session (no captcha needed).
func (sm *ShieldManager) GenerateChallenge(originalURL string, requestProtocol string) (*ShieldSession, error) {
	return sm.GenerateChallengeWithBinding(originalURL, requestProtocol, ChallengeSessionBinding{})
}

func (sm *ShieldManager) GenerateChallengeWithBinding(originalURL string, requestProtocol string, binding ChallengeSessionBinding) (*ShieldSession, error) {
	cfg := sm.Config()
	nonce := GeneratePoWNonce()
	sessionID := shieldGenSessionID()
	envKey := GenerateEnvSessionKey()
	if len(envKey) != envSessionKeySize {
		// 密钥生成失败（crypto/rand 异常）直接拒绝签发，不产生半配态会话。
		return nil, fmt.Errorf("environment session key generation failed")
	}
	session := &ShieldSession{
		ChallengeSessionBinding: binding.normalized(),
		ID:                      sessionID,
		Nonce:                   nonce,
		Difficulty:              cfg.Difficulty,
		TimeoutSecs:             cfg.TimeoutSecs,
		EnvStrictness:           cfg.EnvStrictness,
		EnableEnvCheck:          cfg.EnableEnvCheck,
		EnableBehaviorCheck:     cfg.EnableBehaviorCheck,
		EnvConfigFrozen:         true,
		RequireHTTP2:            cfg.RequireHTTP2,
		RequireHTTP3:            cfg.RequireHTTP3,
		AllowHTTP1:              cfg.AllowHTTP1,
		ProtocolConfigFrozen:    true,
		OriginalURL:             originalURL,
		RequestProtocol:         shieldProtocolValue(requestProtocol),
		EnvKey:                  envKey,
		ClientIP:                binding.clientIPValue(),
		CreatedAt:               time.Now(),
	}
	if err := sm.saveShieldSession(session); err != nil {
		return nil, err
	}
	return session, nil
}

// VerifyChallenge checks PoW + env fingerprint.
// 会话通过原子“取出即删除”获得，保证一份 PoW 解只能被兑换一次；
// 过期会话直接拒绝，不依赖清理协程的调度间隔。
func (sm *ShieldManager) VerifyChallenge(sessionID, captchaAnswer string, powCounter int64, powHash, envFPJSON, requestProtocol string) (bool, string) {
	return sm.VerifyChallengeWithBinding(
		sessionID,
		captchaAnswer,
		powCounter,
		powHash,
		envFPJSON,
		requestProtocol,
		ChallengeSessionBinding{},
	)
}

// VerifyChallengeWithBinding compares the matched-site binding before atomically
// consuming the shield session.
func (sm *ShieldManager) VerifyChallengeWithBinding(sessionID, captchaAnswer string, powCounter int64, powHash, envFPJSON, requestProtocol string, binding ChallengeSessionBinding) (bool, string) {
	session := sm.takeShieldSessionWithBinding(sessionID, binding)
	if session == nil {
		return false, ""
	}
	if session.expiredAt(time.Now()) {
		return false, session.OriginalURL
	}
	if !session.hasFrozenConfig() {
		return false, session.OriginalURL
	}
	if shieldProtocolValue(requestProtocol) != session.RequestProtocol {
		return false, session.OriginalURL
	}
	if !shieldProtocolAllowed(sm.shieldPageConfig(session), requestProtocol) {
		return false, session.OriginalURL
	}
	if !VerifyPoW(session.Nonce, powCounter, powHash, session.Difficulty) {
		return false, session.OriginalURL
	}
	if !session.EnableEnvCheck {
		return true, session.OriginalURL
	}

	fp := DecryptEnvFingerprintWithAAD(
		envFPJSON,
		session.EnvKey,
		EnvFingerprintAAD("shield", session.ID, session.ChallengeSessionBinding),
	)
	if fp == nil {
		return false, session.OriginalURL
	}

	result := ValidateEnvFingerprint(fp)
	if session.EnvStrictness == 0 {
		return result.Score < 100, session.OriginalURL
	}
	if session.EnableBehaviorCheck && session.EnvStrictness > 0 {
		if fp.Behavior == nil {
			// 行为开启时提交必须携带采样，否则脚本化客户端可绕过行为维度。
			return false, session.OriginalURL
		}
		// 方案 B：用会话签发 IP 的只读史评分（不参与绑定排序）。
		// 注入函数为 nil（平台未接线）时该维度评分为 0，不改变基线。
		if history := sm.ipHistoryLookup(); history != nil && session.ClientIP != "" {
			violations, banned := history(session.ClientIP)
			if violations > 0 && result.Score <= 50 {
				added := 0
				reasons := result.Reasons
				if banned {
					added += 20
					reasons = append(reasons, "behavior: source IP currently auto-banned (+20)")
				} else if violations >= 3 {
					added += 15
					reasons = append(reasons, "behavior: source IP repeat violations (+15)")
				} else {
					added += 5
					reasons = append(reasons, "behavior: source IP prior violation (+5)")
				}
				result.Score += added
				result.Reasons = reasons
			}
		}
		if geo := sm.geoAttrLookup(); geo != nil && session.ClientIP != "" && result.Score <= 50 {
			geoScore, geoReasons := geo(session.ClientIP)
			if geoScore > 20 {
				geoScore = 20
			}
			if geoScore > 0 {
				result.Score += geoScore
				for _, r := range geoReasons {
					result.Reasons = append(result.Reasons, "geoip: "+r)
				}
			}
		}
	}
	return result.Score <= 50, session.OriginalURL
}

// WriteShieldChallengeResponse renders the Cloudflare-style shield HTML page.
func (sm *ShieldManager) WriteShieldChallengeResponse(c *app.RequestContext, reqID, originalURL, requestProtocol string, binding ChallengeSessionBinding, statusCode int) {
	prepareChallengeResponseHeaders(c, reqID)
	session, err := sm.GenerateChallengeWithBinding(originalURL, requestProtocol, binding)
	if err != nil {
		c.String(500, "shield challenge generation failed")
		return
	}
	cfg := sm.shieldPageConfig(session)
	powScript := GeneratePoWWASMScript(session.Difficulty, session.Nonce)
	envJS := ""
	behaviorJS := ""
	aad := EnvFingerprintAAD("shield", session.ID, binding)
	envJS = EnvCheckJSEncrypted(EnvSessionKeyHex(session.EnvKey), aad)
	if cfg.EnableEnvCheck && cfg.EnableBehaviorCheck {
		// 行为开启时改用带行为合并的信封模板（Rust 侧
		// collect_and_encrypt_fingerprint_with_behavior 合并 behavior 字段），
		// 采样缺失时模板内回退到无行为信封，不阻塞挑战。
		envJS = EnvCheckJSEncryptedWithBehavior(EnvSessionKeyHex(session.EnvKey), aad)
		behaviorJS = shieldBehaviorSamplerJS()
	}
	if envJS == "" {
		c.String(500, "shield environment initialization failed")
		return
	}

	html := shieldPageHTMLWithConfig(session.ID, cfg, session.RequestProtocol, envJS, behaviorJS, powScript)
	c.Data(statusCode, "text/html; charset=utf-8", []byte(html))
}

var shieldPageTmpl = template.Must(template.ParseFS(challengePageFS, "templates/shield.html"))

type shieldPageData struct {
	SessionID            string
	AutoStartDelay       template.JS
	TimeoutMS            template.JS
	MaxRetries           template.JS
	EnableEnvCheck       template.JS
	EnableDevToolsDetect template.JS
	RequireHTTP2         template.JS
	RequireHTTP3         template.JS
	AllowHTTP1           template.JS
	RequestProtocol      string
	EnvJS                template.JS
	BehaviorJS           template.JS
	PowScript            template.JS
}

func shieldPageHTMLWithConfig(sessionID string, cfg ShieldConfig, requestProtocol, envJS, behaviorJS, powScript string) string {
	data := shieldPageData{
		SessionID:            sessionID,
		AutoStartDelay:       template.JS(strconv.Itoa(cfg.AutoStartDelay)),
		TimeoutMS:            template.JS(strconv.Itoa(cfg.TimeoutSecs * 1000)),
		MaxRetries:           template.JS(strconv.Itoa(cfg.MaxRetries)),
		EnableEnvCheck:       template.JS(strconv.FormatBool(cfg.EnableEnvCheck)),
		EnableDevToolsDetect: template.JS(strconv.FormatBool(cfg.EnableDevToolsDetect)),
		RequireHTTP2:         template.JS(strconv.FormatBool(cfg.RequireHTTP2)),
		RequireHTTP3:         template.JS(strconv.FormatBool(cfg.RequireHTTP3)),
		AllowHTTP1:           template.JS(strconv.FormatBool(cfg.AllowHTTP1)),
		RequestProtocol:      shieldProtocolValue(requestProtocol),
		EnvJS:                template.JS(envJS),
		BehaviorJS:           template.JS(behaviorJS),
		PowScript:            template.JS(powScript),
	}
	var buf bytes.Buffer
	if err := shieldPageTmpl.ExecuteTemplate(&buf, "shield.html", data); err != nil {
		return "<!DOCTYPE html><html><body><p>Unable to render security check.</p></body></html>"
	}
	return obfuscateShieldJS(buf.String())
}

func obfuscateShieldJS(html string) string {
	v := randomVarNames(16)
	r := strings.NewReplacer(
		"var sid=", "var "+v[0]+"=",
		",sid,", ","+v[0]+",",
		"'__waf_shield_session':sid", "'__waf_shield_session':"+v[0],
		"autoDelay", v[1],
		"timeoutMs", v[2],
		"maxRetries", v[3],
		"retryCount", v[4],
		"enableEnv", v[5],
		"detectDev,", v[6]+",",
		"detectDev&&", v[6]+"&&",
		"detectDev=", v[6]+"=",
		"requireH2", v[7],
		"requireH3", v[8],
		"allowH1", v[9],
		"requestProto", v[10],
		"envMonitor", v[11],
		"behaviorSampler", v[12],
		"behaviorData", v[13],
		"behaviorSeen", v[14],
		"behaviorOff", v[15],
	)
	return r.Replace(html)
}

/**
 * shieldBehaviorSamplerJS 返回盾页注入的行为心率采样脚本。
 *
 * 采样器在盾页存活期间工作：
 *   1. 计数 pointermove/keydown/keypress 事件与敏感键；
 *   2. 维护 pointermove 的位移与间隔量化序列（capped 64 个样本）；
 *   3. 结束时输出全页共享的 Readonly 报告对象
 *      window.__owaf_behavior_finish_then = null；
 *     （实际由盾页提交脚本调用 window.__owaf_behavior_sample() 取聚合值）。
 *
 * 统计（events/jitter/zero_ratio/entropy/max_speed/action_key）由盾页提交脚本
 * 在加密前合并进行为坑位，随 GM 环境信封提交，永不外发明文。
 * 本函数体由 obfuscateShieldJS 只做变量名替换，不参与逻辑。
 */
func shieldBehaviorSamplerJS() string {
	return `(function(){
if(window.__owaf_behavior_sample)return;
var ev=0,keys=0,d=0,lastX=0,moves=0,zero=0,maxMove=0,speed=0,intervals=[],lastT=0;
function qmove(x,t){if(typeof t!=='number')return;if(lastT){var dt=t-lastT;if(intervals.length>=64)intervals.shift();intervals.push(dt)}lastT=t;if(lastX){var s=Math.abs(x-lastX);if(s>0){moves++;maxMove=Math.max(maxMove,s)}else{zero++}d+=s}lastX=x}
window.addEventListener('pointermove',function(e){if(typeof e.clientX!=='number')return;ev++;qmove(e.clientX,typeof e.timeStamp==='number'?e.timeStamp:Date.now())},{passive:true});
window.addEventListener('keydown',function(e){ev++;var c=e.keyCode||e.which||0;if(c===13||c===9||c===27||c===32||c===8)keys++},{passive:true});
window.addEventListener('keypress',function(){ev++},{passive:true});
function entropy(){var hs={},n=intervals.length;if(n<4)return 0;var i;for(i=0;i<n;i++){var k=intervals[i];hs[k]=(hs[k]||0)+1}var h=0;for(var k in hs){var p=hs[k]/n;h-=p*Math.log(p)}return h}
window.__owaf_behavior_sample=function(){var total=moves+zero;return {events:ev,entropy:+(entropy().toFixed(3)),zero_ratio:+(total?(zero/total).toFixed(3):0),jitter:+(total?(moves/total).toFixed(3):1),max_speed:+(maxMove.toFixed(3)),action_key:keys}};
})();`
}

// shieldSessionTTL 已被强制化删除：会话有效期只来自签发时写入的 TimeoutSecs。

func (sm *ShieldManager) saveShieldSession(s *ShieldSession) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if redis := sm.redisClient(); redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := redis.Set(ctx, sm.prefix+s.ID, data, s.sessionTTL()).Err(); err != nil {
			return fmt.Errorf("store Shield session in Redis: %w", err)
		}
		return nil
	}
	sm.mu.Lock()
	sm.sessions[s.ID] = s
	sm.mu.Unlock()
	return nil
}

// takeShieldSession 原子地取出并删除一个 shield 会话。
// 返回 nil 表示会话不存在或已被其他请求兑换，从而保证 PoW 解的一次性。
func (sm *ShieldManager) takeShieldSessionWithBinding(id string, binding ChallengeSessionBinding) *ShieldSession {
	if id == "" {
		return nil
	}
	binding = binding.normalized()
	if redis := sm.redisClient(); redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		raw, err := takeAndDeleteBoundScript.Run(ctx, redis, []string{sm.prefix + id}, binding.SiteID, binding.Host, binding.Bind).Text()
		data := []byte(raw)
		if err != nil {
			return nil
		}
		if len(data) == 0 {
			return nil
		}
		if session := decodeShieldSession(data); session != nil {
			sm.mu.Lock()
			delete(sm.sessions, id)
			sm.mu.Unlock()
			return session
		}
		return nil
	}
	sm.mu.Lock()
	s, ok := sm.sessions[id]
	if ok && s != nil && s.ChallengeSessionBinding.matches(binding) {
		delete(sm.sessions, id)
	} else {
		ok = false
	}
	sm.mu.Unlock()
	if !ok {
		return nil
	}
	return s
}

func (sm *ShieldManager) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			sm.mu.Lock()
			now := time.Now()
			for id, s := range sm.sessions {
				if s.expiredAt(now) {
					delete(sm.sessions, id)
				}
			}
			if len(sm.sessions) == 0 {
				sm.sessions = make(map[string]*ShieldSession)
			}
			sm.mu.Unlock()
		case <-sm.done:
			return
		}
	}
}

func shieldGenSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
