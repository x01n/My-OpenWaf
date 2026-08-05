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
	ID              string    `json:"id"`
	Nonce           string    `json:"nonce"`
	Difficulty      int       `json:"difficulty"`
	TimeoutSecs     int       `json:"timeout_secs"`
	OriginalURL     string    `json:"original_url"`
	RequestProtocol string    `json:"request_protocol"`
	EnvKey          []byte    `json:"env_key"` // AES key for env fingerprint encryption
	CreatedAt       time.Time `json:"created_at"`
}

func (s *ShieldSession) sessionTTL() time.Duration {
	if s.TimeoutSecs > 0 {
		return time.Duration(s.TimeoutSecs) * time.Second
	}
	return legacyShieldSessionTTL
}

func (s *ShieldSession) expiredAt(now time.Time) bool {
	return now.Sub(s.CreatedAt) > s.sessionTTL()
}

// ShieldManager orchestrates 5-second shield challenges (PoW + env fingerprint).
// Cloudflare-style: user clicks verify -> PoW runs in background -> auto-submit on success.
type ShieldManager struct {
	captcha  *CaptchaManager
	redis    *goredis.Client
	config   ShieldConfig
	prefix   string
	done     chan struct{}
	once     sync.Once
	mu       sync.RWMutex
	sessions map[string]*ShieldSession
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
	return cfg
}

// GenerateChallenge creates a new shield challenge session (no captcha needed).
func (sm *ShieldManager) GenerateChallenge(originalURL string, requestProtocol string) (*ShieldSession, error) {
	return sm.GenerateChallengeWithBinding(originalURL, requestProtocol, ChallengeSessionBinding{})
}

// GenerateChallengeWithBinding creates a shield session bound to the matched site.
func (sm *ShieldManager) GenerateChallengeWithBinding(originalURL string, requestProtocol string, binding ChallengeSessionBinding) (*ShieldSession, error) {
	cfg := sm.Config()
	nonce := GeneratePoWNonce()
	sessionID := shieldGenSessionID()
	var envKey []byte
	if cfg.EnableEnvCheck {
		envKey = GenerateEnvSessionKey()
		if len(envKey) != envSessionKeySize {
			return nil, fmt.Errorf("environment session key generation failed")
		}
	}
	session := &ShieldSession{
		ChallengeSessionBinding: binding.normalized(),
		ID:                      sessionID,
		Nonce:                   nonce,
		Difficulty:              cfg.Difficulty,
		TimeoutSecs:             cfg.TimeoutSecs,
		OriginalURL:             originalURL,
		RequestProtocol:         shieldProtocolValue(requestProtocol),
		EnvKey:                  envKey,
		CreatedAt:               time.Now(),
	}
	sm.saveShieldSession(session)
	return session, nil
}

// VerifyChallenge checks PoW + env fingerprint.
// 会话通过原子“取出即删除”获得，保证一份 PoW 解只能被兑换一次；
// 过期会话直接拒绝，不依赖清理协程的调度间隔。
func (sm *ShieldManager) VerifyChallenge(sessionID, captchaAnswer string, powCounter int64, powHash, envFPJSON, requestProtocol string) (bool, string) {
	return sm.VerifyChallengeWithBinding(sessionID, captchaAnswer, powCounter, powHash, envFPJSON, requestProtocol, ChallengeSessionBinding{})
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
	if !shieldProtocolAllowed(sm.shieldPageConfig(session), requestProtocol) {
		return false, session.OriginalURL
	}
	if !VerifyPoW(session.Nonce, powCounter, powHash, session.Difficulty) {
		return false, session.OriginalURL
	}
	if len(session.EnvKey) > 0 {
		result := ValidateEnvFingerprint(DecryptEnvFingerprint(envFPJSON, session.EnvKey))
		if !result.Pass {
			return false, session.OriginalURL
		}
	}
	return true, session.OriginalURL
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
	powScript := GeneratePoWWASMScript(session.Difficulty, session.Nonce, EnvSessionKeyHex(session.EnvKey))
	envJS := ""
	if cfg.EnableEnvCheck {
		envJS = EnvCheckJSEncrypted(EnvSessionKeyHex(session.EnvKey))
	}

	html := shieldPageHTMLWithConfig(session.ID, cfg, session.RequestProtocol, envJS, powScript)
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
	PowScript            template.JS
}

func shieldPageHTMLWithConfig(sessionID string, cfg ShieldConfig, requestProtocol, envJS, powScript string) string {
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
		PowScript:            template.JS(powScript),
	}
	var buf bytes.Buffer
	if err := shieldPageTmpl.ExecuteTemplate(&buf, "shield.html", data); err != nil {
		return "<!DOCTYPE html><html><body><p>Unable to render security check.</p></body></html>"
	}
	return obfuscateShieldJS(buf.String())
}

func obfuscateShieldJS(html string) string {
	v := randomVarNames(12)
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
	)
	return r.Replace(html)
}

// shieldSessionTTL 是 shield 会话的有效期，Redis 与内存两条路径共用。
const legacyShieldSessionTTL = 5 * time.Minute

func (sm *ShieldManager) saveShieldSession(s *ShieldSession) {
	if redis := sm.redisClient(); redis != nil {
		data, _ := json.Marshal(s)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if redis.Set(ctx, sm.prefix+s.ID, data, s.sessionTTL()).Err() == nil {
			return
		}
	}
	sm.mu.Lock()
	sm.sessions[s.ID] = s
	sm.mu.Unlock()
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
		if err == nil && len(data) > 0 {
			var s ShieldSession
			if json.Unmarshal(data, &s) == nil {
				sm.mu.Lock()
				delete(sm.sessions, id)
				sm.mu.Unlock()
				return &s
			}
			return nil
		}
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
