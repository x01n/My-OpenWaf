package challenge

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"

	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// CaptchaType defines the type of CAPTCHA to generate.
type CaptchaType string

const (
	CaptchaTypeClick  CaptchaType = "click"
	CaptchaTypeSlide  CaptchaType = "slide"
	CaptchaTypeRotate CaptchaType = "rotate"
	CaptchaTypeMath   CaptchaType = "math" // Built-in math captcha (no external resources needed)
)

// CaptchaSession stores the server-side state for a pending CAPTCHA verification.
type CaptchaSession struct {
	ChallengeSessionBinding
	ID        string      `json:"id"`
	Type      CaptchaType `json:"type"`
	Answer    string      `json:"answer"` // JSON-encoded expected answer
	CreatedAt time.Time   `json:"created_at"`
	ExpiresAt time.Time   `json:"expires_at"`
	// EnvKey 是会话绑定的环境指纹加密密钥（32 字节）。
	// 与 shield_challenge 一致，用于解密客户端提交的 __waf_env_fp。
	// 为空表示该会话未启用浏览器/环境检查。
	EnvKey []byte `json:"env_key,omitempty"`
}

// CaptchaChallenge is the data sent to the client.
type CaptchaChallenge struct {
	SessionID string `json:"session_id"`
	Type      string `json:"type"`
	MasterImg string `json:"master_img"` // base64 data URI
	ThumbImg  string `json:"thumb_img"`  // base64 data URI (for click/slide)
	Prompt    string `json:"prompt"`     // e.g. "Click the characters in order" or "Solve: 3+7=?"
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	Fallback  bool   `json:"fallback"`
	// EnvKeyHex 是会话绑定环境指纹密钥的十六进制编码，供页面注入环境采集 JS。
	// 为空表示该验证码未启用浏览器/环境检查。
	EnvKeyHex string `json:"-"`
}

func (ch *CaptchaChallenge) MarkFallback(requested CaptchaType) *CaptchaChallenge {
	if ch != nil && requested != "" && ch.Type != string(requested) {
		ch.Fallback = true
	}
	return ch
}

// CaptchaManager handles CAPTCHA generation and verification with Redis session storage.
type CaptchaManager struct {
	redis   *goredis.Client
	prefix  string
	timeout time.Duration
	done    chan struct{}
	once    sync.Once

	// go-captcha 高级验证码提供器
	goCaptcha *GoCaptchaProvider

	// Fallback in-memory store when Redis is unavailable
	mu       sync.RWMutex
	sessions map[string]*CaptchaSession
}

// NewCaptchaManager creates a new CaptchaManager.
// redis can be nil (will use in-memory fallback).
func NewCaptchaManager(redis *goredis.Client, timeout time.Duration) *CaptchaManager {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	cm := &CaptchaManager{
		redis:    redis,
		prefix:   "owaf:captcha:",
		timeout:  timeout,
		done:     make(chan struct{}),
		sessions: make(map[string]*CaptchaSession),
	}
	// Start cleanup goroutine for in-memory sessions
	go cm.cleanupLoop()
	return cm
}

func (cm *CaptchaManager) Close() {
	cm.once.Do(func() { close(cm.done) })
}

func (cm *CaptchaManager) redisClient() *goredis.Client {
	if cm == nil {
		return nil
	}
	cm.mu.RLock()
	client := cm.redis
	cm.mu.RUnlock()
	return client
}

func (cm *CaptchaManager) SetRedis(redis *goredis.Client) {
	if cm == nil {
		return
	}
	cm.mu.Lock()
	cm.redis = redis
	cm.mu.Unlock()
}

// SetGoCaptchaProvider 设置 go-captcha 高级验证码提供器。
func (cm *CaptchaManager) SetGoCaptchaProvider(p *GoCaptchaProvider) {
	cm.mu.Lock()
	cm.goCaptcha = p
	cm.mu.Unlock()
}

func (cm *CaptchaManager) SetTimeout(timeout time.Duration) {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	cm.mu.Lock()
	cm.timeout = timeout
	cm.mu.Unlock()
}

func (cm *CaptchaManager) timeoutValue() time.Duration {
	cm.mu.RLock()
	timeout := cm.timeout
	cm.mu.RUnlock()
	if timeout <= 0 {
		return 120 * time.Second
	}
	return timeout
}

// Generate creates a new CAPTCHA challenge of the specified type.
// Returns the challenge data to render to the client.
// Generate 生成指定类型的验证码。
// envCheck 为 true 时会为该会话绑定一个环境指纹密钥，
// 页面据此注入浏览器/环境采集 JS，验证时校验环境指纹。
func (cm *CaptchaManager) Generate(captchaType CaptchaType, envCheck bool) (*CaptchaChallenge, error) {
	return cm.GenerateWithBinding(captchaType, envCheck, ChallengeSessionBinding{})
}

// GenerateWithBinding creates a CAPTCHA session bound to the matched site.
func (cm *CaptchaManager) GenerateWithBinding(captchaType CaptchaType, envCheck bool, binding ChallengeSessionBinding) (*CaptchaChallenge, error) {
	binding = binding.normalized()
	var envKey []byte
	if envCheck {
		envKey = GenerateEnvSessionKey()
		if len(envKey) != envSessionKeySize {
			return nil, fmt.Errorf("environment session key generation failed")
		}
	}
	var (
		challenge *CaptchaChallenge
		err       error
	)
	switch captchaType {
	case CaptchaTypeMath:
		return cm.generateMath(envKey, binding)
	case CaptchaTypeClick:
		challenge, err = cm.generateClick(envKey, binding)
	case CaptchaTypeSlide:
		challenge, err = cm.generateSlide(envKey, binding)
	case CaptchaTypeRotate:
		challenge, err = cm.generateRotate(envKey, binding)
	default:
		return cm.generateMath(envKey, binding)
	}
	if err != nil {
		return nil, err
	}
	return challenge.MarkFallback(captchaType), nil
}

// Verify checks a client's CAPTCHA answer against the stored session.
// 会话通过原子“取出即删除”获得，保证一份正确答案只能被兑换一次。
func (cm *CaptchaManager) Verify(sessionID, answer string) bool {
	return cm.VerifyWithBinding(sessionID, answer, ChallengeSessionBinding{})
}

// VerifyWithBinding atomically consumes a CAPTCHA session only after the
// request's matched-site binding has been checked.
func (cm *CaptchaManager) VerifyWithBinding(sessionID, answer string, binding ChallengeSessionBinding) bool {
	session := cm.takeSessionWithBinding(sessionID, binding)
	if session == nil {
		return false
	}

	if time.Now().After(session.ExpiresAt) {
		return false
	}

	return constantTimeEqualString(session.Answer, answer)
}

// constantTimeEqualString 以常量时间比较两个字符串，避免逐字节比较泄漏答案前缀。
func constantTimeEqualString(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// takeAndDeleteScript 原子地取出并删除一个会话键。
// Redis 的 GET+DEL 若拆成两条命令，并发请求会同时读到同一会话，
// 导致同一个验证码答案/PoW 解被重复兑换，因此必须用 Lua 保证原子性。
// 使用 EVAL 而非 GETDEL 是为了兼容 Redis 6.2 之前的服务端。
var takeAndDeleteBoundScript = goredis.NewScript(`
local v = redis.call('GET', KEYS[1])
if not v then
  return ''
end
local ok, session = pcall(cjson.decode, v)
if not ok or type(session) ~= 'table' then
  return ''
end
if tostring(session.site_id or '') ~= ARGV[1] then
  return ''
end
if string.lower(tostring(session.host or '')) ~= string.lower(ARGV[2]) then
  return ''
end
if tostring(session.bind or '') ~= ARGV[3] then
  return ''
end
redis.call('DEL', KEYS[1])
return v
`)

// takeSession 原子地取出并删除一个验证码会话。
// 返回 nil 表示会话不存在或已被其他请求兑换。
func (cm *CaptchaManager) takeSessionWithBinding(sessionID string, binding ChallengeSessionBinding) *CaptchaSession {
	if sessionID == "" {
		return nil
	}
	binding = binding.normalized()
	if redis := cm.redisClient(); redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		key := cm.prefix + sessionID
		raw, err := takeAndDeleteBoundScript.Run(ctx, redis, []string{key}, binding.SiteID, binding.Host, binding.Bind).Text()
		if err != nil {
			return nil
		}
		data := []byte(raw)
		if len(data) == 0 {
			return nil
		}
		var session CaptchaSession
		if json.Unmarshal(data, &session) != nil {
			return nil
		}
		cm.mu.Lock()
		delete(cm.sessions, sessionID)
		cm.mu.Unlock()
		return &session
	}

	cm.mu.Lock()
	session, ok := cm.sessions[sessionID]
	if ok && session != nil && session.ChallengeSessionBinding.matches(binding) {
		delete(cm.sessions, sessionID)
	} else {
		ok = false
	}
	cm.mu.Unlock()
	if !ok {
		return nil
	}
	return session
}

const (
	// mathAnswerMin/mathAnswerMax 界定内置算式验证码的答案取值范围。
	// 先均匀抽取答案再反推算式，可保证答案在整个区间上均匀分布；
	// 旧实现先抽取操作数再计算答案，导致答案集中在 81 个取值上、
	// 且分布呈三角形，猜测最高频答案的命中率约 2.5%，配合无限次重新取题
	// 即可低成本暴力绕过。
	mathAnswerMin = 100
	mathAnswerMax = 999

	// mathOperandMin/mathOperandMax 界定第二个操作数，保持“三位数 ± 两位数”
	// 的心算难度，同时让第一个操作数最多为四位、可在验证码画布内完整渲染。
	mathOperandMin = 11
	mathOperandMax = 99
)

// randomMathProblem 生成一道算式验证码题目，返回题面与答案。
// 答案在 [mathAnswerMin, mathAnswerMax] 上均匀分布。
func randomMathProblem() (expr string, answer int) {
	answer = mathAnswerMin + randIntN(mathAnswerMax-mathAnswerMin+1)
	operand := mathOperandMin + randIntN(mathOperandMax-mathOperandMin+1)
	if randIntN(2) == 0 {
		// answer = a + operand
		return fmt.Sprintf("%d + %d = ?", answer-operand, operand), answer
	}
	// answer = a - operand
	return fmt.Sprintf("%d - %d = ?", answer+operand, operand), answer
}

// generateMath creates a simple math CAPTCHA (addition/subtraction).
func (cm *CaptchaManager) generateMath(envKey []byte, binding ChallengeSessionBinding) (*CaptchaChallenge, error) {
	expr, answer := randomMathProblem()

	sessionID := generateSessionID()
	session := &CaptchaSession{
		ChallengeSessionBinding: binding,
		ID:                      sessionID,
		Type:                    CaptchaTypeMath,
		Answer:                  fmt.Sprintf("%d", answer),
		CreatedAt:               time.Now(),
		ExpiresAt:               time.Now().Add(cm.timeoutValue()),
		EnvKey:                  envKey,
	}

	if err := cm.storeSession(session); err != nil {
		return nil, err
	}

	// Generate a simple image with the math expression
	imgData := cm.renderMathImage(expr)

	return &CaptchaChallenge{
		SessionID: sessionID,
		Type:      string(CaptchaTypeMath),
		MasterImg: "data:image/png;base64," + imgData,
		Prompt:    "请计算图中的算式",
		Width:     200,
		Height:    80,
		EnvKeyHex: EnvSessionKeyHex(envKey),
	}, nil
}

// renderMathImage creates a simple PNG image containing the math expression.
func (cm *CaptchaManager) renderMathImage(expr string) string {
	width, height := 200, 80
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Background with noise
	bgColor := color.RGBA{240, 243, 248, 255}
	draw.Draw(img, img.Bounds(), &image.Uniform{bgColor}, image.Point{}, draw.Src)

	// Add noise dots.
	// 一次性读取随机字节再切分，避免每个噪点做 5 次 crypto/rand 系统调用——
	// 验证码是可被匿名请求无限触发的路径，逐点取随机数会成为 CPU 消耗点。
	const noiseDots = 100
	noise := make([]byte, noiseDots*5)
	_, _ = rand.Read(noise)
	for i := 0; i < noiseDots; i++ {
		o := i * 5
		x := int(noise[o]) * width / 256
		y := int(noise[o+1]) * height / 256
		img.Set(x, y, color.RGBA{noise[o+2] % 200, noise[o+3] % 200, noise[o+4] % 200, 255})
	}

	// Draw simple text using pixel font (no external font dependency)
	cm.drawText(img, expr, 20, 35)

	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// drawText draws text on an image using a basic pixel font.
func (cm *CaptchaManager) drawText(img *image.RGBA, text string, startX, startY int) {
	textColor := color.RGBA{30, 41, 59, 255}
	x := startX
	for _, ch := range text {
		pattern := getCharPattern(ch)
		if pattern == nil {
			x += 12
			continue
		}
		for row, rowData := range pattern {
			for col, pixel := range rowData {
				if pixel == 1 {
					// Draw 2x2 for better visibility
					img.Set(x+col*2, startY+row*2, textColor)
					img.Set(x+col*2+1, startY+row*2, textColor)
					img.Set(x+col*2, startY+row*2+1, textColor)
					img.Set(x+col*2+1, startY+row*2+1, textColor)
				}
			}
		}
		x += len(pattern[0])*2 + 4
	}
}

// storeSession saves a session to Redis or in-memory fallback.
func (cm *CaptchaManager) storeSession(session *CaptchaSession) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	if redis := cm.redisClient(); redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		key := cm.prefix + session.ID
		timeout := cm.timeoutValue()
		if err := redis.Set(ctx, key, data, timeout).Err(); err != nil {
			return fmt.Errorf("store CAPTCHA session in Redis: %w", err)
		}
		return nil
	}

	cm.mu.Lock()
	cm.sessions[session.ID] = session
	cm.mu.Unlock()
	return nil
}

// loadSession retrieves a session from Redis or in-memory fallback.
func (cm *CaptchaManager) loadSession(sessionID string) (*CaptchaSession, error) {
	if redis := cm.redisClient(); redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		key := cm.prefix + sessionID
		data, err := redis.Get(ctx, key).Bytes()
		if err == nil {
			var session CaptchaSession
			if json.Unmarshal(data, &session) == nil {
				return &session, nil
			}
		}
		// Fall through to in-memory on Redis error
	}

	cm.mu.RLock()
	session, ok := cm.sessions[sessionID]
	cm.mu.RUnlock()
	if !ok {
		return nil, nil
	}
	return session, nil
}

// deleteSession removes a session from storage.
func (cm *CaptchaManager) deleteSession(sessionID string) {
	if redis := cm.redisClient(); redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		redis.Del(ctx, cm.prefix+sessionID)
	}

	cm.mu.Lock()
	delete(cm.sessions, sessionID)
	cm.mu.Unlock()
}

// cleanupLoop periodically removes expired in-memory sessions.
func (cm *CaptchaManager) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			cm.mu.Lock()
			for id, s := range cm.sessions {
				if now.After(s.ExpiresAt) {
					delete(cm.sessions, id)
				}
			}
			if len(cm.sessions) == 0 {
				cm.sessions = make(map[string]*CaptchaSession)
			}
			cm.mu.Unlock()
		case <-cm.done:
			return
		}
	}
}

func generateSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// getCharPattern returns a 5x5 pixel pattern for basic ASCII characters.
func getCharPattern(ch rune) [][]int {
	patterns := map[rune][][]int{
		'0': {{1, 1, 1}, {1, 0, 1}, {1, 0, 1}, {1, 0, 1}, {1, 1, 1}},
		'1': {{0, 1, 0}, {1, 1, 0}, {0, 1, 0}, {0, 1, 0}, {1, 1, 1}},
		'2': {{1, 1, 1}, {0, 0, 1}, {1, 1, 1}, {1, 0, 0}, {1, 1, 1}},
		'3': {{1, 1, 1}, {0, 0, 1}, {1, 1, 1}, {0, 0, 1}, {1, 1, 1}},
		'4': {{1, 0, 1}, {1, 0, 1}, {1, 1, 1}, {0, 0, 1}, {0, 0, 1}},
		'5': {{1, 1, 1}, {1, 0, 0}, {1, 1, 1}, {0, 0, 1}, {1, 1, 1}},
		'6': {{1, 1, 1}, {1, 0, 0}, {1, 1, 1}, {1, 0, 1}, {1, 1, 1}},
		'7': {{1, 1, 1}, {0, 0, 1}, {0, 0, 1}, {0, 0, 1}, {0, 0, 1}},
		'8': {{1, 1, 1}, {1, 0, 1}, {1, 1, 1}, {1, 0, 1}, {1, 1, 1}},
		'9': {{1, 1, 1}, {1, 0, 1}, {1, 1, 1}, {0, 0, 1}, {1, 1, 1}},
		'+': {{0, 0, 0}, {0, 1, 0}, {1, 1, 1}, {0, 1, 0}, {0, 0, 0}},
		'-': {{0, 0, 0}, {0, 0, 0}, {1, 1, 1}, {0, 0, 0}, {0, 0, 0}},
		'=': {{0, 0, 0}, {1, 1, 1}, {0, 0, 0}, {1, 1, 1}, {0, 0, 0}},
		'?': {{1, 1, 1}, {0, 0, 1}, {0, 1, 1}, {0, 0, 0}, {0, 1, 0}},
		' ': {{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}},
	}
	p, ok := patterns[ch]
	if !ok {
		return nil
	}
	return p
}
