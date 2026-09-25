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

	"My-OpenWaf/internal/waf/challenge/gm"
)

// CaptchaType defines the type of CAPTCHA to generate.
type CaptchaType string

const (
	CaptchaTypeClick  CaptchaType = "click"
	CaptchaTypeSlide  CaptchaType = "slide"
	CaptchaTypeRotate CaptchaType = "rotate"
	CaptchaTypeMath   CaptchaType = "math" // Built-in math captcha (no external resources needed)
)

// IsValidCaptchaType reports whether t is one of the supported CAPTCHA modes.
func IsValidCaptchaType(t CaptchaType) bool {
	switch t {
	case CaptchaTypeMath, CaptchaTypeClick, CaptchaTypeSlide, CaptchaTypeRotate:
		return true
	default:
		return false
	}
}

// ValidateCaptchaType validates a CAPTCHA mode used by persisted global settings.
func ValidateCaptchaType(t CaptchaType) error {
	if !IsValidCaptchaType(t) {
		return fmt.Errorf("unsupported captcha type %q", t)
	}
	return nil
}

// CaptchaSession stores the server-side state for a pending CAPTCHA verification.
type CaptchaSession struct {
	ChallengeSessionBinding
	ID        string      `json:"id"`
	Type      CaptchaType `json:"type"`
	Answer    string      `json:"answer"` // JSON-encoded expected answer
	CreatedAt time.Time   `json:"created_at"`
	ExpiresAt time.Time   `json:"expires_at"`
	// EnvKey 是会话绑定的环境指纹加密会话主密钥（32 字节，页面下发 hex 前 64 字符）。
	// 与 shield_challenge 一致，用于解密客户端提交的 __waf_env_fp。
	// 强制化语义：EnvKey 必须恒非空（否则验证直接失败），签发侧全量下发。
	EnvKey []byte `json:"env_key,omitempty"`
}

type CaptchaItemPayload struct {
	Type      string `json:"type"`
	Prompt    string `json:"prompt"`
	MasterImg string `json:"master_img,omitempty"`
	ThumbImg  string `json:"thumb_img,omitempty"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	InputMode string `json:"input_mode,omitempty"`
}

// CaptchaChallenge is the data sent to the client.
type CaptchaChallenge struct {
	SessionID   string `json:"session_id"`
	Type        string `json:"type"`
	MasterImg   string `json:"master_img"`
	ThumbImg    string `json:"thumb_img"`
	Prompt      string `json:"prompt"` // e.g. "Click the characters in order" or "Solve: 3+7=?"
	Width       int    `json:"width"`
	Height      int    `json:"height"`
	CaptchaData string `json:"captcha_data"`
	EnvKeyHex   string `json:"-"`
}

// captchaItemDataAAD 是题目/答案信封的 AAD（标签生成器产物，禁止散落字面量）。
var captchaItemDataAAD = gm.EnvelopeAAD(gm.EnvelopeLabel("captcha", gm.GMEnvelopeVersion), gm.PurposeChallengeData)

const captchaItemDataMaxPlaintext = 512 * 1024

func EncryptChallengeData(payload string, sessionKey []byte) (string, error) {
	if len(sessionKey) != envSessionKeySize {
		return "", fmt.Errorf("invalid challenge data session key length")
	}
	raw, err := envEncrypt([]byte(payload), sessionKey, []byte(captchaItemDataAAD), gm.DomainCaptchaItem)
	if err != nil {
		return "", err
	}
	return gm.Encode(raw), nil
}

func DecryptChallengeData(envelope string, sessionKey []byte) *CaptchaItemPayload {
	if len(sessionKey) != envSessionKeySize {
		return nil
	}
	raw, err := gm.Decode(envelope)
	if err != nil {
		return nil
	}
	plaintext, err := envDecrypt(raw, sessionKey, []byte(captchaItemDataAAD), gm.DomainCaptchaItem)
	if err != nil || len(plaintext) == 0 || len(plaintext) > captchaItemDataMaxPlaintext {
		return nil
	}
	var payload CaptchaItemPayload
	if json.Unmarshal(plaintext, &payload) != nil {
		return nil
	}
	return &payload
}

// EncryptCaptchaAnswer 用会话主密钥封装客户端答案提交（域 DomainCaptchaAnswer），
// 与 WASM 侧 gm_encrypt_challenge_answer 的字面语义一致，供测试与工具路径构造提交。
func EncryptCaptchaAnswer(payload string, sessionKey []byte) (string, error) {
	if len(sessionKey) != envSessionKeySize {
		return "", fmt.Errorf("invalid answer session key length")
	}
	raw, err := envEncrypt([]byte(payload), sessionKey, []byte(captchaItemDataAAD), gm.DomainCaptchaAnswer)
	if err != nil {
		return "", err
	}
	return gm.Encode(raw), nil
}

func newCaptchaChallenge(sessionID string, key []byte, items *CaptchaItems) (*CaptchaChallenge, error) {
	if items == nil {
		return nil, fmt.Errorf("captcha items not provided")
	}
	payload, err := json.Marshal(CaptchaItemPayload{
		Type:      string(items.Type),
		Prompt:    items.Prompt,
		MasterImg: items.MasterImg,
		ThumbImg:  items.ThumbImg,
		Width:     items.Width,
		Height:    items.Height,
		InputMode: inputModeForCaptcha(string(items.Type)),
	})
	if err != nil {
		return nil, err
	}
	envelope, err := EncryptChallengeData(string(payload), key)
	if err != nil {
		return nil, err
	}
	return &CaptchaChallenge{
		SessionID:   sessionID,
		Type:        string(items.Type),
		Prompt:      items.Prompt,
		Width:       items.Width,
		Height:      items.Height,
		CaptchaData: envelope,
		EnvKeyHex:   EnvSessionKeyHex(key),
	}, nil
}

// CaptchaItems 是单个验证码题目的原始素材。
type CaptchaItems struct {
	Type      CaptchaType
	Prompt    string
	MasterImg string
	ThumbImg  string
	Width     int
	Height    int
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

	// sessions 是 Redis 不可用时的内存会话库（部署形态，非兼容回退）。
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

func (cm *CaptchaManager) GenerateWithBinding(captchaType CaptchaType, envCheck bool, binding ChallengeSessionBinding) (*CaptchaChallenge, error) {
	binding = binding.normalized()
	_ = envCheck
	envKey := GenerateEnvSessionKey()
	if len(envKey) != envSessionKeySize {
		// 密钥生成失败（crypto/rand 异常）直接拒绝签发，不产生半配态会话。
		return nil, fmt.Errorf("environment session key generation failed")
	}
	switch captchaType {
	case CaptchaTypeMath:
		return cm.generateMath(envKey, binding)
	case CaptchaTypeClick:
		return cm.generateClick(envKey, binding)
	case CaptchaTypeSlide:
		return cm.generateSlide(envKey, binding)
	case CaptchaTypeRotate:
		return cm.generateRotate(envKey, binding)
	default:
		return nil, fmt.Errorf("unsupported captcha type %q", captchaType)
	}
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

	plain := decryptAnswerEnvelope(answer, session)
	return constantTimeEqualString(session.Answer, plain)
}

// decryptAnswerEnvelope 只接受 GM v2 答案信封（域 DomainCaptchaAnswer）。
// 强制化语义：明文答案或旧格式密文一律拒绝（返回空字符串），不保留兼容回退。
func decryptAnswerEnvelope(answer string, session *CaptchaSession) string {
	if session == nil || len(session.EnvKey) != envSessionKeySize {
		return ""
	}
	raw, err := gm.Decode(answer)
	if err != nil {
		return ""
	}
	plaintext, err := envDecrypt(raw, session.EnvKey, []byte(captchaItemDataAAD), gm.DomainCaptchaAnswer)
	if err != nil || len(plaintext) == 0 || len(plaintext) > 64*1024 {
		return ""
	}
	return string(plaintext)
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
// 答案在 [mathAnswerMin, mathAnswerMax] 上均匀分布：
// 三种运算都按「先抽答案与第二个操作数、再反推第一个操作数」的方式出题，
// 除法额外抽取商值反推被除数，保证整除且被除数不超过四位数、
// 可在验证码画布内完整渲染。
// 乘法题不进入题库：积型题面无法反推出三位数答案（11..99 之积最小 121，
// 与答案均匀区间冲突），故题库为加减除三种；乘号字模保留在
// getCharPattern 中以备渲染其他题面字符集时使用。
func randomMathProblem() (expr string, answer int) {
	answer = mathAnswerMin + randIntN(mathAnswerMax-mathAnswerMin+1)
	operand := mathOperandMin + randIntN(mathOperandMax-mathOperandMin+1)
	switch op := randIntN(3); op {
	case 0:
		// answer = a + operand
		return fmt.Sprintf("%d + %d = ?", answer-operand, operand), answer
	case 1:
		// answer = a - operand
		return fmt.Sprintf("%d - %d = ?", answer+operand, operand), answer
	default:
		// answer = dividend / divisor；先抽商（2..10），保证整除且除数不为零。
		// 商上限取 10：answer≤999 时被除数≤9990，稳定在四位数以内，
		// 「9990 ÷ 10 = ?」仍可放进 200px 画布。
		quotient := 2 + randIntN(9)
		return fmt.Sprintf("%d ÷ %d = ?", answer*quotient, quotient), answer
	}
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

	return newCaptchaChallenge(sessionID, envKey, &CaptchaItems{
		Type:      CaptchaTypeMath,
		Prompt:    "请计算图中的算式",
		MasterImg: "data:image/png;base64," + imgData,
		Width:     200,
		Height:    80,
	})
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

	// 干扰线：在文本之后绘制，采用半透明暗色，避免吞掉题面笔画。
	// 随机端点与步长来自 crypto/rand，线条不参与答案判定。
	const noiseLines = 2
	lines := make([]byte, noiseLines*4)
	_, _ = rand.Read(lines)
	for i := 0; i < noiseLines; i++ {
		x1 := int(lines[i*4]) * width / 256
		y1 := int(lines[i*4+1]) * height / 256
		x2 := int(lines[i*4+2]) * width / 256
		y2 := int(lines[i*4+3]) * height / 256
		drawLine(img, x1, y1, x2, y2, color.RGBA{148, 163, 184, 120})
	}

	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// drawLine draws a one-pixel line between two points using Bresenham's algorithm.
func drawLine(img *image.RGBA, x1, y1, x2, y2 int, c color.RGBA) {
	dx := x2 - x1
	if dx < 0 {
		dx = -dx
	}
	dy := y2 - y1
	if dy < 0 {
		dy = -dy
	}
	sx, sy := 1, 1
	if x1 > x2 {
		sx = -1
	}
	if y1 > y2 {
		sy = -1
	}
	err := dx - dy
	for {
		if x1 >= 0 && x1 < img.Bounds().Dx() && y1 >= 0 && y1 < img.Bounds().Dy() {
			img.Set(x1, y1, c)
		}
		if x1 == x2 && y1 == y2 {
			break
		}
		e2 := 2 * err
		if e2 > -dy {
			err -= dy
			x1 += sx
		}
		if e2 < dx {
			err += dx
			y1 += sy
		}
	}
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
		'×': {{1, 0, 1}, {0, 1, 0}, {0, 1, 0}, {0, 1, 0}, {1, 0, 1}},
		'÷': {{0, 0, 0}, {0, 1, 0}, {0, 0, 0}, {0, 1, 0}, {0, 0, 0}},
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

func VerifyCaptchaEnvEnvelope(envFPJSON string, session *CaptchaSession) bool {
	if session == nil {
		return false
	}
	if len(session.EnvKey) != envSessionKeySize {
		return false
	}
	fp := DecryptEnvFingerprintWithAAD(
		envFPJSON,
		session.EnvKey,
		EnvFingerprintAAD("captcha", session.ID, session.ChallengeSessionBinding),
	)
	if fp == nil {
		return false
	}
	result := ValidateEnvFingerprint(fp)
	if result.Score >= 100 || !result.Pass {
		return false
	}
	return true
}
