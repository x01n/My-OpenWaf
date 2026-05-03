package waf

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math/big"
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
	ID        string      `json:"id"`
	Type      CaptchaType `json:"type"`
	Answer    string      `json:"answer"` // JSON-encoded expected answer
	CreatedAt time.Time   `json:"created_at"`
	ExpiresAt time.Time   `json:"expires_at"`
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
}

// CaptchaManager handles CAPTCHA generation and verification with Redis session storage.
type CaptchaManager struct {
	redis   *goredis.Client
	prefix  string
	timeout time.Duration

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
		sessions: make(map[string]*CaptchaSession),
	}
	// Start cleanup goroutine for in-memory sessions
	go cm.cleanupLoop()
	return cm
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
func (cm *CaptchaManager) Generate(captchaType CaptchaType) (*CaptchaChallenge, error) {
	switch captchaType {
	case CaptchaTypeMath:
		return cm.generateMath()
	case CaptchaTypeClick, CaptchaTypeSlide, CaptchaTypeRotate:
		// For image-based captcha types, fall back to math if no resources configured
		return cm.generateMath()
	default:
		return cm.generateMath()
	}
}

// Verify checks a client's CAPTCHA answer against the stored session.
func (cm *CaptchaManager) Verify(sessionID, answer string) bool {
	session, err := cm.loadSession(sessionID)
	if err != nil || session == nil {
		return false
	}
	// Delete session after verification attempt (one-time use)
	cm.deleteSession(sessionID)

	if time.Now().After(session.ExpiresAt) {
		return false
	}

	return session.Answer == answer
}

// generateMath creates a simple math CAPTCHA (addition/subtraction).
func (cm *CaptchaManager) generateMath() (*CaptchaChallenge, error) {
	a, _ := rand.Int(rand.Reader, big.NewInt(50))
	b, _ := rand.Int(rand.Reader, big.NewInt(30))
	opRand, _ := rand.Int(rand.Reader, big.NewInt(2))

	aVal := int(a.Int64()) + 1
	bVal := int(b.Int64()) + 1
	var answer int
	var expr string

	if opRand.Int64() == 0 {
		answer = aVal + bVal
		expr = fmt.Sprintf("%d + %d = ?", aVal, bVal)
	} else {
		if aVal < bVal {
			aVal, bVal = bVal, aVal
		}
		answer = aVal - bVal
		expr = fmt.Sprintf("%d - %d = ?", aVal, bVal)
	}

	sessionID := generateSessionID()
	session := &CaptchaSession{
		ID:        sessionID,
		Type:      CaptchaTypeMath,
		Answer:    fmt.Sprintf("%d", answer),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(cm.timeoutValue()),
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
	}, nil
}

// renderMathImage creates a simple PNG image containing the math expression.
func (cm *CaptchaManager) renderMathImage(expr string) string {
	width, height := 200, 80
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Background with noise
	bgColor := color.RGBA{240, 243, 248, 255}
	draw.Draw(img, img.Bounds(), &image.Uniform{bgColor}, image.Point{}, draw.Src)

	// Add noise dots
	for i := 0; i < 100; i++ {
		x, _ := rand.Int(rand.Reader, big.NewInt(int64(width)))
		y, _ := rand.Int(rand.Reader, big.NewInt(int64(height)))
		r, _ := rand.Int(rand.Reader, big.NewInt(200))
		g, _ := rand.Int(rand.Reader, big.NewInt(200))
		b, _ := rand.Int(rand.Reader, big.NewInt(200))
		img.Set(int(x.Int64()), int(y.Int64()), color.RGBA{uint8(r.Int64()), uint8(g.Int64()), uint8(b.Int64()), 255})
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

	if cm.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		key := cm.prefix + session.ID
		timeout := cm.timeoutValue()
		err := cm.redis.Set(ctx, key, data, timeout).Err()
		if err == nil {
			return nil
		}
		// Fall through to in-memory on Redis error
	}

	cm.mu.Lock()
	cm.sessions[session.ID] = session
	cm.mu.Unlock()
	return nil
}

// loadSession retrieves a session from Redis or in-memory fallback.
func (cm *CaptchaManager) loadSession(sessionID string) (*CaptchaSession, error) {
	if cm.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		key := cm.prefix + sessionID
		data, err := cm.redis.Get(ctx, key).Bytes()
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
	if cm.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		cm.redis.Del(ctx, cm.prefix+sessionID)
	}

	cm.mu.Lock()
	delete(cm.sessions, sessionID)
	cm.mu.Unlock()
}

// cleanupLoop periodically removes expired in-memory sessions.
func (cm *CaptchaManager) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		cm.mu.Lock()
		for id, s := range cm.sessions {
			if now.After(s.ExpiresAt) {
				delete(cm.sessions, id)
			}
		}
		cm.mu.Unlock()
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
