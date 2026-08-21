package challenge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/image/font/gofont/goregular"
)

/**
 * TestVerifySlideAnswerWithRealGeneration 使用真实 slide.Generate() 输出验证
 * 滑动校验的完整流程，包括 dx/dy 初始偏移量的换算语义。
 *
 * verifySlideAnswer（gocaptcha.go:497-544）从 stored answer 中读取目标坐标 (x,y)
 * 和滑块初始位置 (dx,dy)，用户提交的是相对位移 (offsetX,offsetY)，
 * 最终校验 slide.Validate(dx+offsetX, dy+offsetY, x, y, tolerance)。
 * 纯 JSON 构造的 stored answer 无法验证 dx 非零的真实场景，必须走真实 Generate()。
 */
func TestVerifySlideAnswerWithRealGeneration(t *testing.T) {
	resourceDir := t.TempDir()
	fontPath := filepath.Join(resourceDir, "default.ttf")
	if err := os.WriteFile(fontPath, goregular.TTF, 0o600); err != nil {
		t.Fatalf("write test font: %v", err)
	}

	cfg := DefaultGoCaptchaConfig()
	cfg.ResourceDir = resourceDir
	cfg.FontPath = fontPath
	provider := NewGoCaptchaProvider(cfg, nil)
	if !provider.IsAvailable() {
		t.Fatalf("go-captcha provider is unavailable: %v", provider.initErr)
	}

	tolerance := cfg.SlideTolerance
	if tolerance <= 0 {
		t.Fatalf("SlideTolerance = %d, want a positive default", tolerance)
	}

	// 生成真实滑动验证码，data 包含目标坐标 (x,y) 和滑块初始位置 (dx,dy)
	_, _, data, err := provider.GenerateSlide()
	if err != nil {
		t.Fatalf("generate slide captcha: %v", err)
	}
	if data == nil {
		t.Fatal("generated slide data is nil")
	}

	// stored answer 序列化为 JSON（包含 x, y, dx, dy）
	storedAnswer, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal slide data: %v", err)
	}

	// 验证 dx 非零（ModeBasic 下 dx = RandIntFast(5, cWidth/2)，必然 > 0）
	if data.DX <= 0 {
		t.Fatalf("slide data DX = %d, want > 0 (real Generate() must produce non-zero initial offset)", data.DX)
	}

	// 构造正确的用户答案：offsetX = targetX - dx，offsetY = targetY - dy
	// 使得 dx+offsetX == x，dy+offsetY == y，即精确命中目标
	offsetX := data.X - data.DX
	offsetY := data.Y - data.DY
	userAnswer, err := json.Marshal(map[string]int{"x": offsetX, "y": offsetY})
	if err != nil {
		t.Fatalf("marshal user answer: %v", err)
	}

	// 验证正确答案
	if !verifySlideAnswer(string(storedAnswer), string(userAnswer), tolerance) {
		t.Fatalf("valid slide answer rejected; data=%+v offsetX=%d offsetY=%d", data, offsetX, offsetY)
	}

	// 反向断言：直接提交目标坐标（不减去 dx/dy）必须被拒
	// 这正是修复前的 bug：前端提交绝对坐标而非相对位移，导致偏差恒等于 dx
	wrongAnswer, _ := json.Marshal(map[string]int{"x": data.X, "y": data.Y})
	if data.DX > tolerance {
		// 只有当 dx 超出容差时，直接提交绝对坐标才必然被拒
		if verifySlideAnswer(string(storedAnswer), string(wrongAnswer), tolerance) {
			t.Fatalf("slide answer with raw target coords (no dx offset) was accepted; dx=%d tolerance=%d", data.DX, tolerance)
		}
	}

	// 反向断言：偏移量远超容差必须被拒
	farAnswer, _ := json.Marshal(map[string]int{"x": offsetX + tolerance*10, "y": offsetY})
	if verifySlideAnswer(string(storedAnswer), string(farAnswer), tolerance) {
		t.Fatal("slide answer far off target was accepted")
	}
}

/**
 * TestVerifySlideAnswerRejectsInvalidStoredAnswer 验证 stored answer 字段完整性校验。
 */
func TestVerifySlideAnswerRejectsInvalidStoredAnswer(t *testing.T) {
	const tolerance = 5
	cases := []struct {
		name   string
		stored string
	}{
		{"missing x", `{"y":100,"dx":10,"dy":5}`},
		{"missing y", `{"x":100,"dx":10,"dy":5}`},
		{"missing dx", `{"x":100,"y":100,"dy":5}`},
		{"missing dy", `{"x":100,"y":100,"dx":10}`},
		{"negative x", `{"x":-1,"y":100,"dx":10,"dy":5}`},
		{"negative y", `{"x":100,"y":-1,"dx":10,"dy":5}`},
		{"negative dx", `{"x":100,"y":100,"dx":-1,"dy":5}`},
		{"negative dy", `{"x":100,"y":100,"dx":10,"dy":-1}`},
		{"fractional x", `{"x":10.5,"y":100,"dx":10,"dy":5}`},
		{"fractional dx", `{"x":100,"y":100,"dx":10.5,"dy":5}`},
		{"empty object", `{}`},
		{"invalid json", `not-json`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if verifySlideAnswer(tc.stored, `{"x":90,"y":95}`, tolerance) {
				t.Fatalf("invalid stored answer %s was accepted", tc.stored)
			}
		})
	}
}

/**
 * TestVerifySlideAnswerRejectsInvalidUserPoints 验证用户提交坐标的边界校验。
 */
func TestVerifySlideAnswerRejectsInvalidUserPoints(t *testing.T) {
	const tolerance = 5
	// stored: target=(100,100), initial=(10,5) => correct offset=(90,95)
	stored := `{"x":100,"y":100,"dx":10,"dy":5}`
	cases := []struct {
		name string
		user string
	}{
		{"missing x", `{"y":95}`},
		{"missing y", `{"x":90}`},
		{"negative x", `{"x":-1,"y":95}`},
		{"negative y", `{"x":90,"y":-1}`},
		{"fractional x", `{"x":90.5,"y":95}`},
		{"fractional y", `{"x":90,"y":95.5}`},
		{"far off target", `{"x":999,"y":999}`},
		{"empty object", `{}`},
		{"invalid json", `not-json`},
		{"empty string", ``},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if verifySlideAnswer(stored, tc.user, tolerance) {
				t.Fatalf("invalid user points %s was accepted", tc.user)
			}
		})
	}

	// 正例：精确命中目标（offset = target - initial = 90, 95）必须通过
	if !verifySlideAnswer(stored, `{"x":90,"y":95}`, tolerance) {
		t.Fatal("correct slide offset should be accepted")
	}

	// 正例：仅提交 x（无 y 字段），y 默认为 0，dy=5 => 绝对 y=5，与目标 y=100 差距超容差，应被拒
	if verifySlideAnswer(stored, `{"x":90}`, tolerance) {
		t.Fatal("slide answer with only x (y defaults to 0, far from target) should be rejected")
	}
}
