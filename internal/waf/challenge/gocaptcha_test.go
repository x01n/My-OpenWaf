package challenge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/image/font/gofont/goregular"
)

func TestCaptchaManagerGeneratesSlideWhenGoCaptchaAvailable(t *testing.T) {
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

	master, tile, _, err := provider.GenerateSlide()
	if err != nil {
		t.Fatalf("generate slide captcha from provider: %v", err)
	}
	if master == "" || tile == "" {
		t.Fatal("provider did not return both generated images")
	}

	manager := NewCaptchaManager(nil, time.Minute)
	defer manager.Close()
	manager.SetGoCaptchaProvider(provider)

	challenge, err := manager.Generate(CaptchaTypeSlide, false)
	if err != nil {
		t.Fatalf("generate slide captcha: %v", err)
	}
	if challenge.Type != string(CaptchaTypeSlide) {
		t.Fatalf("generated captcha type = %q, want %q", challenge.Type, CaptchaTypeSlide)
	}
	if challenge.Fallback {
		t.Fatal("available go-captcha provider unexpectedly marked slide challenge as fallback")
	}
	if challenge.MasterImg == "" || challenge.ThumbImg == "" {
		t.Fatal("slide challenge did not include both generated images")
	}
	if !strings.HasPrefix(challenge.MasterImg, "data:image/jpeg;base64,") {
		t.Fatal("slide master image is not a JPEG data URI")
	}
	if !strings.HasPrefix(challenge.ThumbImg, "data:image/png;base64,") {
		t.Fatal("slide tile image is not a PNG data URI")
	}
	if strings.HasPrefix(challenge.MasterImg, "data:image/jpeg;base64,data:") || strings.HasPrefix(challenge.ThumbImg, "data:image/png;base64,data:") {
		t.Fatal("slide challenge contains a nested data URI prefix")
	}
}

/**
 * TestVerifySlideAnswerAcceptsVisuallyAlignedOffset 用真实 slide.Generate() 输出验证
 * 滑动校验的坐标系换算。
 *
 * 这个回归用例必须使用真实 Block：前端模板提交的是 range 滑块的相对位移量，而
 * slide.Validate 的 sx/sy 契约是绝对坐标，两者相差滑块初始位置 dx。go-captcha 在
 * ModeBasic 下 dx = RandIntFast(5, cWidth/2) 恒非零（实测 10..28 px），而默认容差
 * 仅 5 px，因此缺少 dx 补偿时用户拖到视觉对齐处必然被拒。
 *
 * 纯 JSON 构造的 stored answer（dx 缺省为 0）无法暴露该缺陷 —— 这正是它此前未被
 * 发现的原因，所以这里坚持走 Generate()。
 */
func TestVerifySlideAnswerAcceptsVisuallyAlignedOffset(t *testing.T) {
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

	// 多轮取样：dx 是随机值，单次生成可能恰好落在容差内而掩盖坐标系错误。
	const rounds = 8
	sawNonZeroOrigin := false
	for i := 0; i < rounds; i++ {
		_, _, block, err := provider.GenerateSlide()
		if err != nil {
			t.Fatalf("generate slide captcha: %v", err)
		}
		storedAnswer, err := json.Marshal(block)
		if err != nil {
			t.Fatalf("marshal slide block: %v", err)
		}
		if block.DX > 0 {
			sawNonZeroOrigin = true
		}

		// 用户拖到视觉对齐位置时，range 值等于目标位置减去滑块初始位置。
		alignedOffset := block.X - block.DX
		userAnswer := `{"x":` + strconv.Itoa(alignedOffset) + `}`
		if !verifySlideAnswer(string(storedAnswer), userAnswer, tolerance) {
			t.Fatalf("round %d: visually aligned offset %d rejected (x=%d dx=%d tolerance=%d); "+
				"slide.Validate expects absolute coordinates, so dx must be added back",
				i, alignedOffset, block.X, block.DX, tolerance)
		}

		// 反向断言：把位移量当绝对坐标直接提交必须被拒，否则说明换算被绕过、
		// 容差被放大到足以掩盖 dx 偏差。
		if block.DX > tolerance {
			rawAnswer := `{"x":` + strconv.Itoa(block.X) + `}`
			if verifySlideAnswer(string(storedAnswer), rawAnswer, tolerance) {
				t.Fatalf("round %d: raw target x=%d accepted as an offset (dx=%d tolerance=%d), "+
					"the offset-to-absolute conversion is not being applied",
					i, block.X, block.DX, tolerance)
			}
		}
	}

	if !sawNonZeroOrigin {
		t.Fatalf("no generated block had a non-zero dx across %d rounds; "+
			"the regression this test guards cannot be observed", rounds)
	}
}

/**
 * TestVerifySlideAnswerRejectsIncompleteStoredAnswer 验证缺少坐标原点字段的
 * stored answer 被拒绝，而不是把缺失字段当作 0 静默放宽校验。
 */
func TestVerifySlideAnswerRejectsIncompleteStoredAnswer(t *testing.T) {
	const tolerance = 5
	cases := []struct {
		name   string
		stored string
	}{
		{"missing dx", `{"x":120,"y":60,"dy":60}`},
		{"missing dy", `{"x":120,"y":60,"dx":30}`},
		{"missing y", `{"x":120,"dx":30,"dy":60}`},
		{"missing x", `{"y":60,"dx":30,"dy":60}`},
		{"negative dx", `{"x":120,"y":60,"dx":-1,"dy":60}`},
		{"non numeric dx", `{"x":120,"y":60,"dx":"30","dy":60}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if verifySlideAnswer(tc.stored, `{"x":90}`, tolerance) {
				t.Fatalf("incomplete stored answer %s was accepted", tc.stored)
			}
		})
	}
}

/**
 * TestVerifySlideAnswerRejectsInvalidUserOffset 验证用户提交的位移量本身的边界校验。
 */
func TestVerifySlideAnswerRejectsInvalidUserOffset(t *testing.T) {
	const tolerance = 5
	stored := `{"x":120,"y":60,"dx":30,"dy":60}`
	cases := []struct {
		name string
		user string
	}{
		{"missing x", `{}`},
		{"negative x", `{"x":-5}`},
		{"non numeric x", `{"x":"90"}`},
		{"fractional x", `{"x":90.5}`},
		{"negative y", `{"x":90,"y":-1}`},
		{"far off target", `{"x":10}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if verifySlideAnswer(stored, tc.user, tolerance) {
				t.Fatalf("invalid user offset %s was accepted", tc.user)
			}
		})
	}

	// 正例：视觉对齐位移（120-30=90）必须通过，确认上面的拒绝不是因为整体失效。
	if !verifySlideAnswer(stored, `{"x":90}`, tolerance) {
		t.Fatal("visually aligned offset 90 should be accepted for dx=30 x=120")
	}
}
