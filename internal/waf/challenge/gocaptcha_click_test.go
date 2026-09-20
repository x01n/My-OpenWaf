package challenge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/image/font/gofont/goregular"
)

/**
 * TestVerifyClickAnswerWithRealGeneration 使用真实 click.Generate() 输出验证
 * 点击校验的完整流程，包括 rangeCheckDots 的索引重写语义。
 *
 * click.rangeCheckDots（click.go:347-372）从全量 dots 中随机选取验证子集，并把
 * 子集的 Index 重写为连续 0..N-1，与 go-captcha 官方 Validate 的循环顺序契约一致。
 * 纯 JSON 构造的 stored answer 无法验证这层映射逻辑，必须走真实 Generate()。
 */
func TestVerifyClickAnswerWithRealGeneration(t *testing.T) {
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

	tolerance := cfg.ClickTolerance
	if tolerance <= 0 {
		t.Fatalf("ClickTolerance = %d, want a positive default", tolerance)
	}

	// 生成真实点击验证码，data 是 rangeCheckDots 返回的验证子集（Index 已重写为 0..N-1）
	_, _, data, err := provider.GenerateClick()
	if err != nil {
		t.Fatalf("generate click captcha: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("generated click data is empty")
	}

	storedAnswer, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal click data: %v", err)
	}

	// 构造按索引顺序点击的用户答案：点击每个 dot 的中心点
	var userPoints []ClickPoint
	for i := 0; i < len(data); i++ {
		dot, ok := data[i]
		if !ok {
			t.Fatalf("missing dot at index %d", i)
		}
		// 点击 dot 的中心：x + width/2, y + height/2（y 已是左上角）
		userPoints = append(userPoints, ClickPoint{
			X: dot.X + dot.Width/2,
			Y: dot.Y + dot.Height/2,
		})
	}
	userAnswer, err := json.Marshal(userPoints)
	if err != nil {
		t.Fatalf("marshal user points: %v", err)
	}

	// 验证正确答案
	if !verifyClickAnswer(string(storedAnswer), string(userAnswer), tolerance) {
		t.Fatalf("valid click answer rejected; data=%+v userPoints=%+v", data, userPoints)
	}

	// 反向断言：点数不匹配必须被拒
	wrongCount := userPoints[:len(userPoints)-1]
	wrongAnswer, _ := json.Marshal(wrongCount)
	if verifyClickAnswer(string(storedAnswer), string(wrongAnswer), tolerance) {
		t.Fatal("click answer with wrong point count was accepted")
	}

	// 反向断言：顺序错误必须被拒（交换前两个点）
	if len(userPoints) >= 2 {
		swapped := make([]ClickPoint, len(userPoints))
		copy(swapped, userPoints)
		swapped[0], swapped[1] = swapped[1], swapped[0]
		swappedAnswer, _ := json.Marshal(swapped)
		if verifyClickAnswer(string(storedAnswer), string(swappedAnswer), tolerance) {
			t.Fatal("click answer with swapped order was accepted")
		}
	}
}

/**
 * TestVerifyClickAnswerRejectsInvalidStoredAnswer 验证 stored answer 字段完整性校验。
 */
func TestVerifyClickAnswerRejectsInvalidStoredAnswer(t *testing.T) {
	const tolerance = 20
	cases := []struct {
		name   string
		stored string
	}{
		{"missing index", `{"0":{"x":10,"y":20,"width":30,"height":30}}`},
		{"negative index", `{"0":{"index":-1,"x":10,"y":20,"width":30,"height":30}}`},
		{"index out of bounds", `{"0":{"index":5,"x":10,"y":20,"width":30,"height":30}}`},
		{"duplicate index", `{"0":{"index":0,"x":10,"y":20,"width":30,"height":30},"1":{"index":0,"x":50,"y":60,"width":30,"height":30}}`},
		{"missing x", `{"0":{"index":0,"y":20,"width":30,"height":30}}`},
		{"missing y", `{"0":{"index":0,"x":10,"width":30,"height":30}}`},
		{"negative x", `{"0":{"index":0,"x":-1,"y":20,"width":30,"height":30}}`},
		{"negative y", `{"0":{"index":0,"x":10,"y":-1,"width":30,"height":30}}`},
		{"missing width", `{"0":{"index":0,"x":10,"y":20,"height":30}}`},
		{"missing height", `{"0":{"index":0,"x":10,"y":20,"width":30}}`},
		{"zero width", `{"0":{"index":0,"x":10,"y":20,"width":0,"height":30}}`},
		{"zero height", `{"0":{"index":0,"x":10,"y":20,"width":30,"height":0}}`},
		{"negative width", `{"0":{"index":0,"x":10,"y":20,"width":-10,"height":30}}`},
		{"negative height", `{"0":{"index":0,"x":10,"y":20,"width":30,"height":-10}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if verifyClickAnswer(tc.stored, `[{"x":25,"y":35}]`, tolerance) {
				t.Fatalf("invalid stored answer %s was accepted", tc.stored)
			}
		})
	}
}

/**
 * TestVerifyClickAnswerRejectsInvalidUserPoints 验证用户提交坐标的边界校验。
 */
func TestVerifyClickAnswerRejectsInvalidUserPoints(t *testing.T) {
	const tolerance = 20
	stored := `{"0":{"index":0,"x":10,"y":20,"width":30,"height":30}}`
	cases := []struct {
		name string
		user string
	}{
		{"missing x", `[{"y":35}]`},
		{"missing y", `[{"x":25}]`},
		{"negative x", `[{"x":-5,"y":35}]`},
		{"negative y", `[{"x":25,"y":-5}]`},
		{"non numeric x", `[{"x":"25","y":35}]`},
		{"non numeric y", `[{"x":25,"y":"35"}]`},
		{"fractional x", `[{"x":25.5,"y":35}]`},
		{"fractional y", `[{"x":25,"y":35.5}]`},
		{"far off target", `[{"x":999,"y":999}]`},
		{"empty array", `[]`},
		{"wrong count", `[{"x":25,"y":35},{"x":60,"y":75}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if verifyClickAnswer(stored, tc.user, tolerance) {
				t.Fatalf("invalid user points %s was accepted", tc.user)
			}
		})
	}

	// 正例：点击 dot 中心点必须通过（中心 = x+width/2, y+height/2 = 10+15, 20+15 = 25, 35）
	if !verifyClickAnswer(stored, `[{"x":25,"y":35}]`, tolerance) {
		t.Fatal("click on center point should be accepted")
	}
}

/**
 * TestVerifyClickAnswerRejectsMalformedJSON 验证 stored 与 user 两侧的 JSON 结构异常。
 *
 * 覆盖非 JSON 文本、类型错位（数组/对象互换）、null 字面量、空对象、字段值为 null、
 * 小数与超出 int 范围的数值。这些形态都应在反序列化或 getInt 阶段被拒。
 */
func TestVerifyClickAnswerRejectsMalformedJSON(t *testing.T) {
	const tolerance = 20
	const validStored = `{"0":{"index":0,"x":10,"y":20,"width":30,"height":30}}`
	const validUser = `[{"x":25,"y":35}]`

	storedCases := []struct {
		name   string
		stored string
	}{
		{"not json", `not json at all`},
		{"truncated json", `{"0":{"index":0,`},
		{"array instead of object", `[{"index":0,"x":10,"y":20,"width":30,"height":30}]`},
		{"null literal", `null`},
		{"empty object", `{}`},
		{"dot value is string", `{"0":"abc"}`},
		{"dot value is empty object", `{"0":{}}`},
		{"index is null", `{"0":{"index":null,"x":10,"y":20,"width":30,"height":30}}`},
		{"index is fractional", `{"0":{"index":0.5,"x":10,"y":20,"width":30,"height":30}}`},
		{"x is fractional", `{"0":{"index":0,"x":10.5,"y":20,"width":30,"height":30}}`},
		{"width is fractional", `{"0":{"index":0,"x":10,"y":20,"width":30.5,"height":30}}`},
		{"x is string", `{"0":{"index":0,"x":"10","y":20,"width":30,"height":30}}`},
		{"x is bool", `{"0":{"index":0,"x":true,"y":20,"width":30,"height":30}}`},
		{"index overflows int", `{"0":{"index":1e20,"x":10,"y":20,"width":30,"height":30}}`},
		{"x overflows int", `{"0":{"index":0,"x":1e20,"y":20,"width":30,"height":30}}`},
	}
	for _, tc := range storedCases {
		t.Run("stored/"+tc.name, func(t *testing.T) {
			if verifyClickAnswer(tc.stored, validUser, tolerance) {
				t.Fatalf("malformed stored answer %s was accepted", tc.stored)
			}
		})
	}

	userCases := []struct {
		name string
		user string
	}{
		{"not json", `not json at all`},
		{"truncated json", `[{"x":25,`},
		{"object instead of array", `{"x":25,"y":35}`},
		{"null literal", `null`},
		{"array of nulls", `[null]`},
		{"array of numbers", `[25]`},
	}
	for _, tc := range userCases {
		t.Run("user/"+tc.name, func(t *testing.T) {
			if verifyClickAnswer(validStored, tc.user, tolerance) {
				t.Fatalf("malformed user answer %s was accepted", tc.user)
			}
		})
	}
}

/**
 * TestVerifyClickAnswerToleranceBoundary 验证容差窗口的精确边界。
 *
 * click.Validate（click/validate.go:21-31）的接受域为
 * sx ∈ [max(dx, dx-padding), max(dx, dx-padding)+width+2*padding]，sy 同理。
 * 对 dot(x=10, y=20, w=30, h=30)：padding=20 时 sx ∈ [10,80]、sy ∈ [20,90]；
 * padding=0 时收缩为 sx ∈ [10,40]、sy ∈ [20,50]。负容差在进入 Validate 前即被拒。
 */
func TestVerifyClickAnswerToleranceBoundary(t *testing.T) {
	const stored = `{"0":{"index":0,"x":10,"y":20,"width":30,"height":30}}`
	cases := []struct {
		name      string
		user      string
		tolerance int
		want      bool
	}{
		{"tol20 left edge inside", `[{"x":10,"y":35}]`, 20, true},
		{"tol20 left edge outside", `[{"x":9,"y":35}]`, 20, false},
		{"tol20 right edge inside", `[{"x":80,"y":35}]`, 20, true},
		{"tol20 right edge outside", `[{"x":81,"y":35}]`, 20, false},
		{"tol20 top edge inside", `[{"x":25,"y":20}]`, 20, true},
		{"tol20 top edge outside", `[{"x":25,"y":19}]`, 20, false},
		{"tol20 bottom edge inside", `[{"x":25,"y":90}]`, 20, true},
		{"tol20 bottom edge outside", `[{"x":25,"y":91}]`, 20, false},
		{"tol20 corner inside", `[{"x":80,"y":90}]`, 20, true},
		{"tol0 left top edge inside", `[{"x":10,"y":20}]`, 0, true},
		{"tol0 right bottom edge inside", `[{"x":40,"y":50}]`, 0, true},
		{"tol0 right edge outside", `[{"x":41,"y":50}]`, 0, false},
		{"tol0 bottom edge outside", `[{"x":40,"y":51}]`, 0, false},
		{"negative tolerance rejects valid point", `[{"x":25,"y":35}]`, -1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := verifyClickAnswer(stored, tc.user, tc.tolerance); got != tc.want {
				t.Fatalf("verifyClickAnswer(%s, tolerance=%d) = %v, want %v",
					tc.user, tc.tolerance, got, tc.want)
			}
		})
	}
}

/**
 * TestVerifyClickAnswerOrdersDotsByIndexField 验证点击顺序由 dot 的 index 字段决定，
 * 而非 stored map 的键顺序。
 *
 * stored 的 map 键与 index 字段刻意错位（键 "0" 承载 index=1），因此若实现按键顺序
 * 比对就会把用户第一个点匹配到错误的 dot，正例将失败。
 */
func TestVerifyClickAnswerOrdersDotsByIndexField(t *testing.T) {
	const tolerance = 20
	const stored = `{"0":{"index":1,"x":100,"y":100,"width":30,"height":30},` +
		`"1":{"index":0,"x":10,"y":20,"width":30,"height":30}}`

	// 按 index 升序点击各 dot 中心：index=0 → (25,35)，index=1 → (115,115)
	if !verifyClickAnswer(stored, `[{"x":25,"y":35},{"x":115,"y":115}]`, tolerance) {
		t.Fatal("clicks ordered by index field should be accepted")
	}
	// 按 map 键顺序点击必须被拒
	if verifyClickAnswer(stored, `[{"x":115,"y":115},{"x":25,"y":35}]`, tolerance) {
		t.Fatal("clicks ordered by map key were accepted")
	}
}
