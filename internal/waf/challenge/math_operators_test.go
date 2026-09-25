package challenge

import (
	"encoding/base64"
	"fmt"
	"image/png"
	"strings"
	"testing"
)

/**
 * TestMathProblemOperatorsAndUniformity 验证扩展后的加减除题面：
 * 题面可解析、运算结果与答案一致、三种运算符都会出现、
 * 答案仍落在 [mathAnswerMin, mathAnswerMax] 均匀区间内。
 * 乘法题面不在题库中（详见 randomMathProblem 注释），仅校验除法的整除语义。
 */
func TestMathProblemOperatorsAndUniformity(t *testing.T) {
	freq := make(map[int]int, 2000)
	operators := make(map[string]int)
	const samples = 8000
	for i := 0; i < samples; i++ {
		expr, answer := randomMathProblem()
		if answer < mathAnswerMin || answer > mathAnswerMax {
			t.Fatalf("answer %d outside declared range for %q", answer, expr)
		}
		freq[answer]++

		var a, b int
		var op string
		if _, err := fmt.Sscanf(expr, "%d %s %d = ?", &a, &op, &b); err != nil {
			t.Fatalf("unparsable expression %q: %v", expr, err)
		}
		want := 0
		switch op {
		case "+":
			want = a + b
		case "-":
			want = a - b
		case "÷":
			if b == 0 || a%b != 0 {
				t.Fatalf("division problem must be exact, got %q", expr)
			}
			want = a / b
		default:
			t.Fatalf("unexpected operator %q in %q", op, expr)
		}
		if want != answer {
			t.Fatalf("expression %q evaluates to %d, stored answer is %d", expr, want, answer)
		}
		operators[op]++
	}
	for _, op := range []string{"+", "-", "÷"} {
		if operators[op] == 0 {
			t.Errorf("operator %q never appeared in %d samples", op, samples)
		}
	}
	maxCount := 0
	for _, n := range freq {
		if n > maxCount {
			maxCount = n
		}
	}
	if best := float64(maxCount) / float64(samples); best > 0.01 {
		t.Fatalf("most frequent math captcha answer hit rate = %.4f (>1%%), distinct answers = %d", best, len(freq))
	}
	if len(freq) < 200 {
		t.Fatalf("math captcha answer space too small: %d distinct answers", len(freq))
	}
}

/**
 * TestRenderMathImageIsDecodablePNG 验证内置算式验证码图片输出为有效 PNG：
 * 扩展题面字符（×/÷）经过 5x5 点阵回退路径与干扰线绘制后仍可被解码，
 * 且渲染失败时不回落为明文提示。
 */
func TestRenderMathImageIsDecodablePNG(t *testing.T) {
	cm := &CaptchaManager{}
	for _, expr := range []string{
		"381 + 47 = ?",
		"905 - 66 = ?",
		"12 × 34 = ?",
		"9990 ÷ 10 = ?",
	} {
		encoded := cm.renderMathImage(expr)
		if !strings.HasPrefix(encoded, "") && !strings.HasPrefix(encoded, "data:") {
			t.Fatalf("renderMathImage(%q) returned an invalid base64 payload", expr)
		}
		if strings.HasPrefix(encoded, "data:") {
			encoded = strings.TrimPrefix(encoded, "data:image/png;base64,")
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("renderMathImage(%q) produced invalid base64: %v", expr, err)
		}
		img, err := png.Decode(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatalf("renderMathImage(%q) produced an undecodable PNG: %v", expr, err)
		}
		bounds := img.Bounds()
		if bounds.Dx() != 200 || bounds.Dy() != 80 {
			t.Fatalf("renderMathImage(%q) size = %dx%d, want 200x80", expr, bounds.Dx(), bounds.Dy())
		}
	}
}
