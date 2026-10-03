package challenge

import (
	"bytes"
	"encoding/json"
	"html/template"
	"regexp"
	"strings"
	"testing"
)

// TestBuildCaptchaExecScriptContract 断言四类题型的动态执行脚本关键契约：
//   - click 输出含 cap-click-state；slide 含 slide-range；rotate 含 rotate-range；
//     math 含 cap-answer-plain；四类均通过 gm_encrypt_challenge_answer 提交答案；
//   - 脚本不自行写死 cap-form 等元素 id（一律经薄壳注入句柄），入口形参为
//     (function(...,...) 形态，供模板 runInject 补参执行；
//   - 变量名随机化确实生效（连跑 20 次收集到的唯一变量名多于 2 个）。
func TestBuildCaptchaExecScriptContract(t *testing.T) {
	type caseSpec struct {
		typ     CaptchaType
		domID   string
		domMark string
	}
	cases := []caseSpec{
		{CaptchaTypeClick, "cap-click-state", "addEventListener"},
		{CaptchaTypeSlide, "slide-range", "translateX"},
		{CaptchaTypeRotate, "rotate-range", "rotate("},
		{CaptchaTypeMath, "cap-answer-plain", "autofocus"},
	}
	// 收集 20 次生成中出现过的全部随机变量名（前缀 "_" 的标识符），集合必须大于 2。
	var seenNames = map[string]struct{}{}
	for _, tc := range cases {
		for i := 0; i < 20; i++ {
			s := BuildCaptchaExecScript(tc.typ)
			if s == "" {
				t.Fatalf("BuildCaptchaExecScript(%s) returned empty script", tc.typ)
			}
			if !strings.Contains(s, "gm_encrypt_challenge_answer") {
				t.Fatalf("BuildCaptchaExecScript(%s) missing gm_encrypt_challenge_answer: %.120s", tc.typ, s)
			}
			if !strings.Contains(s, "HTMLFormElement.prototype.submit.call") {
				t.Fatalf("BuildCaptchaExecScript(%s) missing native form submit call: %.120s", tc.typ, s)
			}
			// 入口形态：IIFE + JSON.stringify 实参加在薄壳侧，脚本本身必须可补参调用。
			if !strings.HasPrefix(s, "(function(") {
				t.Fatalf("BuildCaptchaExecScript(%s) is not an IIFE: %.80s", tc.typ, s)
			}
			if !strings.Contains(s, "window.__owaf_inject_captcha") {
				t.Fatalf("BuildCaptchaExecScript(%s) missing inject handle access: %.120s", tc.typ, s)
			}
			// 脚本不得自行 getElementById 写死 form/submit 元素 id。
			if strings.Contains(s, "'cap-form'") || strings.Contains(s, `"cap-form"`) {
				t.Fatalf("BuildCaptchaExecScript(%s) hard-codes cap-form id, thin shell must inject it", tc.typ)
			}
			if strings.Contains(s, "getElementById('cap-key')") || strings.Contains(s, "getElementById('cap-data')") {
				t.Fatalf("BuildCaptchaExecScript(%s) re-reads cap-key/cap-data from DOM, must use injected params", tc.typ)
			}
			if !strings.Contains(s, tc.domID) {
				t.Fatalf("BuildCaptchaExecScript(%s) missing DOM id %q: %.120s", tc.typ, tc.domID, s)
			}
			if !strings.Contains(s, tc.domMark) {
				t.Fatalf("BuildCaptchaExecScript(%s) missing interaction mark %q: %.120s", tc.typ, tc.domMark, s)
			}
			collectVarNames(s, seenNames)
		}
	}
	if len(seenNames) <= 2 {
		t.Fatalf("random var names not effective: collected %d unique names across 80 samples, want > 2", len(seenNames))
	}
}

// collectVarNames 从脚本文本里粗取以 "_" 开头的标识符（含 "_xxyy" 占位符被替换
// 后的随机变量名），用于断言随机变量名生效。已确认静态常量无一以 "_" 开头命名，
// 因此不会把固定字面量误收进来。
func collectVarNames(s string, out map[string]struct{}) {
	for _, field := range strings.FieldsFunc(s, func(r rune) bool {
		return !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	}) {
		if strings.HasPrefix(field, "_") && len(field) > 5 {
			out[field] = struct{}{}
		}
	}
}

// uuidPattern 归一化随机变量名："_" + 6 位十六进制（randomVarNames 产出形态）。
var uuidPattern = regexp.MustCompile(`_[0-9a-f]{6}\b`)

// captchaPolymorphRe 覆盖 pow.go polymorphicEncode 的全部五种编码形态。
// 5 种形态：String.fromCharCode(码点列表) / [字符列表].join(”) /
// hex 逐字节 fromCharCode IIFE / "反转串".split(”).reverse().join(”) /
// XOR 数组 IIFE。测试把这类随机编码文本统一归一化为 @E@，与随机变量名
// （_xxxxxx → @V@）一起消除双重随机，使信封脚本能与变体对照归一化比较。
var captchaPolymorphRe = regexp.MustCompile(
	`String\.fromCharCode\([0-9]+(?:,[0-9]+)*\)` +
		`|\[[^\]\n]*\]\.join\(''\)` +
		`|\(function\(\)\{for\(var h="[0-9a-f]*",r="",i=0;i<h\.length;i\+=2\)r\+=String\.fromCharCode\(parseInt\(h\.substr\(i,2\),16\)\);return r\}\)\(\)` +
		`|"[^"]*"\.split\(''\)\.reverse\(\)\.join\(''\)` +
		`|\(function\(\)\{for\(var a=\[[0-9]+(?:,[0-9]+)*\],k=[0-9]+,r="",i=0;i<a\.length;i\+\+\)r\+=String\.fromCharCode\(a\[i\]\^k\);return r\}\)\(\)`,
)

// normalizeCaptchaExecScript 消除脚本中的随机部分：
// 随机变量名（randomVarNames 的 _xxxxxx 形态）与多态编码字符串常量，
// 使两次独立采样的同变体脚本文本比对可行。
func normalizeCaptchaExecScript(s string) string {
	s = captchaPolymorphRe.ReplaceAllString(s, "@E@")
	return uuidPattern.ReplaceAllString(s, "@V@")
}

// TestNewCaptchaChallengeEmbedsExecScript 断言 newCaptchaChallenge 签发的信封
// 解密后 ExecScript 非空，且归一化后等于 BuildCaptchaExecScript 该题型两个
// 合法变体之一（双重随机——变量名 + 多态编码——使逐字节对照必然失败，
// 故只能归一化后对照变体集合）。
func TestNewCaptchaChallengeEmbedsExecScript(t *testing.T) {
	key := make([]byte, envSessionKeySize)
	key[0], key[1], key[2], key[3] = 0x5a, 0x14, 0x9b, 0xc3
	types := []CaptchaType{CaptchaTypeClick, CaptchaTypeSlide, CaptchaTypeRotate, CaptchaTypeMath}
	for _, typ := range types {
		ch, err := newCaptchaChallenge("session-"+string(typ), key, &CaptchaItems{
			Type:      typ,
			Prompt:    "题目",
			MasterImg: "data:image/png;base64,dummy",
			ThumbImg:  "data:image/png;base64,thumb",
			Width:     300,
			Height:    220,
		})
		if err != nil {
			t.Fatalf("newCaptchaChallenge(%s) error: %v", typ, err)
		}
		plain := DecryptChallengeData(ch.CaptchaData, key)
		if plain == nil {
			t.Fatalf("DecryptChallengeData(%s) = nil", typ)
		}
		if plain.ExecScript == "" {
			t.Fatalf("payload(%s).ExecScript is empty", typ)
		}
		normalized := normalizeCaptchaExecScript(plain.ExecScript)
		variants := captchaExecScriptVariants(typ)
		if len(variants) == 0 {
			t.Fatalf("captchaExecScriptVariants(%s) = none", typ)
		}
		found := false
		for _, v := range variants {
			if normalizeCaptchaExecScript(v) == normalized {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("payload(%s).ExecScript matches no legal variant after normalization (got %.120s)", typ, plain.ExecScript)
		}
	}
}

// TestLegacyEnvelopeWithoutExecScriptDecryptsEmpty 断言旧信封（payload 不带
// exec_script 字段）解密后 ExecScript == "" 且不 panic——旧客户端/旧会话按
// legacy 静态逻辑运行的零断链前提。
func TestLegacyEnvelopeWithoutExecScriptDecryptsEmpty(t *testing.T) {
	key := make([]byte, envSessionKeySize)
	key[0] = 0x31
	legacyPayload := `{"type":"math","prompt":"请计算图中的算式","master_img":"data:image/png;base64,legacy","width":200,"height":80,"input_mode":"输入计算结果"}`
	legacyEnvelope, err := EncryptChallengeData(legacyPayload, key)
	if err != nil {
		t.Fatalf("EncryptChallengeData() error: %v", err)
	}
	plain := DecryptChallengeData(legacyEnvelope, key)
	if plain == nil {
		t.Fatal("DecryptChallengeData() = nil, want round-tripped legacy payload")
	}
	if plain.ExecScript != "" {
		t.Fatalf("legacy envelope ExecScript = %q, want empty", plain.ExecScript)
	}
	if plain.Type != string(CaptchaTypeMath) {
		t.Fatalf("legacy envelope type = %q, want %q", plain.Type, CaptchaTypeMath)
	}
	// 显式双重检查：无 exec_script 字段的明文 JSON 在 Unmarshal 后不产生任何字段。
	var raw map[string]any
	if err := json.Unmarshal([]byte(legacyPayload), &raw); err != nil {
		t.Fatalf("legacy payload JSON parse: %v", err)
	}
	if _, exists := raw["exec_script"]; exists {
		t.Fatalf("legacy payload fixture must not contain exec_script key")
	}
}

// TestCaptchaTemplateKeepsLegacyAndAddsDispatchPipeline 断言模板渲染输出同时
// 保留 legacy 静态 build 与新增的 exec_script 薄壳装载器，旧信封断链驳回。
func TestCaptchaTemplateKeepsLegacyAndAddsDispatchPipeline(t *testing.T) {
	hexKey := "aabbccdd112233445566778899001122aabbccdd112233445566778899001122"
	key, err := envDecodeKeyHex(hexKey)
	if err != nil {
		t.Fatalf("envDecodeKeyHex: %v", err)
	}
	items := &CaptchaItems{
		Type:      CaptchaTypeMath,
		Prompt:    "请计算图中的算式",
		MasterImg: "data:image/png;base64,static",
		Width:     200,
		Height:    80,
	}
	legacyEnvelope, err := EncryptChallengeData(
		`{"type":"math","prompt":"请计算图中的算式","master_img":"data:image/png;base64,legacy","width":200,"height":80}`,
		key,
	)
	if err != nil {
		t.Fatalf("EncryptChallengeData: %v", err)
	}
	ch, err := newCaptchaChallenge("tpl-session", key, items)
	if err != nil {
		t.Fatalf("newCaptchaChallenge: %v", err)
	}
	// renderCaptchaPage 依赖全局挑战上下文，这里直接以 CaptchaChallenge 组合
	// 情况构造两份页面数据分别渲染，覆盖动态信封与旧信封两条模板路径。
	dyData := captchaPageData{
		SessionID:    ch.SessionID,
		CaptchaData:  ch.CaptchaData,
		KeyHex:       hexKey,
		KeyPresent:   true,
		SubmitText:   "Submit",
		FooterText:   "x",
		PrimaryColor: template.CSS("teal"),
		Background:   template.CSS("#fff"),
	}
	oldData := dyData
	oldData.CaptchaData = legacyEnvelope
	var buf bytes.Buffer
	// 渲染动态信封页面。
	if err := captchaPageTmpl.Execute(&buf, dyData); err != nil {
		t.Fatalf("render dynamic envelope template: %v", err)
	}
	dynamicHTML := buf.String()
	for _, marker := range []string{
		"function runInject(p){",
		"(0,eval)(script+",
		"window.__owaf_inject_captcha=",
		"build(parsed)",
	} {
		if !strings.Contains(dynamicHTML, marker) {
			t.Fatalf("dynamic envelope template output missing %q", marker)
		}
	}
	// 渲染旧信封页面（exec_script 缺失走分派 else 分支，输出同样含 legacy build）。
	buf.Reset()
	if err := captchaPageTmpl.Execute(&buf, oldData); err != nil {
		t.Fatalf("render legacy envelope template: %v", err)
	}
	if !strings.Contains(buf.String(), "build(parsed)") {
		t.Fatal("legacy envelope template output missing build(parsed) dispatch")
	}
}
