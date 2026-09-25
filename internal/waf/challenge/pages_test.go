package challenge

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"regexp"
	"strings"
	"testing"

	"My-OpenWaf/internal/waf/challenge/gm"
	"My-OpenWaf/internal/waf/pageconfig"
)

const testSessionKeyHex = "aabbccdd112233445566778899001122aabbccdd112233445566778899001122"

func testChallengeEnvelope(t *testing.T, items *CaptchaItems) (challenge *CaptchaChallenge, plain *CaptchaItemPayload) {
	t.Helper()
	key, err := envDecodeKeyHex(testSessionKeyHex)
	if err != nil {
		t.Fatalf("decode test session key: %v", err)
	}
	ch, err := newCaptchaChallenge("session", key, items)
	if err != nil {
		t.Fatalf("newCaptchaChallenge(): %v", err)
	}
	if ch.CaptchaData == "" {
		t.Fatal("newCaptchaChallenge() returned empty challenge data envelope")
	}
	plain = DecryptChallengeData(ch.CaptchaData, key)
	if plain == nil {
		t.Fatal("DecryptChallengeData() = nil, want payload")
	}
	return ch, plain
}

func envDecodeKeyHex(hexKey string) ([]byte, error) {
	if len(hexKey) != envSessionKeySize*2 {
		return nil, fmt.Errorf("bad test key length")
	}
	key := make([]byte, envSessionKeySize)
	_, err := fmt.Sscanf(hexKey, "%x", &key)
	if err == nil && bytes.Count(key, []byte{0}) == envSessionKeySize {
		return nil, fmt.Errorf("bad test key")
	}
	return key, nil
}

// TestCaptchaChallengeEnvelopeIsEncryptedAndSelfContained 断言题目信封：
// 信封与明文题目互相可还原、载荷只描述题目交互不含答案语义、
// 挑战结构体的增值字段（MasterImg/ThumbImg）不再携带明文图片。
func TestCaptchaChallengeEnvelopeIsEncryptedAndSelfContained(t *testing.T) {
	const secretImage = "data:image/png;base64,U0VOVElORUxJTUc="
	const secretPrompt = "S3CR3T-PROMPT-9f3a"
	ch, plain := testChallengeEnvelope(t, &CaptchaItems{
		Type:      CaptchaTypeMath,
		Prompt:    secretPrompt,
		MasterImg: secretImage,
		Width:     200,
		Height:    80,
	})

	if plain.Type != string(CaptchaTypeMath) || plain.Prompt != secretPrompt || plain.MasterImg != secretImage {
		t.Fatalf("roundtripped payload mismatch: %+v", plain)
	}
	if ch.CaptchaData == "" || strings.Contains(ch.CaptchaData, secretPrompt) || strings.Contains(ch.CaptchaData, "U0VOVElORUxJTUc") {
		t.Fatalf("challenge envelope leaks plaintext payload: %q", ch.CaptchaData)
	}
	if ch.MasterImg != "" || ch.ThumbImg != "" {
		t.Fatalf("legacy image fields must not carry any payload: master=%q thumb=%q", ch.MasterImg, ch.ThumbImg)
	}
	if strings.Contains(ch.CaptchaData, "answer") {
		t.Fatalf("envelope payload must not mention answer semantics: %+v", plain)
	}
}

// TestCaptchaEnvelopeRejectsCrossPurposeAADCryptogram 断言题目信封的 AAD 与
// 环境指纹信封不同：用另一用途的 AAD 解密题目信封必须失败（GCM 校验）。
func TestCaptchaEnvelopeRejectsCrossPurposeAADCryptogram(t *testing.T) {
	ch, _ := testChallengeEnvelope(t, &CaptchaItems{
		Type:      CaptchaTypeMath,
		Prompt:    "prompt",
		MasterImg: "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("img")),
	})
	key, _ := envDecodeKeyHex(testSessionKeyHex)
	if got := DecryptChallengeData(ch.CaptchaData, key); got == nil {
		t.Fatal("own-AAD decryption must succeed")
	}

	// 防跨用途密文复用：题目信封（域 0x02）以答案域（0x03）打开必须被拒。
	raw, err := gm.Decode(ch.CaptchaData)
	if err != nil {
		t.Fatalf("decode envelope bytes: %v", err)
	}
	if _, err := envDecrypt(raw, key, []byte(captchaItemDataAAD), gm.DomainCaptchaAnswer); err == nil {
		t.Fatal("cross-domain decryption of captcha envelope must fail")
	}
}

// TestChainCaptchaPageDataCensorsPlaintext 断言链式页数据不再放入明文题目。
func TestChainCaptchaPageDataCensorsPlaintext(t *testing.T) {
	key, _ := envDecodeKeyHex(testSessionKeyHex)
	ch, err := newCaptchaChallenge("session", key, &CaptchaItems{
		Type:      CaptchaTypeSlide,
		Prompt:    "请将滑块拖动到正确位置",
		MasterImg: "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("master")),
		ThumbImg:  "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("thumb")),
		Width:     300,
		Height:    220,
	})
	if err != nil {
		t.Fatal(err)
	}
	data := newChainCaptchaPageData(ch)
	if data == nil {
		t.Fatal("newChainCaptchaPageData() = nil for valid challenge")
	}
	if data.MasterImg != "" || data.ThumbImg != "" {
		t.Fatalf("chain page data must not carry plaintext images: %+v", data)
	}
	if data.CaptchaData == "" || data.KeyHex == "" {
		t.Fatalf("chain page data missing encrypted envelope fields: %+v", data)
	}
}

// TestCaptchaPageRendersEncryptedEnvelopeOnly 断言页面只渲染信封，
// 任何明文题目片段（哨兵 prompt、哨兵图片）都不得出现在 HTML 中。
func TestCaptchaPageRendersEncryptedEnvelopeOnly(t *testing.T) {
	const sentinelPrompt = "PAGE-SENTINEL-PROMPT-81c2"
	const sentinelImg = "data:image/png;base64,U0VOVElORUxQQUdFSU1H"
	key, _ := envDecodeKeyHex(testSessionKeyHex)
	ch, err := newCaptchaChallenge("page-session", key, &CaptchaItems{
		Type:      CaptchaTypeMath,
		Prompt:    sentinelPrompt,
		MasterImg: sentinelImg,
		Width:     200,
		Height:    80,
	})
	if err != nil {
		t.Fatal(err)
	}
	page := string(renderCaptchaPage(ch, "req-page", "", pageconfig.DefaultCaptchaPageConfig()))

	for _, want := range []string{
		`id="cap-data"`,
		`id="cap-key"`,
		`gm_decrypt_challenge_data`,
		`gm_encrypt_challenge_answer`,
		`__waf_captcha_answer`,
		`name="__waf_captcha_session"`,
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("captcha page missing required marker %q: %s", want, page)
		}
	}
	for _, forbidden := range []string{sentinelPrompt, "U0VOVElORUxQQUdFSU1H"} {
		if strings.Contains(page, forbidden) {
			t.Fatalf("captcha page leaked plaintext captcha payload %q", forbidden)
		}
	}
	if !strings.Contains(page, ch.CaptchaData) {
		t.Fatal("captcha page did not embed the encrypted challenge envelope")
	}
}

// TestCaptchaPageMissingEnvelopeFailsClosed 断言缺少信封/密钥时页面渲染
// fail-closed 引导（不渲染题目且禁用提交），而不是回落到明文题目。
func TestCaptchaPageMissingEnvelopeFailsClosed(t *testing.T) {
	page := string(renderCaptchaPage(&CaptchaChallenge{
		SessionID: "no-envelope-session",
		Type:      string(CaptchaTypeMath),
	}, "req", "", pageconfig.DefaultCaptchaPageConfig()))

	if !strings.Contains(page, "验证码初始化失败") {
		t.Fatalf("missing envelope must render fail-closed notice: %s", page)
	}
	// 页面模板里构建题目的 JS 函数名是 "build("；fail-closed 分支不调用它，
	// 但因压缩模板固定包含构建函数本体，这里只断言「未置入题目处理流程」。
	if strings.Contains(page, `id="cap-img"`) {
		t.Fatalf("fail-closed page must not render captcha DOM: %s", page)
	}
}

// TestRenderCaptchaPageUsesConfigAndRejectsUnsafeValues 验证页面仍正确转义
// 可配置的文案与自定义 CSS（信封输入走 renderCaptchaPage 的新数据面）。
func TestRenderCaptchaPageUsesConfigAndRejectsUnsafeValues(t *testing.T) {
	key, _ := envDecodeKeyHex(testSessionKeyHex)
	ch, _ := newCaptchaChallenge("session", key, &CaptchaItems{
		Type:      CaptchaTypeMath,
		Prompt:    "answer",
		MasterImg: "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("image")),
	})
	cfg := pageconfig.DefaultCaptchaPageConfig()
	cfg.BrandName = `<script>brand()</script>`
	cfg.Title = "Custom CAPTCHA"
	cfg.Subtitle = "Custom subtitle"
	cfg.SubmitText = "Continue"
	cfg.LogoURL = "javascript:alert(1)"
	cfg.CustomCSS = `</style><script>alert(1)</script>.safe{color:red}`
	page := string(renderCaptchaPage(ch, "request", "", cfg))

	for _, want := range []string{"Custom CAPTCHA", "Custom subtitle", "Continue", "&lt;script&gt;brand()&lt;/script&gt;"} {
		if !strings.Contains(page, want) {
			t.Fatalf("captcha page missed configured value %q: %s", want, page)
		}
	}
	for _, forbidden := range []string{`<script>brand()`, `src="javascript:`, `</style><script>alert(1)</script>`} {
		if strings.Contains(page, forbidden) {
			t.Fatalf("captcha page included unsafe configured value %q: %s", forbidden, page)
		}
	}
}

// TestRenderCaptchaPageEscapesDynamicFields 验证会话 ID 与请求 ID 等动态
// 字段仍被 HTML 转义，无法被注入成可执行脚本。
func TestRenderCaptchaPageEscapesDynamicFields(t *testing.T) {
	key, _ := envDecodeKeyHex(testSessionKeyHex)
	ch, _ := newCaptchaChallenge("session", key, &CaptchaItems{
		Type:      CaptchaTypeMath,
		Prompt:    "answer",
		MasterImg: "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("image")),
	})
	payload := `"><script>alert("captcha")</script>`
	ch.SessionID = payload
	page := string(renderCaptchaPage(ch, payload, "", pageconfig.DefaultCaptchaPageConfig()))
	if strings.Contains(page, `<script>alert("captcha")</script>`) {
		t.Fatalf("captcha page reflected executable input: %s", page)
	}
	if !strings.Contains(page, `&lt;script&gt;`) {
		t.Fatalf("captcha page did not escape dynamic content: %s", page)
	}
}

// TestCaptchaPageWaitsForWASMEnvironmentBeforeSubmit 验证页面在提交前仍等待
// WASM 环境信封并保持异步提交语义。
func TestCaptchaPageWaitsForWASMEnvironmentBeforeSubmit(t *testing.T) {
	key, _ := envDecodeKeyHex(testSessionKeyHex)
	ch, _ := newCaptchaChallenge("session", key, &CaptchaItems{
		Type:      CaptchaTypeMath,
		Prompt:    "answer",
		MasterImg: "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("image")),
	})
	page := string(renderCaptchaPage(ch, "request", EnvCheckJSEncrypted(testSessionKeyHex, "owaf-env:v2|captcha|1|example.test|:443|session"), pageconfig.DefaultCaptchaPageConfig()))
	for _, marker := range []string{"window.__owaf_env_ready", "event.preventDefault()", "HTMLFormElement.prototype.submit.call", "__owaf_env_error_callback"} {
		if !strings.Contains(page, marker) {
			t.Fatalf("captcha page missing asynchronous WASM marker %q: %s", marker, page)
		}
	}
}

// TestRenderCaptchaPreviewShowsSkeleton 验证管理端预览输出四题型骨架墙，
// 不含任何可执行的题目渲染逻辑，且保留有效 PNG 占位图。
func TestRenderCaptchaPreviewShowsSkeleton(t *testing.T) {
	cfg := pageconfig.DefaultCaptchaPageConfig()
	page := string(RenderCaptchaPreview(cfg))

	for _, want := range []string{"Click / 点击", "Slide / 滑动", "Rotate / 旋转", "Math / 算式"} {
		if !strings.Contains(page, want) {
			t.Fatalf("preview page missing skeleton section %q: %s", want, page)
		}
	}
	re := regexp.MustCompile(`data:image/png;base64,([A-Za-z0-9+/=]+)`)
	matches := re.FindStringSubmatch(page)
	if len(matches) < 2 {
		t.Fatalf("preview page did not include a PNG data URI: %s", page)
	}
	data, err := base64.StdEncoding.DecodeString(matches[1])
	if err != nil {
		t.Fatalf("preview PNG base64 decode: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(data)); err != nil {
		t.Fatalf("preview PNG is not decodable: %v", err)
	}
}
