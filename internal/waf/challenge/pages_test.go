package challenge

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"regexp"
	"strings"
	"testing"

	"My-OpenWaf/internal/waf/pageconfig"
)

func TestCaptchaImageURLAllowsGeneratedDataImagesOnly(t *testing.T) {
	validPNG := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("png"))
	validJPEG := "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString([]byte("jpeg"))
	if got := captchaImageURL(validPNG); string(got) != validPNG {
		t.Fatalf("captchaImageURL() rejected PNG data image: %q", got)
	}
	if got := captchaImageURL(validJPEG); string(got) != validJPEG {
		t.Fatalf("captchaImageURL() rejected JPEG data image: %q", got)
	}
	for _, raw := range []string{
		"javascript:alert(1)",
		"data:text/html;base64,PHNjcmlwdD4=",
		"data:image/png;base64,not-base64",
	} {
		if got := captchaImageURL(raw); got != "" {
			t.Fatalf("captchaImageURL(%q) = %q, want empty", raw, got)
		}
	}
}

func TestCaptchaImageURLRejectsNestedDataURI(t *testing.T) {
	nested := "data:image/png;base64,data:image/png;base64,ZmFrZQ=="
	if got := captchaImageURL(nested); got != "" {
		t.Fatalf("captchaImageURL accepted nested data URI: %q", got)
	}
}

func TestRenderCaptchaPageUsesRotateThumbForInteraction(t *testing.T) {
	image := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("image"))
	page := string(renderCaptchaPage(&CaptchaChallenge{
		SessionID: "session",
		Type:      string(CaptchaTypeRotate),
		MasterImg: image,
		ThumbImg:  image,
	}, "request", "", pageconfig.DefaultCaptchaPageConfig()))
	if !strings.Contains(page, `id="rotate-thumb"`) || !strings.Contains(page, `rotateThumb.style.transform='rotate('`) {
		t.Fatalf("rotate page does not bind rotation to thumb image: %s", page)
	}
	if strings.Contains(page, `img.style.transform='rotate('`) {
		t.Fatalf("rotate page still rotates the master image: %s", page)
	}
}

func TestRenderCaptchaPageUsesConfigAndRejectsUnsafeValues(t *testing.T) {
	image := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("image"))
	cfg := pageconfig.DefaultCaptchaPageConfig()
	cfg.BrandName = `<script>brand()</script>`
	cfg.Title = "Custom CAPTCHA"
	cfg.Subtitle = "Custom subtitle"
	cfg.SubmitText = "Continue"
	cfg.LogoURL = "javascript:alert(1)"
	cfg.CustomCSS = `</style><script>alert(1)</script>.safe{color:red}`
	page := string(renderCaptchaPage(&CaptchaChallenge{
		SessionID: "session",
		Type:      string(CaptchaTypeMath),
		MasterImg: image,
		Prompt:    "answer",
	}, "request", "", cfg))

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

func TestRenderCaptchaPageEscapesDynamicFields(t *testing.T) {
	payload := `"><script>alert("captcha")</script>`
	image := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("image"))
	page := string(renderCaptchaPage(&CaptchaChallenge{
		SessionID: payload,
		Type:      string(CaptchaTypeMath),
		MasterImg: image,
		Prompt:    payload,
	}, payload, "", pageconfig.DefaultCaptchaPageConfig()))
	if strings.Contains(page, `<script>alert("captcha")</script>`) {
		t.Fatalf("captcha page reflected executable input: %s", page)
	}
	if !strings.Contains(page, `&lt;script&gt;`) {
		t.Fatalf("captcha page did not escape dynamic content: %s", page)
	}
}

func TestCaptchaPageWaitsForWASMEnvironmentBeforeSubmit(t *testing.T) {
	image := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("image"))
	page := string(renderCaptchaPage(&CaptchaChallenge{
		SessionID: "session",
		Type:      string(CaptchaTypeMath),
		MasterImg: image,
		Prompt:    "answer",
	}, "request", EnvCheckJSEncrypted("aabbccdd112233445566778899001122aabbccdd112233445566778899001122", "owaf-env:v1|captcha|1|example.test|:443|session"), pageconfig.DefaultCaptchaPageConfig()))
	for _, marker := range []string{"window.__owaf_env_ready", "event.preventDefault()", "HTMLFormElement.prototype.submit.call", "__owaf_env_error_callback"} {
		if !strings.Contains(page, marker) {
			t.Fatalf("captcha page missing asynchronous WASM marker %q: %s", marker, page)
		}
	}
}

func TestRenderCaptchaPreviewIncludesValidPNG(t *testing.T) {
	cfg := pageconfig.DefaultCaptchaPageConfig()
	page := string(RenderCaptchaPreview(cfg))
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
