package proxy

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"net"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/imagery"
	"My-OpenWaf/internal/snapshot"
)

// pngFixture 生成一张确定性的 PNG，供图像转换用例使用。
//
// @param t 测试上下文。
// @return PNG 字节。
func pngFixture(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 64, 48))
	for y := 0; y < 48; y++ {
		for x := 0; x < 64; x++ {
			img.SetRGBA(x, y, color.RGBA{
				R: uint8((x * 255) / 64),
				G: uint8((y * 255) / 48),
				B: 128,
				A: 255,
			})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode fixture png: %v", err)
	}
	return buf.Bytes()
}

// imageTestSite 构造一个启用图像转换的站点运行时。
//
// @param adaptive 是否开启自适应 WebP。
// @return 站点运行时。
func imageTestSite(adaptive bool) snapshot.SiteRuntime {
	rt := snapshot.SiteRuntime{}
	rt.Site.ID = 1
	rt.ImageTransform.Enabled = true
	rt.ImageTransform.AdaptiveWebP = adaptive
	rt.ImageTransform = rt.ImageTransform.Normalize()
	return rt
}

// imageTestContext 构造带查询参数与 Accept 头的请求上下文。
//
// @param query 原始查询串（不含 "?"）。
// @param accept Accept 头取值。
// @return Hertz 请求上下文。
func imageTestContext(query, accept string) *app.RequestContext {
	c := app.NewContext(0)
	c.Request.SetMethod("GET")
	c.Request.SetRequestURI("/asset.png")
	c.URI().SetQueryString(query)
	if accept != "" {
		c.Request.Header.Set("Accept", accept)
	}
	return c
}

// TestImageProcessValueFirstWins 重复参数只取首个，不拼接。
func TestImageProcessValueFirstWins(t *testing.T) {
	c := imageTestContext("image_process=format,png&image_process=format,jpeg", "")
	if got := imageProcessValue(c); got != "format,png" {
		t.Fatalf("imageProcessValue = %q, want the first value", got)
	}
}

// TestImageProcessValueMissing 无参数时返回空串。
func TestImageProcessValueMissing(t *testing.T) {
	if got := imageProcessValue(imageTestContext("other=1", "")); got != "" {
		t.Fatalf("imageProcessValue = %q, want empty", got)
	}
}

// TestImageTransformPlanDisabledByDefault 总开关关闭时不产生计划。
func TestImageTransformPlanDisabledByDefault(t *testing.T) {
	rt := snapshot.SiteRuntime{}
	rt.ImageTransform.Enabled = false
	c := imageTestContext("image_process=format,png", "image/webp")
	if plan := imageTransformPlanFor(rt, c); plan != nil {
		t.Fatalf("plan = %+v, want nil when disabled", plan)
	}
}

// TestImageTransformPlanExplicitParams 显式参数产生计划（非自适应时）。
func TestImageTransformPlanExplicitParams(t *testing.T) {
	rt := imageTestSite(false)
	c := imageTestContext("image_process=resize,w_100", "image/jpeg")
	plan := imageTransformPlanFor(rt, c)
	if plan == nil {
		t.Fatal("plan is nil")
	}
	if plan.opts.Resize == nil || plan.opts.Resize.Width != 100 {
		t.Fatalf("opts.Resize = %+v", plan.opts.Resize)
	}
	if plan.adaptiveWebP {
		t.Fatal("adaptiveWebP must be false without the site flag")
	}
}

// TestImageTransformPlanInvalidParamsRejected 参数非法时原图直通。
func TestImageTransformPlanInvalidParamsRejected(t *testing.T) {
	rt := imageTestSite(false)
	for _, q := range []string{
		"image_process=format,avif",
		"image_process=resize,w_-5",
		"image_process=rotate,45",
		"image_process=watermark,image_aHR0cA",
	} {
		if plan := imageTransformPlanFor(rt, imageTestContext(q, "")); plan != nil {
			t.Fatalf("%s: plan = %+v, want nil", q, plan)
		}
	}
}

// TestImageTransformPlanAdaptiveRequiresAccept 自适应 WebP 的触发条件。
func TestImageTransformPlanAdaptiveRequiresAccept(t *testing.T) {
	rt := imageTestSite(true)

	// 无任何参数 + Accept 含 webp → 只走自适应。
	plan := imageTransformPlanFor(rt, imageTestContext("", "image/avif,image/webp"))
	if plan == nil {
		t.Fatal("adaptive plan is nil with image/webp in Accept")
	}
	if !plan.adaptiveWebP {
		t.Fatal("adaptiveWebP = false, want true")
	}

	// 无参数且 Accept 不含 webp → 不转换。
	if plan := imageTransformPlanFor(rt, imageTestContext("", "image/jpeg")); plan != nil {
		t.Fatalf("plan = %+v, want nil without image/webp", plan)
	}

	// 显式参数 + Accept 不含 webp → 仍执行显式转换，但不转 WebP。
	plan = imageTransformPlanFor(rt, imageTestContext("image_process=resize,w_50", "image/jpeg"))
	if plan == nil {
		t.Fatal("explicit plan is nil")
	}
	if plan.adaptiveWebP {
		t.Fatal("adaptiveWebP = true without image/webp in Accept")
	}
}

// TestImageTransformPlanExplicitWebPSkipsNegotiation 显式 format,webp 时
// 不再重复协商。
func TestImageTransformPlanExplicitWebPSkipsNegotiation(t *testing.T) {
	rt := imageTestSite(true)
	plan := imageTransformPlanFor(rt, imageTestContext("image_process=format,webp", "image/jpeg"))
	if plan == nil {
		t.Fatal("plan is nil")
	}
	if plan.adaptiveWebP {
		t.Fatal("adaptiveWebP must be false when webp was requested explicitly")
	}
}

// TestImageContentTypeUpper 可转换内容类型的白名单。
func TestImageContentTypeUpper(t *testing.T) {
	yes := []string{
		"image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp",
		"image/bmp", "image/x-ms-bmp", "image/tiff",
		"image/png; charset=binary", "IMAGE/WEBP",
	}
	for _, ct := range yes {
		if !imageContentTypeUpper(ct) {
			t.Fatalf("imageContentTypeUpper(%q) = false, want true", ct)
		}
	}
	no := []string{"", "text/html", "application/json", "image/svg+xml", "video/mp4", "image/avif"}
	for _, ct := range no {
		if imageContentTypeUpper(ct) {
			t.Fatalf("imageContentTypeUpper(%q) = true, want false", ct)
		}
	}
}

// TestApplyImageTransformAdaptiveWebPDeclaresVary 自适应 WebP 必须声明
// Vary: Accept，且 ContentType 与输出字节一致。
func TestApplyImageTransformAdaptiveWebPDeclaresVary(t *testing.T) {
	rt := imageTestSite(true)
	c := imageTestContext("", "image/webp")
	entity := identityResponseEntity{
		Path:        "/asset.png",
		ContentType: "image/png",
		Body:        pngFixture(t),
		Request:     c,
	}
	got := applyImageTransform(context.Background(), entity, rt, c)
	if !got.ImageVariant {
		t.Fatalf("ImageVariant = false; conversion did not happen (ContentType=%q)", got.ContentType)
	}
	if !got.VaryAccept {
		t.Fatal("VaryAccept = false; adaptive WebP must declare Vary: Accept")
	}
	if got.ContentType != "image/webp" {
		t.Fatalf("ContentType = %q, want image/webp", got.ContentType)
	}
	if sniffed := snapFormat(got.Body); sniffed != "webp" {
		t.Fatalf("output bytes are %q, declared %q", sniffed, got.ContentType)
	}
}

// TestApplyImageTransformWithoutWebPAcceptKeepsFormat Accept 不含 webp 时
// 不得转码（返回原格式）。
func TestApplyImageTransformWithoutWebPAcceptKeepsFormat(t *testing.T) {
	rt := imageTestSite(true)
	c := imageTestContext("image_process=resize,w_16", "image/jpeg")
	entity := identityResponseEntity{
		ContentType: "image/png",
		Body:        pngFixture(t),
		Request:     c,
	}
	got := applyImageTransform(context.Background(), entity, rt, c)
	if !got.ImageVariant {
		t.Fatal("explicit resize should still produce an image variant")
	}
	if got.VaryAccept {
		t.Fatal("VaryAccept = true although Accept has no image/webp")
	}
	if got.ContentType != "image/png" {
		t.Fatalf("ContentType = %q, want image/png (no adaptive negotiation)", got.ContentType)
	}
	if f := snapFormat(got.Body); f != "png" {
		t.Fatalf("output bytes are %q, want png", f)
	}
}

// TestApplyImageTransformSkipsNonImage 非图片响应不进入转换路径。
func TestApplyImageTransformSkipsNonImage(t *testing.T) {
	rt := imageTestSite(true)
	c := imageTestContext("image_process=format,webp", "image/webp")
	entity := identityResponseEntity{
		ContentType: "text/html",
		Body:        []byte("<html></html>"),
		Request:     c,
	}
	got := applyImageTransform(context.Background(), entity, rt, c)
	if got.ContentType != "text/html" || string(got.Body) != "<html></html>" {
		t.Fatal("non-image content type must passthrough")
	}
}

// TestApplyImageTransformPassthroughOnBadBytes 畸形图片字节原图直通。
func TestApplyImageTransformPassthroughOnBadBytes(t *testing.T) {
	rt := imageTestSite(false)
	c := imageTestContext("image_process=resize,w_10", "")
	entity := identityResponseEntity{
		ContentType: "image/png",
		Body:        []byte("not a png"),
		Request:     c,
	}
	got := applyImageTransform(context.Background(), entity, rt, c)
	if string(got.Body) != "not a png" || got.ContentType != "image/png" {
		t.Fatal("malformed image bytes must passthrough")
	}
	if got.ImageVariant {
		t.Fatal("ImageVariant = true although nothing was transformed")
	}
}

// TestAppendVaryAcceptIdempotent Vary 追加必须幂等且不丢失既有维度。
func TestAppendVaryAcceptIdempotent(t *testing.T) {
	c := app.NewContext(0)
	appendVaryAccept(c)
	if got := string(c.Response.Header.Peek("Vary")); got != "Accept" {
		t.Fatalf("Vary = %q, want Accept", got)
	}
	appendVaryAccept(c)
	if got := string(c.Response.Header.Peek("Vary")); got != "Accept" {
		t.Fatalf("Vary = %q after second call, want Accept", got)
	}

	c2 := app.NewContext(0)
	c2.Response.Header.Set("Vary", "Cookie")
	appendVaryAccept(c2)
	if got := string(c2.Response.Header.Peek("Vary")); got != "Cookie, Accept" {
		t.Fatalf("Vary = %q, want %q", got, "Cookie, Accept")
	}
	appendVaryAccept(c2)
	if got := string(c2.Response.Header.Peek("Vary")); got != "Cookie, Accept" {
		t.Fatalf("Vary = %q after repeat, want unchanged", got)
	}
}

// TestWatermarkTextForReadsDynamicConfig 水印文案取自站点动态防护配置。
func TestWatermarkTextForReadsDynamicConfig(t *testing.T) {
	rt := snapshot.SiteRuntime{}
	rt.DynamicProtection.WatermarkText = "confidential"
	if got := watermarkTextFor(rt); got != "confidential" {
		t.Fatalf("watermarkTextFor = %q", got)
	}
}

// 编译期断言：time 与 net 被引用（供后续超时/客户端 IP 用例复用）。
var (
	_ = time.Second
	_ net.IP
)

// snapFormat 用 imagery 的嗅探能力判断输出字节的真实格式。
//
// @param data 图片字节。
// @return 格式名；无法识别时为空串。
func snapFormat(data []byte) string {
	return imagery.SniffFormat(data)
}
