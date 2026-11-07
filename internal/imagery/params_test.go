package imagery

import (
	"context"
	"testing"
)

// TestParseESASyntaxExamples 用 ESA 官方文档的原始示例逐条验证解析。
//
// 示例取自 ESA 文档中的 image_process 写法（原样）：
//
//	resize,p_80
//	resize,l_200/threshold,1024000
//	resize,l_200 / resize,s_200 / resize,w_200 / resize,h_200
//	resize,fw_200,fh_200
//	crop,w_200,h_200,g_se / crop,x_10,y_10,w_400,h_200 / crop,mid,w_400,h_200
//	rotate,90 / format,png / quality,Q_90 / bright,50 / contrast,50 / sharpen,100
func TestParseESASyntaxExamples(t *testing.T) {
	t.Run("percent resize", func(t *testing.T) {
		opts, err := Parse("resize,p_80")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if opts.Resize == nil || opts.Resize.Percent != 80 {
			t.Fatalf("Percent = %+v, want 80", opts.Resize)
		}
	})

	t.Run("long side with threshold", func(t *testing.T) {
		opts, err := Parse("resize,l_200/threshold,1024000")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if opts.Resize == nil || opts.Resize.LongSide != 200 || opts.Resize.Threshold != 1024000 {
			t.Fatalf("Resize = %+v, want LongSide=200 Threshold=1024000", opts.Resize)
		}
	})

	t.Run("long short width height", func(t *testing.T) {
		for _, tc := range []struct {
			raw   string
			check func(*ResizeSpec) bool
		}{
			{"resize,l_200", func(s *ResizeSpec) bool { return s.LongSide == 200 }},
			{"resize,s_200", func(s *ResizeSpec) bool { return s.ShortSide == 200 }},
			{"resize,w_200", func(s *ResizeSpec) bool { return s.Width == 200 }},
			{"resize,h_200", func(s *ResizeSpec) bool { return s.Height == 200 }},
		} {
			opts, err := Parse(tc.raw)
			if err != nil {
				t.Fatalf("%s: err = %v", tc.raw, err)
			}
			if opts.Resize == nil || !tc.check(opts.Resize) {
				t.Fatalf("%s: Resize = %+v", tc.raw, opts.Resize)
			}
		}
	})

	t.Run("fit width and height", func(t *testing.T) {
		opts, err := Parse("resize,fw_200,fh_200")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if opts.Resize == nil || opts.Resize.FitWidth != 200 || opts.Resize.FitHeight != 200 {
			t.Fatalf("Resize = %+v", opts.Resize)
		}
	})

	t.Run("crop grid", func(t *testing.T) {
		opts, err := Parse("crop,w_200,h_200,g_se")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if opts.Crop == nil || opts.Crop.Width != 200 || opts.Crop.Height != 200 || opts.Crop.Gravity != "se" {
			t.Fatalf("Crop = %+v", opts.Crop)
		}
	})

	t.Run("crop coordinate", func(t *testing.T) {
		opts, err := Parse("crop,x_10,y_10,w_400,h_200")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if opts.Crop == nil || opts.Crop.X != 10 || opts.Crop.Y != 10 || opts.Crop.Width != 400 || opts.Crop.Height != 200 {
			t.Fatalf("Crop = %+v", opts.Crop)
		}
	})

	t.Run("crop center", func(t *testing.T) {
		opts, err := Parse("crop,mid,w_400,h_200")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if opts.Crop == nil || !opts.Crop.Center || opts.Crop.Width != 400 || opts.Crop.Height != 200 {
			t.Fatalf("Crop = %+v", opts.Crop)
		}
	})

	t.Run("rotate", func(t *testing.T) {
		opts, err := Parse("rotate,90")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if opts.Rotate != 90 {
			t.Fatalf("Rotate = %d, want 90", opts.Rotate)
		}
	})

	t.Run("format", func(t *testing.T) {
		opts, err := Parse("format,png")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if opts.Format != FormatPNG {
			t.Fatalf("Format = %q, want png", opts.Format)
		}
	})

	t.Run("quality absolute", func(t *testing.T) {
		opts, err := Parse("quality,Q_90")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if opts.Quality != 90 {
			t.Fatalf("Quality = %d, want 90", opts.Quality)
		}
	})

	t.Run("color ops", func(t *testing.T) {
		opts, err := Parse("bright,50")
		if err != nil || opts.Bright == nil || *opts.Bright != 50 {
			t.Fatalf("bright: opts=%+v err=%v", opts.Bright, err)
		}
		opts, err = Parse("contrast,50")
		if err != nil || opts.Contrast == nil || *opts.Contrast != 50 {
			t.Fatalf("contrast: opts=%+v err=%v", opts.Contrast, err)
		}
		opts, err = Parse("sharpen,100")
		if err != nil || opts.Sharpen == nil || *opts.Sharpen != 100 {
			t.Fatalf("sharpen: opts=%+v err=%v", opts.Sharpen, err)
		}
	})
}

// TestParseRejectsInvalidValues 参数注入与越界必须被拒绝（不是静默忽略）。
func TestParseRejectsInvalidValues(t *testing.T) {
	bad := []string{
		"resize,w_-1",
		"resize,w_0",
		"resize,h_-200",
		"resize,p_0",
		"resize,p_200",
		"resize,threshold,-5",
		"quality,Q_0",
		"quality,Q_101",
		"quality,Q_abc",
		"rotate,-90",
		"rotate,45",
		"rotate,abc",
		"bright,-101",
		"bright,101",
		"contrast,99999",
		"sharpen,49",
		"sharpen,400",
		"crop,w_-1",
		"crop,x_-1",
		"crop,g_xx",
		"format,avif",
		"format,jp2",
		"format,heic",
		// 参数注入：JS/CSS 包装、超大长度、控制字符。
		"resize,w_200<script>",
		"format,png;rm -rf /",
		"quality,Q_90%00",
		"rotate,90\n180",
	}
	for _, raw := range bad {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("Parse(%q) succeeded; must be rejected", raw)
		}
	}
}

// TestParseRejectsWatermarkExternalResources 覆盖 SSRF 与内容注入边界。
func TestParseRejectsWatermarkExternalResources(t *testing.T) {
	bad := []string{
		"watermark,image_aHR0cDovL2V2aWwuZXhhbXBsZS9hLnBuZw",
		"watermark,text_SGVsbG8",
		"watermark,text_SGVsbG8,g_se",
		"watermark,image_x,g_nw",
		"watermark,type_aHlzb25n",
		"watermark,color_FF0000",
		"watermark,fill_1",
		"watermark,size_40",
		"watermark,rotate_90",
	}
	for _, raw := range bad {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("Parse(%q) succeeded; external watermark resources must be rejected", raw)
		}
	}
}

// TestParseAcceptsWatermarkPositionOnly 位置参数（不含外部资源）应被接受。
func TestParseAcceptsWatermarkPositionOnly(t *testing.T) {
	opts, err := Parse("watermark,g_se,x_10,y_10,t_50")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if opts.Watermark == nil {
		t.Fatal("Watermark is nil")
	}
	if opts.Watermark.Gravity != "se" || opts.Watermark.X != 10 || opts.Watermark.Y != 10 || opts.Watermark.Opacity != 50 {
		t.Fatalf("Watermark = %+v", opts.Watermark)
	}
}

// TestParseIgnoresUnknownOperations 未知操作名与未知参数名忽略，不整体失败。
func TestParseIgnoresUnknownOperations(t *testing.T) {
	opts, err := Parse("blur,50/resize,w_200/unknown,x_1")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if opts.Resize == nil || opts.Resize.Width != 200 {
		t.Fatalf("Resize = %+v, want Width=200", opts.Resize)
	}
}

// TestParseEmptyAndSeparators 空值与多余分隔符不产生操作。
func TestParseEmptyAndSeparators(t *testing.T) {
	for _, raw := range []string{"", "   ", "///", ",,,", "///,resize,,w_100//"} {
		opts, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q) err = %v", raw, err)
		}
		if raw == "///,resize,,w_100//" {
			if opts.Resize == nil || opts.Resize.Width != 100 {
				t.Fatalf("Parse(%q) Resize = %+v", raw, opts.Resize)
			}
			continue
		}
		if !opts.IsZero() {
			t.Fatalf("Parse(%q) = %+v, want zero options", raw, opts)
		}
	}
}

// TestTransformInfoShortCircuitsPixelOps info 必须短路所有像素变换。
func TestTransformInfoShortCircuitsPixelOps(t *testing.T) {
	in := mustReadTestdata(t, "fixture.png")
	opts, err := Parse("info")
	if err != nil {
		t.Fatalf("Parse(info): %v", err)
	}
	res := Transform(context.Background(), in, "image/png", opts, "", DecodeLimits{})
	if !res.Changed {
		t.Fatalf("info should produce a new body; SkipReason=%q", res.SkipReason)
	}
	if res.ContentType != "application/json; charset=utf-8" {
		t.Fatalf("ContentType = %q", res.ContentType)
	}
	if res.Info == nil {
		t.Fatal("Info is nil")
	}
	if got := res.Info["ImageWidth"].Value; got != "120" {
		t.Fatalf("ImageWidth = %q, want 120", got)
	}
	if got := res.Info["ImageHeight"].Value; got != "80" {
		t.Fatalf("ImageHeight = %q, want 80", got)
	}
	if got := res.Info["Format"].Value; got != "png" {
		t.Fatalf("Format = %q, want png", got)
	}
	if got := res.Info["FrameCount"].Value; got != "1" {
		t.Fatalf("FrameCount = %q, want 1", got)
	}
}

// TestTransformInfoReportsOriginalNotTransformed 覆盖 ESA 明确口径：
// 即使同时给出缩放参数，info 仍报告原图尺寸。
func TestTransformInfoReportsOriginalNotTransformed(t *testing.T) {
	in := mustReadTestdata(t, "fixture.png")
	opts, err := Parse("info/resize,w_10")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	res := Transform(context.Background(), in, "image/png", opts, "", DecodeLimits{})
	if res.Info["ImageWidth"].Value != "120" {
		t.Fatalf("ImageWidth = %q, want original 120 (info must describe the source image)", res.Info["ImageWidth"].Value)
	}
}

// TestTransformAnimatedGIFFrameCount 动画 GIF 的 FrameCount 必须如实报告。
func TestTransformAnimatedGIFFrameCount(t *testing.T) {
	in := mustReadTestdata(t, "fixture.animated.gif")
	opts, err := Parse("info")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	res := Transform(context.Background(), in, "image/gif", opts, "", DecodeLimits{})
	if got := res.Info["FrameCount"].Value; got != "2" {
		t.Fatalf("FrameCount = %q, want 2", got)
	}
}

// TestTransformPassthroughOnBadInput 畸形输入必须原图直通，不报错。
func TestTransformPassthroughOnBadInput(t *testing.T) {
	opts, err := Parse("format,png/resize,w_10")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, in := range [][]byte{nil, {}, []byte("garbage"), mustReadTestdata(t, "fixture.png")[:20]} {
		res := Transform(context.Background(), in, "image/png", opts, "", DecodeLimits{})
		if len(res.Body) != len(in) {
			t.Fatalf("input %d bytes → output %d bytes; must passthrough", len(in), len(res.Body))
		}
		if res.Changed {
			t.Fatalf("Changed = true for undecodable input")
		}
	}
}

// TestTransformFormatConversionSetsContentType 格式转换后 ContentType 必须与
// 输出字节一致（覆盖现状缺陷 2 的同类问题）。
func TestTransformFormatConversionSetsContentType(t *testing.T) {
	cases := []struct {
		raw     string
		wantFmt string
		wantCT  string
	}{
		{"format,png", "png", "image/png"},
		{"format,jpeg", "jpeg", "image/jpeg"},
		{"format,gif", "gif", "image/gif"},
		{"format,bmp", "bmp", "image/bmp"},
		{"format,tiff", "tiff", "image/tiff"},
		{"format,webp", "webp", "image/webp"},
	}
	in := mustReadTestdata(t, "fixture.png")
	for _, tc := range cases {
		opts, err := Parse(tc.raw)
		if err != nil {
			t.Fatalf("%s: Parse: %v", tc.raw, err)
		}
		res := Transform(context.Background(), in, "image/png", opts, "", DecodeLimits{})
		if !res.Changed {
			t.Fatalf("%s: not changed; SkipReason=%q", tc.raw, res.SkipReason)
		}
		if res.ContentType != tc.wantCT {
			t.Fatalf("%s: ContentType = %q, want %q", tc.raw, res.ContentType, tc.wantCT)
		}
		if got := SniffFormat(res.Body); got != tc.wantFmt {
			t.Fatalf("%s: actual bytes are %q, declared %q", tc.raw, got, tc.wantCT)
		}
	}
}
