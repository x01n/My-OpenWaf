package imagery

import (
	"image"
	"image/color"
	"testing"
)

// TestResizeBounds 覆盖 resize 的边界：超出原图、0、负数。
//
// 语义（与 ESA resize 对齐）：只缩不放，目标超过原图时该维度取原图长度；
// 非正参数表示不约束该维度；两者都非正时返回原像素。
func TestResizeBounds(t *testing.T) {
	src := fixtureRGBA(100, 50)

	cases := []struct {
		name         string
		w, h         int
		wantW, wantH int
	}{
		{"shrink both", 40, 20, 40, 20},
		{"upscale requested", 500, 500, 100, 50},
		{"upscale one side", 200, 20, 100, 20},
		{"zero both", 0, 0, 100, 50},
		{"negative both", -10, -10, 100, 50},
		{"negative width only", -1, 20, 100, 20},
		{"zero width keeps height", 0, 20, 100, 20},
		{"target equals source", 100, 50, 100, 50},
		{"floor to 1px", 1, 1, 1, 1},
	}
	for _, tc := range cases {
		got := Resize(src, tc.w, tc.h)
		b := got.Bounds()
		if b.Dx() != tc.wantW || b.Dy() != tc.wantH {
			t.Fatalf("%s: Resize(%d,%d) = %dx%d, want %dx%d", tc.name, tc.w, tc.h, b.Dx(), b.Dy(), tc.wantW, tc.wantH)
		}
	}
}

// TestResizeByLongShortSide 覆盖按长边/短边等比缩放。
func TestResizeByLongShortSide(t *testing.T) {
	src := fixtureRGBA(200, 100)

	long := ResizeByLongSide(src, 100)
	if b := long.Bounds(); b.Dx() != 100 || b.Dy() != 50 {
		t.Fatalf("ResizeByLongSide(100) = %dx%d, want 100x50", b.Dx(), b.Dy())
	}

	short := ResizeByShortSide(src, 50)
	if b := short.Bounds(); b.Dx() != 100 || b.Dy() != 50 {
		t.Fatalf("ResizeByShortSide(50) = %dx%d, want 100x50", b.Dx(), b.Dy())
	}

	// 超原图尺寸不放大。
	big := ResizeByLongSide(src, 1000)
	if b := big.Bounds(); b.Dx() != 200 || b.Dy() != 100 {
		t.Fatalf("ResizeByLongSide(1000) = %dx%d, want unchanged 200x100", b.Dx(), b.Dy())
	}
	// 非正参数不缩放。
	for _, v := range []int{0, -5} {
		got := ResizeByLongSide(src, v)
		if b := got.Bounds(); b.Dx() != 200 || b.Dy() != 100 {
			t.Fatalf("ResizeByLongSide(%d) = %dx%d, want unchanged", v, b.Dx(), b.Dy())
		}
	}
}

// TestCropBounds 覆盖 crop 的越界、负数与 0 尺寸。
func TestCropBounds(t *testing.T) {
	src := fixtureRGBA(100, 50)

	cases := []struct {
		name         string
		r            image.Rectangle
		wantW, wantH int
	}{
		{"in range", image.Rect(10, 10, 50, 40), 40, 30},
		{"exceeds right/bottom", image.Rect(80, 40, 200, 200), 20, 10},
		{"negative origin clamps", image.Rect(-50, -50, 20, 20), 20, 20},
		{"zero width", image.Rect(10, 10, 10, 40), 100, 50},
		{"zero height", image.Rect(10, 10, 50, 10), 100, 50},
		// image.Rect 自身会把反向坐标规范化为 (min,max)，因此「反向矩形」
		// 到达 Crop 时已是 (10,10)-(50,40)，按 40x30 裁剪。
		{"reversed rect normalized by image.Rect", image.Rect(50, 40, 10, 10), 40, 30},
		{"outside entirely", image.Rect(500, 500, 600, 600), 100, 50},
		{"full", image.Rect(0, 0, 100, 50), 100, 50},
	}
	for _, tc := range cases {
		got := Crop(src, tc.r)
		b := got.Bounds()
		if b.Dx() != tc.wantW || b.Dy() != tc.wantH {
			t.Fatalf("%s: Crop(%v) = %dx%d, want %dx%d", tc.name, tc.r, b.Dx(), b.Dy(), tc.wantW, tc.wantH)
		}
	}
}

// TestCropCenterBounds 覆盖居中裁剪的越界与 0/负尺寸。
func TestCropCenterBounds(t *testing.T) {
	src := fixtureRGBA(100, 50)
	cases := []struct {
		name         string
		w, h         int
		wantW, wantH int
	}{
		{"normal", 40, 20, 40, 20},
		{"width too big", 500, 20, 100, 20},
		{"negative", -5, -5, 100, 50},
		{"zero", 0, 0, 100, 50},
	}
	for _, tc := range cases {
		got := CropCenter(src, tc.w, tc.h)
		b := got.Bounds()
		if b.Dx() != tc.wantW || b.Dy() != tc.wantH {
			t.Fatalf("%s: CropCenter(%d,%d) = %dx%d, want %dx%d", tc.name, tc.w, tc.h, b.Dx(), b.Dy(), tc.wantW, tc.wantH)
		}
	}
}

// TestRotateBounds 覆盖 90/180/270 的尺寸交换与非标准角度。
func TestRotateBounds(t *testing.T) {
	src := fixtureRGBA(100, 50)
	cases := []struct {
		deg          int
		wantW, wantH int
	}{
		{0, 100, 50},
		{90, 50, 100},
		{180, 100, 50},
		{270, 50, 100},
		{360, 100, 50},
		{-90, 50, 100},
		{45, 100, 50},  // 非整数 90° 倍：原样返回
		{450, 50, 100}, // 450 % 360 = 90
	}
	for _, tc := range cases {
		got := Rotate(src, tc.deg)
		b := got.Bounds()
		if b.Dx() != tc.wantW || b.Dy() != tc.wantH {
			t.Fatalf("Rotate(%d) = %dx%d, want %dx%d", tc.deg, b.Dx(), b.Dy(), tc.wantW, tc.wantH)
		}
	}
}

// TestRotatePixelMapping 校验 4 个角点的映射方向（顺时针）。
func TestRotatePixelMapping(t *testing.T) {
	img := newRGBA(3, 2)
	// 记号：左上 A、右上 B、左下 C、右下 D
	img.Set(0, 0, colorRGB(255, 0, 0))   // A 左上
	img.Set(2, 0, colorRGB(0, 255, 0))   // B 右上
	img.Set(0, 1, colorRGB(0, 0, 255))   // C 左下
	img.Set(2, 1, colorRGB(255, 255, 0)) // D 右下

	// 顺时针 90°：A→右上、B→右下、C→左上、D→左下
	r90 := Rotate(img, 90)
	if b := r90.Bounds(); b.Dx() != 2 || b.Dy() != 3 {
		t.Fatalf("Rotate(90) dims = %dx%d, want 2x3", b.Dx(), b.Dy())
	}
	if r, g, bl, _ := r90.At(1, 0).RGBA(); r != 0xffff || g != 0 || bl != 0 {
		t.Fatalf("Rotate(90) top-right = %v, want red (A)", r90.At(1, 0))
	}
	if r, g, bl, _ := r90.At(0, 0).RGBA(); r != 0 || g != 0 || bl != 0xffff {
		t.Fatalf("Rotate(90) top-left = %v, want blue (C)", r90.At(0, 0))
	}
	if r, g, bl, _ := r90.At(1, 2).RGBA(); r != 0 || g != 0xffff || bl != 0 {
		t.Fatalf("Rotate(90) bottom-right = %v, want green (B)", r90.At(1, 2))
	}

	// 180°：A↔D，B↔C
	r180 := Rotate(img, 180)
	if r, g, bl, _ := r180.At(2, 1).RGBA(); r != 0xffff || g != 0 || bl != 0 {
		t.Fatalf("Rotate(180) bottom-right = %v, want red (A)", r180.At(2, 1))
	}
}

// colorRGB 构造不透明 RGB 颜色。
//
// @param r、g、b 通道值。
// @return 不透明的 RGBA 颜色。
func colorRGB(r, g, b uint8) color.RGBA {
	return color.RGBA{R: r, G: g, B: b, A: 255}
}

// TestAdjustBrightnessContrastBounds 覆盖 bright/contrast 的取值钳制与恒等。
func TestAdjustBrightnessContrastBounds(t *testing.T) {
	src := fixtureRGBA(32, 32)

	if got := AdjustBrightness(src, 0); got != src {
		t.Fatal("AdjustBrightness(0) must return input unchanged")
	}
	if got := AdjustContrast(src, 0); got != src {
		t.Fatal("AdjustContrast(0) must return input unchanged")
	}
	// 越界值被钳制到 ±100，且不应 panic。
	for _, v := range []int{-1000, -100, 100, 1000} {
		if b := AdjustBrightness(src, v).Bounds(); b.Dx() != 32 || b.Dy() != 32 {
			t.Fatalf("AdjustBrightness(%d) dims changed", v)
		}
		if b := AdjustContrast(src, v).Bounds(); b.Dx() != 32 || b.Dy() != 32 {
			t.Fatalf("AdjustContrast(%d) dims changed", v)
		}
	}
	// 全白图提亮不变（钳制饱和）。
	white := newRGBA(4, 4)
	for i := range white.Pix {
		white.Pix[i] = 255
	}
	bright := AdjustBrightness(white, 100)
	if r := bright.Pix[0]; r != 255 {
		t.Fatalf("brightening white changed red to %d", r)
	}
}

// TestSharpenBounds 覆盖 sharpen 的取值区间与恒等。
func TestSharpenBounds(t *testing.T) {
	src := fixtureRGBA(32, 32)
	if got := Sharpen(src, 0); got != src {
		t.Fatal("Sharpen(0) must return input unchanged")
	}
	for _, v := range []int{-10, 1, 50, 100, 399, 1000} {
		if b := Sharpen(src, v).Bounds(); b.Dx() != 32 || b.Dy() != 32 {
			t.Fatalf("Sharpen(%d) dims changed", v)
		}
	}
	// 小于 3px 的图无法卷积，必须原样返回而不 panic。
	tiny := fixtureRGBA(2, 2)
	if got := Sharpen(tiny, 100); got != tiny {
		t.Fatal("Sharpen on 2x2 must return input unchanged")
	}
}
