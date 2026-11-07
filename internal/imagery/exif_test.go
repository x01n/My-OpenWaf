package imagery

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"testing"
)

// makeAdaptiveJPEG 生成一张带 EXIF Orientation 的 JPEG，用于 auto-orient 测试。
//
// @param orientation 写入的 Orientation 值。
// @param w、h 图像尺寸。
// @return JPEG 字节。
func makeAdaptiveJPEG(t *testing.T, orientation int, w, h int) []byte {
	t.Helper()
	img := fixtureRGBA(w, h)
	base := encodeTo(t, FormatJPEG, img)

	exif := buildExifOrientation(orientation)
	seg := make([]byte, 0, len(exif)+4)
	seg = append(seg, 0xFF, 0xE1)
	payload := append([]byte("Exif\x00\x00"), exif...)
	seg = append(seg, byte((len(payload)+2)>>8), byte(len(payload)+2))
	seg = append(seg, payload...)

	// 插到 SOI(2) 之后、其余段之前。
	out := make([]byte, 0, len(base)+len(seg))
	out = append(out, base[:2]...)
	out = append(out, seg...)
	out = append(out, base[2:]...)
	return out
}

// buildExifOrientation 构造最小的 EXIF（TIFF 头 + 一个 Orientation 条目）。
//
// @param orientation Orientation 值（1-8）。
// @return TIFF 字节（"II" 小端，含 0x0112 标签）。
func buildExifOrientation(orientation int) []byte {
	// TIFF 头(8) + IFD 计数(2) + 条目(12) + 下一 IFD 偏移(4) = 26
	buf := make([]byte, 26)
	buf[0], buf[1] = 'I', 'I'                   // 小端
	buf[2], buf[3] = 42, 0                      // 42
	buf[4], buf[5], buf[6], buf[7] = 8, 0, 0, 0 // 第一个 IFD 偏移 = 8
	buf[8], buf[9] = 1, 0                       // 条目数 = 1
	// 条目：tag=0x0112 type=3(SHORT) count=1 value=<orientation>
	buf[10], buf[11] = 0x12, 0x01
	buf[12], buf[13] = 3, 0
	buf[14], buf[15], buf[16], buf[17] = 1, 0, 0, 0
	buf[18], buf[19] = byte(orientation), 0
	return buf
}

// TestExifOrientationJPEG 覆盖 JPEG 容器下的 EXIF 朝向读取。
func TestExifOrientationJPEG(t *testing.T) {
	for _, want := range []int{1, 3, 6, 8} {
		data := makeAdaptiveJPEG(t, want, 12, 8)
		if got := exifOrientation(data); got != want {
			t.Fatalf("exifOrientation(oriented %d) = %d", want, got)
		}
	}
	// 无 EXIF 的 JPEG。
	plain := encodeTo(t, FormatJPEG, fixtureRGBA(8, 8))
	if got := exifOrientation(plain); got != 0 {
		t.Fatalf("exifOrientation(no exif) = %d, want 0", got)
	}
}

// TestExifOrientationMalformedInputs 畸形输入不得 panic，一律返回 0。
func TestExifOrientationMalformedInputs(t *testing.T) {
	cases := map[string][]byte{
		"nil":            nil,
		"empty":          {},
		"short":          {0xFF, 0xD8},
		"truncated tiff": {0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10, 'E', 'x', 'i', 'f', 0, 0},
		"bad endian":     {0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x0C, 'E', 'x', 'i', 'f', 0, 0, 'X', 'X'},
		"junk":           bytes.Repeat([]byte{0xAB}, 4096),
	}
	for name, data := range cases {
		if got := exifOrientation(data); got != 0 {
			t.Fatalf("%s: exifOrientation = %d, want 0", name, got)
		}
	}
}

// TestApplyOrientationAllValues 覆盖 8 种 EXIF 朝向的尺寸与角点映射。
func TestApplyOrientationAllValues(t *testing.T) {
	// 3x2 图，四角标记方向。
	mk := func() *image.RGBA {
		img := newRGBA(3, 2)
		img.Set(0, 0, color.RGBA{255, 0, 0, 255})   // A 左上
		img.Set(2, 0, color.RGBA{0, 255, 0, 255})   // B 右上
		img.Set(0, 1, color.RGBA{0, 0, 255, 255})   // C 左下
		img.Set(2, 1, color.RGBA{255, 255, 0, 255}) // D 右下
		return img
	}

	cases := []struct {
		orientation  int
		wantW, wantH int
		check        func(t *testing.T, img *image.RGBA)
	}{
		{1, 3, 2, nil}, // 不变
		{2, 3, 2, func(t *testing.T, img *image.RGBA) {
			// 水平镜像：A 到右上
			if r, _, _, _ := img.At(2, 0).RGBA(); r != 0xffff {
				t.Fatalf("orientation 2: top-right = %v, want red", img.At(2, 0))
			}
		}},
		{3, 3, 2, func(t *testing.T, img *image.RGBA) {
			// 180°：A 到右下
			if r, _, _, _ := img.At(2, 1).RGBA(); r != 0xffff {
				t.Fatalf("orientation 3: bottom-right = %v, want red", img.At(2, 1))
			}
		}},
		{4, 3, 2, func(t *testing.T, img *image.RGBA) {
			// 垂直镜像：A 到左下
			if r, _, _, _ := img.At(0, 1).RGBA(); r != 0xffff {
				t.Fatalf("orientation 4: bottom-left = %v, want red", img.At(0, 1))
			}
		}},
		{5, 2, 3, nil},
		{6, 2, 3, func(t *testing.T, img *image.RGBA) {
			// 顺时针 90°：A 到右上
			if r, _, _, _ := img.At(1, 0).RGBA(); r != 0xffff {
				t.Fatalf("orientation 6: top-right = %v, want red", img.At(1, 0))
			}
		}},
		{7, 2, 3, nil},
		{8, 2, 3, nil},
	}
	for _, tc := range cases {
		got := applyOrientation(mk(), tc.orientation)
		b := got.Bounds()
		if b.Dx() != tc.wantW || b.Dy() != tc.wantH {
			t.Fatalf("orientation %d: dims = %dx%d, want %dx%d", tc.orientation, b.Dx(), b.Dy(), tc.wantW, tc.wantH)
		}
		if tc.check != nil {
			tc.check(t, got)
		}
	}
}

// TestTransformAutoOrientAppliesRotation auto-orient 参数要真的改变像素。
func TestTransformAutoOrientAppliesRotation(t *testing.T) {
	in := makeAdaptiveJPEG(t, 6, 40, 20) // Orientation=6 → 顺时针 90°，宽高互换
	opts, err := Parse("auto-orient")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	res := Transform(context.Background(), in, "image/jpeg", opts, "", DecodeLimits{})
	if !res.Changed {
		t.Fatalf("auto-orient did not change the image; SkipReason=%q", res.SkipReason)
	}
	decoded, err := Decode(res.Body, DecodeLimits{})
	if err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if decoded.Width != 20 || decoded.Height != 40 {
		t.Fatalf("oriented dims = %dx%d, want 20x40", decoded.Width, decoded.Height)
	}
}

// TestTransformAutoOrientWithoutExifIsIdentity 无 EXIF 时 auto-orient 不改像素，
// 但仍按原格式重编码（尺寸不变）。
func TestTransformAutoOrientWithoutExifIsIdentity(t *testing.T) {
	in := encodeTo(t, FormatPNG, fixtureRGBA(16, 16))
	opts, err := Parse("auto-orient")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	res := Transform(context.Background(), in, "image/png", opts, "", DecodeLimits{})
	decoded, err := Decode(res.Body, DecodeLimits{})
	if err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if decoded.Width != 16 || decoded.Height != 16 {
		t.Fatalf("dims = %dx%d, want unchanged 16x16", decoded.Width, decoded.Height)
	}
}
