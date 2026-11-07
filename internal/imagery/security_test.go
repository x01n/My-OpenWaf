package imagery

import (
	"bytes"
	"image"
	"image/color"
	"testing"
)

// TestDecodeRejectsHugeDimensions 覆盖解压炸弹：声明超大尺寸的输入必须在
// Decode 之前被拒绝（依据 DecodeConfig 的宽高，而不是文件字节数）。
func TestDecodeRejectsHugeDimensions(t *testing.T) {
	// 构造一个声明 60000x60000 的 PNG：IHDR 里写死尺寸，后面不给真实数据。
	bomb := makeHugePNGHeader(60000, 60000)
	_, err := Decode(bomb, DecodeLimits{})
	if err == nil {
		t.Fatal("Decode accepted a 60000x60000 PNG header")
	}
	if !isTooLarge(err) && !isUnsupported(err) {
		t.Fatalf("unexpected error class: %v", err)
	}
}

// TestDecodeRejectsOversizeBytes 覆盖字节上限。
func TestDecodeRejectsOversizeBytes(t *testing.T) {
	data := mustReadTestdata(t, "fixture.png")
	limits := DecodeLimits{MaxPixels: 1 << 20, MaxSide: 4096, MaxBytes: 64}
	if _, err := Decode(data, limits); err == nil {
		t.Fatal("Decode accepted input above MaxBytes")
	}
}

// TestDecodeRejectsOversizeSide 覆盖单边上限（面积仍在上限内）。
func TestDecodeRejectsOversizeSide(t *testing.T) {
	limits := DecodeLimits{MaxPixels: 1 << 30, MaxSide: 8, MaxBytes: 1 << 20}
	data := mustReadTestdata(t, "fixture.png") // 120x80，超出单边 8
	if _, err := Decode(data, limits); err == nil {
		t.Fatal("Decode accepted input above MaxSide")
	}
}

// TestDecodeRejectsMalformedInput 覆盖畸形字节。
func TestDecodeRejectsMalformedInput(t *testing.T) {
	cases := map[string][]byte{
		"nil":              nil,
		"empty":            {},
		"plain text":       []byte("hello world"),
		"png magic only":   []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A},
		"jpeg magic only":  {0xFF, 0xD8},
		"gif magic only":   []byte("GIF89a"),
		"riff non-webp":    []byte("RIFF????WAVE"),
		"zero dims png":    makePNGWithDims(0, 0),
		"negative-looking": []byte{0xFF, 0xD8, 0xFF, 0xE0},
	}
	for name, data := range cases {
		if _, err := Decode(data, DecodeLimits{}); err == nil {
			t.Fatalf("%s: Decode succeeded on malformed input", name)
		}
	}
}

// TestDecodeForgedWebPHeader 覆盖伪造 WebP 头：仅凭 magic bytes 不足以防御，
// DecodeConfig 必须按真实解码器解析并对畸形头部报错。
func TestDecodeForgedWebPHeader(t *testing.T) {
	// RIFF....WEBPVP8X + 声称 60000x60000 的 VP8X 载荷。
	forged := make([]byte, 0, 64)
	forged = append(forged, []byte("RIFF")...)
	forged = append(forged, 0x30, 0x00, 0x00, 0x00)
	forged = append(forged, []byte("WEBP")...)
	forged = append(forged, []byte("VP8X")...)
	forged = append(forged, 0x0A, 0x00, 0x00, 0x00)
	forged = append(forged, 0x00, 0x00, 0x00, 0x00)
	// 宽高各 24 位小端：60000-1 = 0xEA5F
	forged = append(forged, 0x5F, 0xEA, 0x00)
	forged = append(forged, 0x5F, 0xEA, 0x00)
	forged = append(forged, 0x00, 0x00, 0x00, 0x00)

	_, err := Decode(forged, DecodeLimits{})
	if err == nil {
		t.Fatal("Decode accepted a forged 60000x60000 WebP header")
	}
}

// TestDecodeWithinLimitsSucceeds 正常图片在限额内必须解码成功。
func TestDecodeWithinLimitsSucceeds(t *testing.T) {
	for _, name := range []string{"fixture.png", "fixture.jpg", "fixture.gif", "fixture.bmp", "fixture.tiff", "fixture.webp"} {
		decoded, err := Decode(mustReadTestdata(t, name), DecodeLimits{})
		if err != nil {
			t.Fatalf("%s: Decode: %v", name, err)
		}
		if decoded.Width != 120 || decoded.Height != 80 {
			t.Fatalf("%s: dims = %dx%d, want 120x80", name, decoded.Width, decoded.Height)
		}
	}
}

// TestDecodedImageAlwaysHasZeroOrigin 解码结果必须可被后续 ops 安全使用。
func TestDecodedImageAlwaysHasZeroOrigin(t *testing.T) {
	decoded, err := Decode(mustReadTestdata(t, "fixture.png"), DecodeLimits{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if b := decoded.Image.Bounds(); b.Min != (image.Point{}) {
		t.Fatalf("decoded bounds Min = %v, want (0,0)", b.Min)
	}
}

// makeHugePNGHeader 构造一个只声明尺寸、不携带有效 IDAT 的 PNG。
//
// @param w、h 声称的尺寸。
// @return PNG 字节。
func makeHugePNGHeader(w, h int) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})
	// IHDR
	ihdr := []byte{
		byte(w >> 24), byte(w >> 16), byte(w >> 8), byte(w),
		byte(h >> 24), byte(h >> 16), byte(h >> 8), byte(h),
		8, 2, 0, 0, 0,
	}
	buf.Write([]byte{0, 0, 0, 13})
	buf.Write([]byte("IHDR"))
	buf.Write(ihdr)
	buf.Write([]byte{0, 0, 0, 0}) // CRC 占位
	return buf.Bytes()
}

// makePNGWithDims 构造尺寸为 0 的 PNG 头。
//
// @param w、h 声称的尺寸。
// @return PNG 字节。
func makePNGWithDims(w, h int) []byte {
	return makeHugePNGHeader(w, h)
}

// isTooLarge 判断错误是否属于「超限」类。
func isTooLarge(err error) bool {
	return err != nil && errorsIs(err, ErrTooLarge)
}

// isUnsupported 判断错误是否属于「不支持」类。
func isUnsupported(err error) bool {
	return err != nil && errorsIs(err, ErrUnsupported)
}

// errorsIs 是 errors.Is 的轻量包装，避免测试文件再引入 import 噪声。
func errorsIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}

// TestSniffFormatOnEmptyAndNil 嗅探空输入必须返回空串而不 panic。
func TestSniffFormatOnEmptyAndNil(t *testing.T) {
	if got := SniffFormat(nil); got != "" {
		t.Fatalf("SniffFormat(nil) = %q", got)
	}
	if got := SniffFormat([]byte{}); got != "" {
		t.Fatalf("SniffFormat(empty) = %q", got)
	}
	// 极端：超长垃圾输入不应 panic。
	junk := bytes.Repeat([]byte{0xAB}, 1<<20)
	if got := SniffFormat(junk); got != "" {
		t.Fatalf("SniffFormat(junk) = %q", got)
	}
}

// TestDecodeExtremeInputNoPanic 覆盖极端尺寸像素上的 ops 不 panic。
func TestDecodeExtremeInputNoPanic(t *testing.T) {
	// 1x1 与 16384x1 这类极端宽高比不应触发越界。
	for _, tc := range []struct{ w, h int }{{1, 1}, {1, 64}, {64, 1}} {
		img := fixtureRGBA(tc.w, tc.h)
		_ = Resize(img, 10, 10)
		_ = Crop(img, image.Rect(0, 0, tc.w, tc.h))
		_ = Rotate(img, 90)
		_ = AdjustBrightness(img, 50)
		_ = AdjustContrast(img, -50)
		_ = Sharpen(img, 100)
	}
}

// TestOpsDoNotMutateInput 变换必须返回新画布，不改写入参像素。
func TestOpsDoNotMutateInput(t *testing.T) {
	src := fixtureRGBA(16, 16)
	before := append([]byte(nil), src.Pix...)

	_ = AdjustBrightness(src, 80)
	_ = AdjustContrast(src, 60)
	_ = Sharpen(src, 200)
	_ = Rotate(src, 90)
	_ = Crop(src, image.Rect(2, 2, 10, 10))

	if !bytes.Equal(before, src.Pix) {
		t.Fatal("ops mutated the input pixels in place")
	}
}

// 保持 color 包被引用（测试内构造像素）。
var _ = color.RGBA{}
