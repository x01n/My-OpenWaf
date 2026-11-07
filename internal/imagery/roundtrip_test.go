package imagery

import (
	"bytes"
	"github.com/gen2brain/webp"
	"golang.org/x/image/bmp"
	"golang.org/x/image/tiff"
	"image"
	"image/color"
	"testing"
)

// fixtureRGBA 生成确定性的测试图。
//
// @param w、h 尺寸。
// @return RGBA 像素。
func fixtureRGBA(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, color.RGBA{
				R: uint8((x * 255) / w),
				G: uint8((y * 255) / h),
				B: uint8(((x + y) * 255) / (w + h)),
				A: 255,
			})
		}
	}
	return img
}

// encodeTo 用指定格式把像素编码成字节，供解码往返测试使用。
//
// @param t 测试上下文。
// @param format 目标格式。
// @param img 像素。
// @return 编码后的字节。
func encodeTo(t *testing.T, format Format, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	switch format {
	case FormatBMP:
		if err := bmp.Encode(&buf, img); err != nil {
			t.Fatalf("bmp.Encode: %v", err)
		}
	case FormatTIFF:
		if err := tiff.Encode(&buf, img, nil); err != nil {
			t.Fatalf("tiff.Encode: %v", err)
		}
	case FormatWebP:
		if err := webp.Encode(&buf, img, webp.Options{Quality: 90}); err != nil {
			t.Fatalf("webp.Encode: %v", err)
		}
	default:
		out, _, err := Encode(toRGBA(img), EncodingOptions{Format: format, Quality: 90})
		if err != nil {
			t.Fatalf("Encode(%s): %v", format, err)
		}
		return out
	}
	return buf.Bytes()
}

// TestDecodeEncodeRoundTripAllFormats 覆盖每种格式的解码 → 转换 → 编码往返。
//
// 对每种输入格式：解码 → 缩放 → 编码为目标格式 → 再解码，校验尺寸与像素可读。
func TestDecodeEncodeRoundTripAllFormats(t *testing.T) {
	inputs := []Format{FormatJPEG, FormatPNG, FormatGIF, FormatBMP, FormatTIFF, FormatWebP}
	outputs := []Format{FormatJPEG, FormatPNG, FormatGIF, FormatBMP, FormatTIFF, FormatWebP}
	for _, in := range inputs {
		src := fixtureRGBA(64, 48)
		data := encodeTo(t, in, src)
		decoded, err := Decode(data, DecodeLimits{})
		if err != nil {
			t.Fatalf("Decode(%s): %v", in, err)
		}
		if decoded.Format != in {
			t.Fatalf("Decode(%s) reported format %q", in, decoded.Format)
		}
		if decoded.Width != 64 || decoded.Height != 48 {
			t.Fatalf("Decode(%s) dims = %dx%d, want 64x48", in, decoded.Width, decoded.Height)
		}
		resized := Resize(toRGBA(decoded.Image), 32, 24)
		if b := resized.Bounds(); b.Dx() != 32 || b.Dy() != 24 {
			t.Fatalf("%s → resize: dims = %dx%d, want 32x24", in, b.Dx(), b.Dy())
		}
		for _, out := range outputs {
			encoded, gotFormat, err := Encode(resized, EncodingOptions{Format: out, Quality: 80})
			if err != nil {
				t.Fatalf("%s → %s: Encode error: %v", in, out, err)
			}
			if gotFormat != out {
				t.Fatalf("%s → %s: reported format %q", in, out, gotFormat)
			}
			back, err := Decode(encoded, DecodeLimits{})
			if err != nil {
				t.Fatalf("%s → %s: re-Decode error: %v", in, out, err)
			}
			if back.Format != out {
				t.Fatalf("%s → %s: re-decoded format %q", in, out, back.Format)
			}
			if back.Width != 32 || back.Height != 24 {
				t.Fatalf("%s → %s: re-decoded dims = %dx%d, want 32x24", in, out, back.Width, back.Height)
			}
		}
	}
}

// TestEncodeRejectsUnknownFormat 未知目标格式必须报错，不能静默选一个编码器。
func TestEncodeRejectsUnknownFormat(t *testing.T) {
	img := fixtureRGBA(8, 8)
	for _, name := range []string{"avif", "jp2", "heic", "jxl", "", "bogus"} {
		f := ParseFormat(name)
		if _, _, err := Encode(img, EncodingOptions{Format: f}); err == nil {
			t.Fatalf("Encode(%q) succeeded; unknown formats must be rejected", name)
		}
	}
}

// TestParseFormatAliases 覆盖别名与大小写。
func TestParseFormatAliases(t *testing.T) {
	cases := map[string]Format{
		"jpg":   FormatJPEG,
		"JPEG":  FormatJPEG,
		" png ": FormatPNG,
		"tif":   FormatTIFF,
		"TIFF":  FormatTIFF,
		"WebP":  FormatWebP,
		"gif":   FormatGIF,
		"bmp":   FormatBMP,
		"avif":  "",
		"":      "",
	}
	for in, want := range cases {
		if got := ParseFormat(in); got != want {
			t.Fatalf("ParseFormat(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSniffFormatRecognizesAllInputs WebP/BMP/TIFF 输入必须被识别
// （旧实现只能识别 png/jpeg/gif/webp，且用硬编码 magic 比较）。
func TestSniffFormatRecognizesAllInputs(t *testing.T) {
	src := fixtureRGBA(16, 16)
	cases := []Format{FormatJPEG, FormatPNG, FormatGIF, FormatBMP, FormatTIFF, FormatWebP}
	for _, f := range cases {
		data := encodeTo(t, f, src)
		if got := SniffFormat(data); got != string(f) {
			t.Fatalf("SniffFormat(%s encoded) = %q, want %q", f, got, f)
		}
	}
	if got := SniffFormat([]byte("garbage")); got != "" {
		t.Fatalf("SniffFormat(garbage) = %q, want empty", got)
	}
	if got := SniffFormat(nil); got != "" {
		t.Fatalf("SniffFormat(nil) = %q, want empty", got)
	}
}

// TestEncodeWebPSizeSmallerThanJPEG 确认 WebP 路径真的走通且产物更小。
func TestEncodeWebPSizeSmallerThanJPEG(t *testing.T) {
	img := fixtureRGBA(256, 192)
	webpOut, _, err := Encode(img, EncodingOptions{Format: FormatWebP, Quality: 80})
	if err != nil {
		t.Fatalf("webp encode: %v", err)
	}
	jpegOut, _, err := Encode(img, EncodingOptions{Format: FormatJPEG, Quality: 80})
	if err != nil {
		t.Fatalf("jpeg encode: %v", err)
	}
	if len(webpOut) >= len(jpegOut) {
		t.Fatalf("webp output %d bytes >= jpeg output %d bytes; webp path may not be wired", len(webpOut), len(jpegOut))
	}
	decoded, err := Decode(webpOut, DecodeLimits{})
	if err != nil {
		t.Fatalf("decode webp output: %v", err)
	}
	if decoded.Width != 256 || decoded.Height != 192 {
		t.Fatalf("webp round trip dims = %dx%d", decoded.Width, decoded.Height)
	}
}

// TestEncodeWebPLossless 覆盖无损开关。
func TestEncodeWebPLossless(t *testing.T) {
	img := fixtureRGBA(64, 64)
	lossy, _, err := Encode(img, EncodingOptions{Format: FormatWebP, Quality: 50})
	if err != nil {
		t.Fatalf("lossy webp: %v", err)
	}
	lossless, _, err := Encode(img, EncodingOptions{Format: FormatWebP, Lossless: true})
	if err != nil {
		t.Fatalf("lossless webp: %v", err)
	}
	if len(lossless) <= len(lossy) {
		t.Fatalf("lossless (%d B) should exceed lossy (%d B) for a gradient fixture", len(lossless), len(lossy))
	}
}
