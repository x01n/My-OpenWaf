package imagery

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/jpeg"
	"testing"
)

// largeJPEGFixture 生成一张 4000x3000 的 JPEG，作为 info 快路径收益的标尺。
//
// 选 JPEG 而不是 PNG：JPEG 解码是 CPU 密集的（反 DCT + 上采样），收益不会被
// PNG 的 zlib 解压成本掩盖；4000x3000 按 RGBA 计是 48 MiB，也正是解码器必须
// 分配、而快路径完全不碰的那块内存。
//
// @param b 基准测试上下文。
// @return JPEG 字节。
func largeJPEGFixture(b *testing.B) []byte {
	b.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 4000, 3000))
	for y := 0; y < 3000; y += 5 {
		for x := 0; x < 4000; x += 5 {
			img.Set(x, y, color.RGBA{R: uint8(x % 251), G: uint8(y % 241), B: 96, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 85}); err != nil {
		b.Fatalf("encode: %v", err)
	}
	return buf.Bytes()
}

// BenchmarkInfoPathFullDecode 是改造前的口径：全量解码 + BuildInfo。
func BenchmarkInfoPathFullDecode(b *testing.B) {
	data := largeJPEGFixture(b)
	opts, err := Parse("info")
	if err != nil {
		b.Fatalf("Parse: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Decode(data, DecodeLimits{}); err != nil {
			b.Fatal(err)
		}
		_, encoded := TransformInfoReference(data, opts)
		_ = encoded
	}
}

// BenchmarkInfoPathHeaderOnly 是改造后的口径：只读头 + BuildInfo。
func BenchmarkInfoPathHeaderOnly(b *testing.B) {
	data := largeJPEGFixture(b)
	opts, err := Parse("info")
	if err != nil {
		b.Fatalf("Parse: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := Transform(context.Background(), data, "image/jpeg", opts, "", DecodeLimits{})
		if !res.Changed {
			b.Fatalf("info skipped: %q", res.SkipReason)
		}
	}
}

// TransformInfoReference 复刻改造前 info 分支的行为（全量解码后渲染 JSON）。
//
// 只用于基准对照，不参与生产路径；放在测试文件里以免污染包的非测试面。
//
// @param data 图片字节。
// @param opts 已解析参数（仅使用其 Info 开关）。
// @return 元信息与 JSON 字节。
func TransformInfoReference(data []byte, opts Options) (InfoOutput, []byte) {
	decoded, err := Decode(data, DecodeLimits{})
	if err != nil {
		return nil, nil
	}
	return BuildInfo(data, decoded, exifOrientation(data))
}
