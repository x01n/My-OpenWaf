package imagery

import (
	"bytes"
	"testing"
)

// TestWatermarkMatchesPreMigrationGolden 验证水印迁移后与迁移前逐字节一致。
//
// golden 文件由迁移前的旧 addWatermark（internal/waf/dynamic/watermark.go）对
// 同一 fixture 生成，取数脚本已删除、产物留在 testdata/。
//
// 注意 GIF 一例的比对语义：旧实现在测试进程里能解码 GIF（测试二进制因其它
// 测试间接引入 image/gif），但生产二进制不引入，故旧实现在线上对 GIF 必然
// 返回原图；新实现真的处理 GIF 并把输出格式改为 PNG（GIF 无法承载半透明
// 水印）。因此 GIF 的 golden 只用于确认「像素处理链路未变」，格式变化是
// 有意的修复。
func TestWatermarkMatchesPreMigrationGolden(t *testing.T) {
	cases := []struct {
		name     string
		wantFmt  Format
		wantSame bool // 与 golden 逐字节一致
	}{
		{"fixture.png", FormatPNG, true},
		{"fixture.jpg", FormatJPEG, true},
		{"fixture.gif", FormatPNG, true},
	}
	for _, tc := range cases {
		in := mustReadTestdata(t, tc.name)
		golden := mustReadTestdata(t, tc.name+".watermark.golden")

		out, format, err := Watermark(in, "My-OpenWaf")
		if err != nil {
			t.Fatalf("%s: Watermark returned error: %v", tc.name, err)
		}
		if format != tc.wantFmt {
			t.Fatalf("%s: output format = %q, want %q", tc.name, format, tc.wantFmt)
		}
		if tc.wantSame && !bytes.Equal(out, golden) {
			t.Fatalf("%s: watermark output differs from pre-migration golden (%d bytes vs %d bytes)", tc.name, len(out), len(golden))
		}
	}
}

// TestWatermarkGIFProducesPNGNotGIFBytes 覆盖现状缺陷 2：
// GIF 输入经水印后，输出字节必须是 PNG，且返回的格式要与字节一致。
func TestWatermarkGIFProducesPNGNotGIFBytes(t *testing.T) {
	in := mustReadTestdata(t, "fixture.gif")
	out, format, err := Watermark(in, "My-OpenWaf")
	if err != nil {
		t.Fatalf("Watermark error: %v", err)
	}
	if format != FormatPNG {
		t.Fatalf("format = %q, want png", format)
	}
	if got := SniffFormat(out); got != "png" {
		t.Fatalf("sniffed output format = %q, want png (bytes and declared format must agree)", got)
	}
}

// TestWatermarkGIFIsReachable 覆盖现状缺陷 1：GIF 输入不再走「解码失败返回原图」。
func TestWatermarkGIFIsReachable(t *testing.T) {
	in := mustReadTestdata(t, "fixture.gif")
	out, _, err := Watermark(in, "My-OpenWaf")
	if err != nil {
		t.Fatalf("Watermark error: %v", err)
	}
	if bytes.Equal(in, out) {
		t.Fatal("GIF watermark returned input unchanged: gif decoder is not registered")
	}
}

// TestWatermarkPassthroughForUnsupportedInput 覆盖畸形与空输入：一律原图直通。
func TestWatermarkPassthroughForUnsupportedInput(t *testing.T) {
	cases := map[string][]byte{
		"empty":         {},
		"garbage":       []byte("not an image at all"),
		"truncated png": mustReadTestdata(t, "fixture.png")[:32],
		"truncated jpg": mustReadTestdata(t, "fixture.jpg")[:16],
	}
	for name, in := range cases {
		out, _, err := Watermark(in, "My-OpenWaf")
		if err != nil {
			t.Fatalf("%s: Watermark returned error: %v", name, err)
		}
		if !bytes.Equal(in, out) {
			t.Fatalf("%s: expected passthrough, got %d bytes from %d", name, len(out), len(in))
		}
	}
}

// TestWatermarkUnsupportedFormatPassthrough 覆盖 BMP/TIFF/WebP 输入：
// 水印不处理这三种格式（与迁移前一致），必须原样返回。
func TestWatermarkUnsupportedFormatPassthrough(t *testing.T) {
	for _, name := range []string{"fixture.bmp", "fixture.tiff", "fixture.webp"} {
		in := mustReadTestdata(t, name)
		out, _, err := Watermark(in, "My-OpenWaf")
		if err != nil {
			t.Fatalf("%s: Watermark returned error: %v", name, err)
		}
		if !bytes.Equal(in, out) {
			t.Fatalf("%s: expected passthrough for non-watermarkable format", name)
		}
	}
}
