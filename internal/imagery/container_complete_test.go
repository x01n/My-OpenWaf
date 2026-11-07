package imagery

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestContainerCompleteAcceptsEveryFixture 完整 fixture 必须全部判为完整。
func TestContainerCompleteAcceptsEveryFixture(t *testing.T) {
	accept := []string{
		"fixture.png", "fixture.jpg", "fixture.gif",
		"fixture.animated.gif", "fixture.webp", "fixture.bmp",
	}
	for _, name := range accept {
		data := mustReadTestdata(t, name)
		if !containerComplete(formatOf(t, data), data) {
			t.Errorf("%s: containerComplete = false for an intact file", name)
		}
	}
	// TIFF 是刻意的例外：没有结束标记约定，永远判为未知 → 回退。
	data := mustReadTestdata(t, "fixture.tiff")
	if containerComplete(formatOf(t, data), data) {
		t.Error("fixture.tiff: TIFF must never be accepted by the fast path (no trailing marker convention)")
	}
}

// formatOf 返回图片的规范化格式名。
//
// @param t 测试上下文。
// @param data 图片字节。
// @return 规范化格式。
func formatOf(t *testing.T, data []byte) Format {
	t.Helper()
	_, format, err := decodeConfigChecked(data, DecodeLimits{})
	if err != nil {
		t.Fatalf("decodeConfigChecked: %v", err)
	}
	return format
}

// TestContainerCompleteRejectsTruncations 截断文件必须判为不完整。
//
// 对每个 fixture 穷举所有截断长度：凡是 DecodeConfig 已经成功的长度，容器判定
// 都不允许放行——因为 Decode 在这些长度上全部失败（截断文件的像素数据必然
// 不足）。这条断言就是「快路径不会放行 Decode 会拒绝的输入」的守卫。
func TestContainerCompleteRejectsTruncations(t *testing.T) {
	for _, name := range []string{
		"fixture.png", "fixture.jpg", "fixture.gif",
		"fixture.animated.gif", "fixture.webp", "fixture.bmp",
	} {
		data := mustReadTestdata(t, name)
		for l := 1; l < len(data); l++ {
			truncated := data[:l]
			_, format, err := decodeConfigChecked(truncated, DecodeLimits{})
			if err != nil {
				continue // 头部层面已拒绝，到不了容器判定
			}
			if containerComplete(format, truncated) {
				t.Errorf("%s@%d: containerComplete accepted a truncated file (Decode would reject it)", name, l)
			}
		}
	}
}

// TestGIFContainerCompleteRejectsFakeTrailerByte 覆盖 GIF 尾字节判定的历史缺陷。
//
// 构造一个结构完整、但把尾字节改成非 Trailer 的两帧 GIF，再在其中插入一个
// 0x3B 字节：只看尾字节的判定会把这种文件判成完整，块结构扫描则会正确拒绝。
// 这条测试直接钉住「必须用结构扫描而不是尾字节」这个结论。
func TestGIFContainerCompleteRejectsFakeTrailerByte(t *testing.T) {
	data := mustReadTestdata(t, "fixture.animated.gif")

	if !containerComplete(FormatGIF, data) {
		t.Fatal("baseline: intact animated GIF must be accepted")
	}

	// 去掉 Trailer 0x3B：尾字节不再是 0x3B，两种判定都应拒绝。
	noTrailer := data[:len(data)-1]
	if containerComplete(FormatGIF, noTrailer) {
		t.Error("truncated GIF (trailer removed) accepted")
	}

	// 在文件中间插入一个 0x3B，尾部保持截断状态：尾字节判定无法分辨，
	// 结构扫描必须拒绝（块链在 0x3B 处断开，没有走到文件末尾的 Trailer）。
	withFakeTrailer := append([]byte(nil), noTrailer...)
	mid := len(withFakeTrailer) / 2
	withFakeTrailer = append(withFakeTrailer[:mid], append([]byte{0x3B}, withFakeTrailer[mid:]...)...)
	if withFakeTrailer[len(withFakeTrailer)-1] == 0x3B {
		t.Fatal("test setup error: trailing byte is still 0x3B")
	}
	if containerComplete(FormatGIF, withFakeTrailer) {
		t.Error("GIF with an interior 0x3B accepted: the tail-byte check is not sufficient")
	}
}

// TestContainerCompleteWebPUsesDeclaredRIFFSize RIFF 声明长度必须被核对。
func TestContainerCompleteWebPUsesDeclaredRIFFSize(t *testing.T) {
	data := mustReadTestdata(t, "fixture.webp")
	if !containerComplete(FormatWebP, data) {
		t.Fatal("intact WebP rejected")
	}
	// 把 RIFF 声明长度改小 4 字节 → 声明值与实际长度不符 → 必须拒绝。
	corrupted := append([]byte(nil), data...)
	declared := binary.LittleEndian.Uint32(corrupted[4:8])
	binary.LittleEndian.PutUint32(corrupted[4:8], declared-4)
	if containerComplete(FormatWebP, corrupted) {
		t.Error("WebP with a mismatched RIFF size accepted")
	}
}

// TestContainerCompleteBMPUsesFileSize bfSize 必须被核对。
func TestContainerCompleteBMPUsesFileSize(t *testing.T) {
	data := mustReadTestdata(t, "fixture.bmp")
	if !containerComplete(FormatBMP, data) {
		t.Fatal("intact BMP rejected")
	}
	corrupted := append([]byte(nil), data...)
	binary.LittleEndian.PutUint32(corrupted[2:6], uint32(len(corrupted))-8)
	if containerComplete(FormatBMP, corrupted) {
		t.Error("BMP with a mismatched bfSize accepted")
	}
}

// TestContainerCompletePNGRequiresIEND PNG 必须真的有 IEND。
func TestContainerCompletePNGRequiresIEND(t *testing.T) {
	data := mustReadTestdata(t, "fixture.png")
	if !containerComplete(FormatPNG, data) {
		t.Fatal("intact PNG rejected")
	}
	if containerComplete(FormatPNG, data[:len(data)-1]) {
		t.Error("PNG with its last IEND byte removed accepted")
	}
	if containerComplete(FormatPNG, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}) {
		t.Error("8-byte PNG signature accepted as a complete container")
	}
}

// TestContainerCompleteJPEGRequiresEOI JPEG 必须真的有 EOI。
func TestContainerCompleteJPEGRequiresEOI(t *testing.T) {
	data := mustReadTestdata(t, "fixture.jpg")
	if !containerComplete(FormatJPEG, data) {
		t.Fatal("intact JPEG rejected")
	}
	if containerComplete(FormatJPEG, data[:len(data)-2]) {
		t.Error("JPEG with EOI removed accepted")
	}
	// APP1 里可能出现的 0xFFD9 出现在中间不算数：判定只看最后两个字节。
	interior := append([]byte(nil), data[:len(data)-2]...)
	interior = append(interior[:len(interior)/2], append([]byte{0xFF, 0xD9}, interior[len(interior)/2:]...)...)
	if containerComplete(FormatJPEG, interior) {
		t.Error("JPEG with an interior EOI and no trailing EOI accepted")
	}
}

// TestContainerCompleteUnknownFormatRejected 未知格式一律拒绝（回退到 Decode）。
func TestContainerCompleteUnknownFormatRejected(t *testing.T) {
	if containerComplete(FormatTIFF, mustReadTestdata(t, "fixture.tiff")) {
		t.Error("TIFF accepted")
	}
	if containerComplete(Format("avif"), []byte("....ftypavif....")) {
		t.Error("unknown format accepted")
	}
	if containerComplete(Format(""), nil) {
		t.Error("empty format accepted")
	}
}

// TestDecodeHeaderOnlyNeverReturnsPixelsForCompleteContainers 快路径不得分配像素。
//
// 与 infopath_equiv_test.go 的断言互为补充：那里从 Transform 的角度验证，
// 这里直接验证 decodeHeaderOnly 在所有「容器完整」的 fixture 上 Image 恒为 nil。
func TestDecodeHeaderOnlyNeverReturnsPixelsForCompleteContainers(t *testing.T) {
	for _, name := range []string{
		"fixture.png", "fixture.jpg", "fixture.gif",
		"fixture.animated.gif", "fixture.webp", "fixture.bmp",
	} {
		data := mustReadTestdata(t, name)
		out, err := decodeHeaderOnly(data, DecodeLimits{})
		if err != nil {
			t.Fatalf("%s: decodeHeaderOnly: %v", name, err)
		}
		if out.Image != nil {
			t.Errorf("%s: Image = %T, want nil", name, out.Image)
		}
	}
}

// TestDecodeHeaderOnlyFallsBackForTIFF TIFF 必须回退到全量解码。
func TestDecodeHeaderOnlyFallsBackForTIFF(t *testing.T) {
	data := mustReadTestdata(t, "fixture.tiff")
	out, err := decodeHeaderOnly(data, DecodeLimits{})
	if err != nil {
		t.Fatalf("decodeHeaderOnly: %v", err)
	}
	if out.Image == nil {
		t.Fatal("TIFF did not fall back: no trailing marker convention means the container cannot be confirmed")
	}
	// 回退后的字段仍须与非 info 路径一致。
	full, err := Decode(data, DecodeLimits{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out.Format != full.Format || out.Width != full.Width || out.Height != full.Height || out.FrameCount != full.FrameCount {
		t.Fatalf("fallback result %+v differs from Decode %+v", out, full)
	}
}

// TestGIFBlocksConsumeWholeFileOnSyntheticInputs 结构扫描的边界用例。
func TestGIFBlocksConsumeWholeFileOnSyntheticInputs(t *testing.T) {
	// 最小合法 GIF：header + LSD（无全局色表）+ Trailer。
	minimal := []byte("GIF89a" + "\x01\x00\x01\x00" + "\x00\x00\x00" + "\x3B")
	if !gifBlocksConsumeWholeFile(minimal) {
		t.Error("minimal GIF rejected")
	}
	if gifBlocksConsumeWholeFile(minimal[:len(minimal)-1]) {
		t.Error("minimal GIF without trailer accepted")
	}
	// 尾部多出一个字节 → 结构扫描到 Trailer 时不在文件末尾 → 拒绝。
	if gifBlocksConsumeWholeFile(append(append([]byte(nil), minimal...), 0x00)) {
		t.Error("GIF with a byte after the trailer accepted")
	}
	// 非 GIF 头。
	if gifBlocksConsumeWholeFile([]byte("NOTGIF" + "\x00\x00\x00\x00\x00\x00\x00\x3B")) {
		t.Error("non-GIF header accepted")
	}
	// 全局色表版本：packed=0x80 → 色表 2^(0+1)=2 项 × 3 字节。
	withTable := bytes.Join([][]byte{
		[]byte("GIF89a"),
		{0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00},
		make([]byte, 6),
		{0x3B},
	}, nil)
	if !gifBlocksConsumeWholeFile(withTable) {
		t.Error("GIF with a global colour table rejected")
	}
}
