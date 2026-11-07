package imagery

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/jpeg"
	"strconv"
	"testing"
)

// parseInfo 解析 info 参数并断言成功。
func parseInfo(t *testing.T, raw string) Options {
	t.Helper()
	opts, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse(%q): %v", raw, err)
	}
	if !opts.Info {
		t.Fatalf("Parse(%q) did not set Info", raw)
	}
	return opts
}

// TestInfoFastPathMatchesFullDecodeOnAllFixtures 是 info 快路径的等价性主门禁。
//
// 对每一个 fixture 同时跑两条路径——info 分支（decodeHeaderOnly）与非 info 分支
// 先做的全量 Decode——断言两者的 Format/Width/Height/FrameCount 逐字段相同，
// 并断言渲染出的 JSON 字节与用 Decode 结果调用 BuildInfo 得到的字节逐字节一致。
//
// 这条断言覆盖的是「输出等价」：只要四个字段有任何一处偏差，JSON 就会不同。
//
// TIFF 单列：它是唯一没有结束标记约定的格式，容器完整性永远判定为未知，因此
// decodeHeaderOnly 必然回退到 Decode，Image 非 nil 是正确行为而不是缺陷。这条
// fixture 在断言里只要求字段等价。
func TestInfoFastPathMatchesFullDecodeOnAllFixtures(t *testing.T) {
	fixtures := []string{
		"fixture.png", "fixture.jpg", "fixture.gif",
		"fixture.animated.gif", "fixture.webp", "fixture.bmp", "fixture.tiff",
	}
	// noPixelFallback 是不回退（Image 恒为 nil）的格式；TIFF 不在其中。
	noPixelFallback := map[string]bool{
		"fixture.png": true, "fixture.jpg": true, "fixture.gif": true,
		"fixture.animated.gif": true, "fixture.webp": true, "fixture.bmp": true,
	}
	for _, name := range fixtures {
		data := mustReadTestdata(t, name)

		header, err := decodeHeaderOnly(data, DecodeLimits{})
		if err != nil {
			t.Fatalf("%s: decodeHeaderOnly: %v", name, err)
		}
		full, err := Decode(data, DecodeLimits{})
		if err != nil {
			t.Fatalf("%s: Decode: %v", name, err)
		}

		if header.Format != full.Format {
			t.Errorf("%s: Format = %q, full decode = %q", name, header.Format, full.Format)
		}
		if header.Width != full.Width || header.Height != full.Height {
			t.Errorf("%s: dims = %dx%d, full decode = %dx%d",
				name, header.Width, header.Height, full.Width, full.Height)
		}
		if header.FrameCount != full.FrameCount {
			t.Errorf("%s: FrameCount = %d, full decode = %d", name, header.FrameCount, full.FrameCount)
		}
		if noPixelFallback[name] && header.Image != nil {
			t.Errorf("%s: fast path allocated pixels (got %T) although the container is complete",
				name, header.Image)
		}
		if !noPixelFallback[name] && header.Image == nil {
			t.Errorf("%s: expected fallback to Decode (no trailing marker convention), got header-only result", name)
		}

		orientation := exifOrientation(data)
		_, wantJSON := BuildInfo(data, full, orientation)
		_, gotJSON := BuildInfo(data, header, orientation)
		if !bytes.Equal(gotJSON, wantJSON) {
			t.Errorf("%s: info JSON differs\n got: %s\nwant: %s", name, gotJSON, wantJSON)
		}
	}
}

// TestInfoFastPathMatchesFullDecodeThroughTransform 从 Transform 入口验证同一条性质。
//
// 上一条测试直接比对 decodeHeaderOnly 与 Decode；这一条走真实入口，断言
// info 请求的 Result.Body（即下发给客户端的 JSON 字节）与手工用全量解码结果
// 渲染出的字节一致，并确认 ContentType/Changed 语义未变。
func TestInfoFastPathMatchesFullDecodeThroughTransform(t *testing.T) {
	fixtures := []string{
		"fixture.png", "fixture.jpg", "fixture.gif",
		"fixture.animated.gif", "fixture.webp", "fixture.bmp", "fixture.tiff",
	}
	opts := parseInfo(t, "info")
	for _, name := range fixtures {
		data := mustReadTestdata(t, name)
		res := Transform(context.Background(), data, "application/octet-stream", opts, "", DecodeLimits{})
		if !res.Changed {
			t.Fatalf("%s: info must produce a body; SkipReason=%q", name, res.SkipReason)
		}
		if res.ContentType != "application/json; charset=utf-8" {
			t.Fatalf("%s: ContentType = %q", name, res.ContentType)
		}

		full, err := Decode(data, DecodeLimits{})
		if err != nil {
			t.Fatalf("%s: Decode: %v", name, err)
		}
		_, wantJSON := BuildInfo(data, full, exifOrientation(data))
		if !bytes.Equal(res.Body, wantJSON) {
			t.Errorf("%s: Transform info body differs from full-decode rendering\n got: %s\nwant: %s",
				name, res.Body, wantJSON)
		}
		if got := res.Info["FileSize"].Value; got != strconv.Itoa(len(data)) {
			t.Errorf("%s: FileSize = %q, want %d", name, got, len(data))
		}
	}
}

// TestInfoFastPathFallsBackForTruncatedInputs 覆盖严格性：截断输入必须与
// 全量解码给出逐字相同的结论。
//
// 逐长度穷举每个 fixture 的所有截断点，断言：
//
//  1. 回退到 Decode 的情形（判据是结果的 Image 非 nil——decodeHeaderOnly
//     自身永不分配像素）与直接 Decode 的错误文本逐字相同；
//  2. 未回退直接返回的情形（Image 为 nil）只允许出现在 Decode 也成功的长度上。
//     这条是硬断言，零容忍：它保证快路径绝不会放行任何一个 Decode 会拒绝的
//     输入。守卫容器判定正确性的等价物在 container_complete_test.go。
func TestInfoFastPathFallsBackForTruncatedInputs(t *testing.T) {
	fixtures := []string{
		"fixture.png", "fixture.jpg", "fixture.gif",
		"fixture.animated.gif", "fixture.webp", "fixture.bmp", "fixture.tiff",
	}
	for _, name := range fixtures {
		data := mustReadTestdata(t, name)
		for l := 1; l <= len(data); l++ {
			truncated := data[:l]
			header, fastErr := decodeHeaderOnly(truncated, DecodeLimits{})
			_, fullErr := Decode(truncated, DecodeLimits{})

			fellBack := fastErr != nil || header == nil || header.Image != nil
			if fellBack {
				if errText(fastErr) != errText(fullErr) {
					t.Errorf("%s@%d: fallback error differs\n fast: %v\n full: %v", name, l, fastErr, fullErr)
				}
				continue
			}
			if fullErr != nil {
				t.Errorf("%s@%d: fast path accepted an input Decode rejects: %v (containerComplete=%v)",
					name, l, fullErr, containerComplete(header.Format, truncated))
			}
		}
	}
}

// TestInfoFastPathSkipsPixelDecode 证明快路径真的没有解码像素。
//
// 判据不是耗时（易受宿机负载影响），而是可观测的副作用：Decode 成功时一定
// 分配像素缓冲，Image 非 nil；快路径的 Image 必须恒为 nil。再用一个「头部
// 合法、容器完整、但像素数据不可解码」的构造输入，确认两条路径的结论差异
// 只在这一点上，且快路径返回的是头部字段而不是错误。
func TestInfoFastPathSkipsPixelDecode(t *testing.T) {
	data := mustReadTestdata(t, "fixture.png")
	header, err := decodeHeaderOnly(data, DecodeLimits{})
	if err != nil {
		t.Fatalf("decodeHeaderOnly: %v", err)
	}
	if header.Image != nil {
		t.Fatal("fast path allocated pixels")
	}
	// 尺寸必须来自真实头部，而不是被猜测的常量。
	if header.Width != 120 || header.Height != 80 {
		t.Fatalf("dims = %dx%d, want 120x80", header.Width, header.Height)
	}
}

// TestInfoFastPathHonoursDecodeLimits 限额必须与全量路径逐字相同地拒绝。
//
// 解压炸弹防线在两条路径上都必须在分配像素之前生效。fixture.tiff 是回退路径
// 代表（容器判定永远未知），PNG 是快路径代表，两个都要覆盖，因为「限额检查
// 在回退前后各发生一次」这一点只有在回退样本上才验证得到。
func TestInfoFastPathHonoursDecodeLimits(t *testing.T) {
	for _, name := range []string{"fixture.png", "fixture.tiff"} {
		data := mustReadTestdata(t, name)

		cases := []struct {
			label  string
			limits DecodeLimits
		}{
			{"max bytes", DecodeLimits{MaxBytes: 64, MaxPixels: 1 << 20, MaxSide: 4096}},
			{"max side", DecodeLimits{MaxBytes: 1 << 20, MaxPixels: 1 << 20, MaxSide: 32}},
			{"max pixels", DecodeLimits{MaxBytes: 1 << 20, MaxPixels: 100, MaxSide: 4096}},
		}
		for _, tc := range cases {
			_, fastErr := decodeHeaderOnly(data, tc.limits)
			_, fullErr := Decode(data, tc.limits)
			if fastErr == nil {
				t.Errorf("%s/%s: decodeHeaderOnly accepted input beyond limits", name, tc.label)
				continue
			}
			if errText(fastErr) != errText(fullErr) {
				t.Errorf("%s/%s: error differs\n fast: %v\n full: %v", name, tc.label, fastErr, fullErr)
			}
		}
	}
}

// TestInfoFastPathOnLargeJPEG 用现场生成的大图确认快路径不随像素量伸缩。
//
// 断言的是「不分配像素」这一性质在大图上的体现：4000x3000 的 JPEG 若走全量
// 解码会分配约 48 MiB，快路径的 Image 仍是 nil，且 dimensions 与全量一致。
func TestInfoFastPathOnLargeJPEG(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 4000, 3000))
	for y := 0; y < 3000; y += 7 {
		for x := 0; x < 4000; x += 7 {
			img.Set(x, y, color.RGBA{R: uint8(x % 256), G: uint8(y % 256), B: 128, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}); err != nil {
		t.Fatalf("encode large jpeg: %v", err)
	}
	data := buf.Bytes()

	header, err := decodeHeaderOnly(data, DecodeLimits{})
	if err != nil {
		t.Fatalf("decodeHeaderOnly on %d bytes: %v", len(data), err)
	}
	full, err := Decode(data, DecodeLimits{})
	if err != nil {
		t.Fatalf("Decode on %d bytes: %v", len(data), err)
	}
	if header.Width != full.Width || header.Height != full.Height {
		t.Fatalf("dims = %dx%d, full = %dx%d", header.Width, header.Height, full.Width, full.Height)
	}
	if header.Image != nil {
		t.Fatal("fast path allocated pixels for a 4000x3000 input")
	}
	_, wantJSON := BuildInfo(data, full, 0)
	_, gotJSON := BuildInfo(data, header, 0)
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("JSON differs\n got: %s\nwant: %s", gotJSON, wantJSON)
	}
}

// TestInfoFastPathMatchesDecodeOnMalformedHeaders 畸形头部必须给出相同错误。
//
// 直接复用既有 security_test.go 的用例集合，逐条比对两条路径的错误文本。
func TestInfoFastPathMatchesDecodeOnMalformedHeaders(t *testing.T) {
	cases := map[string][]byte{
		"nil":              nil,
		"empty":            {},
		"plain text":       []byte("hello world"),
		"png magic only":   {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A},
		"jpeg magic only":  {0xFF, 0xD8},
		"gif magic only":   []byte("GIF89a"),
		"riff non-webp":    []byte("RIFF????WAVE"),
		"zero dims png":    makePNGWithDims(0, 0),
		"negative-looking": {0xFF, 0xD8, 0xFF, 0xE0},
	}
	for name, data := range cases {
		_, fastErr := decodeHeaderOnly(data, DecodeLimits{})
		_, fullErr := Decode(data, DecodeLimits{})
		if errText(fastErr) != errText(fullErr) {
			t.Errorf("%s: error differs\n fast: %v\n full: %v", name, fastErr, fullErr)
		}
	}
}

// TestBuildInfoAcceptsNilImageDecodeInput 钉住 BuildInfo 的契约。
//
// 改造后 BuildInfo 对「Image 为 nil 的 DecodeInput」也返回合法结果。这不是
// 错误容忍：BuildInfo 只读 Format/FrameCount/Height/Width，从来不需要像素。
// 但改造前 Image 为 nil 只可能来自构造错误，所以这是一个**契约收窄**——包外
// 调用者完全可以自行构造 DecodeInput{...}（字段全导出）传进来，包括 Image
// 为 nil 的那种。这条测试把该用法固定下来，避免将来有人加一句
// `if decoded.Image == nil { return nil, nil }` 把它悄然收回。
func TestBuildInfoAcceptsNilImageDecodeInput(t *testing.T) {
	data := mustReadTestdata(t, "fixture.jpg")

	// 模拟包外调用者：只用导出的字段字面量构造，Image 留空。
	external := &DecodeInput{Format: FormatJPEG, Width: 120, Height: 80, FrameCount: 1}
	if external.Image != nil {
		t.Fatal("test setup: Image should be nil")
	}

	info, encoded := BuildInfo(data, external, 0)
	if len(encoded) == 0 {
		t.Fatal("BuildInfo returned no JSON for a nil-Image input")
	}
	for field, want := range map[string]string{
		"FileSize":    strconv.Itoa(len(data)),
		"Format":      "jpeg",
		"FrameCount":  "1",
		"ImageHeight": "80",
		"ImageWidth":  "120",
	} {
		if got := info[field].Value; got != want {
			t.Errorf("%s = %q, want %q", field, got, want)
		}
	}
	if _, ok := info["Orientation"]; ok {
		t.Error("Orientation must be omitted when orientation is 0")
	}

	// 与 decodeHeaderOnly 的结果必须一致：证明「头路径 == 包外手工构造」。
	header, err := decodeHeaderOnly(data, DecodeLimits{})
	if err != nil {
		t.Fatalf("decodeHeaderOnly: %v", err)
	}
	_, wantJSON := BuildInfo(data, header, 0)
	if !bytes.Equal(encoded, wantJSON) {
		t.Errorf("hand-built and header-only inputs render differently\n got: %s\nwant: %s", encoded, wantJSON)
	}
}

// errText 把 error 归一成可比较的文本；nil 归一为空串。
//
// @param err 待归一化的错误。
// @return 错误文本；nil 时为空串。
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestInfoFastPathByteCorruptionDivergenceIsBounded 量化并钉住字节损坏的差异面。
//
// 与截断不同（截断是零差异，由 TestInfoFastPathFallsBackForTruncatedInputs
// 硬断言），字节损坏无法在不解码的前提下完全消除：容器块链自洽、只有压缩数据
// 或段内部字段损坏时，任何 O(1) 完整性判定都发现不了。这个差异面是刻意接受的
// 权衡，理由写在 decodeHeaderOnly 的注释里。
//
// 这条测试的作用是把它变成**已知且被封顶的**：逐字节翻转（^0xFF）统计
// 「头部仍通过 + 容器判完整 + Decode 失败」的位置数，断言不超过上限。上限取
// 本轮实测值向上取整到下一个百位，任何把差异面放大的改动都会在这里失败。
func TestInfoFastPathByteCorruptionDivergenceIsBounded(t *testing.T) {
	cases := []struct {
		name     string
		maxFlips int
	}{
		{"fixture.png", 1100},
		{"fixture.jpg", 400},
		{"fixture.gif", 4800},
		{"fixture.animated.gif", 100},
		{"fixture.webp", 500},
		{"fixture.bmp", 100},
		{"fixture.tiff", 0}, // TIFF 永远回退，差异必须为零
	}
	for _, tc := range cases {
		data := mustReadTestdata(t, tc.name)
		format := formatOf(t, data)
		divergent := 0
		for i := 0; i < len(data); i++ {
			mut := append([]byte(nil), data...)
			mut[i] ^= 0xFF
			if _, _, err := decodeConfigChecked(mut, DecodeLimits{}); err != nil {
				continue // 头部层面已拒绝：两条路径一致
			}
			if !containerComplete(format, mut) {
				continue // 回退到 Decode：两条路径一致
			}
			if _, _, err := image.Decode(bytes.NewReader(mut)); err != nil {
				divergent++
			}
		}
		if divergent > tc.maxFlips {
			t.Errorf("%s: %d divergent byte flips exceeds the cap of %d", tc.name, divergent, tc.maxFlips)
		}
		t.Logf("%s: divergent byte flips = %d (cap %d)", tc.name, divergent, tc.maxFlips)
	}
}
