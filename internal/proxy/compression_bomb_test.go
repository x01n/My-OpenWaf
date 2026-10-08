package proxy

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// 本文件锁定压缩炸弹防护的三个门面：请求体转发（流式与非流式）、响应体缓冲、
// 以及逐层限额。多数用例先把上限压到远小于载荷，避免真的分配几十 MiB；上限是
// 进程级可配的，测试期间设置、结束即恢复。
//
// 两侧上限分开：请求侧默认 64 MiB，响应侧默认 8 MiB。

// withDecompressionBudget 在用例期间同时收紧请求侧与响应侧的解压产出上限。
func withDecompressionBudget(t *testing.T, limit int64) {
	t.Helper()
	previousRequest := RequestDecompressionMaxBytes()
	previousResponse := ResponseDecompressionMaxBytes()
	SetRequestDecompressionMaxBytes(limit)
	SetResponseDecompressionMaxBytes(limit)
	t.Cleanup(func() {
		SetRequestDecompressionMaxBytes(previousRequest)
		SetResponseDecompressionMaxBytes(previousResponse)
	})
}

// bombPayload 构造高膨胀比载荷：同一字节重复的明文压缩比极高。
func bombPayload(size int) []byte {
	return bytes.Repeat([]byte("A"), size)
}

func gzipBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func brotliBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := brotli.NewWriter(&buf)
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}
	return buf.Bytes()
}

func zstdBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	return buf.Bytes()
}

// TestDecodeUpstreamRequestBodyBytesStopsAtDecompressionBudget 锁定非流式请求体
// 解压的炸弹上限：超高膨胀比载荷必须在预算处失败，而不是把明文全部展开。
func TestDecodeUpstreamRequestBodyBytesStopsAtDecompressionBudget(t *testing.T) {
	const budget = 1 << 20
	withDecompressionBudget(t, budget)

	// 8 MiB 明文压成约 8 KiB，膨胀比约 1000:1。
	compressed := gzipBytes(t, bombPayload(8<<20))
	if len(compressed) >= budget {
		t.Fatalf("test premise broken: compressed size %d not below budget %d", len(compressed), budget)
	}

	decoded, didDecode, err := decodeUpstreamRequestBodyBytes(compressed, []byte("gzip"))
	if err == nil {
		t.Fatalf("expected decompression budget error, got %d decoded bytes", len(decoded))
	}
	if !errors.Is(err, errDecompressionLimitExceeded) {
		t.Fatalf("error = %v, want errDecompressionLimitExceeded", err)
	}
	if didDecode {
		t.Fatal("didDecode must be false when decompression aborts")
	}
	if decoded != nil {
		t.Fatalf("decoded = %d bytes, want nil (no partial plaintext on bomb)", len(decoded))
	}
}

// TestDecodeUpstreamRequestBodyBytesAllowsBodyWithinBudget 是对照组：预算内的
// 压缩体必须照常完整解压，炸弹防护不得误伤正常请求。
func TestDecodeUpstreamRequestBodyBytesAllowsBodyWithinBudget(t *testing.T) {
	const budget = 1 << 20
	withDecompressionBudget(t, budget)

	payload := bytes.Repeat([]byte("compressible-payload-"), 1000)
	compressed := gzipBytes(t, payload)

	decoded, didDecode, err := decodeUpstreamRequestBodyBytes(compressed, []byte("gzip"))
	if err != nil {
		t.Fatalf("decode within budget returned error: %v", err)
	}
	if !didDecode {
		t.Fatal("expected decode to be applied")
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded %d bytes, want %d", len(decoded), len(payload))
	}
}

// TestDecodeUpstreamRequestBodyStreamStopsAtDecompressionBudget 锁定流式请求体
// 解压的炸弹上限：读取端必须在预算处拿到终止错误，而不是无限读下去。
func TestDecodeUpstreamRequestBodyStreamStopsAtDecompressionBudget(t *testing.T) {
	const budget = 1 << 20
	withDecompressionBudget(t, budget)

	compressed := gzipBytes(t, bombPayload(8<<20))
	reader, didDecode, err := decodeUpstreamRequestBodyStreamBytes(bytes.NewReader(compressed), []byte("gzip"))
	if err != nil {
		t.Fatalf("stream decode construction failed: %v", err)
	}
	if !didDecode {
		t.Fatal("expected stream decode to be applied")
	}
	defer reader.Close()

	read, readErr := io.Copy(io.Discard, reader)
	if readErr == nil {
		t.Fatalf("expected budget error from stream reader, read %d bytes without error", read)
	}
	if !errors.Is(readErr, errDecompressionLimitExceeded) {
		t.Fatalf("error = %v, want errDecompressionLimitExceeded", readErr)
	}
	if read > budget {
		t.Fatalf("read %d bytes, want <= budget %d", read, budget)
	}
}

// TestDecodeUpstreamRequestBodyStreamAllowsBodyWithinBudget 是流式对照组：
// 预算内的压缩体必须能完整读出。
func TestDecodeUpstreamRequestBodyStreamAllowsBodyWithinBudget(t *testing.T) {
	const budget = 1 << 20
	withDecompressionBudget(t, budget)

	payload := bytes.Repeat([]byte("stream-payload-"), 1000)
	compressed := gzipBytes(t, payload)

	reader, didDecode, err := decodeUpstreamRequestBodyStreamBytes(bytes.NewReader(compressed), []byte("gzip"))
	if err != nil {
		t.Fatalf("stream decode construction failed: %v", err)
	}
	if !didDecode {
		t.Fatal("expected stream decode to be applied")
	}
	defer reader.Close()

	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read within budget returned error: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded %d bytes, want %d", len(decoded), len(payload))
	}
}

// TestReadUpstreamResponseBodyStopsAtDecompressionBudget 锁定响应体解压的炸弹
// 上限：上游返回的高膨胀比响应不得被完整展开到内存。
func TestReadUpstreamResponseBodyStopsAtDecompressionBudget(t *testing.T) {
	const budget = 1 << 20
	withDecompressionBudget(t, budget)

	compressed := gzipBytes(t, bombPayload(8<<20))
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Encoding": []string{"gzip"},
			"Content-Type":     []string{"text/plain; charset=utf-8"},
		},
		Body: io.NopCloser(bytes.NewReader(compressed)),
	}

	body, _, err := readUpstreamResponseBody(resp)
	if err == nil {
		t.Fatalf("expected response decompression budget error, got %d bytes", len(body))
	}
	if !errors.Is(err, errDecompressionLimitExceeded) {
		t.Fatalf("error = %v, want errDecompressionLimitExceeded", err)
	}
	if body != nil {
		t.Fatalf("body = %d bytes, want nil", len(body))
	}
}

// TestReadUpstreamResponseBodyLimitedKeepsStreamingSemanticsBelowBudget 锁定
// 「调用方上限」与「炸弹上限」的分工：响应体超过调用方缓冲上限但仍远低于
// 炸弹上限时，必须维持既有语义——返回前缀 + 未读余量，由调用方流式转发，
// 不能因为加了炸弹防护就把正常的大响应变成错误。
func TestReadUpstreamResponseBodyLimitedKeepsStreamingSemanticsBelowBudget(t *testing.T) {
	const budget = 64 << 20
	withDecompressionBudget(t, budget)

	// 4 MiB 明文，压缩后约 4 KiB，远超调用方 1 MiB 的缓冲上限。
	plaintext := bombPayload(4 << 20)
	compressed := gzipBytes(t, plaintext)
	const callerLimit = 1 << 20

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Encoding": []string{"gzip"},
			"Content-Type":     []string{"text/plain; charset=utf-8"},
		},
		Body: io.NopCloser(bytes.NewReader(compressed)),
	}

	body, _, remaining, closeFn, decoded, truncated, err := readUpstreamResponseBodyLimited(resp, callerLimit)
	if err != nil {
		t.Fatalf("readUpstreamResponseBodyLimited returned error: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncated=true when body exceeds caller limit")
	}
	if !decoded {
		t.Fatal("expected decoded=true")
	}
	if len(body) != callerLimit {
		t.Fatalf("prefix = %d bytes, want %d", len(body), callerLimit)
	}
	if remaining == nil {
		t.Fatal("expected remaining reader for streaming forward")
	}
	rest, err := io.ReadAll(remaining)
	if err != nil {
		t.Fatalf("read remainder: %v", err)
	}
	if closeFn != nil {
		if err := closeFn(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}
	if total := len(body) + len(rest); total != len(plaintext) {
		t.Fatalf("prefix+remainder = %d bytes, want %d (no byte loss)", total, len(plaintext))
	}
}

// TestReadUpstreamResponseBodyLimitedReportsBombAboveBudget 是上一条的对偶：
// 响应体超过炸弹上限时必须报错，而不是把前缀当完整明文交给调用方。
func TestReadUpstreamResponseBodyLimitedReportsBombAboveBudget(t *testing.T) {
	const budget = 1 << 20
	withDecompressionBudget(t, budget)

	compressed := gzipBytes(t, bombPayload(8<<20))
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Encoding": []string{"gzip"},
			"Content-Type":     []string{"text/plain; charset=utf-8"},
		},
		Body: io.NopCloser(bytes.NewReader(compressed)),
	}

	// 调用方上限远大于炸弹上限：约束来自炸弹防护。
	body, _, _, _, _, _, err := readUpstreamResponseBodyLimited(resp, 64<<20)
	if err == nil {
		t.Fatalf("expected bomb error, got %d bytes", len(body))
	}
	if !errors.Is(err, errDecompressionLimitExceeded) {
		t.Fatalf("error = %v, want errDecompressionLimitExceeded", err)
	}
}

// TestSetDecompressionMaxBytesRejectsNonPositive 锁定「上限不可被配成关闭」：
// 0 或负数一律回退方向默认值，否则一次环境变量笔误就能关掉炸弹防护。
func TestSetDecompressionMaxBytesRejectsNonPositive(t *testing.T) {
	previousRequest := RequestDecompressionMaxBytes()
	previousResponse := ResponseDecompressionMaxBytes()
	t.Cleanup(func() {
		SetRequestDecompressionMaxBytes(previousRequest)
		SetResponseDecompressionMaxBytes(previousResponse)
	})

	for _, value := range []int64{0, -1, -1 << 40} {
		SetRequestDecompressionMaxBytes(value)
		if got := RequestDecompressionMaxBytes(); got != DefaultRequestDecompressionMaxBytes {
			t.Fatalf("SetRequestDecompressionMaxBytes(%d) => %d, want default %d", value, got, DefaultRequestDecompressionMaxBytes)
		}
		SetResponseDecompressionMaxBytes(value)
		if got := ResponseDecompressionMaxBytes(); got != DefaultResponseDecompressionMaxBytes {
			t.Fatalf("SetResponseDecompressionMaxBytes(%d) => %d, want default %d", value, got, DefaultResponseDecompressionMaxBytes)
		}
	}

	SetRequestDecompressionMaxBytes(4 << 20)
	if got := RequestDecompressionMaxBytes(); got != 4<<20 {
		t.Fatalf("SetRequestDecompressionMaxBytes(4MiB) => %d, want %d", got, 4<<20)
	}
	SetResponseDecompressionMaxBytes(2 << 20)
	if got := ResponseDecompressionMaxBytes(); got != 2<<20 {
		t.Fatalf("SetResponseDecompressionMaxBytes(2MiB) => %d, want %d", got, 2<<20)
	}
}

// TestDecompressionGuardStopsExactlyAtBudget 锁定守卫的边界：正好用满预算的
// 读取必须成功，越过预算的下一次读取才失败。
func TestDecompressionGuardStopsExactlyAtBudget(t *testing.T) {
	const budget = 16
	guard := &decompressionGuard{reader: bytes.NewReader(bytes.Repeat([]byte("x"), 64)), remaining: budget}

	exact := make([]byte, budget)
	if _, err := io.ReadFull(guard, exact); err != nil {
		t.Fatalf("reading exactly the budget returned error: %v", err)
	}
	if guard.remaining != 0 {
		t.Fatalf("remaining = %d, want 0", guard.remaining)
	}
	if _, err := guard.Read(make([]byte, 1)); !errors.Is(err, errDecompressionLimitExceeded) {
		t.Fatalf("read past budget error = %v, want errDecompressionLimitExceeded", err)
	}
}

// TestDecompressionBudgetAppliesToAllSupportedEncodings 确认上限对三种带自述
// 限额的解码器一致生效：炸弹防护不能只覆盖 gzip。
func TestDecompressionBudgetAppliesToAllSupportedEncodings(t *testing.T) {
	const budget = 256 << 10
	withDecompressionBudget(t, budget)

	plaintext := bombPayload(4 << 20)
	cases := []struct {
		encoding string
		body     []byte
	}{
		{encoding: "gzip", body: gzipBytes(t, plaintext)},
		{encoding: "br", body: brotliBytes(t, plaintext)},
		{encoding: "zstd", body: zstdBytes(t, plaintext)},
	}

	for _, tc := range cases {
		t.Run(tc.encoding, func(t *testing.T) {
			if len(tc.body) >= budget {
				t.Fatalf("test premise broken: compressed size %d not below budget %d", len(tc.body), budget)
			}
			_, _, err := decodeUpstreamRequestBodyBytes(tc.body, []byte(tc.encoding))
			if !errors.Is(err, errDecompressionLimitExceeded) {
				t.Fatalf("error = %v, want errDecompressionLimitExceeded", err)
			}
		})
	}
}

// TestDecodeUpstreamRequestBodyBytesLimitsEachLayerIndependently 锁定「逐层
// 上限」：双层嵌套的炸弹必须在内层被截断，不能把外层解出的中间体再放大一次。
//
// 构造（与简报复现一致）：32 MiB 明文 → gzip（约 32 KiB）→ 再 gzip（数百字节）。
// 若两层都不限，第二层会去解 32 MiB 并继续放大。
func TestDecodeUpstreamRequestBodyBytesLimitsEachLayerIndependently(t *testing.T) {
	const plainSize = 32 << 20
	const budget = 1 << 20
	withDecompressionBudget(t, budget)

	inner := gzipBytes(t, bombPayload(plainSize))
	outer := gzipBytes(t, inner)
	if len(inner) >= budget {
		t.Fatalf("测试前提不成立：中间体 %d 字节未低于预算 %d", len(inner), budget)
	}
	t.Logf("明文 %d → 内层 gzip %d 字节 → 外层 gzip %d 字节（每层预算 %d）",
		plainSize, len(inner), len(outer), budget)

	// 单层解压（只声明 gzip）必须成功：外层产出是中间体，远低于预算。
	decodedOnce, didDecode, err := decodeUpstreamRequestBodyBytes(outer, []byte("gzip"))
	if err != nil || !didDecode {
		t.Fatalf("single-layer decode err=%v didDecode=%v", err, didDecode)
	}
	if !bytes.Equal(decodedOnce, inner) {
		t.Fatalf("single-layer decode = %d bytes, want %d", len(decodedOnce), len(inner))
	}

	// 双层解压（gzip, gzip）：第一层产出中间体（通过），第二层要把 32 MiB 解
	// 出来，必须在 1 MiB 预算处被截断。
	_, _, err = decodeUpstreamRequestBodyBytes(outer, []byte("gzip, gzip"))
	if !errors.Is(err, errDecompressionLimitExceeded) {
		t.Fatalf("nested decode error = %v, want errDecompressionLimitExceeded", err)
	}

	// 对照组：预算放宽到能容纳 32 MiB 后，同一份双层输入必须完整解出——
	// 证明上面那次失败是「限额触发」而不是「双层输入本身不可解」。
	withDecompressionBudget(t, 64<<20)
	decoded, didDecode, err := decodeUpstreamRequestBodyBytes(outer, []byte("gzip, gzip"))
	if err != nil || !didDecode {
		t.Fatalf("nested decode within budget err=%v didDecode=%v", err, didDecode)
	}
	if len(decoded) != plainSize {
		t.Fatalf("nested decode = %d bytes, want %d", len(decoded), plainSize)
	}
}

// TestParseContentEncodingsRejectsTooManyLayers 锁定层数上限：声明超过上限的
// 层数会被判为不支持的编码（supported=false），调用方据此走降级放行。
func TestParseContentEncodingsRejectsTooManyLayers(t *testing.T) {
	atLimit := "gzip, gzip, gzip, gzip"
	encodings, supported := parseContentEncodingsBytes([]byte(atLimit))
	if !supported {
		t.Fatalf("layers at limit (%d) must be supported", maxContentEncodingLayers)
	}
	if len(encodings) != maxContentEncodingLayers {
		t.Fatalf("parsed %d layers, want %d", len(encodings), maxContentEncodingLayers)
	}

	overLimit := "gzip, br, deflate, zstd, gzip"
	if _, supported := parseContentEncodingsBytes([]byte(overLimit)); supported {
		t.Fatalf("layers above limit must be rejected as unsupported")
	}
}

// TestZstdDecoderBudgetFollowsConfiguredLimits 锁定 zstd 解码器构造预算跟随
// 配置：默认值必须远低于库自身的 512 MB 窗口 / 64 GiB 内存。
func TestZstdDecoderBudgetFollowsConfiguredLimits(t *testing.T) {
	previousRequest := RequestDecompressionMaxBytes()
	previousResponse := ResponseDecompressionMaxBytes()
	t.Cleanup(func() {
		SetRequestDecompressionMaxBytes(previousRequest)
		SetResponseDecompressionMaxBytes(previousResponse)
	})

	SetRequestDecompressionMaxBytes(64 << 20)
	SetResponseDecompressionMaxBytes(8 << 20)
	if got := zstdDecoderBudget(); got != 64<<20 {
		t.Fatalf("zstdDecoderBudget() = %d, want the larger side (64 MiB)", got)
	}

	SetRequestDecompressionMaxBytes(4 << 20)
	SetResponseDecompressionMaxBytes(16 << 20)
	if got := zstdDecoderBudget(); got != 16<<20 {
		t.Fatalf("zstdDecoderBudget() = %d, want the larger side (16 MiB)", got)
	}
}

// TestReadUpstreamResponseBodyDecodesZstdWithinBudget 是对照组：预算内的 zstd
// 响应必须照常解出，解码器限额不得误伤合法帧。
func TestReadUpstreamResponseBodyDecodesZstdWithinBudget(t *testing.T) {
	const budget = 1 << 20
	withDecompressionBudget(t, budget)

	payload := bytes.Repeat([]byte("zstd-within-budget-"), 1000)
	compressed := zstdBytes(t, payload)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Encoding": []string{"zstd"},
			"Content-Type":     []string{"text/plain; charset=utf-8"},
		},
		Body: io.NopCloser(bytes.NewReader(compressed)),
	}

	body, headers, err := readUpstreamResponseBody(resp)
	if err != nil {
		t.Fatalf("zstd response within budget returned error: %v", err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("decoded %d bytes, want %d", len(body), len(payload))
	}
	if got := headers.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding after decode = %q, want empty", got)
	}
}

// TestDecodeRequestBodyBytesForInspectionStaysWithinInspectionLimit 确认采样
// 解码不受炸弹上限影响：它本来就只解到 WAF 扫描窗（48 KiB），远低于任何
// 合理预算，因此正常的压缩请求体必须仍能解出前缀送检。
func TestDecodeRequestBodyBytesForInspectionStaysWithinInspectionLimit(t *testing.T) {
	// 明文体量必须真的大于扫描窗，否则恒不满窗、测不到截断。
	payload := bytes.Repeat([]byte(`{"note":"<script>alert(1)</script>"}`), 4000)
	compressed := gzipBytes(t, payload)
	if len(payload) <= 48*1024 {
		t.Fatalf("test premise broken: payload %d bytes not above inspection limit", len(payload))
	}

	sample := DecodeRequestBodyInspectionSample(compressed, []byte("gzip"), 48*1024)
	if sample.LimitExceeded {
		t.Fatal("inspection decode reported bomb limit")
	}
	if sample.Undecodable {
		t.Fatal("inspection decode reported undecodable")
	}
	if !sample.DidDecode {
		t.Fatal("expected inspection decode to be applied")
	}
	if !sample.Truncated {
		t.Fatal("expected truncated=true when payload exceeds the inspection limit")
	}
	if len(sample.Decoded) != 48*1024 {
		t.Fatalf("decoded = %d bytes, want %d", len(sample.Decoded), 48*1024)
	}
	if !bytes.Contains(sample.Decoded, []byte("<script>alert(1)</script>")) {
		t.Fatal("attack payload must stay inside the inspection window")
	}
}
