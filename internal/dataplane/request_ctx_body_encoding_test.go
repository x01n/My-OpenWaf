package dataplane

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"math/rand"
	"net/http"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/klauspost/compress/zstd"
)

// newStreamRequestBodyContext 构造带流式请求体的 Hertz 上下文，Content-Length
// 与流长度一致，贴近 hertz 对已知长度请求体的处理形态。
func newStreamRequestBodyContext(body []byte, contentEncoding string) *app.RequestContext {
	return newStreamRequestBodyContextWithStream(body, contentEncoding, &trackingRequestBodyStream{reader: bytes.NewReader(body)})
}

// newStreamRequestBodyContextWithStream 用指定的请求流构造上下文，便于统计
// WAF 采样阶段到底从流里读了多少次。
func newStreamRequestBodyContextWithStream(body []byte, contentEncoding string, stream io.Reader) *app.RequestContext {
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodPost)
	ctx.Request.Header.Set("Content-Type", "application/json")
	if contentEncoding != "" {
		ctx.Request.Header.Set("Content-Encoding", contentEncoding)
	}
	ctx.Request.SetBodyStream(stream, len(body))
	return ctx
}

// countingRequestBodyStream 记录首次预读之后还剩多少次读取，用于证明解压
// 阶段没有从请求流里多读字节。
type countingRequestBodyStream struct {
	reader             io.Reader
	prefetchDone       bool
	readsAfterPrefetch int
}

func (s *countingRequestBodyStream) Read(p []byte) (int, error) {
	n, err := s.reader.Read(p)
	if s.prefetchDone {
		s.readsAfterPrefetch++
	}
	if err == io.EOF {
		s.prefetchDone = true
	}
	return n, err
}

func (s *countingRequestBodyStream) Close() error { return nil }

// newBufferedRequestBodyContext 构造已完整缓冲（非流式）请求体的上下文。
func newBufferedRequestBodyContext(body []byte, contentEncoding string) *app.RequestContext {
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodPost)
	ctx.Request.Header.Set("Content-Type", "application/json")
	if contentEncoding != "" {
		ctx.Request.Header.Set("Content-Encoding", contentEncoding)
	}
	ctx.Request.SetBody(body)
	return ctx
}

// encodeGzip 用标准库把 body 压成单成员 gzip 流。
func encodeGzip(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		t.Fatalf("gzip writer: %v", err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// encodeGzipMembers 把多个成员各自独立压缩后拼接，构造真实的多成员 gzip 流。
func encodeGzipMembers(t *testing.T, members ...[]byte) []byte {
	t.Helper()
	var out []byte
	for _, member := range members {
		out = append(out, encodeGzip(t, member)...)
	}
	return out
}

// encodeZlib 产出带 RFC 1950 封装头的 deflate 流。
func encodeZlib(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(body); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

// encodeRawDeflate 产出无 zlib 头的裸 flate 流，覆盖 deflate 的探测回退分支。
func encodeRawDeflate(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestSpeed)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

// encodeBrotli 产出 brotli 流。
func encodeBrotli(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := brotli.NewWriterLevel(&buf, 4)
	if _, err := w.Write(body); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}
	return buf.Bytes()
}

// encodeZstd 产出 zstd 帧。
func encodeZstd(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	return buf.Bytes()
}

/**
 * requestBodySample 在「流式 + 无 Content-Encoding」时仍必须把 body 流原样
 * 交给转发路径：本用例锁定零额外开销分支的行为不因压缩支持而改变。
 */
func TestRequestBodySampleUncompressedStreamUnchanged(t *testing.T) {
	body := []byte("plain-uncompressed-body")
	ctx := newStreamRequestBodyContext(body, "")

	sample, truncated, size := requestBodySample(ctx)
	if truncated {
		t.Fatal("uncompressed short body must not be reported truncated")
	}
	if !bytes.Equal(sample, body) {
		t.Fatalf("sample = %q, want %q", sample, body)
	}
	if size != int64(len(body)) {
		t.Fatalf("size = %d, want %d", size, len(body))
	}
	// 重新绑定后的请求体流必须原样重放整份请求体：转发路径读的就是它。
	replayed, err := io.ReadAll(ctx.Request.BodyStream())
	if err != nil {
		t.Fatalf("read forwarded stream: %v", err)
	}
	if !bytes.Equal(replayed, body) {
		t.Fatalf("forwarded body = %q, want %q", replayed, body)
	}
	if snap, _ := requestBodySnapshotFromContext(ctx); snap.inspectionPlaintext {
		t.Fatal("uncompressed request must not enter the decode path")
	}
}

/**
 * 支持的内容编码都要能被解压后送检：gzip / x-gzip / deflate（zlib 封装与
 * 裸流）/ br / zstd，以及多层编码按逆序逐层解。
 */
func TestRequestBodySampleDecodesSupportedEncodings(t *testing.T) {
	payload := []byte(`{"note":"<script>alert(1)</script>"}`)
	cases := []struct {
		name     string
		encoding string
		encoded  []byte
	}{
		{name: "gzip", encoding: "gzip", encoded: encodeGzip(t, payload)},
		{name: "x-gzip", encoding: "x-gzip", encoded: encodeGzip(t, payload)},
		{name: "gzip 大写声明", encoding: "GZIP", encoded: encodeGzip(t, payload)},
		{name: "deflate(zlib)", encoding: "deflate", encoded: encodeZlib(t, payload)},
		{name: "deflate(裸流)", encoding: "deflate", encoded: encodeRawDeflate(t, payload)},
		{name: "br", encoding: "br", encoded: encodeBrotli(t, payload)},
		{name: "zstd", encoding: "zstd", encoded: encodeZstd(t, payload)},
		{
			// Content-Encoding 列表按应用顺序书写：br 在内层、gzip 在外层，
			// 解码按逆序从最外层 gzip 开始剥。
			name:     "br, gzip 多层",
			encoding: "br, gzip",
			encoded:  encodeGzip(t, encodeBrotli(t, payload)),
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newStreamRequestBodyContext(tt.encoded, tt.encoding)

			sample, _, _ := requestBodySample(ctx)
			if !bytes.Equal(sample, payload) {
				t.Fatalf("decoded sample = %q, want %q", sample, payload)
			}

			// 解压不得改变转发字节：上游仍收到原始的压缩体，由 proxy 侧解压。
			forwarded, err := io.ReadAll(ctx.Request.BodyStream())
			if err != nil {
				t.Fatalf("read forwarded stream: %v", err)
			}
			if !bytes.Equal(forwarded, tt.encoded) {
				t.Fatalf("forwarded body diverged from request body: got %d bytes want %d bytes", len(forwarded), len(tt.encoded))
			}
		})
	}
}

/**
 * 压缩体本身大于偷读前缀时，转发必须仍然是完整的原始压缩体，且样本只来自
 * 前缀的解压结果、不含任何未压缩的原始字节。解码不读网络，所以这里也不
 * 允许出现「提前从流里多读一截」的行为。
 */
func TestRequestBodySampleDecodesOnlyBufferWithoutReadingStream(t *testing.T) {
	cases := []struct {
		name     string
		encoding string
		encoded  []byte
	}{
		{name: "gzip", encoding: "gzip", encoded: encodeGzip(t, pseudoRandomBody(t, 80<<10, 11))},
		{name: "br", encoding: "br", encoded: encodeBrotli(t, pseudoRandomBody(t, 120<<10, 12))},
		{name: "zstd", encoding: "zstd", encoded: encodeZstd(t, pseudoRandomBody(t, 120<<10, 13))},
		{name: "deflate", encoding: "deflate", encoded: encodeZlib(t, pseudoRandomBody(t, 80<<10, 14))},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newStreamRequestBodyContext(tt.encoded, tt.encoding)
			stream := &countingRequestBodyStream{reader: bytes.NewReader(tt.encoded)}
			ctx.Request.SetBodyStream(stream, len(tt.encoded))

			snap := ensureRequestBodySnapshot(ctx)

			if !snap.inspectionPlaintext {
				t.Fatalf("declared encoding %q was not decoded", tt.encoding)
			}
			if stream.readsAfterPrefetch != 0 {
				t.Fatalf("解码阶段从请求流多读了 %d 次，want 0", stream.readsAfterPrefetch)
			}
			// 偷读前缀只是压缩体的一段，各解码器对「被截断的流」能解出的量
			// 不同：gzip / br / deflate 会交出截断前已解出的块，zstd 会一直
			// 缓冲到帧结束才吐数据，截断时产出为空。共同的不变量是：产出不
			// 超过扫描窗、请求不因此失败、转发字节完好。
			if len(snap.inspectionBody) > requestInspectionBodyLimit {
				t.Fatalf("decoded sample = %d bytes, want <= %d", len(snap.inspectionBody), requestInspectionBodyLimit)
			}
			if !snap.inspectionTruncated {
				t.Fatal("plaintext beyond the scan window must be reported truncated")
			}
			// 有上限保护，截断不得被当成请求级错误。
			if err := requestBodySnapshotError(ctx); err != nil {
				t.Fatalf("requestBodySnapshotError = %v, want nil", err)
			}

			forwarded, err := io.ReadAll(ctx.Request.BodyStream())
			if err != nil {
				t.Fatalf("read forwarded stream: %v", err)
			}
			if !bytes.Equal(forwarded, tt.encoded) {
				t.Fatalf("forwarded body diverged: got %d bytes want %d bytes", len(forwarded), len(tt.encoded))
			}
		})
	}
}

/**
 * 解压产出超过上限时截断送检而不是失败：用户裁定超限放过。样本长度不得超过
 * WAF 扫描窗，且请求本身不得被判定为错误。
 */
func TestRequestBodySampleTruncatesOversizeDecodedBody(t *testing.T) {
	// 高度可压缩的大载荷：解压后远超扫描窗，压缩体却很小。
	payload := bytes.Repeat([]byte("A"), 4<<20)
	encoded := encodeGzip(t, payload)
	if len(encoded) > requestInspectionBodyLimit {
		t.Fatalf("test premise broken: compressed size %d exceeds scan window", len(encoded))
	}

	ctx := newStreamRequestBodyContext(encoded, "gzip")
	snap := ensureRequestBodySnapshot(ctx)

	if !snap.inspectionPlaintext {
		t.Fatal("gzip request body was not decoded")
	}
	if len(snap.inspectionBody) > requestInspectionBodyLimit {
		t.Fatalf("decoded sample = %d bytes, want <= %d", len(snap.inspectionBody), requestInspectionBodyLimit)
	}
	if !snap.inspectionTruncated {
		t.Fatal("oversize decoded body must be reported truncated")
	}

	forwarded, err := io.ReadAll(ctx.Request.BodyStream())
	if err != nil {
		t.Fatalf("read forwarded stream: %v", err)
	}
	if !bytes.Equal(forwarded, encoded) {
		t.Fatalf("forwarded body diverged: got %d bytes want %d bytes", len(forwarded), len(encoded))
	}
}

/**
 * 偷读前缀只是压缩体的一段时，已解出的明文必须照常送检，不因末端读取错误
 * 而丢弃：错误只降级为「样本不完整」，同时不得升级成请求级失败。
 */
func TestRequestBodySampleDecodesStreamBeyondPrefetchedPrefix(t *testing.T) {
	// 高熵正文让压缩后体积超过偷读窗口，明文只能解出前缀覆盖的那部分。
	plain := pseudoRandomBody(t, 80<<10, 1)
	encoded := encodeGzip(t, plain)
	if len(encoded) <= requestInspectionBodyLimit {
		t.Fatalf("test premise broken: compressed size %d within scan window %d", len(encoded), requestInspectionBodyLimit)
	}

	ctx := newStreamRequestBodyContext(encoded, "gzip")
	snap := ensureRequestBodySnapshot(ctx)

	if !snap.inspectionPlaintext {
		t.Fatal("gzip request body was not decoded")
	}
	if !snap.inspectionTruncated {
		t.Fatal("truncated compressed prefix must be reported as an incomplete sample")
	}
	if len(snap.inspectionBody) == 0 {
		t.Fatal("plaintext decoded from the buffer must still be inspected")
	}
	if !bytes.Equal(snap.inspectionBody, plain[:len(snap.inspectionBody)]) {
		t.Fatal("decoded sample does not match the plaintext prefix")
	}
	if err := requestBodySnapshotError(ctx); err != nil {
		t.Fatalf("requestBodySnapshotError = %v, want nil", err)
	}

	forwarded, err := io.ReadAll(ctx.Request.BodyStream())
	if err != nil {
		t.Fatalf("read forwarded stream: %v", err)
	}
	if !bytes.Equal(forwarded, encoded) {
		t.Fatalf("forwarded body diverged: got %d bytes want %d bytes", len(forwarded), len(encoded))
	}
}

// pseudoRandomBody 生成可复现的高熵字节序列，避免压缩把测试载荷缩到扫描窗以内。
func pseudoRandomBody(t *testing.T, size int, seed int64) []byte {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	body := make([]byte, size)
	rng.Read(body)
	return body
}

/**
 * 转发必须只重放一次原始压缩体：前置采样可以多次调用，但重新绑定的请求体
 * 流只回放前缀，唯一性与顺序都不依赖调用次数。上游收到的等于原始请求体。
 */
func TestRequestBodySampleRepeatedSamplingKeepsForwardingIntact(t *testing.T) {
	plain := pseudoRandomBody(t, 80<<10, 21)
	encoded := encodeGzip(t, plain)

	ctx := newStreamRequestBodyContext(encoded, "gzip")
	for i := 0; i < 3; i++ {
		requestBodySample(ctx)
	}

	forwarded, err := io.ReadAll(ctx.Request.BodyStream())
	if err != nil {
		t.Fatalf("read forwarded stream: %v", err)
	}
	if !bytes.Equal(forwarded, encoded) {
		t.Fatalf("forwarded body diverged after repeated sampling: got %d bytes want %d bytes",
			len(forwarded), len(encoded))
	}
}

/**
 * 未压缩的大流式请求体同样要把整份字节交回转发路径，边界处不能丢一段。
 */
func TestRequestBodySampleOversizeStreamPreservesForwarding(t *testing.T) {
	body := bytes.Repeat([]byte("uncompressed-oversize-"), 6000)
	if len(body) <= requestInspectionBodyLimit {
		t.Fatalf("test premise broken: body size %d within scan window", len(body))
	}

	ctx := newStreamRequestBodyContext(body, "")
	snap := ensureRequestBodySnapshot(ctx)

	if snap.inspectionPlaintext {
		t.Fatal("uncompressed request must not enter the decode path")
	}
	if !snap.hasMore {
		t.Fatal("oversize body must be reported truncated")
	}
	forwarded, err := io.ReadAll(ctx.Request.BodyStream())
	if err != nil {
		t.Fatalf("read forwarded stream: %v", err)
	}
	if !bytes.Equal(forwarded, body) {
		t.Fatalf("forwarded body diverged: got %d bytes want %d bytes", len(forwarded), len(body))
	}
}

/**
 * 截断与畸形压缩体不得判成请求失败：解压错误只降级为「部分结果照常送检」，
 * 已有明文必须保留，转发字节必须完好。
 */
func TestRequestBodySampleSurvivesMalformedEncodedBody(t *testing.T) {
	payload := bytes.Repeat([]byte("payload-"), 200)
	gzipped := encodeGzip(t, payload)
	truncatedGzip := gzipped[:len(gzipped)-8]
	second := encodeGzip(t, []byte("second-member-body"))
	truncatedSecond := append(append([]byte(nil), encodeGzipMembers(t, []byte("first-member-body"))...), second[:len(second)-8]...)

	cases := []struct {
		name string
		// encoding 是请求声明的内容编码。
		encoding string
		body     []byte
		// wantRawFallback 为真表示解码在构造期就失败（gzip 缺魔数），样本
		// 回退成原始字节照常检测；为假表示构造成功、读取期失败，样本为空。
		wantRawFallback bool
	}{
		{name: "gzip 尾损", encoding: "gzip", body: truncatedGzip},
		{name: "gzip 多成员第二段截断", encoding: "gzip", body: truncatedSecond},
		{name: "声明 gzip 实为明文", encoding: "gzip", body: payload, wantRawFallback: true},
		{name: "声明 br 实为明文", encoding: "br", body: payload},
		{name: "声明 zstd 实为明文", encoding: "zstd", body: payload},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newStreamRequestBodyContext(tt.body, tt.encoding)
			snap := ensureRequestBodySnapshot(ctx)

			// 声明与实际不符分两条降级路径，都不构成绕过：
			//   构造期失败（gzip 缺魔数）=> didDecode 为 false，样本回退成
			//   原始字节照常检测，攻击载荷因此仍会被检出；
			//   读取期失败（br / zstd 构造成功但内容不符）=> 样本为空，而
			//   转发层随后同样解压失败，请求到不了上游。
			// 共同点是：绝不把「原始压缩字节」当明文，也绝不升级为请求级错误。
			sample, _, _ := requestBodySample(ctx)
			if tt.wantRawFallback {
				if snap.inspectionPlaintext {
					t.Fatal("构造期失败时不应标记为已解压")
				}
				if !bytes.Equal(sample, tt.body) {
					t.Fatalf("回退样本 = %d 字节，want 原始字节 %d 字节", len(sample), len(tt.body))
				}
			} else {
				if !snap.inspectionPlaintext {
					t.Fatal("构造成功的声明必须进入解压路径")
				}
				if bytes.Equal(sample, tt.body) {
					t.Fatal("已解压路径不得把原始压缩字节当作样本")
				}
			}
			if err := requestBodySnapshotError(ctx); err != nil {
				t.Fatalf("requestBodySnapshotError = %v, want nil", err)
			}
			forwarded, err := io.ReadAll(ctx.Request.BodyStream())
			if err != nil {
				t.Fatalf("read forwarded stream: %v", err)
			}
			if !bytes.Equal(forwarded, tt.body) {
				t.Fatalf("forwarded body diverged: got %d bytes want %d bytes", len(forwarded), len(tt.body))
			}
		})
	}
}

/**
 * 已完整缓冲（非流式）的请求体走同一条解压口径：上限一致、缓存只解一次、
 * Content-Encoding 不被识别时按未压缩处理。
 */
func TestRequestBodySampleBufferedEncodings(t *testing.T) {
	payload := []byte(`{"note":"<script>alert(1)</script>"}`)

	ctx := newBufferedRequestBodyContext(encodeGzip(t, payload), "gzip")
	first, truncated, size := requestBodySample(ctx)
	if !bytes.Equal(first, payload) {
		t.Fatalf("buffered decoded sample = %q, want %q", first, payload)
	}
	if truncated {
		t.Fatal("short buffered body must not be truncated")
	}
	if size != int64(len(encodeGzip(t, payload))) {
		t.Fatalf("size = %d, want compressed length %d", size, len(encodeGzip(t, payload)))
	}
	// 第二次采样必须命中缓存，返回同一份结果。
	second, _, _ := requestBodySample(ctx)
	if !bytes.Equal(second, first) {
		t.Fatal("cached inspection diverged from first sample")
	}
	if _, ok := bufferedRequestBodyInspectionFromContext(ctx); !ok {
		t.Fatal("buffered decode result was not cached on the request context")
	}

	oversize := newBufferedRequestBodyContext(encodeGzip(t, bytes.Repeat([]byte("A"), 4<<20)), "gzip")
	sample, truncated, _ := requestBodySample(oversize)
	if len(sample) != requestInspectionBodyLimit {
		t.Fatalf("oversize buffered sample = %d bytes, want %d", len(sample), requestInspectionBodyLimit)
	}
	if !truncated {
		t.Fatal("oversize buffered decoded body must be reported truncated")
	}

	unknown := newBufferedRequestBodyContext(payload, "koi8-r")
	sample, truncated, _ = requestBodySample(unknown)
	if !bytes.Equal(sample, payload) {
		t.Fatalf("unsupported encoding sample = %q, want untouched body", sample)
	}
	if truncated {
		t.Fatal("unsupported encoding must not report truncation")
	}
	if _, ok := bufferedRequestBodyInspectionFromContext(unknown); ok {
		t.Fatal("unsupported encoding must not populate the inspection cache")
	}
}
