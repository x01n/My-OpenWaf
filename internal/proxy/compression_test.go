package proxy

// 本文件锁定四种标准内容编码（gzip/deflate/br/zstd）在边界形态下
// 的行为。正例锁定必须成功的形态（含 deflate 的 zlib/裸流探测回退），
// 负例锁定必须以错误拒绝的输入，防止后续实现漂移。

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"testing"
)

// mustGzipMembersBytes 将多个成员分别以独立 gzip Writer 完成后拼接，
// 构造真实的 multipart gzip 流。gzip.Reader 默认 Multistream 应顺接。
func mustGzipMembersBytes(t *testing.T, members ...[]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, member := range members {
		writer, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
		if err != nil {
			t.Fatalf("create gzip member writer: %v", err)
		}
		if _, err := writer.Write(member); err != nil {
			t.Fatalf("write gzip member: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close gzip member writer: %v", err)
		}
	}
	return buf.Bytes()
}

// mustRawDeflateBytes 构造无 zlib 封装头（无 RFC 1950 头与 Adler-32
// 尾）的纯 RFC 1951 裸流，旧 HTTP 实现的 deflate 常指此形态。
func mustRawDeflateBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer, err := flate.NewWriter(&buf, flate.BestSpeed)
	if err != nil {
		t.Fatalf("create raw deflate writer: %v", err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("write raw deflate body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close raw deflate writer: %v", err)
	}
	return buf.Bytes()
}

// decodeBodyHelper 走完整解码入口，任何层级校验失败都应整体报错。
func decodeBodyHelper(t *testing.T, body []byte, contentEncoding string) ([]byte, error) {
	t.Helper()
	decoded, _, err := decodeUpstreamRequestBodyBytes(body, []byte(contentEncoding))
	return decoded, err
}

// gzip 多成员正例：两个独立 gzip 成员拼接后必须解出全部原文。
func TestDecodeGzipMultiMember(t *testing.T) {
	first := []byte("first-member-payload")
	second := []byte("second-member-payload")
	encoded := mustGzipMembersBytes(t, first, second)
	decoded, err := decodeBodyHelper(t, encoded, "gzip")
	if err != nil {
		t.Fatalf("decode gzip multi-member returned error: %v", err)
	}
	want := append(append([]byte(nil), first...), second...)
	if !bytes.Equal(decoded, want) {
		t.Fatalf("decoded = %q, want %q", decoded, want)
	}
}

// gzip 多成员响应路径正例：readUpstreamResponseBody 的流式解码路径
// 同样必须顺接第二成员并删除 Content-Encoding/Content-Length。
func TestReadUpstreamResponseBodyDecodesGzipMultiMember(t *testing.T) {
	first := []byte("member-one-of-multipart-gzip")
	second := []byte("member-two-of-multipart-gzip")
	encoded := mustGzipMembersBytes(t, first, second)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Encoding": []string{"gzip"},
			"Content-Type":     []string{"text/plain; charset=utf-8"},
			"Content-Length":   []string{strconv.Itoa(len(encoded))},
		},
		Body: io.NopCloser(bytes.NewReader(encoded)),
	}

	body, headers, err := readUpstreamResponseBody(resp)
	if err != nil {
		t.Fatalf("readUpstreamResponseBody returned error: %v", err)
	}
	want := append(append([]byte(nil), first...), second...)
	if !bytes.Equal(body, want) {
		t.Fatalf("decoded = %q, want %q", body, want)
	}
	if got := headers.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding after decode = %q, want empty", got)
	}
}

// gzip 多成员负例：第二成员头被截断，multistream 顺接失败必须报错。
func TestDecodeGzipMultiMemberTruncatedSecondHeader(t *testing.T) {
	first := []byte("complete-first-member")
	encoded := mustGzipMembersBytes(t, first)
	truncatedHeader := encoded[:len(encoded)-10]
	if _, err := decodeBodyHelper(t, truncatedHeader, "gzip"); err == nil {
		t.Fatal("expected error for gzip stream with truncated second member header")
	}
}

// gzip 多成员负例：第二个成员体缺尾（头完整），同样是无效流。
func TestDecodeGzipMultiMemberTruncatedSecondBody(t *testing.T) {
	first := []byte("complete-first-member")
	second := mustGzipBytes(t, []byte("truncated-second-member"))
	encoded := append(append([]byte(nil), mustGzipMembersBytes(t, first)...), second[:len(second)-8]...)
	if _, err := decodeBodyHelper(t, encoded, "gzip"); err == nil {
		t.Fatal("expected error for gzip stream with truncated second member body")
	}
}

// 裸 deflate 正例：无 zlib 头的纯 flate 流经探测回退解出原文。
func TestDecodeRawDeflateBody(t *testing.T) {
	original := []byte("raw-deflate-without-zlib-wrapper")
	encoded := mustRawDeflateBytes(t, original)
	decoded, err := decodeBodyHelper(t, encoded, "deflate")
	if err != nil {
		t.Fatalf("decode raw deflate returned error: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("decoded = %q, want %q", decoded, original)
	}
}

// zlib 封装 deflate 正例：探测未遮蔽 zlib 标准形态，既有语义保持。
func TestDecodeZlibWrappedDeflateStillWorks(t *testing.T) {
	original := []byte("zlib-wrapped-deflate-body")
	encoded := mustDeflateBytes(t, original)
	decoded, err := decodeBodyHelper(t, encoded, "deflate")
	if err != nil {
		t.Fatalf("decode zlib-wrapped deflate returned error: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("decoded = %q, want %q", decoded, original)
	}
}

// 裸 deflate 负例：流被截断，必须报错而非静默输出半个体。
func TestDecodeRawDeflateTruncated(t *testing.T) {
	original := []byte("raw-deflate-that-will-be-truncated")
	encoded := mustRawDeflateBytes(t, original)
	truncated := encoded[:len(encoded)-8]
	if _, err := decodeBodyHelper(t, truncated, "deflate"); err == nil {
		t.Fatal("expected error for truncated raw deflate stream")
	}
}

// deflate 尾随正例：zlib 流后跟尾随字节，标准库读到 Adler-32 尾即止，
// 解码结果不受外层多余字节影响。
func TestDecodeDeflateZlibTailTrailingBytes(t *testing.T) {
	original := []byte("zlib-deflate-with-trailing-bytes")
	encoded := append(mustDeflateBytes(t, original), []byte("trailing")...)
	decoded, err := decodeBodyHelper(t, encoded, "deflate")
	if err != nil {
		t.Fatalf("decode deflate with trailing bytes returned error: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("decoded = %q, want %q", decoded, original)
	}
}

// 裸 deflate 尾随正例：裸流读到 BFINAL 块即止，外层多余字节不影响原文。
func TestDecodeRawDeflateTailTrailingBytes(t *testing.T) {
	original := []byte("raw-deflate-with-trailing-bytes")
	encoded := append(mustRawDeflateBytes(t, original), []byte("trailing")...)
	decoded, err := decodeBodyHelper(t, encoded, "deflate")
	if err != nil {
		t.Fatalf("decode raw deflate with trailing bytes returned error: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("decoded = %q, want %q", decoded, original)
	}
}

// 混合编码链正例：外层裸 deflate 装订 gzip（声明顺序 gzip, deflate，
// 解码先剥 deflate 再剥 gzip），内层裸流形态在递归解码末端同样工作。
func TestDecodeBareRawDeflateViaMixedEncodingChain(t *testing.T) {
	original := []byte("gzip-then-raw-deflate-chain")
	encoded := mustRawDeflateBytes(t, mustGzipBytes(t, original))
	decoded, err := decodeBodyHelper(t, encoded, "gzip, deflate")
	if err != nil {
		t.Fatalf("decode gzip,deflate chain returned error: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("decoded = %q, want %q", decoded, original)
	}
}

// 响应路径 zlib 封装 deflate 正例：既有语义保持，探测不改变标准形态。
func TestReadUpstreamResponseBodyDecodesDeflate(t *testing.T) {
	original := []byte("upstream-zlib-deflate-response-body")
	encoded := mustDeflateBytes(t, original)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Encoding": []string{"deflate"},
			"Content-Type":     []string{"text/plain; charset=utf-8"},
			"Content-Length":   []string{strconv.Itoa(len(encoded))},
		},
		Body: io.NopCloser(bytes.NewReader(encoded)),
	}

	body, headers, err := readUpstreamResponseBody(resp)
	if err != nil {
		t.Fatalf("readUpstreamResponseBody returned error: %v", err)
	}
	if !bytes.Equal(body, original) {
		t.Fatalf("decoded = %q, want %q", body, original)
	}
	if got := headers.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding after decode = %q, want empty", got)
	}
}

// 响应路径裸 deflate 正例：upstreamResponseReader 的探测回退路径同样解出原文。
func TestReadUpstreamResponseBodyDecodesRawDeflate(t *testing.T) {
	original := []byte("upstream-raw-deflate-response-body")
	encoded := mustRawDeflateBytes(t, original)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Encoding": []string{"deflate"},
			"Content-Type":     []string{"text/plain; charset=utf-8"},
			"Content-Length":   []string{strconv.Itoa(len(encoded))},
		},
		Body: io.NopCloser(bytes.NewReader(encoded)),
	}

	body, headers, err := readUpstreamResponseBody(resp)
	if err != nil {
		t.Fatalf("readUpstreamResponseBody returned error: %v", err)
	}
	if !bytes.Equal(body, original) {
		t.Fatalf("decoded = %q, want %q", body, original)
	}
	if got := headers.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding after decode = %q, want empty", got)
	}
}

// zstd 正例：完整帧全量解码。
func TestDecodeZstdComplete(t *testing.T) {
	original := []byte("complete-zstd-frame")
	encoded := mustZstdBytes(t, original)
	decoded, err := decodeBodyHelper(t, encoded, "zstd")
	if err != nil {
		t.Fatalf("decode complete zstd returned error: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("decoded = %q, want %q", decoded, original)
	}
}

// zstd 负例：帧缺尾，必须报错而非返回部分体。
func TestDecodeZstdTruncated(t *testing.T) {
	original := []byte("zstd-frame-that-will-be-truncated")
	encoded := mustZstdBytes(t, original)
	truncated := encoded[:len(encoded)-8]
	if _, err := decodeBodyHelper(t, truncated, "zstd"); err == nil {
		t.Fatal("expected error for truncated zstd stream")
	}
}

// zstd 尾迹负例：完整帧后跟尾随字节会在续帧读取时报 magic number
// mismatch，锁死该库边界行为防漂移。
func TestDecodeZstdWithTrailingBytesReportsMagicError(t *testing.T) {
	original := []byte("zstd-frame-then-garbage-tail")
	encoded := append(mustZstdBytes(t, original), []byte("trailing-garbage")...)
	if _, err := decodeBodyHelper(t, encoded, "zstd"); err == nil {
		t.Fatal("expected error for zstd stream with trailing bytes")
	}
}

// 容量限制错误传播负例：压缩体被截断时，即使包在 IoLimit 窗口内
// 读取，gzip 校验失败也必须如实报错，而非返回部分体或静默丢弃。
func TestReadUpstreamResponseBodyLimitedTruncatedGzipErrors(t *testing.T) {
	original := bytes.Repeat([]byte("z"), 1024)
	truncated := mustGzipBytes(t, original)
	truncated = truncated[:len(truncated)-8]
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Encoding": []string{"gzip"},
			"Content-Type":     []string{"text/plain; charset=utf-8"},
			"Content-Length":   []string{strconv.Itoa(len(truncated))},
		},
		Body: io.NopCloser(bytes.NewReader(truncated)),
	}

	_, _, _, _, _, _, err := readUpstreamResponseBodyLimited(resp, 2048)
	if err == nil {
		t.Fatal("expected error when limit window reads a truncated gzip stream")
	}
}

// 容量限制错误传播正例：IoLimit 窗口足够时按路径正常解出且不截断。
func TestReadUpstreamResponseBodyLimitedWithinLimitDecodes(t *testing.T) {
	original := bytes.Repeat([]byte("z"), 512)
	encoded := mustGzipBytes(t, original)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Encoding": []string{"gzip"},
			"Content-Type":     []string{"text/plain; charset=utf-8"},
			"Content-Length":   []string{strconv.Itoa(len(encoded))},
		},
		Body: io.NopCloser(bytes.NewReader(encoded)),
	}

	body, _, remaining, closeFn, _, truncated, err := readUpstreamResponseBodyLimited(resp, 1024)
	if err != nil {
		t.Fatalf("readUpstreamResponseBodyLimited returned error: %v", err)
	}
	if closeFn != nil {
		_ = closeFn()
	}
	if truncated {
		t.Fatal("expected truncated=false when decoded body fits the limit")
	}
	if remaining != nil {
		t.Fatal("expected nil remaining reader when decoded body fits the limit")
	}
	if !bytes.Equal(body, original) {
		t.Fatalf("decoded = %q, want %q", body, original)
	}
}

// brotli 正例：完整流全量解码。
func TestDecodeBrotliComplete(t *testing.T) {
	original := []byte("complete-brotli-stream")
	encoded := mustBrotliBytes(t, original)
	decoded, err := decodeBodyHelper(t, encoded, "br")
	if err != nil {
		t.Fatalf("decode complete brotli returned error: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("decoded = %q, want %q", decoded, original)
	}
}

// gzip 头缺失负例：声明 gzip 但数据无 gzip 魔数头，必须报错。
func TestDecodeGzipHeaderMissing(t *testing.T) {
	if _, err := decodeBodyHelper(t, []byte("no-gzip-magic-header-here"), "gzip"); err == nil {
		t.Fatal("expected error for body declared gzip without gzip header")
	}
}

// 混合编码链负例：内层 br 截断时整体报错，外层剥除不能掩盖内层失败。
func TestDecodeMixedEncodingInnerBrotliTruncated(t *testing.T) {
	inner := mustBrotliBytes(t, []byte("inner-brotli-body"))
	inner = inner[:len(inner)-8]
	encoded := mustGzipBytes(t, inner)
	if _, err := decodeBodyHelper(t, encoded, "gzip, br"); err == nil {
		t.Fatal("expected error for mixed chain with truncated inner brotli")
	}
}

// 请求体解码入口单层 x-gzip 别名正例：与 gzip 解出完全一致的原文。
func TestDecodeRequestBodyXGzipAlias(t *testing.T) {
	original := []byte("x-gzip-alias-body")
	encoded := mustGzipBytes(t, original)
	decoded, err := decodeBodyHelper(t, encoded, "x-gzip")
	if err != nil {
		t.Fatalf("decode x-gzip returned error: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("decoded = %q, want %q", decoded, original)
	}
}

// 流式入口 zlib 封装 deflate 正例：decodeUpstreamRequestBodyStreamBytes
// 与字节入口行为一致，探针分支在流式路径同样工作。
func TestDecodeRequestBodyStreamZlibDeflate(t *testing.T) {
	original := []byte("stream-zlib-deflate-body")
	encoded := mustDeflateBytes(t, original)
	reader, decoded, err := decodeUpstreamRequestBodyStreamBytes(bytes.NewReader(encoded), []byte("deflate"))
	if err != nil {
		t.Fatalf("decode stream deflate returned error: %v", err)
	}
	if !decoded {
		t.Fatal("expected didDecode=true for stream deflate")
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stream deflate body: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close stream deflate reader: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("decoded = %q, want %q", got, original)
	}
}

// brotli 尾迹负例：完整流后跟尾随字节会在 WriteTo/ReadFrom 路径报
// excessive input，锁死该库边界行为防漂移。
func TestDecodeBrotliWithTrailingBytesReportsExcessiveInput(t *testing.T) {
	original := []byte("brotli-tail-with-extra-bytes")
	encoded := append(mustBrotliBytes(t, original), []byte("brotli-tail")...)
	if _, err := decodeBodyHelper(t, encoded, "br"); err == nil {
		t.Fatal("expected error for brotli stream with trailing bytes")
	}
}

// brotli 负例：报错而非返回部分体。brotli.Reader 延迟读取头，
// 截断流在首次 Read 时如实报错。
func TestDecodeBrotliTruncated(t *testing.T) {
	original := []byte("brotli-stream-that-will-be-truncated")
	encoded := mustBrotliBytes(t, original)
	truncated := encoded[:len(encoded)-8]
	if _, err := decodeBodyHelper(t, truncated, "br"); err == nil {
		t.Fatal("expected error for truncated brotli stream")
	}
}

// brotli 空体形态锁定：入口对零长度体按透传处理（didDecode=false），
// 不尝试解码也不报错。锁死既有语义防漂移。
func TestDecodeBrotliZeroLengthInputIsPassThrough(t *testing.T) {
	got, decoded, err := decodeUpstreamRequestBodyBytes([]byte{}, []byte("br"))
	if err != nil {
		t.Fatalf("decode zero-length body returned error: %v", err)
	}
	if decoded {
		t.Fatal("expected didDecode=false for zero-length body")
	}
	if len(got) != 0 {
		t.Fatalf("decoded body = %q, want empty", got)
	}
}
