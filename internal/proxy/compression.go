package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/andybalholm/brotli"
	"github.com/cloudwego/hertz/pkg/app"
	kgzip "github.com/klauspost/compress/gzip"
	kzlib "github.com/klauspost/compress/zlib"
	"github.com/klauspost/compress/zstd"

	"My-OpenWaf/internal/snapshot"
)

const (
	brotliCompressionLevel              = 4
	DefaultRequestDecompressionMaxBytes = 64 << 20

	// DefaultResponseDecompressionMaxBytes 是响应侧单层解压的产出上限（8 MiB）。
	//
	// 取值依据：maxStreamTransformBufferBytes（8 MiB）已经是响应侧「整体缓冲即
	// 拒」的门槛，响应侧解压上限必须 ≤ 它，否则解压会产出超出门槛的缓冲，白做功。
	DefaultResponseDecompressionMaxBytes = 8 << 20

	// maxContentEncodingLayers 是 Content-Encoding 允许的最大层数。
	//
	// 合法场景不会超过 2-3 层（例如 gzip 再套 gzip 的双重压缩），声明 100 层
	// 只会让每一层都成为一次放大机会。超过即判为畸形，按降级放行处理。
	maxContentEncodingLayers = 4
)

// errDecompressionLimitExceeded 表示解压产出超过硬上限，解压已终止。
//
// 调用方必须把它与「压缩体本身畸形」区分开：超限不是协议错误，而是
// 炸弹防护触发；转发路径遇到它时按原始压缩字节继续，不做 502。
var errDecompressionLimitExceeded = errors.New("decompression output exceeds limit")

/**
 * isDecompressionLimitError 判定一个解码错误是否属于「限额触发」。
 *
 * 三类来源都要算：本包的外层计数器（errDecompressionLimitExceeded）、
 * zstd 解码器自身的窗口/内存限额（zstd.ErrWindowSizeExceeded /
 * zstd.ErrDecoderSizeExceeded）。三者对调用方的含义相同——解压因为超量而
 * 终止，不是压缩体本身畸形——因此按同一种降级处置，审计事件也归到同一类。
 *
 * @param err 解码过程中返回的错误。
 * @returns 是否属于限额触发。
 */
func isDecompressionLimitError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, errDecompressionLimitExceeded) ||
		errors.Is(err, zstd.ErrWindowSizeExceeded) ||
		errors.Is(err, zstd.ErrDecoderSizeExceeded)
}

// decompressionLimits 保存两侧的解压产出上限，由启动期注入。
//
// 用 atomic 而不是普通变量：它在启动期写入一次，之后被所有请求 goroutine
// 读取。进程级而非按调用方传参，是因为它必须独立于调用方给的 maxBodyBytes
// 生效——调用方传 math.MaxInt（或不传）时炸弹防护不能跟着失效。
var (
	requestDecompressionMaxBytes  atomic.Int64
	responseDecompressionMaxBytes atomic.Int64
)

// SetRequestDecompressionMaxBytes 设置请求侧单层解压的产出上限。
//
// 非正值回退到 DefaultRequestDecompressionMaxBytes：把上限配成 0 或负数等于
// 关闭炸弹防护，不能由一次环境变量笔误达成。
func SetRequestDecompressionMaxBytes(limit int64) {
	requestDecompressionMaxBytes.Store(clampDecompressionLimit(limit, DefaultRequestDecompressionMaxBytes))
}

// SetResponseDecompressionMaxBytes 设置响应侧单层解压的产出上限。
func SetResponseDecompressionMaxBytes(limit int64) {
	responseDecompressionMaxBytes.Store(clampDecompressionLimit(limit, DefaultResponseDecompressionMaxBytes))
}

// RequestDecompressionMaxBytes 返回当前生效的请求侧解压产出上限。
func RequestDecompressionMaxBytes() int64 {
	if limit := requestDecompressionMaxBytes.Load(); limit > 0 {
		return limit
	}
	return DefaultRequestDecompressionMaxBytes
}

// ResponseDecompressionMaxBytes 返回当前生效的响应侧解压产出上限。
func ResponseDecompressionMaxBytes() int64 {
	if limit := responseDecompressionMaxBytes.Load(); limit > 0 {
		return limit
	}
	return DefaultResponseDecompressionMaxBytes
}

// clampDecompressionLimit 把上限钳制到可用范围，非正值回退默认。
func clampDecompressionLimit(limit, fallback int64) int64 {
	if limit <= 0 {
		return fallback
	}
	if limit > math.MaxInt64/2 {
		return math.MaxInt64 / 2
	}
	return limit
}

/**
 * layerDecompressionLimit 返回某一层的解压产出上限。
 *
 * 请求侧与响应侧共用同一份解码实现，方向由调用方传入：请求体转发必须解出完整
 * 明文，配额取 64 MiB；响应侧产出会进整段缓冲，配额取 8 MiB（与
 * maxStreamTransformBufferBytes 齐平）。
 *
 * @param encoding 该层的规范编码名。
 * @param requestSide 是否属于请求体解压路径。
 * @returns 该层的产出上限（字节）。
 */
func layerDecompressionLimit(encoding string, requestSide bool) int64 {
	_ = encoding
	if requestSide {
		return RequestDecompressionMaxBytes()
	}
	return ResponseDecompressionMaxBytes()
}

/**
 * zstdDecoderBudget 返回 zstd 解码器构造期用的窗口/内存预算。
 *
 * zstd 在请求体转发路径上出现得最多，且它的解码器默认值（512 MB 窗口 /
 * 64 GiB 内存）比本项目任何合法载荷都大几个数量级。取请求侧与响应侧上限的
 * 较大者，保证「两侧各自的外层上限」才是真正的约束，解码器自身不会先于它
 * 误伤合法帧。
 *
 * @returns 解码器的窗口与内存上限（字节）。
 */
func zstdDecoderBudget() int64 {
	request, response := RequestDecompressionMaxBytes(), ResponseDecompressionMaxBytes()
	if request > response {
		return request
	}
	return response
}

/**
 * decompressionGuard 是流式解压的产出计数器：累计产出超过预算即中断。
 *
 * 流式路径（请求体转发、响应流重压缩）不能预先 LimitReader——解压后的字节是
 * 边读边产的，把上限套在「读」上等于限定响应流总长度，会把正常的流式转发在
 * 上限处掐断。这里改成在产出侧计数，只在真的解出超量内容（压缩炸弹）时失败。
 *
 * 预算由构造时的 layerDecompressionLimit 快照决定（逐层各一份），运行期改配置
 * 不影响已构造的流，避免同一请求中途换标尺。
 *
 * onTrip 在首次越过预算时同步调用一次。流式路径的读取发生在 http 传输层，
 * 调用方拿不到那个时刻，因此把「记事件」挂在触发点上，而不是等错误回到上层
 * ——等回到上层时请求已经中止，事件与失败原因就断了关联。
 */
type decompressionGuard struct {
	reader    io.Reader
	remaining int64
	onTrip    func()
	tripped   bool
}

func (g *decompressionGuard) Read(p []byte) (int, error) {
	if g.remaining <= 0 {
		g.trip()
		return 0, errDecompressionLimitExceeded
	}
	if int64(len(p)) > g.remaining {
		p = p[:g.remaining]
	}
	n, err := g.reader.Read(p)
	g.remaining -= int64(n)
	if errors.Is(err, errDecompressionLimitExceeded) {
		g.trip()
	}
	return n, err
}

// trip 触发一次上限回调，重复越界只上报一次。
func (g *decompressionGuard) trip() {
	if g.tripped {
		return
	}
	g.tripped = true
	if g.onTrip != nil {
		g.onTrip()
	}
}

type responseEncoding string

// ResponseCompressionOptions 是响应压缩协商的一组开关。
//
// DeflateEnabled/ZstdEnabled 与 GzipEnabled/BrotliEnabled 同构，由快照的
// response_compression_deflate_enabled / response_compression_zstd_enabled
// 设置行驱动。四者一起决定候选集与优先级（见 selectClientResponseEncodingBytes），
// 总开关 Enabled 为假时由 normalizeResponseCompressionOptions 统一收敛为全关。
type ResponseCompressionOptions struct {
	Enabled        bool
	BrotliEnabled  bool
	GzipEnabled    bool
	DeflateEnabled bool
	ZstdEnabled    bool
	MinBytes       int
}

const (
	responseEncodingIdentity responseEncoding = ""
	responseEncodingGzip     responseEncoding = "gzip"
	responseEncodingBrotli   responseEncoding = "br"
	responseEncodingDeflate  responseEncoding = "deflate"
	responseEncodingZstd     responseEncoding = "zstd"
)

func DefaultResponseCompressionOptions(brotliEnabled bool) ResponseCompressionOptions {
	return normalizeResponseCompressionOptions(ResponseCompressionOptions{
		Enabled:        snapshot.DefaultResponseCompressionEnabled,
		BrotliEnabled:  brotliEnabled,
		GzipEnabled:    snapshot.DefaultResponseCompressionGzipEnabled,
		DeflateEnabled: snapshot.DefaultResponseCompressionDeflate,
		ZstdEnabled:    snapshot.DefaultResponseCompressionZstd,
		MinBytes:       snapshot.DefaultResponseCompressionMinBytes,
	})
}

func normalizeResponseCompressionOptions(opts ResponseCompressionOptions) ResponseCompressionOptions {
	if opts.MinBytes <= 0 {
		opts.MinBytes = snapshot.DefaultResponseCompressionMinBytes
	}
	// 总开关关闭时，四个编码开关一律视为关闭：调用方多读到一处 Enabled
	// 判定就会泄漏出未协商的编码，这里收敛成单一真值来源。
	if !opts.Enabled {
		opts.BrotliEnabled = false
		opts.GzipEnabled = false
		opts.DeflateEnabled = false
		opts.ZstdEnabled = false
	}
	return opts
}

func responseCompressionMinBytes(minBytes int) int {
	if minBytes <= 0 {
		return snapshot.DefaultResponseCompressionMinBytes
	}
	return minBytes
}

/**
 * readAllUpTo 读取至多 limit+1 字节，并报告产出是否超出 limit。
 *
 * 与 readUpstreamResponseBodyLimitedInternal 同构地多读一个字节：那一个字节
 * 只用于判定越界，不会外泄给调用方。limit 为负时按 0 处理。
 *
 * @param reader 读取来源（通常是解压后的 reader）。
 * @param limit 产出上限。
 * @returns body 实际读到的字节；exceeded 是否超过 limit；err 读取错误。
 */
func readAllUpTo(reader io.Reader, limit int64) ([]byte, bool, error) {
	if limit < 0 {
		limit = 0
	}
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, false, err
	}
	return body, int64(len(body)) > limit, nil
}

func readUpstreamResponseBody(resp *http.Response) ([]byte, http.Header, error) {
	reader, closeFn, decoded, err := upstreamResponseReader(resp)
	if err != nil {
		return nil, nil, err
	}
	if closeFn != nil {
		defer closeFn()
	}

	// 解压产出超过响应侧上限即按压缩炸弹处理：解压已终止，不返回半截明文。
	body, exceeded, err := readAllUpTo(reader, ResponseDecompressionMaxBytes())
	if err != nil {
		if isDecompressionLimitError(err) {
			return nil, nil, errDecompressionLimitExceeded
		}
		return nil, nil, err
	}
	if exceeded {
		return nil, nil, errDecompressionLimitExceeded
	}

	headers := http.Header(nil)
	if resp != nil {
		headers = resp.Header
	}
	if decoded && headers != nil {
		headers = headers.Clone()
		headers.Del("Content-Encoding")
		headers.Del("Content-Length")
	}
	return body, headers, nil
}

func readUpstreamResponseBodyLimited(resp *http.Response, maxBodyBytes int64) ([]byte, http.Header, io.Reader, func() error, bool, bool, error) {
	return readUpstreamResponseBodyLimitedInternal(resp, maxBodyBytes, true)
}

func readUpstreamResponseBodyLimitedForCapture(resp *http.Response, maxBodyBytes int64) ([]byte, http.Header, io.Reader, func() error, bool, bool, error) {
	return readUpstreamResponseBodyLimitedInternal(resp, maxBodyBytes, false)
}

func readUpstreamResponseBodyLimitedInternal(resp *http.Response, maxBodyBytes int64, skipKnownOversize bool) ([]byte, http.Header, io.Reader, func() error, bool, bool, error) {
	reader, closeFn, decoded, err := upstreamResponseReader(resp)
	if err != nil {
		return nil, nil, nil, nil, false, false, err
	}

	headers := http.Header(nil)
	if resp != nil {
		headers = resp.Header
	}
	if decoded && headers != nil {
		headers = headers.Clone()
		headers.Del("Content-Encoding")
		headers.Del("Content-Length")
	}
	if maxBodyBytes < 0 {
		maxBodyBytes = 0
	}
	if maxBodyBytes > int64(math.MaxInt) {
		maxBodyBytes = int64(math.MaxInt)
	}
	if skipKnownOversize && resp != nil && !decoded && resp.ContentLength > maxBodyBytes {
		return nil, headers, reader, closeFn, decoded, true, nil
	}
	// 调用方上限决定「缓冲多少」，响应侧解压上限决定「最多能解出多少」。
	// 两者取小生效；仅当解压上限才是那个约束且真的被突破时，才按压缩炸弹
	// 报错——否则维持既有语义：超出调用方上限的部分退回流式转发，不丢字节。
	// callerLimit <= 0 是 maxBodyBytes == math.MaxInt 时的加法溢出，同样按
	// 「解压上限生效」处理。
	callerLimit := maxBodyBytes + 1
	bombLimit := ResponseDecompressionMaxBytes()
	limit := callerLimit
	bombLimited := false
	if limit <= 0 || limit > bombLimit+1 {
		limit = bombLimit + 1
		bombLimited = true
	}
	body, exceeded, err := readAllUpTo(reader, limit)
	if err != nil {
		if closeFn != nil {
			_ = closeFn()
		}
		return nil, nil, nil, nil, false, false, err
	}
	if exceeded && bombLimited {
		if closeFn != nil {
			_ = closeFn()
		}
		return nil, nil, nil, nil, false, false, errDecompressionLimitExceeded
	}
	if int64(len(body)) <= maxBodyBytes {
		if closeFn != nil {
			if err := closeFn(); err != nil {
				return nil, nil, nil, nil, false, false, err
			}
		}
		return body, headers, nil, nil, decoded, false, nil
	}

	prefixLen := int(maxBodyBytes)
	prefix := append([]byte(nil), body[:prefixLen]...)
	remaining := io.MultiReader(bytes.NewReader(body[prefixLen:]), reader)
	return prefix, headers, remaining, closeFn, decoded, true, nil
}

func contentEncodingHeaderValue(header http.Header) string {
	if header == nil {
		return ""
	}
	return strings.Join(header.Values("Content-Encoding"), ", ")
}

func upstreamResponseReader(resp *http.Response) (io.Reader, func() error, bool, error) {
	if resp == nil || resp.Body == nil {
		return bytes.NewReader(nil), nil, false, nil
	}

	closeBody := func() error { return resp.Body.Close() }
	encodings, supported := parseContentEncodings(contentEncodingHeaderValue(resp.Header))
	if len(encodings) == 0 {
		return resp.Body, closeBody, false, nil
	}
	if !supported {
		return resp.Body, closeBody, false, nil
	}

	current := io.Reader(resp.Body)
	closers := make([]io.Closer, 0, len(encodings))
	decoded := false
	for i := len(encodings) - 1; i >= 0; i-- {
		reader, closer, used, err := newContentDecoderReader(current, encodings[i])
		if err != nil {
			_ = closeContentDecoderClosers(closers)
			_ = resp.Body.Close()
			return nil, nil, false, err
		}
		if !used {
			continue
		}
		current = reader
		decoded = true
		if closer != nil {
			closers = append(closers, closer)
		}
	}
	if !decoded {
		return resp.Body, closeBody, false, nil
	}
	return current, func() error {
		closeErr := closeContentDecoderClosers(closers)
		bodyErr := resp.Body.Close()
		if closeErr != nil {
			return closeErr
		}
		return bodyErr
	}, true, nil
}

func decodeUpstreamRequestBody(body []byte, contentEncoding string) ([]byte, bool, error) {
	return decodeUpstreamRequestBodyBytes(body, []byte(contentEncoding))
}

func decodeUpstreamRequestBodyBytes(body []byte, contentEncoding []byte) ([]byte, bool, error) {
	if len(body) == 0 {
		return body, false, nil
	}

	encodings, supported := parseContentEncodingsBytes(contentEncoding)
	if len(encodings) == 0 {
		return body, false, nil
	}
	if !supported {
		return body, false, nil
	}

	decoded := false
	// 逐层施加请求侧上限：多层嵌套会让每层都成为一次放大机会（外层 1 KiB
	// 解出 1 MiB，内层再把 1 MiB 解成 1 GiB），因此每一层都独立受限，任一层
	// 超限立即中断，不再进下一层。
	for i := len(encodings) - 1; i >= 0; i-- {
		reader, closer, used, err := newContentDecoderReader(bytes.NewReader(body), encodings[i])
		if err != nil {
			return nil, false, err
		}
		if !used {
			continue
		}
		// 非流式路径的炸弹上限：调用方没有给上限（转发前解压必须得到完整
		// 明文）。超限即失败，不返回半截明文——转发路径拿到部分明文会以
		// 「去掉 Content-Encoding 的完整体」形态送上游，比不解压更糟。
		decodedBody, exceeded, readErr := readAllUpTo(reader, layerDecompressionLimit(encodings[i], true))
		closeErr := closeContentDecoder(closer)
		if readErr != nil {
			// zstd 解码器自身的窗口/内存限额也是「配额触发」，归一到同一个
			// 错误上，让调用方的降级判定只有一处。
			if isDecompressionLimitError(readErr) {
				return nil, false, errDecompressionLimitExceeded
			}
			return nil, false, readErr
		}
		if exceeded {
			return nil, false, errDecompressionLimitExceeded
		}
		if closeErr != nil {
			return nil, false, closeErr
		}
		body = decodedBody
		decoded = true
	}
	return body, decoded, nil
}

type readerReadCloser struct {
	io.Reader
}

func (r readerReadCloser) Close() error {
	return nil
}

type decodedBodyReadCloser struct {
	reader     io.Reader
	bodyCloser io.Closer
	closers    []io.Closer
}

func (r *decodedBodyReadCloser) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *decodedBodyReadCloser) Close() error {
	closeErr := closeContentDecoderClosers(r.closers)
	bodyErr := closeContentDecoder(r.bodyCloser)
	if closeErr != nil {
		return closeErr
	}
	return bodyErr
}

func decodeUpstreamRequestBodyStream(body io.Reader, contentEncoding string) (io.ReadCloser, bool, error) {
	return decodeUpstreamRequestBodyStreamBytes(body, []byte(contentEncoding))
}

func decodeUpstreamRequestBodyStreamBytes(body io.Reader, contentEncoding []byte) (io.ReadCloser, bool, error) {
	return decodeUpstreamRequestBodyStreamBytesWithTrip(body, contentEncoding, nil)
}

/**
 * decodeUpstreamRequestBodyStreamBytesWithTrip 是流式解码的带回调形态。
 *
 * onTrip 在解压产出首次越过硬上限时同步触发一次，供调用方在触发点直接记事件：
 * 流式读取发生在 http 传输层，错误回到调用方时请求已经中止，事件与成因就断了
 * 关联。onTrip 为 nil 时行为与 decodeUpstreamRequestBodyStreamBytes 完全一致。
 *
 * @param body 压缩字节流。
 * @param contentEncoding Content-Encoding 原始取值。
 * @param onTrip 上限触发回调；可为 nil。
 * @returns 解压后的 reader、是否应用了编码、构造错误。
 */
func decodeUpstreamRequestBodyStreamBytesWithTrip(body io.Reader, contentEncoding []byte, onTrip func()) (io.ReadCloser, bool, error) {
	if body == nil {
		return nil, false, nil
	}

	encodings, supported := parseContentEncodingsBytes(contentEncoding)
	if len(encodings) == 0 || !supported {
		return readerAsReadCloser(body), false, nil
	}

	// 逐层施加请求侧上限：每层各有一个独立预算，任一层超限立即中断，不把
	// 超量产出交给下一层继续放大。budget 在所有层之间共享同一个 trip 回调，
	// 确保「哪一层先超限」只会被上报一次。
	var tripped bool
	trip := func() {
		if tripped {
			return
		}
		tripped = true
		if onTrip != nil {
			onTrip()
		}
	}

	current := body
	bodyCloser, _ := body.(io.Closer)
	closers := make([]io.Closer, 0, len(encodings))
	decoded := false
	for i := len(encodings) - 1; i >= 0; i-- {
		reader, closer, used, err := newContentDecoderReader(current, encodings[i])
		if err != nil {
			_ = closeContentDecoderClosers(closers)
			_ = closeContentDecoder(bodyCloser)
			return nil, false, err
		}
		if !used {
			continue
		}
		current = &decompressionGuard{
			reader:    reader,
			remaining: layerDecompressionLimit(encodings[i], true),
			onTrip:    trip,
		}
		decoded = true
		if closer != nil {
			closers = append(closers, closer)
		}
	}
	if !decoded {
		return readerAsReadCloser(body), false, nil
	}
	return &decodedBodyReadCloser{
		reader:     current,
		bodyCloser: bodyCloser,
		closers:    closers,
	}, true, nil
}

func readerAsReadCloser(reader io.Reader) io.ReadCloser {
	if reader == nil {
		return nil
	}
	if closer, ok := reader.(io.ReadCloser); ok {
		return closer
	}
	return readerReadCloser{Reader: reader}
}

func parseContentEncodings(raw string) ([]string, bool) {
	return parseContentEncodingsBytes([]byte(raw))
}

func parseContentEncodingsBytes(raw []byte) ([]string, bool) {
	raw = trimASCIIHeaderSpaceBytes(raw)
	if len(raw) == 0 {
		return nil, true
	}

	encodings := make([]string, 0, 4)
	for len(raw) > 0 {
		part := raw
		if comma := bytes.IndexByte(raw, ','); comma >= 0 {
			part = raw[:comma]
			raw = raw[comma+1:]
		} else {
			raw = nil
		}
		part = trimASCIIHeaderSpaceBytes(part)
		if len(part) == 0 {
			continue
		}
		if semi := bytes.IndexByte(part, ';'); semi >= 0 {
			part = trimASCIIHeaderSpaceBytes(part[:semi])
		}
		if len(part) == 0 {
			continue
		}
		encoding, ok := canonicalContentEncodingBytes(part)
		if !ok {
			return nil, false
		}
		encodings = append(encodings, encoding)
		// 层数上限：合法场景不会超过 2-3 层（gzip 再套 gzip 的双重压缩已是上限），
		// 声明更多层只会让每一层都成为一次放大机会。超限按「不支持的编码」处理
		// ——调用方据此走降级放行，而不是把它当成协议错误拒绝请求。
		if len(encodings) > maxContentEncodingLayers {
			return nil, false
		}
	}
	return encodings, true
}

func isSupportedContentEncoding(encoding string) bool {
	switch encoding {
	case "", "identity", "gzip", "x-gzip", "br", "deflate", "zstd":
		return true
	default:
		return false
	}
}

func canonicalContentEncodingBytes(raw []byte) (string, bool) {
	switch len(raw) {
	case 0:
		return "", true
	case len("br"):
		if asciiEqualFoldBytes(raw, "br") {
			return "br", true
		}
	case len("gzip"):
		if asciiEqualFoldBytes(raw, "gzip") {
			return "gzip", true
		}
		if asciiEqualFoldBytes(raw, "zstd") {
			return "zstd", true
		}
	case len("x-gzip"):
		if asciiEqualFoldBytes(raw, "x-gzip") {
			return "x-gzip", true
		}
	case len("deflate"):
		if asciiEqualFoldBytes(raw, "deflate") {
			return "deflate", true
		}
	case len("identity"):
		if asciiEqualFoldBytes(raw, "identity") {
			return "identity", true
		}
	}
	return "", false
}

func newContentDecoderReader(reader io.Reader, encoding string) (io.Reader, io.Closer, bool, error) {
	switch encoding {
	case "", "identity":
		return reader, nil, false, nil
	case "gzip", "x-gzip":
		gzReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, nil, false, err
		}
		return gzReader, gzReader, true, nil
	case "br":
		return brotli.NewReader(reader), nil, true, nil
	case "deflate":
		// 兼容探测：旧 HTTP 实现的 Content-Encoding: deflate 常指向无
		// zlib 封装头的裸 deflate 流。前两个字节满足 RFC 1950 头约束
		// （CM=8、CINFO<=7、首 2 字节可被 31 整除）时按 zlib 解；否则
		// 把已探测字节无缝塞回，按裸 flate 解。
		head := make([]byte, 2)
		if n, err := io.ReadFull(reader, head); err == nil && n == 2 && looksLikeZlibHeader(head) {
			zr, zc := newZlibReader(reader, head)
			return zr, zc, true, nil
		} else if n > 0 {
			reader = io.MultiReader(bytes.NewReader(head[:n]), reader)
		}
		flateReader := flate.NewReader(reader)
		return flateReader, flateReader, true, nil
	case "zstd":
		// klauspost/compress 的解码器默认允许 512 MB 窗口与 64 GiB 解码内存，
		// 两者都远高于本项目的任何合法载荷。按两侧配置的较大值收紧，让库自己
		// 在解压开始前就拒绝超规格的帧，而不是等外层计到上限才中断。
		zstdLimit := uint64(zstdDecoderBudget())
		zstdReader, err := zstd.NewReader(reader,
			zstd.WithDecoderMaxMemory(zstdLimit),
			zstd.WithDecoderMaxWindow(zstdLimit),
		)
		if err != nil {
			return nil, nil, false, err
		}
		readCloser := zstdReader.IOReadCloser()
		return readCloser, readCloser, true, nil
	default:
		return nil, nil, false, nil
	}
}

// looksLikeZlibHeader 按 RFC 1950 第 2.2 节头部规则判定前两字节是否为
// 合法 zlib 头，判定口径与 compress/zlib 的 readHeader 完全一致。
func looksLikeZlibHeader(head []byte) bool {
	if len(head) != 2 {
		return false
	}
	if head[0]&0x0f != 8 || head[0]>>4 > 7 {
		return false
	}
	return (uint16(head[0])<<8|uint16(head[1]))%31 == 0
}

// newZlibReader 从头两字节 + 剩余流构造 zlib reader，供探测逻辑复用。
func newZlibReader(reader io.Reader, head []byte) (io.Reader, io.Closer) {
	zlibReader, err := zlib.NewReader(io.MultiReader(bytes.NewReader(head), reader))
	if err != nil {
		// 头已通过校验，此处失败仅剩 FDICT 字典场景，上游凡带字典头者
		// 一律不可能解出，返回一个立即报错的 reader 保持错误可见性。
		return errorReader{err: err}, nil
	}
	return zlibReader, zlibReader
}

// errorReader 在首次 Read 时返回构造错误，配合 newZlibReader 兜底。
type errorReader struct {
	err error
}

func (r errorReader) Read(p []byte) (int, error) {
	return 0, r.err
}

func closeContentDecoderClosers(closers []io.Closer) error {
	var firstErr error
	for i := len(closers) - 1; i >= 0; i-- {
		if err := closers[i].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func closeContentDecoder(closer io.Closer) error {
	if closer == nil {
		return nil
	}
	return closer.Close()
}

func applyClientResponseCompressionWithOptions(c *app.RequestContext, statusCode int, body []byte, opts ResponseCompressionOptions) []byte {
	if c == nil {
		return body
	}
	if requestCacheControlHasNoTransform(c.Request.Header.PeekAll("Cache-Control")) {
		return body
	}
	opts = normalizeResponseCompressionOptions(opts)
	if !opts.Enabled {
		return body
	}
	if !shouldTransformResponseBodyWithMinBytesBytes(statusCode, c.Response.Header.Peek("Content-Type"), c.Response.Header.ContentEncoding(), c.Response.Header.Peek("Cache-Control"), c.Response.Header.Peek("Content-Range"), len(body), opts.MinBytes) {
		return body
	}

	encoding := selectClientResponseEncodingBytes(c.GetHeader("Accept-Encoding"), opts.BrotliEnabled, opts.GzipEnabled, opts.DeflateEnabled, opts.ZstdEnabled)
	if encoding == responseEncodingIdentity {
		return body
	}

	encodedBody, err := compressResponseBody(body, encoding)
	if err != nil || len(encodedBody) >= len(body) {
		return body
	}

	ensureVaryAcceptEncoding(c)
	c.Response.Header.Set("Content-Encoding", string(encoding))
	c.Response.Header.Del("Content-Length")
	return encodedBody
}

func responseStatusDisallowsBody(statusCode int) bool {
	return (statusCode >= 100 && statusCode < 200) || statusCode == http.StatusNoContent || statusCode == http.StatusNotModified
}

/**
 * selectClientResponseEncoding 按 Accept-Encoding 协商响应编码。
 *
 * 候选顺序即优先级：q 值相同时取靠前者，因此顺序变化会直接改变输出。
 * 当前顺序为 zstd → br → gzip → deflate（用户裁定把 zstd 提到最前）。
 *
 * @param raw Accept-Encoding 头取值。
 * @param brotliEnabled 是否允许 br。
 * @param gzipEnabled 是否允许 gzip。
 * @param deflateEnabled 是否允许 deflate。
 * @param zstdEnabled 是否允许 zstd。
 * @returns 选中的编码；都不允许时为 identity。
 */
func selectClientResponseEncoding(raw string, brotliEnabled bool, gzipEnabled bool, deflateEnabled bool, zstdEnabled bool) responseEncoding {
	offers := parseAcceptEncodingOffers(raw)
	best := responseEncodingIdentity
	bestQ := 0.0
	for _, candidate := range []struct {
		encoding responseEncoding
		enabled  bool
	}{
		{responseEncodingZstd, zstdEnabled},
		{responseEncodingBrotli, brotliEnabled},
		{responseEncodingGzip, gzipEnabled},
		{responseEncodingDeflate, deflateEnabled},
	} {
		if !candidate.enabled {
			continue
		}
		q := acceptEncodingQ(offers, string(candidate.encoding))
		if q <= 0 {
			continue
		}
		if q > bestQ {
			best = candidate.encoding
			bestQ = q
		}
	}
	return best
}

type acceptEncodingScores struct {
	br       float64
	gzip     float64
	deflate  float64
	zstd     float64
	wildcard float64

	hasBR       bool
	hasGzip     bool
	hasDeflate  bool
	hasZstd     bool
	hasWildcard bool
}

/**
 * selectClientResponseEncodingBytes 是 selectClientResponseEncoding 的字节版。
 *
 * 与字符串版必须逐案同解，包括候选顺序（zstd → br → gzip → deflate）。
 * 顺序参与判定：q 值相等时先到的候选胜出，因此这里与字符串版的循环顺序
 * 必须同时改动，任何一侧漏改都会让同一请求在两个调用点协商出不同编码。
 *
 * 注意:每次胜出都必须同步推进 bestQ。zstd 曾经漏掉 bestQ 赋值，只要它排在
 * 首位就会被后续任何 q 值大于 0 的候选覆盖，协商结果退化成「顺序里最后一个
 * 命中的编码」。
 *
 * @param raw Accept-Encoding 头原始字节。
 * @param brotliEnabled 是否允许 br。
 * @param gzipEnabled 是否允许 gzip。
 * @param deflateEnabled 是否允许 deflate。
 * @param zstdEnabled 是否允许 zstd。
 * @returns 选中的编码；都不允许时为 identity。
 */
func selectClientResponseEncodingBytes(raw []byte, brotliEnabled bool, gzipEnabled bool, deflateEnabled bool, zstdEnabled bool) responseEncoding {
	scores := parseAcceptEncodingScoresBytes(raw)
	best := responseEncodingIdentity
	bestQ := 0.0
	if zstdEnabled {
		if q := scores.q(responseEncodingZstd); q > bestQ {
			best = responseEncodingZstd
			bestQ = q
		}
	}
	if brotliEnabled {
		if q := scores.q(responseEncodingBrotli); q > bestQ {
			best = responseEncodingBrotli
			bestQ = q
		}
	}
	if gzipEnabled {
		if q := scores.q(responseEncodingGzip); q > bestQ {
			best = responseEncodingGzip
			bestQ = q
		}
	}
	if deflateEnabled {
		if q := scores.q(responseEncodingDeflate); q > bestQ {
			best = responseEncodingDeflate
			bestQ = q
		}
	}
	return best
}

func parseAcceptEncodingScoresBytes(raw []byte) acceptEncodingScores {
	var scores acceptEncodingScores
	raw = trimASCIIHeaderSpaceBytes(raw)
	for len(raw) > 0 {
		token := raw
		if comma := bytes.IndexByte(raw, ','); comma >= 0 {
			token = raw[:comma]
			raw = raw[comma+1:]
		} else {
			raw = nil
		}
		part := trimASCIIHeaderSpaceBytes(token)
		if len(part) == 0 {
			continue
		}
		name := part
		q := 1.0
		if semi := bytes.IndexByte(part, ';'); semi >= 0 {
			name = trimASCIIHeaderSpaceBytes(part[:semi])
			q = acceptEncodingQParamBytes(part[semi+1:])
		}
		scores.set(name, q)
	}
	return scores
}

func acceptEncodingQParamBytes(params []byte) float64 {
	q := 1.0
	for len(params) > 0 {
		param := params
		if semi := bytes.IndexByte(params, ';'); semi >= 0 {
			param = params[:semi]
			params = params[semi+1:]
		} else {
			params = nil
		}
		kv := trimASCIIHeaderSpaceBytes(param)
		if eq := bytes.IndexByte(kv, '='); eq >= 0 {
			key := trimASCIIHeaderSpaceBytes(kv[:eq])
			if !asciiEqualFoldBytes(key, "q") {
				continue
			}
			value := trimASCIIHeaderSpaceBytes(kv[eq+1:])
			parsed, ok := parseAcceptEncodingQValueBytes(value)
			if !ok {
				continue
			}
			switch {
			case parsed < 0:
				q = 0
			case parsed > 1:
				q = 1
			default:
				q = parsed
			}
		}
	}
	return q
}

func parseAcceptEncodingQValueBytes(value []byte) (float64, bool) {
	value = trimASCIIHeaderSpaceBytes(value)
	if len(value) == 0 {
		return 0, false
	}
	if acceptEncodingQValueNeedsFloatFallback(value) {
		parsed, err := strconv.ParseFloat(string(value), 64)
		return parsed, err == nil && !math.IsNaN(parsed)
	}

	negative := false
	i := 0
	switch value[0] {
	case '+':
		i++
	case '-':
		negative = true
		i++
	}
	if i >= len(value) {
		return 0, false
	}

	var whole int64
	digits := 0
	for i < len(value) && value[i] >= '0' && value[i] <= '9' {
		whole = whole*10 + int64(value[i]-'0')
		i++
		digits++
	}

	frac := 0.0
	scale := 1.0
	if i < len(value) && value[i] == '.' {
		i++
		for i < len(value) && value[i] >= '0' && value[i] <= '9' {
			scale *= 10
			frac += float64(value[i]-'0') / scale
			i++
			digits++
		}
	}
	if digits == 0 || i != len(value) {
		return 0, false
	}

	parsed := float64(whole) + frac
	if negative {
		parsed = -parsed
	}
	return parsed, true
}

func acceptEncodingQValueNeedsFloatFallback(value []byte) bool {
	for _, b := range value {
		switch b {
		case 'e', 'E', 'i', 'I', 'n', 'N':
			return true
		}
	}
	return false
}

func (s *acceptEncodingScores) set(name []byte, q float64) {
	name = trimASCIIHeaderSpaceBytes(name)
	if len(name) == 0 {
		return
	}
	switch len(name) {
	case len("*"):
		if name[0] == '*' {
			if !s.hasWildcard || q > s.wildcard {
				s.wildcard = q
			}
			s.hasWildcard = true
		}
	case len("br"):
		if asciiEqualFoldBytes(name, "br") {
			if !s.hasBR || q > s.br {
				s.br = q
			}
			s.hasBR = true
		}
	case len("gzip"):
		if asciiEqualFoldBytes(name, "gzip") {
			if !s.hasGzip || q > s.gzip {
				s.gzip = q
			}
			s.hasGzip = true
			return
		}
		if asciiEqualFoldBytes(name, "zstd") {
			if !s.hasZstd || q > s.zstd {
				s.zstd = q
			}
			s.hasZstd = true
		}
	case len("deflate"):
		if asciiEqualFoldBytes(name, "deflate") {
			if !s.hasDeflate || q > s.deflate {
				s.deflate = q
			}
			s.hasDeflate = true
		}
	}
}

func (s acceptEncodingScores) q(encoding responseEncoding) float64 {
	switch encoding {
	case responseEncodingBrotli:
		if s.hasBR {
			return s.br
		}
	case responseEncodingGzip:
		if s.hasGzip {
			return s.gzip
		}
	case responseEncodingDeflate:
		if s.hasDeflate {
			return s.deflate
		}
	case responseEncodingZstd:
		if s.hasZstd {
			return s.zstd
		}
	default:
		return 0
	}
	if s.hasWildcard {
		return s.wildcard
	}
	return 0
}

type acceptEncodingOffer struct {
	name string
	q    float64
}

func parseAcceptEncodingOffers(raw string) []acceptEncodingOffer {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	offers := make([]acceptEncodingOffer, 0, strings.Count(raw, ",")+1)
	for _, token := range strings.Split(raw, ",") {
		part := strings.TrimSpace(token)
		if part == "" {
			continue
		}
		name := part
		q := 1.0
		if semi := strings.IndexByte(part, ';'); semi >= 0 {
			name = strings.TrimSpace(part[:semi])
			params := strings.Split(part[semi+1:], ";")
			for _, param := range params {
				kv := strings.SplitN(strings.TrimSpace(param), "=", 2)
				if len(kv) != 2 || !strings.EqualFold(strings.TrimSpace(kv[0]), "q") {
					continue
				}
				if parsed, err := strconv.ParseFloat(strings.TrimSpace(kv[1]), 64); err == nil && !math.IsNaN(parsed) {
					switch {
					case parsed < 0:
						q = 0
					case parsed > 1:
						q = 1
					default:
						q = parsed
					}
				}
			}
		}
		name = strings.ToLower(name)
		if name == "" {
			continue
		}
		offers = append(offers, acceptEncodingOffer{name: name, q: q})
	}
	return offers
}

func acceptEncodingQ(offers []acceptEncodingOffer, target string) float64 {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return 0
	}
	best := 0.0
	hasExact := false
	for _, offer := range offers {
		if offer.name == target {
			hasExact = true
			if offer.q > best {
				best = offer.q
			}
		}
	}
	if hasExact {
		return best
	}
	for _, offer := range offers {
		if offer.name == "*" && offer.q > best {
			best = offer.q
		}
	}
	return best
}

func shouldTransformResponseBodyWithMinBytes(statusCode int, contentType string, contentEncoding string, cacheControl string, contentRange string, bodySize int, minBytes int) bool {
	minBytes = responseCompressionMinBytes(minBytes)
	if bodySize < minBytes {
		return false
	}
	return shouldTransformResponseMetadata(statusCode, contentType, contentEncoding, cacheControl, contentRange)
}

func shouldTransformResponseBodyWithMinBytesBytes(statusCode int, contentType []byte, contentEncoding []byte, cacheControl []byte, contentRange []byte, bodySize int, minBytes int) bool {
	minBytes = responseCompressionMinBytes(minBytes)
	if bodySize < minBytes {
		return false
	}
	return shouldTransformResponseMetadataBytes(statusCode, contentType, contentEncoding, cacheControl, contentRange)
}

func shouldTransformStreamingResponseBody(statusCode int, contentType string, contentEncoding string, cacheControl string, contentRange string, bodySize int, minBytes int) bool {
	if bodySize >= 0 {
		return shouldTransformResponseBodyWithMinBytes(statusCode, contentType, contentEncoding, cacheControl, contentRange, bodySize, minBytes)
	}
	return shouldTransformResponseMetadata(statusCode, contentType, contentEncoding, cacheControl, contentRange)
}

func shouldTransformResponseMetadata(statusCode int, contentType string, contentEncoding string, cacheControl string, contentRange string) bool {
	return shouldTransformResponseMetadataBytes(statusCode, []byte(contentType), []byte(contentEncoding), []byte(cacheControl), []byte(contentRange))
}

func shouldTransformResponseMetadataBytes(statusCode int, contentType []byte, contentEncoding []byte, cacheControl []byte, contentRange []byte) bool {
	if statusCode >= 100 && statusCode < 200 {
		return false
	}
	if statusCode == http.StatusNoContent || statusCode == http.StatusNotModified {
		return false
	}
	if len(trimASCIIHeaderSpaceBytes(contentRange)) != 0 {
		return false
	}
	if cacheControlHasNoTransformBytes(cacheControl) {
		return false
	}
	encoding := normalizedContentEncodingBytes(contentEncoding)
	if encoding != "" && encoding != "identity" {
		return false
	}
	return isCompressibleContentTypeBytes(contentType)
}

func isCompressibleContentType(raw string) bool {
	mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(raw))
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(raw))
	}
	mediaType = strings.ToLower(mediaType)
	if strings.HasPrefix(mediaType, "text/") {
		return true
	}
	switch mediaType {
	case "application/json",
		"application/ld+json",
		"application/manifest+json",
		"application/problem+json",
		"application/javascript",
		"application/x-javascript",
		"application/xml",
		"application/xhtml+xml",
		"application/rss+xml",
		"application/atom+xml",
		"application/x-www-form-urlencoded",
		"image/svg+xml":
		return true
	default:
		return false
	}
}

func isCompressibleContentTypeBytes(raw []byte) bool {
	raw = trimASCIIHeaderSpaceBytes(raw)
	if len(raw) == 0 {
		return false
	}
	mediaType := raw
	if semi := bytes.IndexByte(raw, ';'); semi >= 0 {
		params := raw[semi+1:]
		if !contentTypeParamsAreSimpleBytes(params) {
			return isCompressibleContentType(string(raw))
		}
		mediaType = trimASCIIHeaderSpaceBytes(raw[:semi])
	}
	return isCompressibleMediaTypeBytes(mediaType)
}

func contentTypeParamsAreSimpleBytes(raw []byte) bool {
	for len(raw) > 0 {
		part := raw
		if semi := bytes.IndexByte(raw, ';'); semi >= 0 {
			part = raw[:semi]
			raw = raw[semi+1:]
		} else {
			raw = nil
		}
		part = trimASCIIHeaderSpaceBytes(part)
		if len(part) == 0 {
			return false
		}
		eq := bytes.IndexByte(part, '=')
		if eq <= 0 {
			return false
		}
		key := trimASCIIHeaderSpaceBytes(part[:eq])
		value := trimASCIIHeaderSpaceBytes(part[eq+1:])
		if len(key) == 0 || len(value) == 0 || !isHTTPTokenBytes(key) || !isHTTPTokenBytes(value) {
			return false
		}
	}
	return true
}

func isCompressibleMediaTypeBytes(mediaType []byte) bool {
	if len(mediaType) > len("text/") && asciiEqualFoldBytes(mediaType[:len("text/")], "text/") {
		return true
	}
	switch len(mediaType) {
	case len("image/svg+xml"):
		return asciiEqualFoldBytes(mediaType, "image/svg+xml")
	case len("application/json"):
		return asciiEqualFoldBytes(mediaType, "application/json")
	case len("application/xml"):
		return asciiEqualFoldBytes(mediaType, "application/xml")
	case len("application/ld+json"):
		return asciiEqualFoldBytes(mediaType, "application/ld+json") || asciiEqualFoldBytes(mediaType, "application/rss+xml")
	case len("application/atom+xml"):
		return asciiEqualFoldBytes(mediaType, "application/atom+xml")
	case len("application/xhtml+xml"):
		return asciiEqualFoldBytes(mediaType, "application/xhtml+xml")
	case len("application/javascript"):
		return asciiEqualFoldBytes(mediaType, "application/javascript")
	case len("application/problem+json"):
		return asciiEqualFoldBytes(mediaType, "application/problem+json") || asciiEqualFoldBytes(mediaType, "application/x-javascript")
	case len("application/manifest+json"):
		return asciiEqualFoldBytes(mediaType, "application/manifest+json")
	case len("application/x-www-form-urlencoded"):
		return asciiEqualFoldBytes(mediaType, "application/x-www-form-urlencoded")
	default:
		return false
	}
}

func cacheControlHasNoTransformBytes(raw []byte) bool {
	return asciiContainsFoldBytes(raw, "no-transform")
}

func asciiContainsFoldBytes(raw []byte, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(raw) < len(needle) {
		return false
	}
	for i := 0; i <= len(raw)-len(needle); i++ {
		if asciiEqualFoldBytes(raw[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

func isHTTPTokenBytes(raw []byte) bool {
	for _, b := range raw {
		if !isHTTPTokenByte(b) {
			return false
		}
	}
	return true
}

func isHTTPTokenByte(b byte) bool {
	if b >= '0' && b <= '9' {
		return true
	}
	if b >= 'A' && b <= 'Z' {
		return true
	}
	if b >= 'a' && b <= 'z' {
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

// applyGzipUnit 是 apply/static 路径 gzip 压缩器与输出缓冲的池化单元。
//
// gzip.Writer.Reset 等价于重建 Writer（gzip.go 的 init 语义），
// 且 flate 侧 compressor.reset 对 level 1-6 只重置 fast encoder 状态
// （fastGen.reset 保留 hist 底层数组）而不重分配窗口，故 Reset 是零分配路径。
type applyGzipUnit struct {
	gz  *gzip.Writer
	buf *bytes.Buffer
}

// applyZlibUnit 同 applyGzipUnit，用于 zlib（deflate）编码。
type applyZlibUnit struct {
	zw  *zlib.Writer
	buf *bytes.Buffer
}

var (
	applyGzipUnitPool = &sync.Pool{New: func() any {
		return newApplyGzipUnit()
	}}
	applyZlibUnitPool = &sync.Pool{New: func() any {
		return newApplyZlibUnit()
	}}
)

func newApplyGzipUnit() *applyGzipUnit {
	buf := bytes.NewBuffer(make([]byte, 0, 256<<10))
	gz, _ := gzip.NewWriterLevel(buf, gzip.BestSpeed)
	return &applyGzipUnit{gz: gz, buf: buf}
}

func newApplyZlibUnit() *applyZlibUnit {
	buf := bytes.NewBuffer(make([]byte, 0, 64<<10))
	zw, _ := zlib.NewWriterLevel(buf, zlib.BestSpeed)
	return &applyZlibUnit{zw: zw, buf: buf}
}

func compressResponseBody(body []byte, encoding responseEncoding) ([]byte, error) {
	var buf bytes.Buffer
	switch encoding {
	case responseEncodingBrotli:
		writer := brotli.NewWriterLevel(&buf, brotliCompressionLevel)
		if _, err := writer.Write(body); err != nil {
			_ = writer.Close()
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
	case responseEncodingGzip:
		u := applyGzipUnitPool.Get().(*applyGzipUnit)
		u.buf.Reset()
		u.gz.Reset(u.buf)
		_, writeErr := u.gz.Write(body)
		closeErr := u.gz.Close()
		if writeErr != nil || closeErr != nil {
			applyGzipUnitPool.Put(u)
			if writeErr != nil {
				return nil, writeErr
			}
			return nil, closeErr
		}
		out := append([]byte(nil), u.buf.Bytes()...)
		applyGzipUnitPool.Put(u)
		return out, nil
	case responseEncodingDeflate:
		u := applyZlibUnitPool.Get().(*applyZlibUnit)
		u.buf.Reset()
		u.zw.Reset(u.buf)
		_, writeErr := u.zw.Write(body)
		closeErr := u.zw.Close()
		if writeErr != nil || closeErr != nil {
			applyZlibUnitPool.Put(u)
			if writeErr != nil {
				return nil, writeErr
			}
			return nil, closeErr
		}
		out := append([]byte(nil), u.buf.Bytes()...)
		applyZlibUnitPool.Put(u)
		return out, nil
	case responseEncodingZstd:
		writer, err := zstd.NewWriter(&buf)
		if err != nil {
			return nil, err
		}
		if _, err := writer.Write(body); err != nil {
			_ = writer.Close()
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
	default:
		return body, nil
	}
	return buf.Bytes(), nil
}

func ensureVaryAcceptEncoding(c *app.RequestContext) {
	current := c.Response.Header.Peek("Vary")
	if len(current) == 0 {
		c.Response.Header.Set("Vary", "Accept-Encoding")
		return
	}
	if varyContainsAcceptEncodingBytes(current) {
		return
	}
	next := make([]byte, 0, len(current)+len(", Accept-Encoding"))
	next = append(next, current...)
	next = append(next, ", Accept-Encoding"...)
	c.Response.Header.SetBytesV("Vary", next)
}

func varyContainsAcceptEncodingBytes(raw []byte) bool {
	for len(raw) > 0 {
		token := raw
		if comma := bytes.IndexByte(raw, ','); comma >= 0 {
			token = raw[:comma]
			raw = raw[comma+1:]
		} else {
			raw = nil
		}
		token = trimASCIIHeaderSpaceBytes(token)
		if len(token) == len("Accept-Encoding") && asciiEqualFoldBytes(token, "accept-encoding") {
			return true
		}
	}
	return false
}

var (
	streamGzipWriterPool = &sync.Pool{New: func() any {
		w, _ := kgzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
		return w
	}}
	streamZlibWriterPool = &sync.Pool{New: func() any {
		w, _ := kzlib.NewWriterLevel(io.Discard, zlib.BestSpeed)
		return w
	}}
)

func newStreamCompressWriter(w io.Writer, encoding responseEncoding) (io.Writer, func()) {
	switch encoding {
	case responseEncodingGzip:
		gw := streamGzipWriterPool.Get().(*kgzip.Writer)
		gw.Reset(w)
		return gw, func() {
			_ = gw.Close()
			streamGzipWriterPool.Put(gw)
		}
	case responseEncodingBrotli:
		bw := brotli.NewWriterLevel(w, brotliCompressionLevel)
		return bw, func() { _ = bw.Close() }
	case responseEncodingDeflate:
		dw := streamZlibWriterPool.Get().(*kzlib.Writer)
		dw.Reset(w)
		return dw, func() {
			_ = dw.Close()
			streamZlibWriterPool.Put(dw)
		}
	case responseEncodingZstd:
		zw, _ := zstd.NewWriter(w)
		return zw, func() { _ = zw.Close() }
	default:
		return w, func() {}
	}
}

func normalizedContentEncodingBytes(raw []byte) string {
	raw = trimASCIIHeaderSpaceBytes(raw)
	if len(raw) == 0 {
		return ""
	}
	if bytes.IndexByte(raw, ',') >= 0 {
		return strings.ToLower(string(raw))
	}
	if semi := bytes.IndexByte(raw, ';'); semi >= 0 {
		raw = trimASCIIHeaderSpaceBytes(raw[:semi])
	}
	encoding, ok := canonicalContentEncodingBytes(raw)
	if ok {
		return encoding
	}
	return strings.ToLower(string(raw))
}
