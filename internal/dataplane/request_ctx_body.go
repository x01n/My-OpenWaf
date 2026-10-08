package dataplane

import (
	"bytes"
	"io"
	"sync"

	"My-OpenWaf/internal/proxy"
	"My-OpenWaf/internal/snapshot"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
)

const (
	requestInspectionBodyLimit    = snapshot.WAFBodyScanLimit
	requestBodySnapshotContextKey = "openwaf_request_body_snapshot"

	// requestBodySnapshotReadMaxSize 是**压缩请求**的偷读上限，也是压缩体采样
	// 解码器能看到的全部字节。
	//
	// 压缩请求必须比未压缩请求多读，原因在解码器：解码器只能看到偷读到的前缀，
	// 压缩体超过前缀时后续字节无处可解。zstd 的帧结构要求读到帧结束标记才吐数据，
	// 前缀被截断时一个字节都解不出来，窗口太小会让「合法 zstd 压缩请求体」整条
	// 绕过检测——实测 48 KiB 窗口下 gzip/br/deflate 能解出前缀而 zstd 不能，
	// 60 KiB 左右的压缩体在 64 KiB 窗口下四种编码才齐平。
	//
	// 上界的约束来自 Hertz 的流式请求体语义：chunked 请求的 Request.BodyStream()
	// 是 *ext.bodyStream，它的 Read 会阻塞到凑满请求的字节数（network.Reader.Peek
	// 的「wait full n」契约），读空当前 chunk 后还会继续 Peek 下一个 chunk 的
	// 长度行。于是只要偷读目标超过客户端此刻已写完的字节数，这次读就会挂住；
	// 客户端此时往往正在等上游读取、上游又在等 WAF 转发，两者互等即死锁。
	// internal/app 的一批 pacing 用例正是在锁定这条边界。
	//
	// 两档能拉开差距，是因为分档依据不是「读多少」而是「要不要解压」：未压缩
	// 请求的偷读只为送 WAF 采样，采样窗就是 requestInspectionBodyLimit，多读的
	// 字节没有任何收益，只白担挂起风险；压缩请求则必须凑够解码器能吐出帧尾的
	// 字节数，才谈得上检测。
	requestBodySnapshotReadMaxSize = 64 * 1024

	// requestBodySnapshotReadMaxSizeUncompressed 是**未压缩请求**的偷读上限。
	//
	// 取采样窗本身（+1 只用于判定截断）：未压缩请求送检的就是原始字节，采样窗
	// 之外的内容检测不到也无需看到，因此没有任何多读的理由。这也让绝大多数请求
	// （无 Content-Encoding）完全避开 bodyStream「凑满 n 字节才返回」的挂起风险。
	requestBodySnapshotReadMaxSizeUncompressed = requestInspectionBodyLimit + 1

	// 压缩请求体的 WAF 采样预算。产出上限直接取 WAF 扫描窗本身：检测最多
	// 看 WAFBodyScanLimit 字节，多解压对检测没有增益。
	requestBodyInspectionDecodeLimit = requestInspectionBodyLimit

	requestBodyInspectionContextKey = "openwaf_request_body_inspection_sample"
)

type requestBodySnapshot struct {
	prefetched []byte
	original   io.Reader
	forward    *prefetchedRequestBodyStream
	size       int64
	hasMore    bool
	readErr    error

	// 压缩请求体的采样结果。inspectionPlaintext 为真时 inspectionBody 是解出的
	// 明文前缀，送检用它；为假时调用方回退到 prefetched，与改动前一致。
	inspectionBody      []byte
	inspectionPlaintext bool
	inspectionTruncated bool

	// inspectionUndetectedEncoding 非空表示请求声明了内容编码但采样解码一个
	// 字节都没解出来（压缩体超出偷读前缀、或采样器不支持该编码的形态）。
	// 这是「降级放行」的信号：不解压、不拒绝，按原始压缩字节转发，并记录
	// 一条安全事件说明这部分内容未被检测。
	inspectionUndetectedEncoding string

	// inspectionLimitExceededEncoding 非空表示采样解压的产出超过了压缩炸弹
	// 硬上限，解压已被中断。与 inspectionUndetectedEncoding 的处置相同
	// （降级放行 + 记事件），但事件类型不同，便于区分攻击与客户端缺陷。
	inspectionLimitExceededEncoding string
}

// requestBodyContentEncoding 返回请求声明的内容编码原始取值。
func requestBodyContentEncoding(c *app.RequestContext) []byte {
	if c == nil {
		return nil
	}
	return c.Request.Header.Peek("Content-Encoding")
}

// bufferedRequestBodyInspection 缓存已完整缓冲请求体的解压结果，避免日志
// 预览与检测各自重复解压同一份 body。
type bufferedRequestBodyInspection struct {
	decoded   []byte
	didDecode bool
	truncated bool
}

type prefetchedRequestBodyStream struct {
	mu     sync.Mutex
	reader io.Reader
	closed bool
}

func (s *prefetchedRequestBodyStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.EOF
	}
	return s.reader.Read(p)
}

func (s *prefetchedRequestBodyStream) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func requestBodySampleBeforePipeline(c *app.RequestContext) ([]byte, bool, int64) {
	if IsH2ExtendedWebSocketConnect(c) {
		return nil, false, 0
	}
	return requestBodySample(c)
}

/**
 * requestBodySample 返回送入 WAF 检测的请求体样本。
 *
 * 带 Content-Encoding 的请求送检的是解压后的明文前缀，不是原始压缩字节：
 * 压缩字节里没有明文载荷，直接送检等于放弃检测。
 *
 * @param c Hertz 请求上下文。
 * @returns body 样本；hasMore 是否截断；size 请求体原始字节数。
 */
func requestBodySample(c *app.RequestContext) ([]byte, bool, int64) {
	if c == nil {
		return nil, false, 0
	}
	if c.Request.IsBodyStream() {
		snap := ensureRequestBodySnapshot(c)
		if snap.inspectionPlaintext {
			return snap.inspectionBody, snap.inspectionTruncated, snap.size
		}
		body := snap.prefetched
		if len(body) > requestInspectionBodyLimit {
			body = body[:requestInspectionBodyLimit]
		}
		return body, snap.hasMore, snap.size
	}

	body := c.Request.Body()
	size := int64(len(body))
	if decoded, truncated, didDecode := bufferedRequestBodyInspectionFor(c, body); didDecode {
		return decoded, truncated, size
	}
	if len(body) <= requestInspectionBodyLimit {
		return body, false, size
	}
	return body[:requestInspectionBodyLimit], true, size
}

func ensureRequestBodySnapshot(c *app.RequestContext) requestBodySnapshot {
	if snap, ok := requestBodySnapshotFromContext(c); ok {
		return snap
	}
	if c == nil {
		return requestBodySnapshot{}
	}
	if IsH2ExtendedWebSocketConnect(c) {
		return requestBodySnapshot{}
	}

	stream := c.Request.BodyStream()
	contentLength := c.Request.Header.ContentLength()
	contentEncoding := requestBodyContentEncoding(c)
	snap := requestBodySnapshot{}
	if stream == nil || stream == protocol.NoBody {
		if contentLength >= 0 {
			snap.size = int64(contentLength)
		}
		c.Set(requestBodySnapshotContextKey, snap)
		return snap
	}

	// 按「是否声明了内容编码」分档偷读：未压缩请求只需要够填采样窗，压缩请求
	// 需要够解码器吐出帧尾。两档的取值与理由见常量区注释。
	readMaxSize := requestBodySnapshotReadMaxSizeUncompressed
	if len(contentEncoding) > 0 {
		readMaxSize = requestBodySnapshotReadMaxSize
	}
	prefetched, readErr := io.ReadAll(io.LimitReader(stream, int64(readMaxSize)))
	snap.prefetched = prefetched
	snap.original = stream
	snap.hasMore = len(prefetched) > requestInspectionBodyLimit
	snap.readErr = readErr
	if contentLength >= 0 {
		snap.size = int64(contentLength)
	} else if !snap.hasMore {
		snap.size = int64(len(prefetched))
	}

	// 没有 Content-Encoding 的请求（绝大多数）在此处就返回：不触碰解码器，
	// 转发路径与改动前完全一致，解压也不给这类请求增加任何分配。
	//
	// 有声明时只在偷读前缀（一个已在内存里的完整字节切片）上解压，不读网络：
	// 请求体还没到齐不能成为请求挂在 WAF 采样阶段的原因，上游的上传节奏也
	// 不会被 WAF 提前拉走。前缀可能只是完整压缩体的一段，末端的读取错误由
	// 解码入口降级成「样本不完整」，已解出的明文照常送检。
	if encoding := contentEncoding; len(prefetched) > 0 && len(encoding) > 0 {
		// 偷读到的字节数已经覆盖声明的 Content-Length 时，整段压缩体就在内存
		// 里（长度受偷读窗硬约束，最大 64 KiB）。这个事实让转发路径可以对它
		// 做「先缓冲、再按预算解压」：解压失败或触及炸弹上限时还能回退到原始
		// 压缩字节转发，而不是把半截明文交给上游后落成 502。
		if contentLength >= 0 && int64(len(prefetched)) >= int64(contentLength) {
			proxy.ContextWithBufferedCompressedBody(c)
		}

		sample := proxy.DecodeRequestBodyInspectionSample(prefetched, encoding, requestBodyInspectionDecodeLimit)
		switch {
		case sample.LimitExceeded:
			// 压缩炸弹：采样解压的产出已触及硬上限，解压被中断。已解出的明文
			// 仍然是可信的（截断送检），但转发路径不再解压——重复解压一遍正是
			// 炸弹想要的 CPU/内存开销。记成因，由 handler 落审计事件。
			snap.inspectionLimitExceededEncoding = string(encoding)
			proxy.ContextWithSkippedRequestBodyDecode(c)
			if sample.DidDecode {
				snap.inspectionBody = sample.Decoded
				snap.inspectionPlaintext = true
				snap.inspectionTruncated = true
			}
		case sample.Undecodable:
			// 前缀不足以让解码器吐出任何内容（zstd 超过采样窗即如此）：
			// 一个字节都没解出来，没有东西可检。按用户裁定降级：不拒绝、
			// 按原始压缩字节转发并保留 Content-Encoding，另留审计事件；
			// 同时跳过转发层的重复解压——它同样只会解出 0 字节（或撞上
			// 炸弹限额），白白吃掉 CPU 与内存。
			//
			// inspectionPlaintext 必须置真、样本置空：置假会让 requestBodySample
			// 回退到 prefetched，把**原始压缩字节**当明文送检。压缩字节里没有
			// 明文载荷，拿它跑正则等于在噪声上做判定（实测会出现随机 403）。
			snap.inspectionUndetectedEncoding = string(encoding)
			snap.inspectionPlaintext = true
			snap.inspectionTruncated = true
			proxy.ContextWithSkippedRequestBodyDecode(c)
		case sample.DidDecode:
			snap.inspectionBody = sample.Decoded
			snap.inspectionPlaintext = true
			snap.inspectionTruncated = sample.Truncated
		}
	}

	// 重新绑定请求体流时不能在这里调用 SetBodyStream：Hertz 的
	// SetBodyStream() 会先重置并关闭当前请求体流，这会破坏 HTTP/2
	// 的 requestBody 管道，使 proxy 无法继续把未读完的剩余部分流式送上游。
	//
	// 解压只在偷读前缀的副本上进行，原始流一字节未读，转发路径与改动前
	// 逐字节相同：先回放前缀，再接原始流的剩余部分。
	forward := &prefetchedRequestBodyStream{
		reader: io.MultiReader(bytes.NewReader(prefetched), stream),
	}
	snap.forward = forward
	c.Request.ConstructBodyStream(nil, forward)
	c.Set(requestBodySnapshotContextKey, snap)
	return snap
}

// bufferedRequestBodyInspectionFor 为已完整缓冲的请求体返回解压结果，并在
// 请求上下文里缓存，避免日志预览与检测重复解压。
func bufferedRequestBodyInspectionFor(c *app.RequestContext, body []byte) ([]byte, bool, bool) {
	if len(body) == 0 || c == nil {
		return nil, false, false
	}
	if cached, ok := bufferedRequestBodyInspectionFromContext(c); ok {
		return cached.decoded, cached.truncated, cached.didDecode
	}
	decoded, didDecode, truncated := proxy.DecodeRequestBodyBytesForInspection(body, requestBodyContentEncoding(c), requestBodyInspectionDecodeLimit)
	if didDecode {
		c.Set(requestBodyInspectionContextKey, bufferedRequestBodyInspection{decoded: decoded, didDecode: true, truncated: truncated})
	}
	return decoded, truncated, didDecode
}

func bufferedRequestBodyInspectionFromContext(c *app.RequestContext) (bufferedRequestBodyInspection, bool) {
	if c == nil {
		return bufferedRequestBodyInspection{}, false
	}
	value, exists := c.Get(requestBodyInspectionContextKey)
	if !exists {
		return bufferedRequestBodyInspection{}, false
	}
	cached, ok := value.(bufferedRequestBodyInspection)
	return cached, ok
}

func requestBodySnapshotFromContext(c *app.RequestContext) (requestBodySnapshot, bool) {
	if c == nil {
		return requestBodySnapshot{}, false
	}
	value, exists := c.Get(requestBodySnapshotContextKey)
	if !exists {
		return requestBodySnapshot{}, false
	}
	snap, ok := value.(requestBodySnapshot)
	return snap, ok
}

func requestBodySnapshotError(c *app.RequestContext) error {
	if snap, ok := requestBodySnapshotFromContext(c); ok {
		return snap.readErr
	}
	if c == nil || !c.Request.IsBodyStream() {
		return nil
	}
	return ensureRequestBodySnapshot(c).readErr
}

func restoreOriginalRequestBodyStream(c *app.RequestContext) {
	if snap, ok := requestBodySnapshotFromContext(c); ok && snap.original != nil {
		if snap.forward != nil {
			_ = snap.forward.Close()
		}
		c.Request.ConstructBodyStream(nil, snap.original)
	}
}
