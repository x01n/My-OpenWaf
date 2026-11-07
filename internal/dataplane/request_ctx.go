package dataplane

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"mime"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"

	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/proxy"
	"My-OpenWaf/internal/security"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/waf/bot/tlsfp"
)

const (
	InternalHTTP3ProtoHeader           = "X-OpenWaf-Internal-Proto"
	InternalHTTP3CancelTokenHeader     = "X-OpenWaf-Internal-Cancel-Token"
	InternalHTTP3ResetTokenHeader      = "X-OpenWaf-Internal-Reset-Token"
	InternalHTTP3TLSVersionHeader      = "X-OpenWaf-Internal-TLS-Version"
	InternalHTTP3TLSSNIHeader          = "X-OpenWaf-Internal-TLS-SNI"
	InternalHTTP3TLSALPNHeader         = "X-OpenWaf-Internal-TLS-ALPN"
	InternalHTTP3TLSALPNRawHeader      = "X-OpenWaf-Internal-TLS-ALPN-Raw"
	InternalHTTP3TLSJA3Header          = "X-OpenWaf-Internal-TLS-JA3"
	InternalHTTP3TLSJA3HashHeader      = "X-OpenWaf-Internal-TLS-JA3-Hash"
	InternalHTTP3TLSJA4Header          = "X-OpenWaf-Internal-TLS-JA4"
	InternalHTTP3TLSCipherSuitesHeader = "X-OpenWaf-Internal-TLS-Cipher-Suites"
	InternalHTTP3TLSExtensionsHeader   = "X-OpenWaf-Internal-TLS-Extensions"
	InternalHTTP3TLSCurvesHeader       = "X-OpenWaf-Internal-TLS-Curves"
	InternalHTTP3TLSPointFormatsHeader = "X-OpenWaf-Internal-TLS-Point-Formats"
	// InternalHTTP3ZeroRTTHeader 标记该 h3 请求来自 0-RTT（early data）。
	//
	// 该头只能由本机 h3 回环转发按真实 QUIC 连接状态写入；applyInternalHTTP3RequestMetadata
	// 在非回环或非 h3 请求上会把它清除，因此不能作为外部输入被伪造。
	InternalHTTP3ZeroRTTHeader = "X-OpenWaf-Internal-0RTT"

	internalHTTP3ContextKey        = "dataplane_internal_http3"
	internalHTTP3ZeroRTTContextKey = "dataplane_internal_http3_0rtt"
)

var internalHTTP3CancelSignals = struct {
	sync.Mutex
	items map[string]<-chan struct{}
}{items: make(map[string]<-chan struct{})}

var internalHTTP3ResetClosures = struct {
	sync.Mutex
	items map[string]func()
}{items: make(map[string]func())}

func RegisterInternalHTTP3ResetToken(reset func()) string {
	if reset == nil {
		return ""
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return ""
	}
	token := hex.EncodeToString(raw[:])
	internalHTTP3ResetClosures.Lock()
	internalHTTP3ResetClosures.items[token] = reset
	internalHTTP3ResetClosures.Unlock()
	return token
}

func UnregisterInternalHTTP3ResetToken(token string) {
	if token == "" {
		return
	}
	internalHTTP3ResetClosures.Lock()
	delete(internalHTTP3ResetClosures.items, token)
	internalHTTP3ResetClosures.Unlock()
}

func takeInternalHTTP3ResetClosure(token string) (func(), bool) {
	if token == "" {
		return nil, false
	}
	internalHTTP3ResetClosures.Lock()
	reset, ok := internalHTTP3ResetClosures.items[token]
	delete(internalHTTP3ResetClosures.items, token)
	internalHTTP3ResetClosures.Unlock()
	return reset, ok && reset != nil
}

func RegisterInternalHTTP3CancelSignal(done <-chan struct{}) (string, func()) {
	if done == nil {
		return "", func() {}
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", func() {}
	}
	token := hex.EncodeToString(raw[:])
	internalHTTP3CancelSignals.Lock()
	internalHTTP3CancelSignals.items[token] = done
	internalHTTP3CancelSignals.Unlock()

	unregister := func() {
		internalHTTP3CancelSignals.Lock()
		delete(internalHTTP3CancelSignals.items, token)
		internalHTTP3CancelSignals.Unlock()
	}
	return token, unregister
}

func takeInternalHTTP3CancelSignal(token string) (<-chan struct{}, bool) {
	if token == "" {
		return nil, false
	}
	internalHTTP3CancelSignals.Lock()
	done, ok := internalHTTP3CancelSignals.items[token]
	delete(internalHTTP3CancelSignals.items, token)
	internalHTTP3CancelSignals.Unlock()
	return done, ok && done != nil
}

/**
 * populateRequestCtxHeaders 将请求头拷入 RequestCtx，且只使用小写键名。
 * HeaderKeys 仍保留原始顺序与大小写，供请求头顺序指纹与日志使用。
 */
func populateRequestCtxHeaders(reqCtx *pipeline.RequestCtx, c *app.RequestContext) {
	reqCtx.HeadersLowercase = true
	if reqCtx.Headers == nil {
		reqCtx.Headers = make(map[string]string, 24)
	} else {
		clear(reqCtx.Headers)
	}
	reqCtx.ClearHeaderKeys()
	c.Request.Header.VisitAll(func(k, v []byte) {
		key := string(k)
		lower := lowerRequestHeaderName(key)
		reqCtx.AppendHeaderKey(key)
		reqCtx.Headers[lower] = string(v)
	})
}

func lowerRequestHeaderName(name string) string {
	switch name {
	case "Accept":
		return "accept"
	case "Accept-Encoding":
		return "accept-encoding"
	case "Accept-Language":
		return "accept-language"
	case "Authorization":
		return "authorization"
	case "Cache-Control":
		return "cache-control"
	case "Connection":
		return "connection"
	case "Content-Length":
		return "content-length"
	case "Content-Type":
		return "content-type"
	case "Cookie":
		return "cookie"
	case "DNT":
		return "dnt"
	case "Host":
		return "host"
	case "If-Modified-Since":
		return "if-modified-since"
	case "If-None-Match":
		return "if-none-match"
	case "Origin":
		return "origin"
	case "Pragma":
		return "pragma"
	case "Referer":
		return "referer"
	case "Sec-Ch-Ua":
		return "sec-ch-ua"
	case "Sec-Ch-Ua-Arch":
		return "sec-ch-ua-arch"
	case "Sec-Ch-Ua-Bitness":
		return "sec-ch-ua-bitness"
	case "Sec-Ch-Ua-Full-Version":
		return "sec-ch-ua-full-version"
	case "Sec-Ch-Ua-Full-Version-List":
		return "sec-ch-ua-full-version-list"
	case "Sec-Ch-Ua-Mobile":
		return "sec-ch-ua-mobile"
	case "Sec-Ch-Ua-Model":
		return "sec-ch-ua-model"
	case "Sec-Ch-Ua-Platform":
		return "sec-ch-ua-platform"
	case "Sec-Ch-Ua-Platform-Version":
		return "sec-ch-ua-platform-version"
	case "Sec-Fetch-Dest":
		return "sec-fetch-dest"
	case "Sec-Fetch-Mode":
		return "sec-fetch-mode"
	case "Sec-Fetch-Site":
		return "sec-fetch-site"
	case "Sec-Fetch-User":
		return "sec-fetch-user"
	case "TE":
		return "te"
	case "Upgrade":
		return "upgrade"
	case "Upgrade-Insecure-Requests":
		return "upgrade-insecure-requests"
	case "User-Agent":
		return "user-agent"
	case "X-Client-Data":
		return "x-client-data"
	case "X-Forwarded-For":
		return "x-forwarded-for"
	case "X-Forwarded-Proto":
		return "x-forwarded-proto"
	case "X-Request-Id":
		return "x-request-id"
	}
	if isLowerASCIIRequestHeaderName(name) {
		return name
	}
	return strings.ToLower(name)
}

func isLowerASCIIRequestHeaderName(name string) bool {
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b >= 'A' && b <= 'Z' {
			return false
		}
		if b >= 0x80 {
			return false
		}
	}
	return true
}

func applyInternalHTTP3RequestMetadata(c *app.RequestContext) {
	if c == nil {
		return
	}
	if raw := c.GetHeader(InternalHTTP3ProtoHeader); len(raw) == 0 || !strings.EqualFold(trimRequestHeaderValue(raw), "h3") {
		clearInternalHTTP3RequestMetadataHeaders(c)
		return
	}
	forwardedProto := trimRequestHeaderValue(c.GetHeader("X-Forwarded-Proto"))
	if !strings.EqualFold(forwardedProto, "h3") || !isLoopbackRemoteAddr(c) {
		clearInternalHTTP3RequestMetadataHeaders(c)
		return
	}

	version := trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSVersionHeader))
	sni := trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSSNIHeader))
	alpn := trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSALPNHeader))
	alpnRaw := parseInternalHTTP3ALPNList(trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSALPNRawHeader)))
	ja3 := trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSJA3Header))
	ja3Hash := trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSJA3HashHeader))
	ja4 := trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSJA4Header))
	cipherSuites := parseInternalHTTP3Uint16List(trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSCipherSuitesHeader)))
	extensions := parseInternalHTTP3Uint16List(trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSExtensionsHeader)))
	curves := parseInternalHTTP3Uint16List(trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSCurvesHeader)))
	pointFormats := parseInternalHTTP3Uint8List(trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSPointFormatsHeader)))

	cancelToken := trimRequestHeaderValue(c.GetHeader(InternalHTTP3CancelTokenHeader))
	if done, ok := takeInternalHTTP3CancelSignal(cancelToken); ok {
		c.Set(InternalHTTP3CancelTokenHeader, done)
	}
	if resetToken := trimRequestHeaderValue(c.GetHeader(InternalHTTP3ResetTokenHeader)); resetToken != "" {
		if reset, ok := takeInternalHTTP3ResetClosure(resetToken); ok {
			c.Set(InternalHTTP3ResetTokenHeader, reset)
		}
	}
	zeroRTT := strings.EqualFold(trimRequestHeaderValue(c.GetHeader(InternalHTTP3ZeroRTTHeader)), "1")
	clearInternalHTTP3RequestMetadataHeaders(c)
	c.Set(internalHTTP3ContextKey, true)
	if zeroRTT {
		c.Set(internalHTTP3ZeroRTTContextKey, true)
	}
	security.MarkTrustedInboundHTTP3(c)

	if version == "" && sni == "" && alpn == "" && len(alpnRaw) == 0 && ja3 == "" && ja3Hash == "" && ja4 == "" &&
		len(cipherSuites) == 0 && len(extensions) == 0 && len(curves) == 0 && len(pointFormats) == 0 {
		return
	}

	fp := tlsfp.TLSClientFingerprint{}
	if version != "" {
		fp.TLSVersion = version
	}
	if sni != "" {
		fp.SNI = sni
	}
	// ALPNRaw 是 ClientHello 声明列表，ALPN 是协商结果；两者都保留。
	fp.ALPNRaw = alpnRaw
	if alpn != "" {
		fp.ALPN = []string{alpn}
	} else if len(alpnRaw) > 0 {
		fp.ALPN = append([]string(nil), alpnRaw...)
	}
	if ja3 != "" {
		fp.JA3 = ja3
	}
	if ja3Hash != "" {
		fp.JA3Hash = ja3Hash
	}
	if ja4 != "" {
		fp.JA4 = ja4
	}
	if len(cipherSuites) > 0 {
		fp.CipherSuites = cipherSuites
	}
	if len(extensions) > 0 {
		fp.Extensions = extensions
	}
	if len(curves) > 0 {
		fp.Curves = curves
	}
	if len(pointFormats) > 0 {
		fp.PointFormats = pointFormats
	}
	c.Set(tlsFingerprintContextKey, fp)
}

/**
 * internalHTTP3HeaderNames 是需要剥离的内部 h3 元数据请求头全集。
 *
 * 与 clearInternalHTTP3RequestMetadataHeaders 的删除顺序无关，只用于「确认存在后
 * 逐个删除」；前缀判定依赖 internalHTTP3HeaderPrefix，新增头必须保持同一前缀。
 */
var internalHTTP3HeaderNames = [...]string{
	InternalHTTP3ProtoHeader,
	InternalHTTP3CancelTokenHeader,
	InternalHTTP3ResetTokenHeader,
	InternalHTTP3TLSVersionHeader,
	InternalHTTP3TLSSNIHeader,
	InternalHTTP3TLSALPNHeader,
	InternalHTTP3TLSALPNRawHeader,
	InternalHTTP3TLSJA3Header,
	InternalHTTP3TLSJA3HashHeader,
	InternalHTTP3TLSJA4Header,
	InternalHTTP3TLSCipherSuitesHeader,
	InternalHTTP3TLSExtensionsHeader,
	InternalHTTP3TLSCurvesHeader,
	InternalHTTP3TLSPointFormatsHeader,
	InternalHTTP3ZeroRTTHeader,
}

// internalHTTP3HeaderPrefix 是上述全部内部头共有的小写前缀。
const internalHTTP3HeaderPrefix = "x-openwaf-internal-"

/**
 * hasInternalHTTP3HeaderPrefix 判断请求头名是否属于内部 h3 元数据命名空间。
 *
 * Hertz 按规范化形式存储头名（仅首字母与连字符后字母大写），因此必须大小写无关；
 * 这里逐字节做 ASCII 折叠，避免 strings.ToLower 在每次判定时分配。
 *
 * @param k 请求头名原始字节。
 * @return 是否命中内部头前缀。
 */
func hasInternalHTTP3HeaderPrefix(k []byte) bool {
	if len(k) < len(internalHTTP3HeaderPrefix) {
		return false
	}
	for i := 0; i < len(internalHTTP3HeaderPrefix); i++ {
		c := k[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != internalHTTP3HeaderPrefix[i] {
			return false
		}
	}
	return true
}

/**
 * clearInternalHTTP3RequestMetadataHeaders 剥离客户端可能伪造的内部 h3 元数据头。
 *
 * 绝大多数请求（HTTP/1.1、HTTP/2 以及不带内部头的 h3 回环请求）没有任何内部头。
 * 旧实现对每个请求固定执行 15 次 Header.Del：每次 Del 都要把 key 转成 []byte 并
 * 规范化，属于纯分配+查找开销，在压测中占数据面约 1.3% CPU。这里先用一次
 * VisitAll 做零分配的前缀扫描，确认不存在即直接返回；只有确实出现内部头时才
 * 逐个删除，语义与旧实现完全一致（函数返回后所有内部头都不存在）。
 *
 * @param c Hertz 请求上下文。
 */
func clearInternalHTTP3RequestMetadataHeaders(c *app.RequestContext) {
	if c == nil {
		return
	}
	hasInternal := false
	c.Request.Header.VisitAll(func(k, _ []byte) {
		if !hasInternal && hasInternalHTTP3HeaderPrefix(k) {
			hasInternal = true
		}
	})
	if !hasInternal {
		return
	}
	for _, name := range internalHTTP3HeaderNames {
		c.Request.Header.Del(name)
	}
}

// isInternalHTTP3ZeroRTT 报告当前请求是否来自 0-RTT（early data）。
//
// 只有在 applyInternalHTTP3RequestMetadata 校验通过（h3 内部头 + 回环来源）后
// 才会写入该标记，因此外部客户端无法通过伪造请求头命中。
func isInternalHTTP3ZeroRTT(c *app.RequestContext) bool {
	if c == nil {
		return false
	}
	v, ok := c.Get(internalHTTP3ZeroRTTContextKey)
	if !ok {
		return false
	}
	flag, _ := v.(bool)
	return flag
}

func trimRequestHeaderValue(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func isLoopbackRemoteAddr(c *app.RequestContext) bool {
	if c == nil {
		return false
	}
	return isLoopbackNetAddr(c.RemoteAddr())
}

func isLoopbackNetAddr(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	switch typed := addr.(type) {
	case *net.TCPAddr:
		if typed != nil && typed.IP != nil {
			return typed.IP.IsLoopback()
		}
	case *net.UDPAddr:
		if typed != nil && typed.IP != nil {
			return typed.IP.IsLoopback()
		}
	case *net.IPAddr:
		if typed != nil && typed.IP != nil {
			return typed.IP.IsLoopback()
		}
	}
	host := addr.String()
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

func parseInternalHTTP3Uint16List(raw string) []uint16 {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	values := make([]uint16, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil
		}
		parsed, err := strconv.ParseUint(part, 10, 16)
		if err != nil {
			return nil
		}
		values = append(values, uint16(parsed))
	}
	return values
}

func parseInternalHTTP3Uint8List(raw string) []uint8 {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	values := make([]uint8, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil
		}
		parsed, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return nil
		}
		values = append(values, uint8(parsed))
	}
	return values
}

/**
 * parseInternalHTTP3ALPNList 解析内部头里的 ALPN 声明列表。
 *
 * 与 parseInternalHTTP3Uint16List 的「任一项非法则整体丢弃」不同：ALPN 是
 * 字符串列表，且属于诊断性元数据，单个损坏项不应让整份声明列表消失。
 * 空项被跳过，全空时返回 nil。
 */
func parseInternalHTTP3ALPNList(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		values = append(values, part)
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

func hasInternalHTTP3Marker(c *app.RequestContext) bool {
	if c == nil {
		return false
	}
	if value, ok := c.Get(internalHTTP3ContextKey); ok {
		if marked, ok := value.(bool); ok && marked {
			return true
		}
	}
	if !isLoopbackRemoteAddr(c) {
		return false
	}
	return strings.EqualFold(trimRequestHeaderValue(c.GetHeader(InternalHTTP3ProtoHeader)), "h3") &&
		strings.EqualFold(trimRequestHeaderValue(c.GetHeader("X-Forwarded-Proto")), "h3")
}

/**
 * TrustedInboundForwardedProto 报告已通过认证的入站协议。
 * HTTP/3 回环元数据只有在 applyInternalHTTP3RequestMetadata 同时校验过标记
 * 与回环对端之后才会被采信。
 */
func TrustedInboundForwardedProto(c *app.RequestContext) string {
	if hasInternalHTTP3Marker(c) {
		return "h3"
	}
	return security.TrustedInboundForwardedProto(c)
}

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

	// requestBodyFormBufferMaxSize 是针对明确长度、未压缩 URL 编码表单的
	// 完整缓冲上限。该路径只用于小型、可复现的表单请求，不改变未知长度、
	// chunked、压缩体、multipart 或普通长流的预读预算。
	requestBodyFormBufferMaxSize = 256 * 1024

	// 压缩请求体的 WAF 采样预算。产出上限直接取 WAF 扫描窗本身：检测最多
	// 看 WAFBodyScanLimit 字节，多解压对检测没有增益。
	requestBodyInspectionDecodeLimit = requestInspectionBodyLimit

	requestBodyInspectionContextKey = "openwaf_request_body_inspection_sample"
)

type requestBodySnapshot struct {
	prefetched    []byte
	fullyBuffered bool
	original      io.Reader
	forward       *prefetchedRequestBodyStream
	size          int64
	hasMore       bool
	readErr       error

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

// shouldFullyBufferFormBody 只允许明确长度、未压缩、HTTP/1.x 的小型 URL 编码表单
// 进入完整缓冲路径。未知长度和长流继续使用有界预读，避免因检查尾部阻塞上传。
func shouldFullyBufferFormBody(c *app.RequestContext, contentLength int) bool {
	if c == nil || contentLength < 0 || contentLength > requestBodyFormBufferMaxSize {
		return false
	}
	if len(bytes.TrimSpace(c.Request.Header.Peek("Content-Length"))) == 0 ||
		len(c.Request.Header.Peek("Transfer-Encoding")) > 0 ||
		len(requestBodyContentEncoding(c)) > 0 {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(string(c.Request.Header.ContentType()))
	if err != nil || !strings.EqualFold(mediaType, "application/x-www-form-urlencoded") {
		return false
	}
	protocol := requestProtocol(c)
	return protocol != "h2" && protocol != "h2c" && protocol != "h3"
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

// headTailBodySample 在固定扫描预算内保留请求体头尾，避免仅取前缀时漏掉尾部载荷。
// 此采样只用于检测；JSON 等结构化解析若因中段缺失失败，会由原始目标兜底扫描。
func headTailBodySample(body []byte, limit int) []byte {
	if limit <= 0 || len(body) <= limit {
		return body
	}
	head := limit / 2
	tail := limit - head - 1
	sample := make([]byte, 0, limit)
	sample = append(sample, body[:head]...)
	sample = append(sample, '\n')
	sample = append(sample, body[len(body)-tail:]...)
	return sample
}

/**
 * requestBodySample 返回送入 WAF 检测的请求体样本。
 *
 * 带 Content-Encoding 的请求送检的是解压后的明文；已缓冲请求在预算内保留
 * 头尾，流式请求仅检查预取前缀以避免阻塞客户端上传。
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
		if snap.fullyBuffered {
			return snap.inspectionBody, false, snap.size
		}
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
	return headTailBodySample(body, requestInspectionBodyLimit), true, size
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

	if shouldFullyBufferFormBody(c, contentLength) {
		buffered := make([]byte, contentLength)
		n, readErr := io.ReadFull(stream, buffered)
		buffered = buffered[:n]
		snap.prefetched = buffered
		snap.original = stream
		snap.size = int64(contentLength)
		snap.readErr = readErr
		if readErr == nil {
			snap.fullyBuffered = true
			snap.inspectionBody = buffered
			snap.forward = &prefetchedRequestBodyStream{reader: bytes.NewReader(buffered)}
		} else {
			snap.hasMore = len(buffered) > requestInspectionBodyLimit
			snap.forward = &prefetchedRequestBodyStream{
				reader: io.MultiReader(bytes.NewReader(buffered), stream),
			}
		}
		c.Request.ConstructBodyStream(nil, snap.forward)
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
