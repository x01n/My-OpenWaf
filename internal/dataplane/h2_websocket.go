package dataplane

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/network"
	"github.com/x01n/http2"
	"github.com/x01n/http2/hpack"

	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/snapshot"
)

const h2WSBridgeMaxUpgradeResponseHeaderSize = 1 << 20

const h2WSDirectUpstreamHandshakeTimeout = 5 * time.Second

const h2WSInboundStreamContextKey = "dataplane_h2_extended_connect_stream"

func IsH2WebSocketDirectUpstream(base string) bool {
	lower := strings.ToLower(strings.TrimSpace(base))
	if strings.HasPrefix(lower, "h2c://") {
		return true
	}
	transport, ok := upstreamRPCTransportAlias(base)
	return ok && transport == "h2c"
}

/**
 * upstreamRPCTransportAlias 对齐 upstream.RPCUpstreamAliasForURL 的别名语义，
 * 返回 scheme 对应的目标传输；ok 为 false 表示非 RPC 别名 scheme。
 */
func upstreamRPCTransportAlias(base string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(base))
	sep := strings.Index(lower, "://")
	if sep <= 0 {
		return "", false
	}
	switch lower[:sep+3] {
	case "tls://", "grpcs://", "grpc+tls://", "grpc+https://":
		return "https", true
	case "grpc://":
		return "h2c", true
	default:
		return lower[:sep], false
	}
}

func ForwardH2ExtendedConnectWebSocket(ctx context.Context, reqID string, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, eng *engine.Engine) error {
	if c == nil {
		return errors.New("extended CONNECT bridge requires a request context")
	}
	if IsH2WebSocketDirectUpstream(base) {
		return forwardH2ExtendedConnectDirect(ctx, c, rt, base)
	}
	return bridgeH2ExtendedConnectToWebSocket(ctx, reqID, c, rt, base, clientIP, eng)
}

type h2cInboundStream struct {
	body   io.Reader
	closer func() error
}

// Read 读入站 DATA 帧净荷；请求侧 END_STREAM 后返回 io.EOF。
func (s *h2cInboundStream) Read(p []byte) (int, error) { return s.body.Read(p) }

// Close 关闭入站请求体（幂等）。
func (s *h2cInboundStream) Close() error { return s.closer() }

/**
 * registerH2WSInboundStream 把入站扩展 CONNECT 流的端点挂到 hertz 上下文
 * 中，供桥接路径使用。由 Handler 在 WAF 分支前调用；非扩展 CONNECT
 * 请求上为空操作。
 */
func registerH2WSInboundStream(c *app.RequestContext) {
	if c == nil || !IsH2ExtendedWebSocketConnect(c) {
		return
	}
	if _, ok := c.Get(h2WSInboundStreamContextKey); ok {
		return
	}
	stream := c.Request.BodyStream()
	if stream == nil {
		return
	}
	closer := func() error {
		if rc, ok := stream.(io.ReadCloser); ok {
			return rc.Close()
		}
		return nil
	}
	c.Set(h2WSInboundStreamContextKey, &h2cInboundStream{body: stream, closer: closer})
}

// acquireH2InboundStream 从 hertz 上下文中取入站扩展 CONNECT 流端点。
func acquireH2InboundStream(c *app.RequestContext) (*h2cInboundStream, error) {
	if c == nil {
		return nil, errors.New("extended CONNECT bridge requires a request context")
	}
	value, ok := c.Get(h2WSInboundStreamContextKey)
	if !ok {
		return nil, errors.New("extended CONNECT stream is not registered")
	}
	stream, ok := value.(*h2cInboundStream)
	if !ok || stream == nil {
		return nil, errors.New("extended CONNECT stream registration is invalid")
	}
	return stream, nil
}

/**
 * newH2WSHijackWriter 以与 proxy.StreamResponseViaHijack 相同的通道
 * （http2.NewResponseWriter)构造 HijackWriter；失败时返回错误。
 */
func newH2WSHijackWriter(c *app.RequestContext) (network.ExtWriter, error) {
	if c == nil || c.GetConn() == nil {
		return nil, errors.New("extended CONNECT bridge requires a connection")
	}
	writer, err := http2.NewResponseWriter(c.GetConn())
	if err != nil {
		return nil, fmt.Errorf("extended CONNECT response writer: %w", err)
	}
	return &h2WSFinalizeOnceWriter{inner: writer}, nil
}

/**
 * h2WSFinalizeOnceWriter 把 responseWriter 包成 hertz HijackWriter。
 * Finalize 幂等：桥接结束与错误路径都会触发 Finalize，底层 writer
 * 重复释放流状态会崩，因此只在首次调用时透传。
 */
type h2WSFinalizeOnceWriter struct {
	inner network.ExtWriter
	once  sync.Once
	err   error
}

// Write 把帧净荷写入底层响应流。
func (w *h2WSFinalizeOnceWriter) Write(p []byte) (int, error) { return w.inner.Write(p) }

// Flush 立即刷出响应通道。
func (w *h2WSFinalizeOnceWriter) Flush() error { return w.inner.Flush() }

// Finalize 幂等终结底层响应流。
func (w *h2WSFinalizeOnceWriter) Finalize() error {
	w.once.Do(func() { w.err = w.inner.Finalize() })
	return w.err
}

/**
 * bridgeH2ExtendedConnectToWebSocket 把入站扩展 CONNECT 桥接到 ws/wss/http1
 * 上游：先在上游以 h1 语义完成 WebSocket 升级握手，再把帧字节双向中继。
 */
func bridgeH2ExtendedConnectToWebSocket(ctx context.Context, reqID string, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, eng *engine.Engine) error {
	stream, err := acquireH2InboundStream(c)
	if err != nil {
		return err
	}

	// 与 ForwardWebSocket 相同的 target 语义：base + path + query。
	target := strings.TrimRight(base, "/") + string(c.Path())
	if q := c.URI().QueryString(); len(q) > 0 {
		target += "?" + string(q)
	}
	target = normalizeWebSocketUpstreamTarget(target)

	// 上游 h1 WebSocket 握手必须是 GET（RFC 6455 §4.1）；入站扩展 CONNECT
	// 的 CONNECT 方法只在本端 h2 语义中成立。局部改写方法并恢复，
	// 不触碰 buildWebSocketHandshakeHeaders 的共享签名。
	origMethod := string(c.Method())
	if origMethod != http.MethodGet {
		c.Request.SetMethod(http.MethodGet)
		defer c.Request.SetMethod(origMethod)
	}

	upConn, err := h2WSDialUpstream(target, rt)
	if err != nil {
		stream.Close()
		return err
	}
	defer upConn.Close()

	upProto := strings.ToLower(strings.SplitN(target, "://", 2)[0])
	hdr, err := buildWebSocketHandshakeHeaders(c, pathAndQuery(target), hostFromURL(target), upProto, rt, clientIP)
	if err != nil {
		stream.Close()
		return err
	}
	if _, err := io.WriteString(upConn, hdr); err != nil {
		stream.Close()
		return err
	}

	upReader := bufio.NewReaderSize(upConn, 4096)
	statusLine, respHeaders, err := readHTTPResponseHeadLimited(upReader, h2WSBridgeMaxUpgradeResponseHeaderSize)
	if err != nil {
		return h2WSRejectUpstreamHandshake(c, err)
	}
	if code := httpStatusCodeFromLine(statusLine); code != http.StatusSwitchingProtocols {
		return h2WSRejectUpstreamHandshake(c, fmt.Errorf("upstream websocket handshake status %d", code))
	}
	respHeaders, err = sanitizeWebSocketUpgradeResponseHeaders(respHeaders)
	if err != nil {
		return h2WSRejectUpstreamHandshake(c, err)
	}

	// 扩展 CONNECT 成功语义为 200；WS 协商头按上游 101 语义透传给客户端，
	// h2 响应中不出现 Connection/Upgrade（已被净化）。
	c.Response.Header.Set("Sec-WebSocket-Accept", httpHeaderFromRaw(respHeaders, "Sec-WebSocket-Accept"))
	if v := httpHeaderFromRaw(respHeaders, "Sec-WebSocket-Protocol"); v != "" {
		c.Response.Header.Set("Sec-WebSocket-Protocol", v)
	}
	if v := httpHeaderFromRaw(respHeaders, "Sec-WebSocket-Extensions"); v != "" {
		c.Response.Header.Set("Sec-WebSocket-Extensions", v)
	}
	c.SetStatusCode(http.StatusOK)

	writer, err := newH2WSHijackWriter(c)
	if err != nil {
		stream.Close()
		return err
	}
	c.Response.HijackWriter(writer)
	if _, err := c.Write(nil); err != nil {
		stream.Close()
		return err
	}
	if err := c.Flush(); err != nil {
		stream.Close()
		return err
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		ping := []byte{0x89, 0x80, 0x00, 0x00, 0x00, 0x00}
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := upConn.Write(ping); err != nil {
					return
				}
			}
		}
	}()

	// 双向中继；任一方向错误/EOF 后关闭整条桥。handler 在此期间不得
	// 返回（返回即关流，见文件头取证说明）。
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	return h2WSRelay(stream.body, upConn, writer, 32*1024)
}

func h2WSRejectUpstreamHandshake(c *app.RequestContext, err error) error {
	if c != nil {
		c.SetStatusCode(http.StatusBadGateway)
		c.String(http.StatusBadGateway, "upstream websocket handshake failed")
	}
	return err
}

/**
 * forwardH2ExtendedConnectDirect 对 h2c 上游做 RFC 8441 帧层直通：
 * 用最小客户端帧流发出 CONNECT（h2_ws_frame.go，prior knowledge），
 * 握手成功后把入站流与上游流的净荷双向拷贝。请求头透传执行与
 * buildWebSocketHandshakeHeaders 相同的 hop-by-hop/连接管理头剔除。
 */
func forwardH2ExtendedConnectDirect(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string) error {
	inStream, err := acquireH2InboundStream(c)
	if err != nil {
		return err
	}

	path := string(c.Path())
	query := string(c.URI().QueryString())
	dialHost, target, err := h2DirectUpstreamTarget(base, path, query)
	if err != nil {
		inStream.Close()
		return err
	}

	var passHeaders [][2]string
	stripper := newUpstreamConnectionHeaderStripper(c)
	c.Request.Header.VisitAll(func(k, v []byte) {
		key := strings.ToLower(string(k))
		switch key {
		case "host", "connection", "keep-alive", "proxy-connection", "te", "trailer",
			"transfer-encoding", "forwarded", "x-forwarded-for", "x-forwarded-host",
			"x-forwarded-proto", "content-length", "upgrade", h2WSProtocolHeaderName:
			return
		}
		if stripper.ShouldStrip(k) {
			return
		}
		passHeaders = append(passHeaders, [2]string{string(k), string(v)})
	})

	upStream, err := dialH2CExtendedConnect(ctx, dialHost, target, h2ProtoHeaderValue(c), passHeaders)
	if err != nil {
		inStream.Close()
		return err
	}
	defer upStream.Close()

	select {
	case <-upStream.HandshakeDone():
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(h2WSDirectUpstreamHandshakeTimeout):
		return errors.New("extended CONNECT direct handshake timed out")
	}
	if upStream.ResponseStatus() != http.StatusOK {
		c.SetStatusCode(http.StatusBadGateway)
		c.String(http.StatusBadGateway, "upstream extended CONNECT rejected")
		return nil
	}

	writer, err := newH2WSHijackWriter(c)
	if err != nil {
		return err
	}
	c.Response.HijackWriter(writer)
	c.SetStatusCode(http.StatusOK)
	if _, err := c.Write(nil); err != nil {
		return err
	}
	if err := c.Flush(); err != nil {
		return err
	}
	// h2c 直通无 h1 握手中继（帧层 raw），入站 WS 帧（含 ping/pong）
	// 由 h2WSRelay 原始转发；空档保活在 QUIC/h2 层协商处理，这里不加
	// 应用层 ping 以免污染 h2c 帧流语义。
	stop := context.AfterFunc(ctx, func() {
		_ = upStream.Close()
		_ = inStream.Close()
	})
	defer stop()
	return h2WSRelay(inStream.body, upStream, writer, 32*1024)
}

/**
 * h2WSRelay 在「入站流」与「上游双工连接」之间双向中继（先到先停）。
 * clientRead 是入站请求体；upConn 是上游（TCP 或 h2c 帧流）；clientWrite
 * 是入站响应通道。上游方向 EOF 后终结入站流，入站方向 EOF 后由上游
 * CloseWrite（若支持）半关。
 */
func h2WSRelay(clientRead io.Reader, upConn io.ReadWriteCloser, clientWrite io.Writer, bufSize int) error {
	if bufSize <= 0 {
		bufSize = 32 * 1024
	}
	done := make(chan error, 2)
	// 入站 -> 上游。
	go func() {
		buf := make([]byte, bufSize)
		for {
			n, rerr := clientRead.Read(buf)
			if n > 0 {
				if _, werr := upConn.Write(buf[:n]); werr != nil {
					done <- werr
					return
				}
			}
			if rerr != nil {
				if !errors.Is(rerr, io.EOF) {
					done <- rerr
					return
				}
				if closer, ok := upConn.(interface{ CloseWrite() error }); ok {
					done <- closer.CloseWrite()
				} else {
					done <- nil
				}
				return
			}
		}
	}()
	// 上游 -> 入站。
	go func() {
		buf := make([]byte, bufSize)
		for {
			n, rerr := upConn.Read(buf)
			if n > 0 {
				if _, werr := clientWrite.Write(buf[:n]); werr != nil {
					done <- werr
					return
				}
			}
			if rerr != nil {
				if errors.Is(rerr, io.EOF) {
					done <- nil
				} else {
					done <- rerr
				}
				return
			}
		}
	}()
	first := <-done
	_ = upConn.Close()
	<-done
	return first
}

/**
 * upstreamConnectionHeaderStripper 与 proxy.NewRequestConnectionHeaderStripper
 * 语义一致：把 Connection 头中列出的 token 全部视为逐跳头予以剔除。
 */
type upstreamConnectionHeaderStripper struct {
	tokens map[string]struct{}
}

/**
 * newUpstreamConnectionHeaderStripper 构造连接头剔除器：把 Connection 头
 * 中列出的 token 全部视为逐跳头，与 proxy.NewRequestConnectionHeaderStripper
 * 语义一致（本包不依赖 proxy 内部实现，独立复刻最小闭包）。
 */
func newUpstreamConnectionHeaderStripper(c *app.RequestContext) *upstreamConnectionHeaderStripper {
	s := &upstreamConnectionHeaderStripper{tokens: make(map[string]struct{}, 4)}
	if v := string(c.GetHeader("Connection")); v != "" {
		for token := range strings.SplitSeq(v, ",") {
			s.tokens[strings.ToLower(strings.TrimSpace(token))] = struct{}{}
		}
	}
	return s
}

// ShouldStrip 报告头是否出现在 Connection 头 token 列表中。
func (s *upstreamConnectionHeaderStripper) ShouldStrip(name []byte) bool {
	if s == nil || len(s.tokens) == 0 {
		return false
	}
	_, ok := s.tokens[strings.ToLower(string(name))]
	return ok
}

/**
 * h2DirectUpstreamTarget 从 h2c base 与入站 path/query 算出上游拨号地址
 * 与 CONNECT 请求的绝对 URL（http://authority/path）。
 */
func h2DirectUpstreamTarget(base string, path string, query string) (string, string, error) {
	idx := strings.Index(base, "://")
	if idx < 0 {
		return "", "", errors.New("h2c upstream is missing scheme")
	}
	rest := base[idx+3:]
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "", "", errors.New("h2c upstream is missing host")
	}
	host := rest
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if query != "" && !strings.HasPrefix(query, "?") {
		query = "?" + query
	}
	target := "http://" + host + path + query
	return host, target, nil
}

// httpHeaderFromRaw 在原始 h1 头部行文本中查找指定头（case-insensitive）。
func httpHeaderFromRaw(raw string, name string) string {
	lowerName := strings.ToLower(name)
	for _, line := range strings.Split(raw, "\r\n") {
		k, v, ok := splitHTTPHeaderLine(strings.TrimRight(line, "\r"))
		if ok && strings.ToLower(k) == lowerName {
			return v
		}
	}
	return ""
}

/**
 * readHTTPResponseHeadLimited 从上游读 h1 响应状态行与头部（带显式大小
 * 上限）；状态非 101 时返回错误。与 readHTTPResponseHead 语义一致。
 */
func readHTTPResponseHeadLimited(r *bufio.Reader, limit int) (string, string, error) {
	statusLine, err := readHTTPResponseLineLimited(r, limit)
	if err != nil {
		return "", "", err
	}
	if statusCode := httpStatusCodeFromLine(statusLine); statusCode != http.StatusSwitchingProtocols {
		return "", "", fmt.Errorf("websocket upstream handshake failed with status %d", statusCode)
	}
	remaining := limit - len(statusLine)
	var headers strings.Builder
	for {
		line, err := readHTTPResponseLineLimited(r, remaining)
		if err != nil {
			return "", "", err
		}
		remaining -= len(line)
		headers.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	return statusLine, headers.String(), nil
}

// h2WSDialUpstream 按 target 拨号上游 TCP/TLS（h1 握手桥路径）。
func h2WSDialUpstream(target string, rt snapshot.SiteRuntime) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	host := hostFromURL(target)
	if strings.HasPrefix(strings.ToLower(target), "wss://") {
		return tlsDialWebSocketUpstream(&dialer, host, rt)
	}
	return dialer.Dial("tcp", host)
}

/**
 * 与 h2_ws_frame.go 共享的协议头常量：":protocol" 的字面值在
 * h2ProtoHeaderValue（websocket.go）与 h2c 帧流（h2_ws_frame.go）中使用。
 */
const h2WSProtocolHeaderName = ":protocol"

var _ bytes.Buffer

// h2c 帧类型（RFC 9113）。
const (
	h2FrameData         = 0x0
	h2FrameHeaders      = 0x1
	h2FrameRSTStream    = 0x3
	h2FrameSettings     = 0x4
	h2FramePing         = 0x6
	h2FrameGoAway       = 0x7
	h2FrameWindowUpdate = 0x8
	h2FrameContinuation = 0x9

	h2FlagAck        = 0x1
	h2FlagEndStream  = 0x1
	h2FlagEndHeaders = 0x4
)

const (
	// h2cUpstreamInitialWindow 是发送侧窗口初始值（RFC 9113 默认 64KB）。
	// h2cUpstreamRecvWindow / h2cUpstreamRecvRefill 控制接收侧窗口返还节奏。
	h2cUpstreamInitialWindow = 1 << 16
	h2cUpstreamRecvWindow    = 1 << 30
	h2cUpstreamRecvRefill    = 1 << 20
)

/**
 * h2cExtConnectStream 是到 h2c 上游一条扩展 CONNECT 流的全双工通道。
 *
 * readLoop 单协程解析上游帧并维护状态；Write 用 mutex 序列化并受上游
 * 窗口约束。首响应头到达前 Write 阻塞（此时 DATA 不能被对端受理）。
 */
type h2cExtConnectStream struct {
	conn net.Conn
	br   *bufio.Reader

	target   string      // CONNECT 请求绝对 URL（http://authority/path）
	protocol string      // ":protocol" 值
	headers  [][2]string // 透传常规头（已净化）
	host     string      // ":authority"

	mu            sync.Mutex
	maxFrameSize  uint32 // 对端 MAX_FRAME_SIZE（发送约束）
	initWinConn   int64  // 对端连接窗口剩余
	initWinStream int64  // 对端流窗口剩余
	respStatus    int    // 首响应 :status；收到前为 -1

	handshakeOnce sync.Once
	handshakeDone chan struct{}

	closeOnce sync.Once
	closed    chan struct{}

	writeOnce sync.Once
	writeDone chan struct{}

	dataCh  chan []byte
	readErr error

	// 接收侧窗口簿记。
	recvMu   sync.Mutex
	recvConn int64
	recvStrm int64

	// 响应头解码状态（CONTINUATION 拼接）。
	hdrMu       sync.Mutex
	hdrFragment bytes.Buffer
	hdrStarted  bool
}

/**
 * dialH2CExtendedConnect 拨号到 h2c 上游（prior knowledge）并发出扩展
 * CONNECT 请求头。握手结果经 HandshakeDone/ResponseStatus 暴露；写入
 * 在响应头到达前阻塞。
 */
func dialH2CExtendedConnect(ctx context.Context, dialAddr string, target string, protocol string, passHeaders [][2]string) (*h2cExtConnectStream, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		return nil, err
	}

	s := &h2cExtConnectStream{
		conn:          conn,
		br:            bufio.NewReaderSize(conn, 8<<10),
		target:        target,
		protocol:      protocol,
		headers:       passHeaders,
		host:          hostFromURL(target),
		initWinConn:   h2cUpstreamInitialWindow,
		initWinStream: h2cUpstreamInitialWindow,
		respStatus:    -1,
		handshakeDone: make(chan struct{}),
		closed:        make(chan struct{}),
		writeDone:     make(chan struct{}),
		dataCh:        make(chan []byte, 8),
		recvConn:      h2cUpstreamRecvWindow,
		recvStrm:      h2cUpstreamRecvWindow,
	}
	if err := s.sendPrefaceAndHeaders(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	go s.readLoop(ctx)
	return s, nil
}

// HandshakeDone 在首个响应 HEADERS 到达（或流失败）时关闭。
func (s *h2cExtConnectStream) HandshakeDone() <-chan struct{} { return s.handshakeDone }

// ResponseStatus 返回首响应状态码；未收到响应头时为 -1。
func (s *h2cExtConnectStream) ResponseStatus() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.respStatus
}

// Read 从上游 DATA 净荷读取；上游 END_STREAM 后返回 io.EOF。
func (s *h2cExtConnectStream) Read(p []byte) (int, error) {
	for {
		select {
		case <-s.closed:
			return 0, s.currentErr()
		case data, ok := <-s.dataCh:
			if !ok {
				return 0, io.EOF
			}
			n := copy(p, data)
			if n < len(data) {
				select {
				case s.dataCh <- data[n:]:
				case <-s.closed:
				}
			}
			if n == 0 {
				continue
			}
			return n, nil
		}
	}
}

/**
 * Write 发送 DATA 帧净荷；在首响应头与 SETTINGS 到达前阻塞，随后受
 * 上游窗口约束。引用语义与 net.Conn 相同。
 */
func (s *h2cExtConnectStream) Write(p []byte) (int, error) {
	select {
	case <-s.closed:
		return 0, s.currentErr()
	case <-s.handshakeDone:
	}
	written := 0
	for len(p) > 0 {
		s.mu.Lock()
		limit := s.initWinStream
		if s.initWinConn < limit {
			limit = s.initWinConn
		}
		if mf := int64(s.maxFrameSize); mf > 0 && mf < limit {
			limit = mf
		}
		if limit <= 0 {
			s.mu.Unlock()
			select {
			case <-s.closed:
				return written, s.currentErr()
			case <-s.writeDone:
				return written, nil
			case <-time.After(25 * time.Millisecond):
			}
			continue
		}
		n := int(limit)
		if n > len(p) {
			n = len(p)
		}
		frame := make([]byte, 9+n)
		frame[0] = byte(n >> 16)
		frame[1] = byte(n >> 8)
		frame[2] = byte(n)
		frame[3] = h2FrameData
		binary.BigEndian.PutUint32(frame[5:9], 1) // 客户端流的 ID 为 1
		copy(frame[9:], p[:n])
		s.initWinConn -= int64(n)
		s.initWinStream -= int64(n)
		s.mu.Unlock()

		if _, err := s.conn.Write(frame); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// CloseWrite 发送 END_STREAM 空 DATA 半关写方向（幂等）。
func (s *h2cExtConnectStream) CloseWrite() error {
	s.writeOnce.Do(func() {
		close(s.writeDone)
		frame := make([]byte, 9)
		frame[3] = h2FrameData
		frame[4] = h2FlagEndStream
		binary.BigEndian.PutUint32(frame[5:9], 1)
		_, _ = s.conn.Write(frame)
	})
	return nil
}

// Close 关闭整条连接（幂等），唤醒所有等待方。
func (s *h2cExtConnectStream) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		_ = s.conn.Close()
	})
	return nil
}

func (s *h2cExtConnectStream) currentErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return s.readErr
	}
	return io.EOF
}

func (s *h2cExtConnectStream) signalHandshake() {
	s.handshakeOnce.Do(func() { close(s.handshakeDone) })
}

// sendPrefaceAndHeaders 写连接前缀、空 SETTINGS 与扩展 CONNECT HEADERS。
func (s *h2cExtConnectStream) sendPrefaceAndHeaders() error {
	var buf bytes.Buffer
	buf.WriteString("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	writeH2RawFrame(&buf, h2FrameSettings, 0, 0, nil)

	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	fields := [][2]string{
		{":method", "CONNECT"},
		{":protocol", s.protocol},
		{":scheme", "http"},
		{":authority", s.host},
		{":path", pathAndQuery(s.target)},
	}
	fields = append(fields, s.headers...)
	for _, f := range fields {
		_ = enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	// 扩展 CONNECT 请求流必须保持打开（RFC 8441 §4）：HEADERS 帧不设置
	// END_STREAM，DATA 双工在握手期间持续可用。
	writeH2RawFrame(&buf, h2FrameHeaders, h2FlagEndHeaders, 1, hb.Bytes())

	_, err := s.conn.Write(buf.Bytes())
	return err
}

// readLoop 串行解析上游帧直至错误或流终态。
func (s *h2cExtConnectStream) readLoop(ctx context.Context) {
	done := ctx.Done()
	defer s.signalHandshake()
	header := make([]byte, 9)
	for {
		if done != nil {
			select {
			case <-done:
				s.fail(fmt.Errorf("upstream context closed: %w", ctx.Err()))
				return
			default:
			}
		}
		if _, err := io.ReadFull(s.br, header); err != nil {
			s.fail(errors.Join(io.EOF, fmt.Errorf("read upstream frame: %w", err)))
			return
		}
		length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
		ftype := header[3]
		flags := header[4]
		streamID := binary.BigEndian.Uint32(header[5:9]) & 0x7fffffff

		if err := s.handleFrame(ftype, flags, streamID, length); err != nil {
			s.fail(err)
			return
		}
		if ftype == h2FrameData && flags&h2FlagEndStream != 0 && streamID == 1 {
			// 上游半关：读侧终结，写侧保持可用直至桥关闭。
			s.setReadErr(io.EOF)
			close(s.dataCh)
			return
		}
	}
}

// handleFrame 读净荷并分派；返回致命错误。帧头已消费。
func (s *h2cExtConnectStream) handleFrame(ftype uint8, flags uint8, streamID uint32, length int) error {
	switch ftype {
	case h2FrameSettings:
		payload, err := readH2Payload(s.br, length, 4096)
		if err != nil {
			return err
		}
		if flags&h2FlagAck != 0 {
			return nil
		}
		s.applySettings(payload)
		writeH2RawFrame(s.conn, h2FrameSettings, h2FlagAck, 0, nil)
		return nil
	case h2FrameHeaders, h2FrameContinuation:
		payload, err := readH2Payload(s.br, length, h2WSBridgeMaxUpgradeResponseHeaderSize)
		if err != nil {
			return err
		}
		if ftype == h2FrameContinuation && !s.hdrStarted {
			return errors.New("unexpected CONTINUATION frame")
		}
		s.hdrStarted = true
		s.hdrFragment.Write(payload)
		if flags&h2FlagEndHeaders == 0 {
			return nil
		}
		defer func() {
			s.hdrFragment.Reset()
			s.hdrStarted = false
		}()
		s.parseResponseHeaders(s.hdrFragment.Bytes())
		if flags&h2FlagEndStream != 0 {
			// 上游在响应头就关闭了流：握手即终态。
			return errors.New("upstream closed extended CONNECT at response headers")
		}
		s.signalHandshake()
		return nil
	case h2FrameData:
		payload, err := readH2Payload(s.br, length, h2cUpstreamRecvRefill)
		if err != nil {
			return err
		}
		if streamID == 1 && len(payload) > 0 {
			select {
			case s.dataCh <- payload:
			case <-s.closed:
				return io.EOF
			}
		}
		s.recvMu.Lock()
		s.recvStrm -= int64(length)
		s.recvConn -= int64(length)
		stLow := s.recvStrm < h2cUpstreamRecvRefill
		cnLow := s.recvConn < h2cUpstreamRecvRefill
		s.recvMu.Unlock()
		if stLow || cnLow {
			if err := s.refundRecvWindow(streamID); err != nil {
				return err
			}
		}
		return nil
	case h2FrameWindowUpdate:
		if length != 4 {
			return errors.New("malformed WINDOW_UPDATE frame")
		}
		var inc [4]byte
		if _, err := io.ReadFull(s.br, inc[:]); err != nil {
			return err
		}
		v := int64(binary.BigEndian.Uint32(inc[:]) & 0x7fffffff)
		s.mu.Lock()
		if streamID == 0 {
			s.initWinConn += v
		} else if streamID == 1 {
			s.initWinStream += v
		}
		s.mu.Unlock()
		return nil
	case h2FramePing:
		payload, err := readH2Payload(s.br, length, 8)
		if err != nil {
			return err
		}
		if flags&h2FlagAck != 0 {
			return nil
		}
		if length != 8 {
			return errors.New("malformed PING frame")
		}
		ack := prependH2FrameHeader(h2FramePing, h2FlagAck, 0, payload)
		if _, err = s.conn.Write(ack); err != nil {
			return err
		}
		return nil
	case h2FrameGoAway:
		if err := discardRead(s.br, length); err != nil {
			return err
		}
		return errors.New("upstream sent GOAWAY")
	case h2FrameRSTStream:
		if err := discardRead(s.br, length); err != nil {
			return err
		}
		return errors.New("upstream reset stream")
	default:
		return discardRead(s.br, length)
	}
}

// parseResponseHeaders 解码首响应头块；:status 记入 respStatus。
func (s *h2cExtConnectStream) parseResponseHeaders(block []byte) {
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if f.Name == ":status" {
			code, err := strconv.Atoi(f.Value)
			if err == nil {
				s.mu.Lock()
				s.respStatus = code
				s.mu.Unlock()
			}
		}
	})
	if _, err := dec.Write(block); err != nil {
		s.setReadErr(fmt.Errorf("decode upstream response headers: %w", err))
	}
}

// applySettings 应用上游 SETTINGS 中的窗口类参数。
func (s *h2cExtConnectStream) applySettings(payload []byte) {
	if len(payload)%6 != 0 {
		s.setReadErr(errors.New("malformed SETTINGS frame from upstream"))
		return
	}
	for i := 0; i+6 <= len(payload); i += 6 {
		id := binary.BigEndian.Uint16(payload[i : i+2])
		val := binary.BigEndian.Uint32(payload[i+2 : i+6])
		s.mu.Lock()
		switch id {
		case 0x4: // SETTINGS_INITIAL_WINDOW_SIZE
			s.initWinStream = int64(val)
		case 0x5: // SETTINGS_MAX_FRAME_SIZE
			if val >= 16384 {
				s.maxFrameSize = val
			}
		}
		s.mu.Unlock()
	}
}

// refundRecvWindow 向对端返还连接级与流级 WINDOW_UPDATE 额度。
func (s *h2cExtConnectStream) refundRecvWindow(streamID uint32) error {
	s.recvMu.Lock()
	inc := int64(h2cUpstreamRecvRefill)
	if deficit := h2cUpstreamRecvWindow - s.recvConn; deficit < inc {
		inc = deficit
	}
	if deficit := h2cUpstreamRecvWindow - s.recvStrm; deficit < inc {
		inc = deficit
	}
	if inc <= 0 {
		s.recvMu.Unlock()
		return nil
	}
	s.recvConn += inc
	s.recvStrm += inc
	s.recvMu.Unlock()

	var incBytes [4]byte
	binary.BigEndian.PutUint32(incBytes[:], uint32(inc))
	connFrame := prependH2FrameHeader(h2FrameWindowUpdate, 0, 0, incBytes[:])
	strmFrame := prependH2FrameHeader(h2FrameWindowUpdate, 0, streamID, incBytes[:])
	var buf bytes.Buffer
	buf.Write(connFrame)
	buf.Write(strmFrame)
	_, err := s.conn.Write(buf.Bytes())
	return err
}

func (s *h2cExtConnectStream) setReadErr(err error) {
	s.mu.Lock()
	if s.readErr == nil {
		s.readErr = err
	}
	s.mu.Unlock()
}

func (s *h2cExtConnectStream) fail(err error) {
	if err == nil {
		err = io.EOF
	}
	s.setReadErr(err)
	s.signalHandshake()
	s.Close()
}

// readH2Payload 读 length 字节净荷，超过 cap 视为畸形帧。
func readH2Payload(r *bufio.Reader, length int, capLimit int) ([]byte, error) {
	if length > capLimit {
		return nil, fmt.Errorf("h2 frame payload too large: %d", length)
	}
	p := make([]byte, length)
	if length == 0 {
		return p, nil
	}
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	return p, nil
}

func discardRead(r *bufio.Reader, length int) error {
	if length == 0 {
		return nil
	}
	_, err := r.Discard(length)
	return err
}

// prependH2FrameHeader 组出「帧头 + 净荷」的完整帧字节。
func prependH2FrameHeader(ftype uint8, flags uint8, streamID uint32, payload []byte) []byte {
	frame := make([]byte, 9+len(payload))
	n := len(payload)
	frame[0] = byte(n >> 16)
	frame[1] = byte(n >> 8)
	frame[2] = byte(n)
	frame[3] = ftype
	frame[4] = flags
	binary.BigEndian.PutUint32(frame[5:9], streamID)
	copy(frame[9:], payload)
	return frame
}

func writeH2RawFrame(w io.Writer, ftype uint8, flags uint8, streamID uint32, payload []byte) {
	frame := prependH2FrameHeader(ftype, flags, streamID, payload)
	_, _ = w.Write(frame)
}
