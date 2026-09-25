package dataplane

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/network"
	"github.com/x01n/http2"

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

// upstreamRPCTransportAlias 对齐 upstream.RPCUpstreamAliasForURL 的别名语义，
// 返回 scheme 对应的目标传输；ok 为 false 表示非 RPC 别名 scheme。
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

// registerH2WSInboundStream 把入站扩展 CONNECT 流的端点挂到 hertz 上下文
// 中，供桥接路径使用。由 Handler 在 WAF 分支前调用；非扩展 CONNECT
// 请求上为空操作。
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

// newH2WSHijackWriter 以与 proxy.StreamResponseViaHijack 相同的通道
// （http2.NewResponseWriter)构造 HijackWriter；失败时返回错误。
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

// h2WSFinalizeOnceWriter 把 responseWriter 包成 hertz HijackWriter。
// Finalize 幂等：桥接结束与错误路径都会触发 Finalize，底层 writer
// 重复释放流状态会崩，因此只在首次调用时透传。
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

// bridgeH2ExtendedConnectToWebSocket 把入站扩展 CONNECT 桥接到 ws/wss/http1
// 上游：先在上游以 h1 语义完成 WebSocket 升级握手，再把帧字节双向中继。
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

	// 双向中继；任一方向错误/EOF 后关闭整条桥。handler 在此期间不得
	// 返回（返回即关流，见文件头取证说明）。
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	return h2WSRelay(stream.body, upConn, writer, 32*1024)
}

// h2WSRejectUpstreamHandshake 在握手失败时向入站扩展 CONNECT 返回 502
// 并终结流；此时尚未接管 HijackWriter，使用 hertz 标准响应通道。
func h2WSRejectUpstreamHandshake(c *app.RequestContext, err error) error {
	if c != nil {
		c.SetStatusCode(http.StatusBadGateway)
		c.String(http.StatusBadGateway, "upstream websocket handshake failed")
	}
	return err
}

// forwardH2ExtendedConnectDirect 对 h2c 上游做 RFC 8441 帧层直通：
// 用最小客户端帧流发出 CONNECT（h2_ws_frame.go，prior knowledge），
// 握手成功后把入站流与上游流的净荷双向拷贝。请求头透传执行与
// buildWebSocketHandshakeHeaders 相同的 hop-by-hop/连接管理头剔除。
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
	stop := context.AfterFunc(ctx, func() {
		_ = upStream.Close()
		_ = inStream.Close()
	})
	defer stop()
	return h2WSRelay(inStream.body, upStream, writer, 32*1024)
}

// h2WSRelay 在「入站流」与「上游双工连接」之间双向中继（先到先停）。
// clientRead 是入站请求体；upConn 是上游（TCP 或 h2c 帧流）；clientWrite
// 是入站响应通道。上游方向 EOF 后终结入站流，入站方向 EOF 后由上游
// CloseWrite（若支持）半关。
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

// upstreamConnectionHeaderStripper 与 proxy.NewRequestConnectionHeaderStripper
// 语义一致：把 Connection 头中列出的 token 全部视为逐跳头予以剔除。
type upstreamConnectionHeaderStripper struct {
	tokens map[string]struct{}
}

// newUpstreamConnectionHeaderStripper 构造连接头剔除器：把 Connection 头
// 中列出的 token 全部视为逐跳头，与 proxy.NewRequestConnectionHeaderStripper
// 语义一致（本包不依赖 proxy 内部实现，独立复刻最小闭包）。
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

// h2DirectUpstreamTarget 从 h2c base 与入站 path/query 算出上游拨号地址
// 与 CONNECT 请求的绝对 URL（http://authority/path）。
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

// readHTTPResponseHeadLimited 从上游读 h1 响应状态行与头部（带显式大小
// 上限）；状态非 101 时返回错误。与 readHTTPResponseHead 语义一致。
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

// 与 h2_ws_frame.go 共享的协议头常量：":protocol" 的字面值在
// h2ProtoHeaderValue（websocket.go）与 h2c 帧流（h2_ws_frame.go）中使用。
const h2WSProtocolHeaderName = ":protocol"

var _ bytes.Buffer
