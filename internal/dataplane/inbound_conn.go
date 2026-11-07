package dataplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudwego/gopkg/net/connstate"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	"github.com/cloudwego/hertz/pkg/network"
	forkhttp2 "github.com/x01n/http2"

	dpstream "My-OpenWaf/internal/dataplane/stream"
	dptlsfp "My-OpenWaf/internal/dataplane/tlsfp"
	"My-OpenWaf/internal/waf/bot/tlsfp"
	"My-OpenWaf/internal/waf/drop"
)

type FixURIConn struct {
	net.Conn
	checked     bool
	prefix      []byte
	fingerprint tlsfp.TLSClientFingerprint
}

func NewFixURIConn(conn net.Conn) net.Conn {
	return &FixURIConn{Conn: conn}
}

func (c *FixURIConn) NetConn() net.Conn {
	return c.Conn
}

func (c *FixURIConn) Handshake() error {
	if tlsConn, ok := c.Conn.(interface{ Handshake() error }); ok {
		return tlsConn.Handshake()
	}
	return nil
}

func (c *FixURIConn) ConnectionState() tls.ConnectionState {
	if tlsConn, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return tlsConn.ConnectionState()
	}
	return tls.ConnectionState{}
}

func (c *FixURIConn) TLSFingerprint() (tlsfp.TLSClientFingerprint, bool) {
	if fp, ok := tlsfp.TLSFingerprintFromConn(c.Conn); ok {
		return fp, true
	}
	return c.fingerprint, c.fingerprint.HasValue()
}

func (c *FixURIConn) SetTLSHandshakeInfo(version string, sni string, alpn string) {
	if version != "" {
		c.fingerprint.TLSVersion = version
	}
	if sni != "" {
		c.fingerprint.SNI = sni
	}
	// 只写协商结果（ALPN）；ALPNRaw 是 ClientHello 声明列表，保持只读。
	c.fingerprint.SetNegotiatedALPN(alpn)
	dptlsfp.SetTLSHandshakeInfoOnConn(c.Conn, version, sni, alpn)
}

func (c *FixURIConn) Read(b []byte) (int, error) {
	if c.checked {
		if len(c.prefix) > 0 {
			n := copy(b, c.prefix)
			c.prefix = c.prefix[n:]
			return n, nil
		}
		return c.Conn.Read(b)
	}
	c.checked = true

	if stateProvider, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		if stateProvider.ConnectionState().NegotiatedProtocol == "h2" {
			return c.Conn.Read(b)
		}
	}

	n, err := c.Conn.Read(b)
	if n == 0 {
		return n, err
	}

	data := b[:n]
	if len(data) > 0 && data[0] == 0x16 {
		return n, err
	}
	sp := bytes.IndexByte(data, ' ')
	if sp < 0 || sp+1 >= n || data[sp+1] == '/' || data[sp+1] == '*' {
		return n, err
	}

	fixed := make([]byte, n+1)
	copy(fixed, data[:sp+1])
	fixed[sp+1] = '/'
	copy(fixed[sp+2:], data[sp+1:n])

	written := copy(b, fixed)
	if written < len(fixed) {
		c.prefix = append([]byte(nil), fixed[written:]...)
	}
	return written, err
}

/**
 * ReadFrom 把「由 Reader 驱动的整块写出」直接交给底层连接。
 *
 * Hertz 的 standard.Conn.ReadFrom 只在底层连接实现 io.ReaderFrom 时才走零分配
 * 分支；否则退化为 var buf [32*1024]byte 的堆分配（该局部数组因传入接口方法
 * 而逃逸）。FixURIConn 只改写第一次读到的请求行，写方向与底层连接完全等价，
 * 因此这里原样转发给底层，让 net.TCPConn.ReadFrom 用池化缓冲完成拷贝，消除
 * 每个响应一次 32 KiB 的临时分配。
 *
 * @param r 待转发的响应体读取器。
 * @return 已写入字节数与错误。
 */
func (c *FixURIConn) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := c.Conn.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	// 用只暴露 Write 的包装避免 io.Copy 再次命中本方法的 ReaderFrom 快路径。
	return io.Copy(struct{ io.Writer }{c}, r)
}

type fixURIHertzConn struct {
	net.Conn
	readBuf     []byte
	write       bytes.Buffer
	fingerprint tlsfp.TLSClientFingerprint
}

func newFixURIHertzConn(conn net.Conn) *fixURIHertzConn {
	return &fixURIHertzConn{Conn: conn}
}

func (c *fixURIHertzConn) NetConn() net.Conn {
	return c.Conn
}

func (c *fixURIHertzConn) Read(b []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func (c *fixURIHertzConn) Write(b []byte) (int, error) {
	if err := c.Flush(); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func (c *fixURIHertzConn) SetReadTimeout(t time.Duration) error {
	if t <= 0 {
		return c.SetReadDeadline(time.Time{})
	}
	return c.SetReadDeadline(time.Now().Add(t))
}

func (c *fixURIHertzConn) SetWriteTimeout(t time.Duration) error {
	if t <= 0 {
		return c.SetWriteDeadline(time.Time{})
	}
	return c.SetWriteDeadline(time.Now().Add(t))
}

func (c *fixURIHertzConn) Peek(n int) ([]byte, error) {
	for len(c.readBuf) < n {
		buf := make([]byte, max(4096, n-len(c.readBuf)))
		read, err := c.Conn.Read(buf)
		if read > 0 {
			c.readBuf = append(c.readBuf, buf[:read]...)
		}
		if err != nil {
			if len(c.readBuf) >= n {
				break
			}
			return c.readBuf, err
		}
	}
	return c.readBuf[:n], nil
}

func (c *fixURIHertzConn) Skip(n int) error {
	if len(c.readBuf) < n {
		if _, err := c.Peek(n); err != nil {
			return err
		}
	}
	c.readBuf = c.readBuf[n:]
	return nil
}

func (c *fixURIHertzConn) Release() error {
	return nil
}

func (c *fixURIHertzConn) Len() int {
	return len(c.readBuf)
}

func (c *fixURIHertzConn) ReadByte() (byte, error) {
	if len(c.readBuf) == 0 {
		if _, err := c.Peek(1); err != nil {
			return 0, err
		}
	}
	b := c.readBuf[0]
	c.readBuf = c.readBuf[1:]
	return b, nil
}

func (c *fixURIHertzConn) ReadBinary(n int) ([]byte, error) {
	if len(c.readBuf) < n {
		if _, err := c.Peek(n); err != nil {
			return nil, err
		}
	}
	buf := append([]byte(nil), c.readBuf[:n]...)
	c.readBuf = c.readBuf[n:]
	return buf, nil
}

func (c *fixURIHertzConn) Malloc(n int) ([]byte, error) {
	pos := c.write.Len()
	c.write.Grow(n)
	_, _ = c.write.Write(make([]byte, n))
	return c.write.Bytes()[pos : pos+n], nil
}

func (c *fixURIHertzConn) WriteBinary(b []byte) (int, error) {
	return c.write.Write(b)
}

func (c *fixURIHertzConn) Flush() error {
	for c.write.Len() > 0 {
		n, err := c.Conn.Write(c.write.Bytes())
		if err != nil {
			return err
		}
		c.write.Next(n)
	}
	return nil
}

func (c *fixURIHertzConn) Handshake() error {
	if tlsConn, ok := c.Conn.(interface{ Handshake() error }); ok {
		return tlsConn.Handshake()
	}
	return nil
}

func (c *fixURIHertzConn) ConnectionState() tls.ConnectionState {
	if tlsConn, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return tlsConn.ConnectionState()
	}
	return tls.ConnectionState{}
}

func (c *fixURIHertzConn) TLSFingerprint() (tlsfp.TLSClientFingerprint, bool) {
	if fp, ok := tlsfp.TLSFingerprintFromConn(c.Conn); ok {
		return fp, true
	}
	return c.fingerprint, c.fingerprint.HasValue()
}

func (c *fixURIHertzConn) SetTLSHandshakeInfo(version string, sni string, alpn string) {
	if version != "" {
		c.fingerprint.TLSVersion = version
	}
	if sni != "" {
		c.fingerprint.SNI = sni
	}
	// 只写协商结果（ALPN）；ALPNRaw 是 ClientHello 声明列表，保持只读。
	c.fingerprint.SetNegotiatedALPN(alpn)
	dptlsfp.SetTLSHandshakeInfoOnConn(c.Conn, version, sni, alpn)
}

type fixURIListener struct {
	net.Listener
}

func NewFixURIListener(ln net.Listener) net.Listener {
	return &fixURIListener{Listener: ln}
}

func (l *fixURIListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewFixURIConn(c), nil
}

type fixURITLSTransport struct {
	readBufferSize           int
	network                  string
	addr                     string
	keepAliveTimeout         time.Duration
	readTimeout              time.Duration
	senseClientDisconnection bool
	tls                      *tls.Config
	listenConfig             *net.ListenConfig
	handler                  network.OnData
	OnAccept                 func(net.Conn) context.Context
	OnConnect                func(context.Context, network.Conn) context.Context
	active                   int32
	shuttingDown             int32
	mu                       sync.RWMutex
	ln                       net.Listener
}

func NewFixURITLSTransporter(options *config.Options) network.Transporter {
	return &fixURITLSTransport{
		readBufferSize:           options.ReadBufferSize,
		network:                  options.Network,
		addr:                     options.Addr,
		keepAliveTimeout:         options.KeepAliveTimeout,
		readTimeout:              options.ReadTimeout,
		senseClientDisconnection: options.SenseClientDisconnection,
		tls:                      options.TLS,
		ln:                       options.Listener,
		listenConfig:             options.ListenConfig,
		OnAccept:                 options.OnAccept,
		OnConnect:                options.OnConnect,
	}
}

func (t *fixURITLSTransport) Listener() net.Listener {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.ln
}

func (t *fixURITLSTransport) ListenAndServe(onData network.OnData) error {
	t.handler = onData
	return t.serve()
}

func (t *fixURITLSTransport) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	return t.Shutdown(ctx)
}

func (t *fixURITLSTransport) Shutdown(ctx context.Context) error {
	atomic.StoreInt32(&t.shuttingDown, 1)
	if ln := t.Listener(); ln != nil {
		_ = ln.Close()
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if atomic.LoadInt32(&t.active) <= 0 {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (t *fixURITLSTransport) serve() error {
	t.mu.Lock()
	if t.ln == nil {
		var err error
		if t.listenConfig != nil {
			t.ln, err = t.listenConfig.Listen(context.Background(), t.network, t.addr)
		} else {
			t.ln, err = net.Listen(t.network, t.addr)
		}
		if err != nil {
			t.mu.Unlock()
			return err
		}
	}
	ln := t.ln
	t.mu.Unlock()
	hlog.SystemLogger().Infof("HTTP server listening on address=%s", ln.Addr().String())
	for {
		ctx := context.Background()
		conn, err := ln.Accept()
		if err != nil {
			if atomic.LoadInt32(&t.shuttingDown) > 0 || strings.Contains(err.Error(), "closed") {
				return nil
			}
			hlog.SystemLogger().Errorf("Accept err: %v", err)
			return err
		}
		atomic.AddInt32(&t.active, 1)
		if t.OnAccept != nil {
			ctx = t.OnAccept(conn)
		}

		go func(ctx context.Context, conn net.Conn) {
			defer atomic.AddInt32(&t.active, -1)

			var c network.Conn
			if t.tls != nil {
				tlsConn := tls.Server(conn, t.tls)
				c = newFixURIHertzConn(NewFixURIConn(tlsConn))
				if err := tlsConn.Handshake(); err != nil {
					_ = conn.Close()
					return
				}
			} else {
				c = newFixURIHertzConn(conn)
			}
			if t.OnConnect != nil {
				ctx = t.OnConnect(ctx, c)
			}
			if t.senseClientDisconnection {
				var cancelCtx context.CancelFunc
				ctx, cancelCtx = context.WithCancel(ctx)
				defer cancelCtx()
				stater, err := connstate.ListenConnState(conn,
					connstate.WithOnRemoteClosed(connstate.OnRemoteClosed(cancelCtx)),
				)
				if err != nil {
					hlog.SystemLogger().Errorf("ListenConnState failed: %v, connection close detection disabled", err)
				} else {
					defer stater.Close()
				}
			}
			t.handler(ctx, c)
		}(ctx, conn)
	}
}

/**
 * h2StreamResetter 用 fork 自己的 ErrCode 命名类型声明签名：接口方法签名
 * 的身份比较要求类型完全相同，两个不同包各自定义的 uint32 命名类型
 * （dataplane.http2ErrCode vs http2.ErrCode）不满足 identical 规则，
 * 用本地类型声明会让断言恒 false——这是 r7.44 的原始缺陷。
 */
type h2StreamResetter interface {
	ResetStreamHandler(code forkhttp2.ErrCode) bool
}

const h2ErrCodeCancel = forkhttp2.ErrCodeCancel

func maybeH2ResetStream(guard *InboundProtocolGuard, code forkhttp2.ErrCode) bool {
	if guard == nil || guard.conn == nil {
		return false
	}
	resetter, ok := guard.conn.(h2StreamResetter)
	if !ok || resetter == nil {
		return false
	}
	return resetter.ResetStreamHandler(code)
}

/**
 * maybeH3ResetStream 执行 internal/app 在入站请求时注册的逐请求 HTTP/3 重置闭包。
 * 该闭包在本 goroutine 上同步执行 quic.Stream.CancelWrite(H3_REQUEST_CANCELED)，
 * 因此 handler 返回时流已被取消，此后任何写入尝试（包括 quic-go 自己在 handler
 * 之后的 flush）都会失败且不发出任何帧。这里的请求是一条回环请求，其 token 已由
 * applyInternalHTTP3RequestMetadata 从内部请求头中消费。闭包是一次性的：执行时
 * 会清空上下文槽位，因此重复的、紧邻 drop 的调用不会二次触发。
 */
func maybeH3ResetStream(c *app.RequestContext) bool {
	if c == nil {
		return false
	}
	value, ok := c.Get(InternalHTTP3ResetTokenHeader)
	if !ok {
		return false
	}
	reset, ok := value.(func())
	if !ok || reset == nil {
		return false
	}
	reset()
	c.Set(InternalHTTP3ResetTokenHeader, (func())(nil))
	return true
}

type InboundProtocolGuard struct {
	protocol string // "http/1.1" / "http/1.0" / "http/2.0" / "h2" / "h3" / ""(未知)
	conn     any    // 请求处理开始时捕获的连接(h1 为 *fixURIHertzConn/TlsConn)
}

/**
 * NewInboundProtocolGuard 在 handler 入口捕获协议与连接。构造零反射:
 * 6 层包裹解包(rawTCPConnForRST)由 CloseForDrop 在执行 RST 的瞬间按需做
 * 一次——绝大多数请求不会触发 drop,热路径不再为每个安全判定付反射成本
 * (r7.45 性能修正,此前的 hasRaw 构造期缓存已被移除)。
 */
func NewInboundProtocolGuard(c *app.RequestContext) *InboundProtocolGuard {
	if c == nil {
		return &InboundProtocolGuard{}
	}
	var conn any
	if c.GetConn() != nil {
		conn = c.GetConn()
	}
	protocol := normalizeHTTPProtocol(c.Request.Header.GetProtocol())
	// h3 在数据面的物理载体是 h3 服务发起的本机 h1 回环请求，
	// 协议头只会是 HTTP/1.1；若不按内部 h3 标记纠正，drop 会把
	// 回环 TCP 当作终端连接关闭，既不是 QUIC 流级取消，也无法区分
	// 真正的 h1 客户端。标记在 applyInternalHTTP3RequestMetadata 中
	// 已校验过回环来源，外部无法伪造。
	if isInternalHTTP3Request(c) {
		protocol = "h3"
	}
	return &InboundProtocolGuard{
		protocol: protocol,
		conn:     conn,
	}
}

/**
 * ProtocolName 返回 handler 入口处捕获并归一化后的入站协议；
 * 返回空串表示协议未知或上下文为 nil。
 */
func (g *InboundProtocolGuard) ProtocolName() string {
	if g == nil {
		return ""
	}
	return g.protocol
}

func (g *InboundProtocolGuard) IsStreamMultiplexed() bool {
	if g == nil {
		return true
	}
	switch g.protocol {
	case "h2", "h2c", "h3", "http/2.0", "http/2":
		return true
	default:
		// 未知协议不再按多路复用处理：能解包出 TCP 连接时直接终止
		// 连接，比「既不关连接也不写响应」的伪成功更接近 drop 语义。
		return false
	}
}

// IsH3 报告当前请求是否为经本机回环转发的 HTTP/3 请求。
func (g *InboundProtocolGuard) IsH3() bool {
	return g != nil && g.protocol == "h3"
}

func (g *InboundProtocolGuard) tcpDropTarget() net.Conn {
	if g == nil || g.conn == nil {
		return nil
	}
	if g.IsStreamMultiplexed() {
		return nil
	}
	return rawTCPConnForRST(g.conn)
}

func (g *InboundProtocolGuard) CloseForDrop() bool {
	target := g.tcpDropTarget()
	if target == nil {
		return false
	}
	if cur := rawTCPConnForRST(g.conn); !sameNetAddr(cur, target) {
		return false
	}
	_ = target.Close()
	return true
}

/**
 * AbortForDrop 执行协议级 drop 终止，绝不以 HTTP 响应代替 drop。
 *
 * 终止顺序按协议语义分派：
 *   - HTTP/2 / h2c：对命中的流发 RST_STREAM(CANCEL)，共享连接保持可用；
 *     流级复位不可用时关闭底层 TCP，保证该连接不会继续承载请求。
 *   - HTTP/3：执行 h3 服务侧注册的流级取消闭包（CancelWrite 或连接级
 *     CONNECTION_CLOSE）；闭包缺失时关闭本机回环 TCP，由 h3 服务侧的
 *     取消链路终止 QUIC 流。
 *   - HTTP/1.x：SetLinger(0) + Close 发 RST。
 *
 * 返回 false 只表示所有终止通道都不可用（例如上下文没有任何连接），
 * 调用方仍不得回写 403/502 拦截页。
 *
 * @param c        当前请求上下文，h3 流级闭包存放于此。
 * @param executor 连接级 drop 执行器，可为 nil。
 * @param reason   本次 drop 的上下文，用于统计与告警。
 * @return 是否已发起至少一种协议级终止。
 */
func (g *InboundProtocolGuard) AbortForDrop(c *app.RequestContext, executor *drop.DropExecutor, reason drop.DropReason) bool {
	if g == nil {
		return false
	}
	switch g.protocol {
	case "h2", "h2c", "http/2.0", "http/2":
		if maybeH2ResetStream(g, h2ErrCodeCancel) {
			return true
		}
	case "h3":
		if maybeH3ResetStream(c) {
			return true
		}
	}
	// 协议级通道不可用：关闭底层连接。h2 关闭整条共享连接是流级复位
	// 失败后的最后手段；h3 关闭的是本机回环 TCP，由 h3 侧取消链路收尾。
	return g.closeForDrop(executor, reason)
}

/**
 * Execute 执行带统计的 TCP drop（仅连接级语义）。
 *
 * 执行顺序刻意是「先 executor、后兜底 Close」：`DropExecutor.Execute` 会在
 * 关闭前对 `*net.TCPConn` 调 `SetLinger(0)`，对端因此收到 RST 而不是优雅 FIN。
 * 旧实现先 `CloseForDrop()` 把 fd 关掉，再对已关闭的连接调 `SetLinger(0)`，
 * 必然返回 `ErrClosed`，RST 语义形同虚设。现在把可写目标直接交给 executor。
 *
 * executor 为 nil 或已禁用时退回直接 `Close()`，与历史「drop 关闭连接」语义一致。
 *
 * 多路复用协议不会在这里关闭共享连接：h2 走流级 RST_STREAM，h3 由
 * AbortForDrop 消费流级取消闭包。返回值 false 不再表示「改为拦截页」，
 * 调用方必须使用 AbortForDrop 完成协议级终止。
 *
 * @param executor drop 执行器，可为 nil。
 * @param reason   本次 drop 的上下文，用于统计与告警。
 * @return 连接是否已被关闭。
 */
func (g *InboundProtocolGuard) Execute(executor *drop.DropExecutor, reason drop.DropReason) bool {
	if g == nil {
		return false
	}
	if g.IsStreamMultiplexed() {
		if g.protocol == "h2" || g.protocol == "h2c" || g.protocol == "http/2.0" || g.protocol == "http/2" {
			return maybeH2ResetStream(g, h2ErrCodeCancel)
		}
		return false
	}
	return g.closeForDrop(executor, reason)
}

/**
 * closeForDrop 关闭当前请求的底层 TCP 连接。
 *
 * 仅用于 HTTP/1.x 的正常 drop 路径，以及多路复用协议流级终止失败后的
 * 最后兜底。调用前必须已经完成协议级尝试。
 *
 * @param executor drop 执行器，可为 nil。
 * @param reason   本次 drop 的上下文，用于统计与告警。
 * @return 连接是否已被关闭。
 */
func (g *InboundProtocolGuard) closeForDrop(executor *drop.DropExecutor, reason drop.DropReason) bool {
	if g == nil || g.conn == nil {
		return false
	}
	target := rawTCPConnForRST(g.conn)
	if target == nil {
		return false
	}
	// 同一性校验：确认解包出来的 fd 仍对应当前请求的连接，避免把复用池里
	// 的连接误当作本次请求的连接关闭。
	if cur := rawTCPConnForRST(g.conn); !sameNetAddr(cur, target) {
		return false
	}
	if executor != nil && executor.Enabled() {
		if err := executor.Execute(target, reason); err == nil {
			return true
		}
	}
	_ = target.Close()
	return true
}

func RawTCPConnForRST(conn any) net.Conn {
	return rawTCPConnForRST(conn)
}

/**
 * RawTCPConn 返回解包后的 TCP 基础连接，没有则返回 nil。
 * 测试用它来对回环监听器的连接做同一性断言。
 */
func (g *InboundProtocolGuard) RawTCPConn() net.Conn {
	if g == nil {
		return nil
	}
	return rawTCPConnForRST(g.conn)
}

func rawTCPConnForRST(conn any) net.Conn {
	cur := conn
	seen := map[any]struct{}{}
	for i := 0; i < 6 && cur != nil; i++ {
		if _, dup := seen[cur]; dup {
			return nil
		}
		seen[cur] = struct{}{}
		if tc, ok := cur.(*net.TCPConn); ok {
			return tc
		}
		cur = nextConnLink(cur)
	}
	return nil
}

/**
 * netConnUnwrapper 覆盖本仓库与标准库中显式暴露底层 net.Conn 的包装器：
 * fixURIHertzConn/FixURIConn 的 NetConn、crypto/tls.Conn 的 NetConn 等。
 * 显式解包优先于反射，既避免每次 drop 都走反射，也不依赖字段布局。
 */
type netConnUnwrapper interface {
	NetConn() net.Conn
}

/**
 * netConnUnwrapMethod 覆盖以 Unwrap() net.Conn 暴露底层的包装器。
 */
type netConnUnwrapMethod interface {
	Unwrap() net.Conn
}

func nextConnLink(conn any) net.Conn {
	if c, ok := conn.(netConnUnwrapper); ok {
		if inner := c.NetConn(); inner != nil {
			return inner
		}
	}
	if c, ok := conn.(netConnUnwrapMethod); ok {
		if inner := c.Unwrap(); inner != nil {
			return inner
		}
	}
	switch c := conn.(type) {
	case net.Conn:
		return connLinkOrNil(c)
	default:
		return nil
	}
}

func connLinkOrNil(conn net.Conn) net.Conn {
	v := reflect.ValueOf(conn)
	if !v.IsValid() {
		return nil
	}
	v = dpstream.AccessibleValue(v)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return nil
	}
	elem := v.Elem()
	if elem.Kind() != reflect.Struct {
		return nil
	}
	return firstConnField(elem)
}

func firstConnField(elem reflect.Value) net.Conn {
	for i := 0; i < elem.NumField(); i++ {
		field := dpstream.AccessibleValue(elem.Field(i))
		if !field.IsValid() {
			continue
		}
		if field.Kind() == reflect.Pointer && field.IsNil() {
			continue
		}
		if c, ok := field.Interface().(net.Conn); ok && c != nil {
			return c
		}
	}
	return nil
}

func sameNetAddr(a, b net.Conn) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	la, ra := a.LocalAddr(), a.RemoteAddr()
	lb, rb := b.LocalAddr(), b.RemoteAddr()
	if la == nil || ra == nil || lb == nil || rb == nil {
		return false
	}
	return la.String() == lb.String() && ra.String() == rb.String()
}
