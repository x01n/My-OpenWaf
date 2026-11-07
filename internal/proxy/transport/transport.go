// Package transport 承载上游连接层的池化实现：共享 http.Transport / http.Client /
// Hertz h2c / HTTP/3 客户端及其池生命周期（修剪、关闭、统计），以及请求协议与响应
// 大小未知标记的上下文存取。
//
// 切分自 internal/proxy/proxy.go：父包 proxy 引用本包的导出符号，本包不反向依赖
// 父包，二者不构成 import 环。
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	hertzclient "github.com/cloudwego/hertz/pkg/app/client"
	hertzprotocol "github.com/cloudwego/hertz/pkg/protocol"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	http2 "github.com/x01n/http2"
	http2config "github.com/x01n/http2/config"
	http2factory "github.com/x01n/http2/factory"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/upstream"
)

type ByteSliceReadCloser struct {
	Data []byte
	pos  int
}

func (r *ByteSliceReadCloser) Read(p []byte) (int, error) {
	if r.pos >= len(r.Data) {
		return 0, io.EOF
	}
	n := copy(p, r.Data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *ByteSliceReadCloser) Close() error {
	return nil
}

type FinishOnCanceledReadCloser struct {
	Body      io.ReadCloser
	CancelCtx context.Context
}

func (r *FinishOnCanceledReadCloser) Read(p []byte) (int, error) {
	n, err := r.Body.Read(p)
	if err != nil && r.CancelCtx != nil && r.CancelCtx.Err() != nil {
		return n, io.EOF
	}
	return n, err
}

func (r *FinishOnCanceledReadCloser) Close() error {
	return r.Body.Close()
}

// transportKey 唯一标识一份上游 TLS 配置。
type transportKey struct {
	tlsServerName string
	tlsSkipVerify bool
	// clientCertFingerprint 只存储证书链 DER 的 SHA-256 摘要（十六进制下采样）：
	// 未经编码的完整 PEM 不得进入 map 键（日志/pprof 可倾泻键内容）。
	// 证书内容变化时摘要变化，传输池旧键自然失效，旧连接随后被 Prune/超时回收。
	clientCertFingerprint string
	isHTTPS               bool
	h2cPrior              bool
}

// upstreamClientCertFingerprint 计算站点级上游客户端证书的检索指纹。
//
// 已配置时返回空串以外的前 16 字节 SHA-256 十六进制摘要。输入取快照预计算
// 好的证书链 DER（snapshot 构建期完成 PEM 解析），零 PEM 解析 / 零私钥触碰。
func upstreamClientCertFingerprint(rt snapshot.SiteRuntime) string {
	return upstream.UpstreamClientCertFingerprint(rt)
}

var (
	transportMu   sync.RWMutex
	transportPool = make(map[transportKey]*http.Transport)
)

// 用户请求路径的连接建立与响应头等待超时，取值与探活路径对齐
// （internal/upstream/health.go）：
//
//   - 拨号与 TLS 握手取 health.go:23 的 defaultHTTPProbeTLSHandshakeTimeout（10s）；
//   - TCP keepalive 取 health.go:21 的 defaultHTTPProbeTCPKeepAlive（30s，与
//     net.Dialer 零值默认一致，显式写出以锁定行为）；
//   - 响应头等待取 30s，与缓冲路径客户端的整体超时（internal/proxy/proxy.go
//     中 SharedPooledClient 的 30s 档）同级，只约束上游首个响应字节之前的等待。
//
// 补齐前这三个字段都是零值：拨号无超时（连接建立交给内核 SYN 重传，Linux 约
// 130s）、TLS 握手无超时、响应头无超时，用户请求路径比探活路径约束更松。
//
// 声明为 var 而非 const，仅为让同包测试能以短超时驱动真实的超时行为；运行期
// 不做任何写入。
var (
	upstreamDialTimeout           = 10 * time.Second
	upstreamTCPKeepAlive          = 30 * time.Second
	upstreamTLSHandshakeTimeout   = 10 * time.Second
	upstreamResponseHeaderTimeout = 30 * time.Second
)

// newUpstreamDialer 构造共享上游 transport 的拨号器。
func newUpstreamDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   upstreamDialTimeout,
		KeepAlive: upstreamTCPKeepAlive,
	}
}

/**
 * SharedTransportForUpstream 以选定的上游 scheme 作为池的键取共享 transport。
 *
 * @param rt 站点运行时。
 * @param base 上游基础 URL。
 * @return 该 scheme 对应的共享 http.Transport。
 */
func SharedTransportForUpstream(rt snapshot.SiteRuntime, base string) *http.Transport {
	return sharedTransportForUpstreamClassified(rt, isHTTPSUpstreamBase(base))
}

// sharedTransportForUpstreamClassified 是 SharedTransportForUpstream 的
// 免归一入口：调用方已通过 ResolveUpstreamBase 求得 isHTTPS，直接取池。
func sharedTransportForUpstreamClassified(rt snapshot.SiteRuntime, isHTTPS bool) *http.Transport {
	key := transportKey{
		isHTTPS: isHTTPS,
	}
	if isHTTPS {
		key.tlsServerName = rt.Site.UpstreamTLSServerName
		key.tlsSkipVerify = rt.Site.UpstreamTLSSkipVerify
		key.clientCertFingerprint = upstreamClientCertFingerprint(rt)
	}

	transportMu.RLock()
	if tr, ok := transportPool[key]; ok {
		transportMu.RUnlock()
		return tr
	}
	transportMu.RUnlock()

	tr := &http.Transport{
		// 空闲池容量必须覆盖上游并发峰值：池容量小于并发时，响应结束释放的
		// 连接会因池满被直接关闭，下一个请求只能重新拨号，形成「每请求一次
		// TCP 建连 + 一次 TIME-WAIT」的抖动（实测并发 320 时 TIME-WAIT 数量
		// 与已完成请求数 1:1）。512/512 与 MaxConnsPerHost 对齐，保证上限内
		// 释放的连接一定能回池复用；IdleConnTimeout 30s 仍会让峰值后的空闲
		// 连接自然回收，不会长期占用内存。
		MaxIdleConns: 1024,

		MaxIdleConnsPerHost: 512,

		IdleConnTimeout: 30 * time.Second,
		// 空闲连接超时，避免长时间占用资源。
		ReadBufferSize:  16 << 10,
		WriteBufferSize: 16 << 10,
		// 预分配读写缓冲区，减少高并发下的内存分配压力。
		ExpectContinueTimeout: time.Second,
		// 强制尝试使用 HTTP/2，即使上游未明确声明支持。
		ForceAttemptHTTP2: true,
		// 禁用 HTTP/2 的压缩，避免 CRIME 攻击。
		DisableCompression: true,
		// 每上游并发连接上限，避免一次性洪峰占满所有临时端口，导致 i/o timeout。
		// 与空闲池同量级，保证上限内的连接释放后都能回池复用。
		MaxConnsPerHost: 512,
		// 连接建立与响应头等待超时，与探活路径
		// internal/upstream/health.go 的 newHTTPProbeTransport 同量级对齐。
		DialContext:           newUpstreamDialer().DialContext,
		TLSHandshakeTimeout:   upstreamTLSHandshakeTimeout,
		ResponseHeaderTimeout: upstreamResponseHeaderTimeout,
	}
	if isHTTPS {
		tr.TLSClientConfig = &tls.Config{
			ServerName:         rt.Site.UpstreamTLSServerName,
			InsecureSkipVerify: rt.Site.UpstreamTLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
			// 复用 TLS 会话（session ticket/ID），命中时走简化握手，
			// 避免每条新连接都做完整握手。每个上游 transport 独享一份缓存，
			// 容量与 MaxIdleConnsPerHost 对齐。
			ClientSessionCache: tls.NewLRUClientSessionCache(128),
		}
		if cert, hasCert, err := upstream.UpstreamClientCertificate(rt); err != nil {
			// 取证书内容失败时仅记录告警并继续无客户端证书握手：
			// 由上游服务端决定最终拒绝与否，避免站点整体不可用。
			slog.Warn("shared upstream transport skipped client cert", slog.String("site_host", rt.Site.Host), slog.String("error", err.Error()))
		} else if hasCert {
			tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
		}
	}

	transportMu.Lock()
	if existing, ok := transportPool[key]; ok {
		transportMu.Unlock()
		return existing
	}
	transportPool[key] = tr
	transportMu.Unlock()
	return tr
}

func isHTTPSUpstreamBase(base string) bool {
	// RPC 别名（tls/grpcs/grpc+tls/grpc+https）归一后与 https 同语义，
	// 与 https/h2c 复用同一 transport 池键。
	target, _, ok := upstream.RPCUpstreamAliasForURL(base)
	if ok {
		return target == "https"
	}
	const scheme = "https://"
	if len(base) < len(scheme) {
		return false
	}
	for i := 0; i < len(scheme); i++ {
		b := base[i]
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if b != scheme[i] {
			return false
		}
	}
	return true
}

// clientPool 按 transport 缓存 http.Client 实例，避免重复分配。
var (
	clientPoolMu        sync.RWMutex
	clientCache         = make(map[*http.Transport]*http.Client)
	noTimeoutClientPool = make(map[*http.Transport]*http.Client)
)

func sharedClient(tr *http.Transport) *http.Client {
	clientPoolMu.RLock()
	if hc, ok := clientCache[tr]; ok {
		clientPoolMu.RUnlock()
		return hc
	}
	clientPoolMu.RUnlock()

	hc := &http.Client{Transport: tr, Timeout: 60 * time.Second}
	clientPoolMu.Lock()
	if existing, ok := clientCache[tr]; ok {
		clientPoolMu.Unlock()
		return existing
	}
	clientCache[tr] = hc
	clientPoolMu.Unlock()
	return hc
}

func sharedNoTimeoutClient(tr *http.Transport) *http.Client {
	clientPoolMu.RLock()
	if hc, ok := noTimeoutClientPool[tr]; ok {
		clientPoolMu.RUnlock()
		return hc
	}
	clientPoolMu.RUnlock()

	hc := &http.Client{Transport: tr, Timeout: 0}
	clientPoolMu.Lock()
	if existing, ok := noTimeoutClientPool[tr]; ok {
		clientPoolMu.Unlock()
		return existing
	}
	noTimeoutClientPool[tr] = hc
	clientPoolMu.Unlock()
	return hc
}

/**
 * rtClientPool 按 RoundTripper 接口值缓存无超时 http.Client 实例。
 *
 * 流式调用方（SSE）因此可以按上游 transport 复用一个 client，而不是每请求分配一个。
 */
var (
	rtClientMu   sync.RWMutex
	rtClientPool = make(map[http.RoundTripper]*http.Client)
)

/**
 * SharedNoTimeoutClientForRoundTripper 返回绑定到指定 RoundTripper 的缓存无超时 http.Client。
 *
 * 适用于长生命周期的流式响应。
 *
 * @param rt 上游 RoundTripper。
 * @return 该 RoundTripper 对应的共享无超时 client。
 */
func SharedNoTimeoutClientForRoundTripper(rt http.RoundTripper) *http.Client {
	rtClientMu.RLock()
	if hc, ok := rtClientPool[rt]; ok {
		rtClientMu.RUnlock()
		return hc
	}
	rtClientMu.RUnlock()

	hc := &http.Client{Transport: rt, Timeout: 0}
	rtClientMu.Lock()
	if existing, ok := rtClientPool[rt]; ok {
		rtClientMu.Unlock()
		return existing
	}
	rtClientPool[rt] = hc
	rtClientMu.Unlock()
	return hc
}

type hertzClientKey struct {
	tlsServerName string
	tlsSkipVerify bool
	h2c           bool
}

var (
	hertzClientMu    sync.RWMutex
	hertzClientCache = make(map[hertzClientKey]*hertzclient.Client)
)

// hertzH2CUpstreamGates 按上游 host 限制同时"在飞"的 h2c 请求数。
//
// 存在的理由：hertz 的 WithMaxConnsPerHost 只对 http1 的 ClientOptions.MaxConns
// 生效（hertz@v0.10.6 pkg/app/client/client.go:508 的 newHttp1OptionFromClient 只在
// clientFactory == nil 时才被调用，而本路径在 :340 已 SetClientFactory），
// x01n/http2 fork 的 config.ClientConfig 也没有任何连接数旋钮，因此 h2c 路径
// 此前完全没有并发上限：一次洪峰会让每条入站请求各拨一条上游连接，与入站连接
// 争用同一个本机临时端口池（默认 32728 个），实测耗尽后成片 i/o timeout。
//
// 容量与原来那行无效的 WithMaxConnsPerHost(128) 的意图一致：128。
// 注意语义差别：这是"并发请求数"闸门而非"TCP 连接数"闸门 —— h2c 上多条流共享
// 一条连接，闸门只能约束在飞请求数，真正的连接数是 fork 内部
// （acquireConn → createConn/ReserveNewRequest）按对端 SETTINGS_MAX_CONCURRENT_STREAMS
// 决定的。
//
// gate 的释放点是响应体关闭（hertzResponseBody.Close），不是 DoHertzUpstream 返回：
// 后者只等到响应头，若在返回时就释放，闸门只限制握手不限制传输，长响应体（SSE、
// 大文件）会重新变成无上限。
var (
	hertzH2CGateMu sync.Mutex
	hertzH2CGates  = make(map[string]chan struct{})
)

// hertzH2CUpstreamGateCapacity 是每个上游 host 的在飞 h2c 请求上限。
//
// 声明为 var 而非 const，仅为让同包测试能以小容量驱动闸门阻塞；运行期不做写入。
// 取值必须在建闸门前改动（闸门按当时的容量创建）。
var hertzH2CUpstreamGateCapacity = 128

// acquireHertzH2CGate 按 host 取/建闸门并占用一个名额。
//
// 调用方必须把返回的释放函数交给响应体关闭路径调用 —— 不得在 Do 返回后就释放。
// ctx 在等待名额期间取消时返回 ctx 错误，并【不】占用名额，因此释放函数为 nil。
func acquireHertzH2CGate(ctx context.Context, host string) (release func(), err error) {
	hertzH2CGateMu.Lock()
	gate := hertzH2CGates[host]
	if gate == nil {
		gate = make(chan struct{}, hertzH2CUpstreamGateCapacity)
		hertzH2CGates[host] = gate
	}
	hertzH2CGateMu.Unlock()

	select {
	case gate <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() { <-gate })
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// resetHertzH2CUpstreamGates 清空闸门表，仅供同包测试隔离使用。
func resetHertzH2CUpstreamGates() {
	hertzH2CGateMu.Lock()
	hertzH2CGates = make(map[string]chan struct{})
	hertzH2CGateMu.Unlock()
}

func sharedHertzH2CClient() (*hertzclient.Client, error) {
	key := hertzClientKey{h2c: true}
	hertzClientMu.RLock()
	if cli, ok := hertzClientCache[key]; ok {
		hertzClientMu.RUnlock()
		return cli, nil
	}
	hertzClientMu.RUnlock()
	// 这里刻意不传 WithMaxConnsPerHost / WithDialTimeout：两条都是死配置。
	// 前者只对 http1 工厂生效（见 hertzH2CUpstreamGates 注释），后者同样只经
	// newHttp1OptionFromClient 进入 http1.ClientOptions，对 fork 的
	// config.ClientConfig.DialTimeout 无影响（fork 自带 1s 默认值，
	// 见 x01n/http2@v0.3.0/config/client_option.go:253）。
	cli, err := hertzclient.NewClient(
		hertzclient.WithResponseBodyStream(true),
		hertzclient.WithDisablePathNormalizing(true),
		hertzclient.WithNoDefaultUserAgentHeader(true),
		hertzclient.WithKeepAlive(true),
	)
	if err != nil {
		return nil, err
	}
	cli.SetClientFactory(http2factory.NewClientFactory(
		http2config.WithAllowHTTP(true),
	))
	hertzClientMu.Lock()
	if existing, ok := hertzClientCache[key]; ok {
		hertzClientMu.Unlock()
		return existing, nil
	}
	hertzClientCache[key] = cli
	hertzClientMu.Unlock()
	return cli, nil
}

func shouldUseHertzUpstream(base string) bool {
	// grpc:// 归一为 h2c，与 h2c:// 共用 Hertz h2 prior knowledge 路径。
	target, _, ok := upstream.RPCUpstreamAliasForURL(base)
	if ok {
		return target == "h2c"
	}
	return strings.HasPrefix(strings.ToLower(base), "h2c://")
}

const upstreamHTTPProtocolContextKey = "owaf.upstream_http_protocol"
const responseSizeUnknownContextKey = "owaf.response_size_unknown"

func SetUpstreamHTTPProtocol(c *app.RequestContext, proto string) {
	proto = strings.TrimSpace(proto)
	if c == nil || proto == "" {
		return
	}
	c.Set(upstreamHTTPProtocolContextKey, proto)
}

func UpstreamHTTPProtocol(c *app.RequestContext) string {
	if c == nil {
		return ""
	}
	value, ok := c.Get(upstreamHTTPProtocolContextKey)
	if !ok {
		return ""
	}
	proto, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(proto)
}

func MarkResponseSizeUnknown(c *app.RequestContext) {
	if c == nil {
		return
	}
	c.Set(responseSizeUnknownContextKey, true)
}

func ResponseSizeUnknown(c *app.RequestContext) bool {
	if c == nil {
		return false
	}
	value, ok := c.Get(responseSizeUnknownContextKey)
	if !ok {
		return false
	}
	unknown, ok := value.(bool)
	return ok && unknown
}

func releaseHertzUpstreamRequest(req *hertzprotocol.Request) {
	if req == nil {
		return
	}
	_ = req.CloseBodyStream()
	hertzprotocol.ReleaseRequest(req)
}

func releaseHertzUpstreamRequestWhenDone(req *hertzprotocol.Request, doneSignals []<-chan struct{}) {
	releaseHertzUpstreamResourcesWhenDone(req, nil, doneSignals)
}

func releaseHertzUpstreamResourcesWhenDone(req *hertzprotocol.Request, resp *hertzprotocol.Response, doneSignals []<-chan struct{}) {
	if req == nil && resp == nil {
		return
	}
	release := func() {
		if resp != nil {
			hertzprotocol.ReleaseResponse(resp)
		}
		releaseHertzUpstreamRequest(req)
	}
	if len(doneSignals) == 0 {
		release()
		return
	}
	allDone := true
	for _, done := range doneSignals {
		select {
		case <-done:
		default:
			allDone = false
		}
	}
	if allDone {
		release()
		return
	}
	go func() {
		for _, done := range doneSignals {
			<-done
		}
		release()
	}()
}

func hertzHeaderToHTTPHeader(src interface{ VisitAll(func(key, value []byte)) }) http.Header {
	dst := make(http.Header)
	src.VisitAll(func(key, value []byte) {
		name := http.CanonicalHeaderKey(string(key))
		if name == "" {
			name = string(key)
		}
		dst.Add(name, string(value))
	})
	return dst
}

func hertzTrailerToHTTPHeader(src *hertzprotocol.Trailer) http.Header {
	dst := make(http.Header)
	if src == nil {
		return dst
	}
	src.VisitAll(func(key, value []byte) {
		name := http.CanonicalHeaderKey(string(key))
		if name == "" {
			name = string(key)
		}
		dst.Add(name, string(value))
	})
	return dst
}

type hertzResponseBody struct {
	reader        io.Reader
	resp          *hertzprotocol.Response
	req           *hertzprotocol.Request
	requestDone   []<-chan struct{}
	trailer       http.Header
	cancel        context.CancelFunc
	mu            sync.Mutex
	cond          *sync.Cond
	activeReaders int
	closing       bool
	closed        bool
	closeErr      error
}

func (b *hertzResponseBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	if b.closing || b.closed {
		b.mu.Unlock()
		return 0, io.EOF
	}
	reader := b.reader
	b.activeReaders++
	b.mu.Unlock()

	n, err := reader.Read(p)

	b.mu.Lock()
	if err != nil {
		b.syncTrailerLocked()
	}
	b.activeReaders--
	if b.activeReaders == 0 && b.cond != nil {
		b.cond.Broadcast()
	}
	b.mu.Unlock()
	return n, err
}

func (b *hertzResponseBody) Close() error {
	b.mu.Lock()
	if b.closed {
		err := b.closeErr
		b.mu.Unlock()
		return err
	}
	if b.closing {
		b.initCondLocked()
		for !b.closed {
			b.cond.Wait()
		}
		err := b.closeErr
		b.mu.Unlock()
		return err
	}
	b.closing = true
	cancel := b.cancel
	b.cancel = nil
	b.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	b.mu.Lock()
	b.initCondLocked()
	for b.activeReaders > 0 {
		b.cond.Wait()
	}
	b.syncTrailerLocked()
	resp := b.resp
	req := b.req
	requestDone := b.requestDone
	b.resp = nil
	b.req = nil
	b.requestDone = nil
	b.mu.Unlock()

	var closeErr error
	if resp != nil {
		closeErr = resp.CloseBodyStream()
	}
	releaseHertzUpstreamResourcesWhenDone(req, resp, requestDone)

	b.mu.Lock()
	b.closeErr = closeErr
	b.closed = true
	b.cond.Broadcast()
	b.mu.Unlock()
	return closeErr
}

func (b *hertzResponseBody) initCondLocked() {
	if b.cond == nil {
		b.cond = sync.NewCond(&b.mu)
	}
}

func (b *hertzResponseBody) syncTrailerLocked() {
	if b.resp == nil || b.trailer == nil {
		return
	}
	for k := range b.trailer {
		delete(b.trailer, k)
	}
	for k, vv := range hertzTrailerToHTTPHeader(b.resp.Header.Trailer()) {
		b.trailer[k] = append([]string(nil), vv...)
	}
}

func httpProtoForBase(base string) string {
	// RPC 别名与对应传输 scheme 同语义：tls/grpcs 同 https，grpc 同 h2c。
	if target, _, ok := upstream.RPCUpstreamAliasForURL(base); ok {
		if target == "h2c" || target == "https" {
			return "HTTP/2.0"
		}
		return "HTTP/1.1"
	}
	lower := strings.ToLower(base)
	switch {
	case strings.HasPrefix(lower, "h2c://"):
		return "HTTP/2.0"
	case strings.HasPrefix(lower, "https://"):
		return "HTTP/2.0"
	default:
		return "HTTP/1.1"
	}
}

func HertzResponseToHTTPResponse(base string, hresp *hertzprotocol.Response, hreq *hertzprotocol.Request, requestDone []<-chan struct{}, cancel context.CancelFunc) *http.Response {
	if hresp == nil {
		return nil
	}
	body := hresp.BodyStream()
	trailer := make(http.Header)
	return &http.Response{
		StatusCode:    hresp.StatusCode(),
		Proto:         httpProtoForBase(base),
		ContentLength: int64(hresp.Header.ContentLength()),
		Header:        hertzHeaderToHTTPHeader(&hresp.Header),
		Trailer:       trailer,
		Body:          &hertzResponseBody{reader: body, resp: hresp, req: hreq, requestDone: requestDone, trailer: trailer, cancel: cancel},
	}
}

func copyHTTPRequestHeadersToHertz(dst *hertzprotocol.Request, src *http.Request) {
	if dst == nil || src == nil {
		return
	}
	if src.Body != nil {
		if src.ContentLength > 0 {
			dst.SetBodyStream(src.Body, int(src.ContentLength))
		} else {
			dst.SetBodyStream(src.Body, -1)
		}
	}
	for k, vv := range src.Header {
		for _, v := range vv {
			dst.Header.Add(k, v)
		}
	}
	if src.Host != "" {
		dst.Header.SetHost(src.Host)
	}
}

func DoHertzUpstream(ctx context.Context, rt snapshot.SiteRuntime, base string, req *http.Request) (*hertzprotocol.Response, *hertzprotocol.Request, []<-chan struct{}, context.CancelFunc, error) {
	if req == nil {
		return nil, nil, nil, nil, errors.New("nil upstream request")
	}
	var (
		clientInst *hertzclient.Client
		err        error
	)
	clientInst, err = sharedHertzH2CClient()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// 在飞请求闸门：fork 无连接数旋钮，只能在此按 host 限流（见
	// hertzH2CUpstreamGates）。闸门在真正的上游 round trip 之前占用，
	// 名额不足时等待，等待期间允许 ctx 取消。
	releaseGate, err := acquireHertzH2CGate(ctx, req.URL.Host)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	hreq := hertzprotocol.AcquireRequest()
	hreq.SetRequestURI(req.URL.String())
	hreq.Header.SetMethod(req.Method)
	hreq.URI().DisablePathNormalizing = true
	copyHTTPRequestHeadersToHertz(hreq, req)
	resp := hertzprotocol.AcquireResponse()
	requestCtx, cancel := context.WithCancel(ctx)
	// 释放点：requestCtx 结束即释放名额，而正常路径下 requestCtx 只由
	// hertzResponseBody.Close 持有的 cancel 关闭 —— 即"响应体关闭时"释放，
	// 不是本函数返回时释放：本函数只等到响应头，若此处就释放，闸门将只约束
	// 握手而放任长响应体（SSE、大文件）无上限并发。客户端断开（ctx 结束）
	// 与错误返回路径同样经此释放，不留泄漏面。
	stopGateRelease := context.AfterFunc(requestCtx, releaseGate)
	requestDone := make([]<-chan struct{}, 0, 1)
	requestCtx = http2.WithRequestDoneObserver(requestCtx, func(done <-chan struct{}) {
		requestDone = append(requestDone, done)
	})
	if err := clientInst.Do(requestCtx, hreq, resp); err != nil {
		stopGateRelease()
		releaseGate()
		cancel()
		releaseHertzUpstreamResourcesWhenDone(hreq, resp, requestDone)
		return nil, nil, nil, nil, err
	}
	return resp, hreq, requestDone, cancel, nil
}

/**
 * NormalizeUpstreamURL 把上游 URL 归一为 Go 标准库能处理的 http(s):// 形式。
 *
 * 涉及两类改写：h2c:// 与 h3:// 分别归一为 http:// 与 https://；RPC 别名
 * （grpc:// -> http://，tls:// / grpcs:// / grpc+tls:// / grpc+https:// -> https://）
 * 归一到对应传输 scheme。
 *
 * @param raw 原始上游 URL。
 * @return 归一后的 URL；无需归一或别名不识别时原样返回。
 */
func NormalizeUpstreamURL(raw string) string {
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "h2c://") {
		return "http://" + raw[6:]
	}
	if strings.HasPrefix(lower, "h3://") {
		return "https://" + raw[5:]
	}
	if target, rest, ok := upstream.RPCUpstreamAliasForURL(raw); ok {
		if target == "https" {
			return "https://" + rest
		}
		if target == "h2c" {
			return "http://" + rest
		}
	}
	return raw
}

// UpstreamBaseResolution 是对同一 base 的一次性 scheme 分类结果：
// normalized 与旧的 NormalizeUpstreamURL / UpstreamRoundTripperForBase
// 归一输出逐字节相同；transport 与 HertzH2C 分别复现旧行为。
//
// 分类只应在本函数内做一次；任何新调用点都从这里取值，不要
// 再对同一个 base 单独展开 RPCUpstreamAliasForURL/ToLower/前缀扫描，
// 否则三套分支结构的数据会重新漂移。
type UpstreamBaseResolution struct {
	Normalized string            // http(s):// 形式的 URL 前缀
	Transport  http.RoundTripper // 非 Hertz 路径 transport
	HertzH2C   bool              // == 旧的 shouldUseHertzUpstream(base)
}

func ResolveUpstreamBase(rt snapshot.SiteRuntime, base string) UpstreamBaseResolution {
	lower := strings.ToLower(base)
	if strings.HasPrefix(lower, "h2c://") {
		// 与旧 h2c 分支逐字节相同；base 切片必须切原串，
		// 前缀折叠匹配只在判定阶段。
		return UpstreamBaseResolution{
			Normalized: "http://" + base[6:],
			Transport:  h2cTransportForUpstream(),
			HertzH2C:   true,
		}
	}
	if strings.HasPrefix(lower, "h3://") {
		// h3Host 截断只到第一个 '/'，与 PruneInactiveUpstreamTransports
		// 的池键构造保持一致（见该函数 h3Host 提取逻辑）。
		h3Host := base[5:]
		if i := strings.IndexByte(h3Host, '/'); i >= 0 {
			h3Host = h3Host[:i]
		}
		return UpstreamBaseResolution{
			Normalized: "https://" + base[5:],
			Transport:  http3TransportForUpstream(rt, h3Host),
			HertzH2C:   false,
		}
	}
	if target, rest, ok := upstream.RPCUpstreamAliasForURL(base); ok {
		// 别名命中在量产数据面上不可达（snapshot 构建期已展开），语义保留。
		if target == "h2c" {
			return UpstreamBaseResolution{
				Normalized: "http://" + rest,
				Transport:  h2cTransportForUpstream(),
				HertzH2C:   true,
			}
		}
		return UpstreamBaseResolution{
			Normalized: "https://" + rest,
			Transport:  sharedTransportForUpstreamClassified(rt, true),
			HertzH2C:   false,
		}
	}
	return UpstreamBaseResolution{
		Normalized: base,
		Transport:  sharedTransportForUpstreamClassified(rt, isHTTPSUpstreamBase(base)),
		HertzH2C:   false,
	}
}

/**
 * UpstreamRoundTripperForBase 为给定上游 scheme 返回合适的 http.RoundTripper 与归一化 base URL。
 *
 * @param rt 站点运行时。
 * @param base 上游基础 URL。
 * @return 传输实现与该 base 的归一化 URL。
 */
func UpstreamRoundTripperForBase(rt snapshot.SiteRuntime, base string) (http.RoundTripper, string) {
	res := ResolveUpstreamBase(rt, base)
	return res.Transport, res.Normalized
}

var (
	h2cTransportMu   sync.RWMutex
	h2cTransportInst *http.Transport
)

func h2cTransportForUpstream() *http.Transport {
	h2cTransportMu.RLock()
	if h2cTransportInst != nil {
		h2cTransportMu.RUnlock()
		return h2cTransportInst
	}
	h2cTransportMu.RUnlock()

	tr := &http.Transport{
		MaxIdleConns:        512,
		MaxIdleConnsPerHost: 128,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
	}
	tr.Protocols = new(http.Protocols)
	tr.Protocols.SetUnencryptedHTTP2(true)

	h2cTransportMu.Lock()
	if h2cTransportInst != nil {
		h2cTransportMu.Unlock()
		return h2cTransportInst
	}
	h2cTransportInst = tr
	h2cTransportMu.Unlock()
	return tr
}

func http3TransportForUpstream(rt snapshot.SiteRuntime, upstreamHost string) *http3.Transport {
	key := http3TransportKey{
		upstreamHost:          upstreamHost,
		tlsServerName:         rt.Site.UpstreamTLSServerName,
		tlsSkipVerify:         rt.Site.UpstreamTLSSkipVerify,
		clientCertFingerprint: upstreamClientCertFingerprint(rt),
	}
	http3TransportMu.RLock()
	if tr, ok := http3TransportPool[key]; ok {
		http3TransportMu.RUnlock()
		return tr
	}
	http3TransportMu.RUnlock()

	tlsCfg := &tls.Config{
		ServerName:         rt.Site.UpstreamTLSServerName,
		InsecureSkipVerify: rt.Site.UpstreamTLSSkipVerify,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{http3.NextProtoH3},
		// 复用 QUIC/TLS1.3 会话，命中后可走 1-RTT 恢复握手，降低上游 QUIC 连接建立开销。
		ClientSessionCache: tls.NewLRUClientSessionCache(32),
	}
	if cert, hasCert, err := upstream.UpstreamClientCertificate(rt); err != nil {
		slog.Warn("h3 upstream transport skipped client cert", slog.String("site_host", rt.Site.Host), slog.String("error", err.Error()))
	} else if hasCert {
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	tr := &http3.Transport{
		TLSClientConfig:    tlsCfg,
		DisableCompression: true,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:  30 * time.Second,
			KeepAlivePeriod: 15 * time.Second,
			// 作为客户端不需要服务端反向开双向流；quic-go 的 http3 默认值也是 -1。
			// 保留 256 会让恶意/异常上游按连接再开 256 条流，纯属无谓的内存暴露面。
			MaxIncomingStreams:             -1,
			InitialStreamReceiveWindow:     2 << 20,
			MaxStreamReceiveWindow:         6 << 20,
			InitialConnectionReceiveWindow: 4 << 20,
			MaxConnectionReceiveWindow:     15 << 20,
		},
	}
	http3TransportMu.Lock()
	if existing, ok := http3TransportPool[key]; ok {
		http3TransportMu.Unlock()
		return existing
	}
	http3TransportPool[key] = tr
	http3TransportMu.Unlock()
	return tr
}

/**
 * http3ClientPools 按 http3.Transport 缓存 http.Client 实例，每个超时档位一份。
 *
 * 缓冲路径用 http3Clients（整体超时 30 s），流式路径用 http3NoTimeoutClients，
 * 与 HTTP/1 的一对 transport 缓存结构一致。
 */
var (
	http3ClientMu         sync.RWMutex
	http3Clients          = make(map[*http3.Transport]*http.Client)
	http3NoTimeoutClients = make(map[*http3.Transport]*http.Client)
)

/**
 * SharedPooledClient 为解析出的上游 transport 返回池化 http.Client，按 transport 类型选池。
 *
 * 分流规则：
 * - *http.Transport 走 sharedClient / sharedNoTimeoutClient（原缓存）；
 * - *http3.Transport 走本文件新增的 http3Clients / http3NoTimeoutClients，
 *   与 transport 生命周期同步增减，使 UpstreamTransportPoolStats 的
 *   HTTP3Clients / HTTP3NoTimeoutClients 反映真实池规模（不再恒 0）。
 *
 * @param transport 已解析的上游 RoundTripper。
 * @param timeout 客户端整体超时；<= 0 表示无超时档位。
 * @return 该 transport 对应的池化 client。
 */
func SharedPooledClient(transport http.RoundTripper, timeout time.Duration) *http.Client {
	var hc *http.Client
	switch tr := transport.(type) {
	case *http.Transport:
		if timeout > 0 {
			return sharedClient(tr)
		}
		return sharedNoTimeoutClient(tr)
	case *http3.Transport:
		if timeout > 0 {
			http3ClientMu.RLock()
			if existing, ok := http3Clients[tr]; ok {
				http3ClientMu.RUnlock()
				return existing
			}
			http3ClientMu.RUnlock()

			hc = &http.Client{Transport: newUpstreamHTTP3RoundTripper(tr), Timeout: timeout}
			http3ClientMu.Lock()
			if existing, ok := http3Clients[tr]; ok {
				http3ClientMu.Unlock()
				return existing
			}
			http3Clients[tr] = hc
			http3ClientMu.Unlock()
			return hc
		}
		http3ClientMu.RLock()
		if existing, ok := http3NoTimeoutClients[tr]; ok {
			http3ClientMu.RUnlock()
			return existing
		}
		http3ClientMu.RUnlock()

		hc = &http.Client{Transport: newUpstreamHTTP3RoundTripper(tr), Timeout: 0}
		http3ClientMu.Lock()
		if existing, ok := http3NoTimeoutClients[tr]; ok {
			http3ClientMu.Unlock()
			return existing
		}
		http3NoTimeoutClients[tr] = hc
		http3ClientMu.Unlock()
		return hc
	default:
		// SSE 等经 SharedNoTimeoutClientForRoundTripper 的 RoundTripper 变体不在此列；
		// 剩余形态无法按 transport 池化，回到原有每请求分配的保守路径。
		return &http.Client{Transport: transport, Timeout: timeout}
	}
}

// PruneStats 记录被修剪掉的上游 transport 与 client 数量。
type PruneStats struct {
	HTTPTransports           int
	HTTP2CleartextTransports int
	HTTPClients              int
	HTTPNoTimeoutClients     int
	HTTP3Transports          int
	HTTP3Clients             int
	HTTP3NoTimeoutClients    int
}

/**
 * Changed 判断是否有任何 transport 或 client 被修剪。
 *
 * @return 有修剪发生时返回 true。
 */
func (s PruneStats) Changed() bool {
	return s.HTTPTransports > 0 || s.HTTP2CleartextTransports > 0 || s.HTTPClients > 0 || s.HTTPNoTimeoutClients > 0 ||
		s.HTTP3Transports > 0 || s.HTTP3Clients > 0 || s.HTTP3NoTimeoutClients > 0
}

/**
 * PruneInactiveUpstreamTransports 移除快照中已无任何站点引用的 transport 与 client。
 *
 * @param sn 当前快照。
 * @return 各类池的修剪计数。
 */
func PruneInactiveUpstreamTransports(sn *snapshot.Snapshot) PruneStats {
	if sn == nil || len(sn.Sites) == 0 {
		return PruneStats{}
	}
	// 用当前快照构建活跃 transport 键集合。站点可配置多条上游，每条经
	// transportKeyForUpstream 映射到一个池键，必须【逐条计入】：只取首条会让
	// 其余在用 transport 被判为不活跃而删除。无上游的站点不建池（调用方在取
	// 上游前已按「无上游」返回 502），故不必计入。
	active := make(map[transportKey]struct{})
	for _, rt := range sn.Sites {
		for _, base := range rt.UpstreamURLs {
			active[transportKeyForUpstream(base, *rt)] = struct{}{}
		}
	}

	var stats PruneStats
	transportMu.Lock()
	for key, tr := range transportPool {
		if _, ok := active[key]; !ok {
			delete(transportPool, key)
			if key.h2cPrior {
				stats.HTTP2CleartextTransports++
			} else {
				stats.HTTPTransports++
			}
			// 连带移除配套的 client。
			clientPoolMu.Lock()
			if _, ok := clientCache[tr]; ok {
				delete(clientCache, tr)
				stats.HTTPClients++
			}
			if _, ok := noTimeoutClientPool[tr]; ok {
				delete(noTimeoutClientPool, tr)
				stats.HTTPNoTimeoutClients++
			}
			clientPoolMu.Unlock()
		}
	}
	transportMu.Unlock()

	// 修剪 h3 transport 与配套 client：h3 请求路径经 UpstreamRoundTripperForBase
	// 只对 h3:// 站点调用，与 HTTP/1 的 active transportKey 无关，须另行计算
	// h3 transport key 的活跃集；client 池以 *http3.Transport 为键，transport
	// 从池中移除后 client 同步移除，否则统计会虚报「已无 transport 的 client」。
	activeH3 := make(map[http3TransportKey]struct{})
	for _, rt := range sn.Sites {
		// 与 HTTP/1 活跃集同口径：逐条上游判断。多上游站点里非首条的 h3 上游
		// 同样要计入，否则其在用 transport 会被判为不活跃而删除。
		for _, base := range rt.UpstreamURLs {
			if !strings.HasPrefix(strings.ToLower(base), "h3://") {
				continue
			}
			// 与 UpstreamRoundTripperForBase 一致：剥离 h3:// 前缀后取 host 部分作为 key。
			hostPart := base[len("h3://"):]
			if i := strings.IndexByte(hostPart, '/'); i >= 0 {
				hostPart = hostPart[:i]
			}
			key := http3TransportKey{
				upstreamHost:          hostPart,
				tlsServerName:         rt.Site.UpstreamTLSServerName,
				tlsSkipVerify:         rt.Site.UpstreamTLSSkipVerify,
				clientCertFingerprint: upstreamClientCertFingerprint(*rt),
			}
			activeH3[key] = struct{}{}
		}
	}
	http3TransportMu.Lock()
	for key, tr := range http3TransportPool {
		if _, ok := activeH3[key]; ok {
			continue
		}
		delete(http3TransportPool, key)
		stats.HTTP3Transports++
		http3ClientMu.Lock()
		if _, ok := http3Clients[tr]; ok {
			delete(http3Clients, tr)
			stats.HTTP3Clients++
		}
		if _, ok := http3NoTimeoutClients[tr]; ok {
			delete(http3NoTimeoutClients, tr)
			stats.HTTP3NoTimeoutClients++
		}
		http3ClientMu.Unlock()
	}
	http3TransportMu.Unlock()
	return stats
}

/**
 * CloseIdleUpstreamTransports 关闭所有已缓存 transport 上的空闲连接。
 *
 * @return 依次为 HTTP、H2C、HTTP/3 transport 的关闭数量。
 */
func CloseIdleUpstreamTransports() (int, int, int) {
	var httpCount, h2cCount, h3Count int
	transportMu.RLock()
	all := make([]*http.Transport, 0, len(transportPool))
	for key, tr := range transportPool {
		all = append(all, tr)
		if key.h2cPrior {
			h2cCount++
		} else {
			httpCount++
		}
	}
	transportMu.RUnlock()
	for _, tr := range all {
		tr.CloseIdleConnections()
	}
	// 与上面 HTTP/1 分支同构：锁内复制到切片、锁外遍历。直接在读锁外 range
	// 会与 Prune 的 delete、建池方的赋值并发，触发 Go 运行时的
	// "concurrent map iteration and map write" 致命错误（不可 recover）。
	http3TransportMu.RLock()
	allH3 := make([]*http3.Transport, 0, len(http3TransportPool))
	for _, tr := range http3TransportPool {
		allH3 = append(allH3, tr)
	}
	h3Count = len(allH3)
	http3TransportMu.RUnlock()
	for _, tr := range allH3 {
		tr.CloseIdleConnections()
	}
	return httpCount, h2cCount, h3Count
}

/**
 * transportKeyForUpstream 依据上游基础 URL 与站点运行时构造 transport 键。
 *
 * @param base 上游基础 URL。
 * @param rt 站点运行时。
 * @return 传输池键。
 */
/**
 * transportKeyForUpstream 由上游 base URL 与站点运行时构造 transport 池键。
 *
 * 键必须与真正建池的 sharedTransportForUpstreamClassified【同构】，否则活跃集
 * 匹配不到池内条目，在用 transport 会被 PruneInactiveUpstreamTransports 误删：
 *
 *   - TLS 维度只在 isHTTPS 为真时写入（明文上游的 transport 不带 TLSClientConfig，
 *     哪怕站点填了 SNI / skip-verify / 客户端证书）；
 *   - h2cPrior 恒为零值 —— h2c 走 h2cTransportForUpstream 单例，从不写入本池。
 *
 * 多上游站点须对【每一条】上游调用本函数，否则非首条上游的 scheme 不在活跃集里。
 *
 * @param base 单条上游 base URL。
 * @param rt 站点运行时快照。
 * @return 与建池方一致的 transport 池键。
 */
func transportKeyForUpstream(base string, rt snapshot.SiteRuntime) transportKey {
	key := transportKey{}
	if base != "" {
		// RPC 别名先做归一，保证 tls/grpcs 与 https 在 transport 池中同键。
		if target, _, ok := upstream.RPCUpstreamAliasForURL(base); ok {
			key.isHTTPS = target == "https"
		} else if u, err := url.Parse(base); err == nil {
			key.isHTTPS = u.Scheme == "https" || u.Scheme == "wss"
		}
	}
	if key.isHTTPS {
		key.tlsServerName = rt.Site.UpstreamTLSServerName
		key.tlsSkipVerify = rt.Site.UpstreamTLSSkipVerify
		key.clientCertFingerprint = upstreamClientCertFingerprint(rt)
	}
	return key
}

// 上游连接的 HTTP/3 transport 池。
type http3TransportKey struct {
	upstreamHost          string
	tlsServerName         string
	tlsSkipVerify         bool
	clientCertFingerprint string
}

var (
	http3TransportMu   sync.RWMutex
	http3TransportPool = make(map[http3TransportKey]*http3.Transport)
)

/**
 * UpstreamTransportPoolStats 承载上游传输池的瞬时统计。
 *
 * HTTP3Clients / HTTP3NoTimeoutClients 反映 http3ClientPools 的真实规模
 * （h3 上游请求路径按 transport 池化），不再是占位常量。
 */
type UpstreamTransportPoolStats struct {
	HTTPTransports           int
	HTTP2CleartextTransports int
	HTTP3Transports          int
	HTTPClients              int
	HTTPNoTimeoutClients     int
	HTTP3Clients             int
	HTTP3NoTimeoutClients    int
}

/**
 * UpstreamTransportPoolStatsSnapshot 返回当前各池的统计快照。
 *
 * @return 传输池统计。
 */
func UpstreamTransportPoolStatsSnapshot() UpstreamTransportPoolStats {
	transportMu.RLock()
	httpTransports := 0
	h2cTransports := 0
	for key := range transportPool {
		if key.h2cPrior {
			h2cTransports++
		} else {
			httpTransports++
		}
	}
	transportMu.RUnlock()

	clientPoolMu.RLock()
	httpClients := len(clientCache)
	noTimeoutClients := len(noTimeoutClientPool)
	clientPoolMu.RUnlock()

	http3TransportMu.RLock()
	http3Transports := len(http3TransportPool)
	http3TransportMu.RUnlock()

	http3ClientMu.RLock()
	http3ClientsN := len(http3Clients)
	http3NoTimeoutClientsN := len(http3NoTimeoutClients)
	http3ClientMu.RUnlock()

	return UpstreamTransportPoolStats{
		HTTPTransports:           httpTransports,
		HTTP2CleartextTransports: h2cTransports,
		HTTP3Transports:          http3Transports,
		HTTPClients:              httpClients,
		HTTPNoTimeoutClients:     noTimeoutClients,
		HTTP3Clients:             http3ClientsN,
		HTTP3NoTimeoutClients:    http3NoTimeoutClientsN,
	}
}
