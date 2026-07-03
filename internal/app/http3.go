package app

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"My-OpenWaf/internal/dataplane"
	snapshotpkg "My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/upstream"
	"My-OpenWaf/internal/waf/bot"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type HTTP3Server struct {
	server         *http3.Server
	proxyTransport *http.Transport
	bind           string
	routeTable     http3RouteTable
	log            *slog.Logger
	stopChan       chan struct{}
	stopOnce       sync.Once
	listenMu       sync.Mutex
	packetConn     net.PacketConn
	spinStarted    bool
	spinDone       chan struct{}
	spinDoneOnce   sync.Once
}

type http3TLSFingerprintContextKey struct{}

type http3HandshakeFingerprintStore struct {
	mu    sync.Mutex
	items map[string]http3HandshakeFingerprintEntry
}

type http3HandshakeFingerprintEntry struct {
	fingerprint bot.TLSClientFingerprint
	createdAt   time.Time
}

const (
	http3HandshakeFingerprintTTL       = 2 * time.Minute
	http3LoopbackDialTimeout           = 5 * time.Second
	http3LoopbackTCPKeepAlive          = 30 * time.Second
	http3LoopbackTLSHandshakeTimeout   = 10 * time.Second
	http3LoopbackIdleConnTimeout       = 90 * time.Second
	http3LoopbackExpectContinueTimeout = time.Second
)

type http3RouteTable struct {
	exact             map[string]string
	wildcard          map[string]string
	defaultTCPBind    string
	exactConflicts    []string
	wildcardConflicts []string
}

type http3RouteConflictDiagnostics struct {
	UDPBind       string
	ExactHosts    []string
	WildcardHosts []string
}

func (d http3RouteConflictDiagnostics) HasConflicts() bool {
	return len(d.ExactHosts) > 0 || len(d.WildcardHosts) > 0
}

func (d http3RouteConflictDiagnostics) Summary() string {
	if !d.HasConflicts() {
		return ""
	}
	var parts []string
	if len(d.ExactHosts) > 0 {
		parts = append(parts, "exact="+strings.Join(d.ExactHosts, ","))
	}
	if len(d.WildcardHosts) > 0 {
		parts = append(parts, "wildcard="+strings.Join(d.WildcardHosts, ","))
	}
	return strings.Join(parts, ";")
}

type http3ServerPlan struct {
	Bind       string
	Tag        string
	RouteTable http3RouteTable
	TLSConfig  *tls.Config
}

type http3SNICertificate struct {
	bind string
	cert *tls.Certificate
}

type http3RequestTrailerSyncReadCloser struct {
	body   io.ReadCloser
	source *http.Request
	target http.Header
	once   sync.Once
}

func (r *http3RequestTrailerSyncReadCloser) Read(p []byte) (int, error) {
	n, err := r.body.Read(p)
	if err == io.EOF {
		r.once.Do(r.syncTrailers)
	}
	return n, err
}

func (r *http3RequestTrailerSyncReadCloser) Close() error {
	return r.body.Close()
}

func (r *http3RequestTrailerSyncReadCloser) syncTrailers() {
	if r.source == nil || r.target == nil {
		return
	}
	copyHTTPHeaderInto(r.target, r.source.Trailer)
}

func copyHTTPHeaderInto(dst http.Header, src http.Header) {
	if dst == nil {
		return
	}
	for key := range dst {
		delete(dst, key)
	}
	for key, values := range src {
		if len(values) == 0 {
			dst[key] = nil
			continue
		}
		cloned := make([]string, len(values))
		copy(cloned, values)
		dst[key] = cloned
	}
}

type http3AltSvcAdvertisement struct {
	value      string
	tcpBind    string
	udpBind    string
	routeTable http3RouteTable
}

type HTTP3ServerConfig struct {
	Bind       string
	RouteTable http3RouteTable
	TLSConfig  *tls.Config
	Log        *slog.Logger
}

func NewHTTP3Server(cfg HTTP3ServerConfig) *HTTP3Server {
	proxy := &httputil.ReverseProxy{}
	proxy.FlushInterval = -1
	proxy.ModifyResponse = func(resp *http.Response) error {
		contentType := strings.ToLower(resp.Header.Get("Content-Type"))
		contentEncoding := resp.Header.Get("Content-Encoding")
		if strings.Contains(contentType, "text/event-stream") || contentEncoding != "" {
			resp.Header.Del("Content-Length")
			resp.ContentLength = -1
		}
		return nil
	}
	handshakeFingerprints := newHTTP3HandshakeFingerprintStore()
	proxyTransport := &http.Transport{
		TLSClientConfig:       http3LoopbackTLSConfig(),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       http3LoopbackIdleConnTimeout,
		TLSHandshakeTimeout:   http3LoopbackTLSHandshakeTimeout,
		ExpectContinueTimeout: http3LoopbackExpectContinueTimeout,
		DisableCompression:    true,
		DialContext: (&net.Dialer{
			Timeout:   http3LoopbackDialTimeout,
			KeepAlive: http3LoopbackTCPKeepAlive,
		}).DialContext,
	}
	proxy.Transport = proxyTransport
	proxy.Rewrite = func(pr *httputil.ProxyRequest) {
		if pr == nil || pr.Out == nil {
			return
		}
		targetBind, ok := resolveHTTP3TCPBind(cfg.RouteTable, pr.In)
		if !ok {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = ""
			return
		}

		originalHost := pr.In.Host
		pr.Out.URL.Scheme = "https"
		pr.Out.URL.Host = loopbackTargetHost(targetBind)
		pr.Out.URL.RawQuery = pr.In.URL.RawQuery
		clearInternalHTTP3TLSHeaders(pr.Out.Header)
		pr.SetXForwarded()
		if originalHost != "" {
			pr.Out.Host = originalHost
			pr.Out.Header.Set("X-Forwarded-Host", originalHost)
		} else {
			pr.Out.Header.Del("X-Forwarded-Host")
		}
		pr.Out.Header.Set("X-Forwarded-Proto", "h3")
		pr.Out.Header.Set(dataplane.InternalHTTP3ProtoHeader, "h3")
		if strings.EqualFold(strings.TrimSpace(pr.Out.Method), http.MethodHead) && pr.Out.ContentLength <= 0 {
			pr.Out.Body = nil
			pr.Out.GetBody = nil
			pr.Out.ContentLength = 0
			pr.Out.TransferEncoding = nil
			pr.Out.Header.Del("Content-Length")
		}
		if len(pr.In.Trailer) > 0 || len(pr.Out.Trailer) > 0 {
			pr.Out.Header.Set("TE", "trailers")
			if pr.Out.Body != nil {
				if pr.Out.Trailer == nil {
					pr.Out.Trailer = make(http.Header, len(pr.In.Trailer))
					for key := range pr.In.Trailer {
						pr.Out.Trailer[key] = nil
					}
				}
				pr.Out.Body = &http3RequestTrailerSyncReadCloser{
					body:   pr.Out.Body,
					source: pr.In,
					target: pr.Out.Trailer,
				}
			}
		}
		applyHTTP3ProxyTLSHeaders(pr.Out)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := resolveHTTP3TCPBind(cfg.RouteTable, r); !ok {
			http.Error(w, "no HTTP/3 route target", http.StatusBadGateway)
			return
		}
		w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(cfg.Bind)))
		proxy.ServeHTTP(w, r)
	})

	tlsCfg := cfg.TLSConfig.Clone()
	instrumentHTTP3TLSConfig(tlsCfg, handshakeFingerprints)
	tlsCfg.NextProtos = []string{"h3"}
	if tlsCfg.MinVersion == 0 || tlsCfg.MinVersion < tls.VersionTLS13 {
		tlsCfg.MinVersion = tls.VersionTLS13
	}
	if tlsCfg.MaxVersion != 0 && tlsCfg.MaxVersion < tls.VersionTLS13 {
		tlsCfg.MaxVersion = tls.VersionTLS13
	}

	h3Server := &http3.Server{
		Addr:      cfg.Bind,
		Handler:   handler,
		TLSConfig: tlsCfg,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			if conn == nil {
				return ctx
			}
			if fp, ok := handshakeFingerprints.Take(conn.LocalAddr(), conn.RemoteAddr()); ok {
				ctx = contextWithHTTP3TLSFingerprint(ctx, fp)
			}
			return ctx
		},
	}

	return &HTTP3Server{
		server:         h3Server,
		proxyTransport: proxyTransport,
		bind:           cfg.Bind,
		routeTable:     cfg.RouteTable,
		log:            cfg.Log,
		stopChan:       make(chan struct{}),
		spinDone:       make(chan struct{}),
	}
}

func http3LoopbackTLSConfig() *tls.Config {
	cfg := upstream.HTTPSClientTLSConfig("", true)
	cfg.NextProtos = []string{"h2", "http/1.1"}
	return cfg
}

func http3LoopbackTLSCipherSuites() []uint16 {
	cfg := upstream.HTTPSClientTLSConfig("", true)
	if cfg == nil {
		return nil
	}
	return cfg.CipherSuites
}

func (s *HTTP3Server) Spin() {
	s.listenMu.Lock()
	s.spinStarted = true
	s.listenMu.Unlock()
	defer s.markSpinDone()

	s.log.Info("HTTP/3 QUIC server starting",
		slog.String("udp_bind", s.bind),
		slog.String("targets", s.routeTable.targetSummary()),
	)
	select {
	case <-s.stopChan:
		return
	default:
	}
	packetConn, err := net.ListenPacket("udp", s.bind)
	if err != nil {
		select {
		case <-s.stopChan:
			return
		default:
			s.log.Error("HTTP/3 server error", slog.Any("err", err))
			return
		}
	}
	if !s.setPacketConn(packetConn) {
		_ = packetConn.Close()
		return
	}
	defer func() {
		s.clearPacketConn(packetConn)
		_ = packetConn.Close()
	}()
	if err := s.server.Serve(packetConn); err != nil && err != http.ErrServerClosed {
		select {
		case <-s.stopChan:
			// 正常关闭
		default:
			s.log.Error("HTTP/3 server error", slog.Any("err", err))
		}
	}
}

func (s *HTTP3Server) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var shutdownErr error
	s.stopOnce.Do(func() {
		close(s.stopChan)
		if s.proxyTransport != nil {
			s.proxyTransport.CloseIdleConnections()
		}
		shutdownErr = s.server.Shutdown(ctx)
		if err := s.closePacketConn(); err != nil && !errors.Is(err, net.ErrClosed) {
			shutdownErr = errors.Join(shutdownErr, err)
		}
	})
	if done, ok := s.spinDoneIfStarted(); ok {
		select {
		case <-done:
		case <-ctx.Done():
			shutdownErr = errors.Join(shutdownErr, ctx.Err())
		}
	}
	return shutdownErr
}

func (s *HTTP3Server) setPacketConn(conn net.PacketConn) bool {
	s.listenMu.Lock()
	defer s.listenMu.Unlock()
	select {
	case <-s.stopChan:
		return false
	default:
	}
	s.packetConn = conn
	return true
}

func (s *HTTP3Server) clearPacketConn(conn net.PacketConn) {
	s.listenMu.Lock()
	defer s.listenMu.Unlock()
	if s.packetConn == conn {
		s.packetConn = nil
	}
}

func (s *HTTP3Server) closePacketConn() error {
	s.listenMu.Lock()
	conn := s.packetConn
	s.packetConn = nil
	s.listenMu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.Close()
}

func (s *HTTP3Server) spinDoneIfStarted() (<-chan struct{}, bool) {
	s.listenMu.Lock()
	defer s.listenMu.Unlock()
	if !s.spinStarted || s.spinDone == nil {
		return nil, false
	}
	return s.spinDone, true
}

func (s *HTTP3Server) markSpinDone() {
	if s.spinDone == nil {
		return
	}
	s.spinDoneOnce.Do(func() {
		close(s.spinDone)
	})
}

func newHTTP3HandshakeFingerprintStore() *http3HandshakeFingerprintStore {
	return &http3HandshakeFingerprintStore{
		items: make(map[string]http3HandshakeFingerprintEntry),
	}
}

func contextWithHTTP3TLSFingerprint(ctx context.Context, fp bot.TLSClientFingerprint) context.Context {
	if !fp.HasValue() {
		return ctx
	}
	return context.WithValue(ctx, http3TLSFingerprintContextKey{}, fp)
}

func http3TLSFingerprintFromContext(ctx context.Context) (bot.TLSClientFingerprint, bool) {
	fp, ok := ctx.Value(http3TLSFingerprintContextKey{}).(bot.TLSClientFingerprint)
	return fp, ok && fp.HasValue()
}

func instrumentHTTP3TLSConfig(tlsCfg *tls.Config, fingerprints *http3HandshakeFingerprintStore) {
	if tlsCfg == nil || fingerprints == nil {
		return
	}
	if tlsCfg.GetConfigForClient == nil && tlsCfg.GetCertificate == nil {
		tlsCfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			fingerprints.StoreFromClientHello(hello)
			return nil, nil
		}
		return
	}
	if previous := tlsCfg.GetConfigForClient; previous != nil {
		tlsCfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			fingerprints.StoreFromClientHello(hello)
			cfg, err := previous(hello)
			if cfg != nil {
				instrumentHTTP3TLSConfig(cfg, fingerprints)
			}
			return cfg, err
		}
	}
	if previous := tlsCfg.GetCertificate; previous != nil {
		tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			fingerprints.StoreFromClientHello(hello)
			return previous(hello)
		}
	}
}

func clearInternalHTTP3TLSHeaders(headers http.Header) {
	headers.Del(dataplane.InternalHTTP3ProtoHeader)
	headers.Del(dataplane.InternalHTTP3TLSVersionHeader)
	headers.Del(dataplane.InternalHTTP3TLSSNIHeader)
	headers.Del(dataplane.InternalHTTP3TLSALPNHeader)
	headers.Del(dataplane.InternalHTTP3TLSJA3Header)
	headers.Del(dataplane.InternalHTTP3TLSJA3HashHeader)
	headers.Del(dataplane.InternalHTTP3TLSJA4Header)
	headers.Del(dataplane.InternalHTTP3TLSCipherSuitesHeader)
	headers.Del(dataplane.InternalHTTP3TLSExtensionsHeader)
	headers.Del(dataplane.InternalHTTP3TLSCurvesHeader)
	headers.Del(dataplane.InternalHTTP3TLSPointFormatsHeader)
}

func applyHTTP3ProxyTLSHeaders(r *http.Request) {
	if r == nil {
		return
	}
	fp := http3RequestTLSFingerprint(r)
	if fp.TLSVersion != "" {
		r.Header.Set(dataplane.InternalHTTP3TLSVersionHeader, fp.TLSVersion)
	}
	if fp.SNI != "" {
		r.Header.Set(dataplane.InternalHTTP3TLSSNIHeader, fp.SNI)
	}
	if len(fp.ALPN) > 0 && strings.TrimSpace(fp.ALPN[0]) != "" {
		r.Header.Set(dataplane.InternalHTTP3TLSALPNHeader, strings.TrimSpace(fp.ALPN[0]))
	}
	if fp.JA3 != "" {
		r.Header.Set(dataplane.InternalHTTP3TLSJA3Header, fp.JA3)
	}
	if fp.JA3Hash != "" {
		r.Header.Set(dataplane.InternalHTTP3TLSJA3HashHeader, fp.JA3Hash)
	}
	if fp.JA4 != "" {
		r.Header.Set(dataplane.InternalHTTP3TLSJA4Header, fp.JA4)
	}
	if len(fp.CipherSuites) > 0 {
		r.Header.Set(dataplane.InternalHTTP3TLSCipherSuitesHeader, formatHTTP3Uint16List(fp.CipherSuites))
	}
	if len(fp.Extensions) > 0 {
		r.Header.Set(dataplane.InternalHTTP3TLSExtensionsHeader, formatHTTP3Uint16List(fp.Extensions))
	}
	if len(fp.Curves) > 0 {
		r.Header.Set(dataplane.InternalHTTP3TLSCurvesHeader, formatHTTP3Uint16List(fp.Curves))
	}
	if len(fp.PointFormats) > 0 {
		r.Header.Set(dataplane.InternalHTTP3TLSPointFormatsHeader, formatHTTP3Uint8List(fp.PointFormats))
	}
}

func http3RequestTLSFingerprint(r *http.Request) bot.TLSClientFingerprint {
	if r == nil {
		return bot.TLSClientFingerprint{}
	}
	fp, _ := http3TLSFingerprintFromContext(r.Context())
	if r.TLS != nil {
		if version := tlsVersionName(r.TLS.Version); version != "" {
			fp.TLSVersion = version
		}
		if sni := strings.TrimSpace(r.TLS.ServerName); sni != "" {
			fp.SNI = sni
		}
		if alpn := strings.TrimSpace(r.TLS.NegotiatedProtocol); alpn != "" {
			fp.ALPN = []string{alpn}
		}
	}
	return fp
}

func http3HandshakeFingerprintKey(localAddr net.Addr, remoteAddr net.Addr) string {
	if localAddr == nil || remoteAddr == nil {
		return ""
	}
	return localAddr.Network() + "\x00" + localAddr.String() + "\x00" + remoteAddr.Network() + "\x00" + remoteAddr.String()
}

func (s *http3HandshakeFingerprintStore) StoreFromClientHello(hello *tls.ClientHelloInfo) {
	if s == nil || hello == nil || hello.Conn == nil {
		return
	}
	s.Store(hello.Conn.LocalAddr(), hello.Conn.RemoteAddr(), bot.TLSFingerprintFromClientHelloInfo(hello, 'q'))
}

func (s *http3HandshakeFingerprintStore) Store(localAddr net.Addr, remoteAddr net.Addr, fp bot.TLSClientFingerprint) {
	if s == nil || !fp.HasValue() {
		return
	}
	key := http3HandshakeFingerprintKey(localAddr, remoteAddr)
	if key == "" {
		return
	}
	s.mu.Lock()
	s.pruneExpiredLocked(time.Now())
	s.items[key] = http3HandshakeFingerprintEntry{
		fingerprint: fp,
		createdAt:   time.Now(),
	}
	s.mu.Unlock()
}

func (s *http3HandshakeFingerprintStore) Take(localAddr net.Addr, remoteAddr net.Addr) (bot.TLSClientFingerprint, bool) {
	if s == nil {
		return bot.TLSClientFingerprint{}, false
	}
	key := http3HandshakeFingerprintKey(localAddr, remoteAddr)
	if key == "" {
		return bot.TLSClientFingerprint{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(time.Now())
	entry, ok := s.items[key]
	if !ok {
		return bot.TLSClientFingerprint{}, false
	}
	delete(s.items, key)
	return entry.fingerprint, entry.fingerprint.HasValue()
}

func (s *http3HandshakeFingerprintStore) pruneExpiredLocked(now time.Time) {
	for key, entry := range s.items {
		if now.Sub(entry.createdAt) > http3HandshakeFingerprintTTL {
			delete(s.items, key)
		}
	}
}

func formatHTTP3Uint16List(values []uint16) string {
	if len(values) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(values) * 6)
	for i, value := range values {
		if i > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(strconv.FormatUint(uint64(value), 10))
	}
	return builder.String()
}

func formatHTTP3Uint8List(values []uint8) string {
	if len(values) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(values) * 4)
	for i, value := range values {
		if i > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(strconv.FormatUint(uint64(value), 10))
	}
	return builder.String()
}

func resolveHTTP3TCPBind(routeTable http3RouteTable, r *http.Request) (string, bool) {
	if r != nil {
		if bind, ok := routeTable.Resolve(r.Host); ok {
			return bind, true
		}
		if r.TLS != nil {
			if bind, ok := routeTable.Resolve(r.TLS.ServerName); ok {
				return bind, true
			}
		}
	}
	return routeTable.Resolve("")
}

func (t http3RouteTable) Resolve(host string) (string, bool) {
	normalized := snapshotpkg.NormalizeMatchHost(host)
	if normalized != "" {
		if bind, ok := t.exact[normalized]; ok {
			return bind, true
		}
		if net.ParseIP(normalized) == nil {
			if idx := strings.Index(normalized, "."); idx > 0 {
				if bind, ok := t.wildcard["*."+normalized[idx+1:]]; ok {
					return bind, true
				}
			}
		}
	}
	if t.defaultTCPBind != "" {
		return t.defaultTCPBind, true
	}
	return "", false
}

func (t http3RouteTable) targetSummary() string {
	seen := make(map[string]struct{})
	var binds []string
	for _, bind := range t.exact {
		if _, ok := seen[bind]; ok {
			continue
		}
		seen[bind] = struct{}{}
		binds = append(binds, bind)
	}
	for _, bind := range t.wildcard {
		if _, ok := seen[bind]; ok {
			continue
		}
		seen[bind] = struct{}{}
		binds = append(binds, bind)
	}
	if t.defaultTCPBind != "" {
		if _, ok := seen[t.defaultTCPBind]; !ok {
			binds = append(binds, t.defaultTCPBind)
		}
	}
	sort.Strings(binds)
	return strings.Join(binds, ",")
}

func (t http3RouteTable) conflictDiagnostics(udpBind string) http3RouteConflictDiagnostics {
	return http3RouteConflictDiagnostics{
		UDPBind:       strings.TrimSpace(udpBind),
		ExactHosts:    cloneHTTP3StringSlice(t.exactConflicts),
		WildcardHosts: cloneHTTP3StringSlice(t.wildcardConflicts),
	}
}

func buildHTTP3ServerPlans(sn *snapshotpkg.Snapshot) map[string]http3ServerPlan {
	plans := make(map[string]http3ServerPlan)
	if sn == nil {
		return plans
	}

	grouped := make(map[string][]snapshotpkg.SiteRuntime)
	for _, rt := range uniqueHTTP3SiteRuntimes(sn) {
		if !effectiveHTTP3Enabled(rt) {
			continue
		}
		udpBind := http3BindForSite(rt)
		if strings.TrimSpace(udpBind) == "" {
			udpBind = rt.Bind
		}
		grouped[udpBind] = append(grouped[udpBind], rt)
	}

	var udpBinds []string
	for bind := range grouped {
		udpBinds = append(udpBinds, bind)
	}
	sort.Strings(udpBinds)

	for _, udpBind := range udpBinds {
		runtimes := grouped[udpBind]
		sort.Slice(runtimes, func(i, j int) bool {
			if runtimes[i].Bind != runtimes[j].Bind {
				return runtimes[i].Bind < runtimes[j].Bind
			}
			return runtimes[i].Site.ID < runtimes[j].Site.ID
		})
		routeTable := buildHTTP3RouteTable(runtimes)
		logHTTP3RouteTableConflicts(udpBind, routeTable)
		tlsCfg := buildHTTP3ServerTLSConfigWithRouteTable(udpBind, runtimes, routeTable, sn)
		if tlsCfg == nil {
			continue
		}
		plans[http3ListenerName(udpBind)] = http3ServerPlan{
			Bind:       udpBind,
			Tag:        http3ListenerFingerprint(udpBind, runtimes, routeTable, sn),
			RouteTable: routeTable,
			TLSConfig:  tlsCfg,
		}
	}
	return plans
}

func buildHTTP3AltSvcAdvertisement(siteRT snapshotpkg.SiteRuntime, sn *snapshotpkg.Snapshot) (http3AltSvcAdvertisement, bool) {
	return buildHTTP3AltSvcAdvertisementWithPlans(siteRT, sn, nil)
}

func buildHTTP3AltSvcAdvertisementWithPlans(siteRT snapshotpkg.SiteRuntime, sn *snapshotpkg.Snapshot, plans map[string]http3ServerPlan) (http3AltSvcAdvertisement, bool) {
	if !effectiveHTTP3Enabled(siteRT) {
		return http3AltSvcAdvertisement{}, false
	}
	udpBind := http3BindForSite(siteRT)
	if strings.TrimSpace(udpBind) == "" {
		udpBind = siteRT.Bind
	}
	if plans == nil {
		plans = buildHTTP3ServerPlans(sn)
	}
	plan, ok := plans[http3ListenerName(udpBind)]
	if !ok {
		return http3AltSvcAdvertisement{}, false
	}
	return http3AltSvcAdvertisement{
		value:      fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(plan.Bind)),
		tcpBind:    siteRT.Bind,
		udpBind:    plan.Bind,
		routeTable: plan.RouteTable,
	}, true
}

func (a http3AltSvcAdvertisement) valueForHost(host string) (string, bool) {
	bind, ok := a.routeTable.Resolve(host)
	if !ok || bind != a.tcpBind {
		return "", false
	}
	return a.value, true
}

func buildHTTP3RouteTable(runtimes []snapshotpkg.SiteRuntime) http3RouteTable {
	exact := make(map[string]string)
	wildcard := make(map[string]string)
	exactConflicts := make(map[string]struct{})
	wildcardConflicts := make(map[string]struct{})
	uniqueTCPBinds := make(map[string]struct{})

	for _, rt := range runtimes {
		uniqueTCPBinds[rt.Bind] = struct{}{}
		for _, rawHost := range splitHTTP3Hosts(rt.Site.Host) {
			host := snapshotpkg.NormalizeMatchHost(rawHost)
			if host == "" {
				continue
			}
			if strings.HasPrefix(host, "*.") {
				if bind, exists := wildcard[host]; exists && bind != rt.Bind {
					wildcardConflicts[host] = struct{}{}
					delete(wildcard, host)
					continue
				}
				if _, conflicted := wildcardConflicts[host]; !conflicted {
					wildcard[host] = rt.Bind
				}
				continue
			}
			if bind, exists := exact[host]; exists && bind != rt.Bind {
				exactConflicts[host] = struct{}{}
				delete(exact, host)
				continue
			}
			if _, conflicted := exactConflicts[host]; !conflicted {
				exact[host] = rt.Bind
			}
		}
	}

	defaultTCPBind := ""
	if len(uniqueTCPBinds) == 1 {
		for bind := range uniqueTCPBinds {
			defaultTCPBind = bind
		}
	}
	return http3RouteTable{
		exact:             exact,
		wildcard:          wildcard,
		defaultTCPBind:    defaultTCPBind,
		exactConflicts:    sortedHTTP3ConflictHosts(exactConflicts),
		wildcardConflicts: sortedHTTP3ConflictHosts(wildcardConflicts),
	}
}

func logHTTP3RouteTableConflicts(udpBind string, routeTable http3RouteTable) {
	diagnostics := routeTable.conflictDiagnostics(udpBind)
	if !diagnostics.HasConflicts() {
		return
	}
	slog.Warn("HTTP/3 route table host conflicts ignored",
		slog.String("udp_bind", diagnostics.UDPBind),
		slog.String("summary", diagnostics.Summary()),
		slog.Any("exact_hosts", diagnostics.ExactHosts),
		slog.Any("wildcard_hosts", diagnostics.WildcardHosts),
	)
}

func cloneHTTP3StringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func sortedHTTP3ConflictHosts(hosts map[string]struct{}) []string {
	if len(hosts) == 0 {
		return nil
	}
	out := make([]string, 0, len(hosts))
	for host := range hosts {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func buildHTTP3ServerTLSConfig(udpBind string, runtimes []snapshotpkg.SiteRuntime, sn *snapshotpkg.Snapshot) *tls.Config {
	return buildHTTP3ServerTLSConfigWithRouteTable(udpBind, runtimes, buildHTTP3RouteTable(runtimes), sn)
}

func buildHTTP3ServerTLSConfigWithRouteTable(udpBind string, runtimes []snapshotpkg.SiteRuntime, routeTable http3RouteTable, sn *snapshotpkg.Snapshot) *tls.Config {
	if sn == nil || len(runtimes) == 0 {
		return nil
	}

	allowedTCPBinds := make(map[string]struct{}, len(runtimes))
	var defaultSiteCert *tls.Certificate
	for _, rt := range runtimes {
		allowedTCPBinds[rt.Bind] = struct{}{}
		if defaultSiteCert != nil {
			continue
		}
		if rt.TLSConfig != nil && len(rt.TLSConfig.Certificates) > 0 {
			cert := rt.TLSConfig.Certificates[0]
			defaultSiteCert = &cert
			continue
		}
		if rt.Certificate != nil {
			cert, err := tls.X509KeyPair([]byte(rt.Certificate.CertPEM), []byte(rt.Certificate.KeyPEM))
			if err == nil {
				if staple, ok := snapshotpkg.ParseOCSPStaple(rt.Certificate.OCSPStaplePEM); ok {
					cert.OCSPStaple = staple
				}
				defaultSiteCert = &cert
			}
		}
	}

	sniCertMap := make(map[string]http3SNICertificate)
	sniCertConflicts := make(map[string]struct{})
	for sniKey, cert := range sn.SiteTLSCertBySNI {
		for bind := range allowedTCPBinds {
			prefix := "sni:" + bind + "\x00"
			if !strings.HasPrefix(sniKey, prefix) {
				continue
			}
			sni := strings.TrimPrefix(sniKey, prefix)
			if _, conflicted := sniCertConflicts[sni]; conflicted {
				break
			}
			if existing, exists := sniCertMap[sni]; exists && existing.bind != bind {
				delete(sniCertMap, sni)
				sniCertConflicts[sni] = struct{}{}
				break
			}
			c := cert
			sniCertMap[sni] = http3SNICertificate{bind: bind, cert: &c}
			break
		}
	}

	if defaultSiteCert == nil && len(sniCertMap) == 0 {
		selfSigned := selfSignedForBind(udpBind)
		if selfSigned == nil {
			return nil
		}
		defaultSiteCert = selfSigned
	}

	curves := snapshotpkg.ParseCurvePreferences(sn.TLSDefaults.CurvePreferences)
	if len(curves) == 0 {
		curves = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
	}

	allowedBindCount := len(allowedTCPBinds)
	return &tls.Config{
		MinVersion:               tls.VersionTLS13,
		MaxVersion:               tls.VersionTLS13,
		NextProtos:               []string{"h3"},
		CurvePreferences:         curves,
		PreferServerCipherSuites: sn.TLSDefaults.PreferServerCipherSuites,
		SessionTicketsDisabled:   !sn.TLSDefaults.SessionTicketsEnabled,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni := strings.ToLower(strings.TrimSpace(hello.ServerName))
			if sni == "" {
				if sn.TLSDefaults.SelfSignedOnIP {
					return selfSignedForBind(udpBind), nil
				}
				if defaultSiteCert != nil {
					return defaultSiteCert, nil
				}
				return selfSignedForBind(udpBind), nil
			}
			routeBind := ""
			if allowedBindCount > 1 {
				var ok bool
				routeBind, ok = routeTable.Resolve(sni)
				if !ok {
					return selfSignedForBind(udpBind), nil
				}
			}
			if cert, ok := http3SNICertForRoute(sniCertMap, sni, routeBind); ok {
				return cert, nil
			}
			if allowedBindCount == 1 && defaultSiteCert != nil {
				return defaultSiteCert, nil
			}
			return selfSignedForBind(udpBind), nil
		},
	}
}

func http3SNICertForRoute(sniCertMap map[string]http3SNICertificate, sni string, routeBind string) (*tls.Certificate, bool) {
	if cert, ok := http3SNICertEntryForRoute(sniCertMap, sni, routeBind); ok {
		return cert, true
	}
	if idx := strings.Index(sni, "."); idx > 0 {
		return http3SNICertEntryForRoute(sniCertMap, "*."+sni[idx+1:], routeBind)
	}
	return nil, false
}

func http3SNICertEntryForRoute(sniCertMap map[string]http3SNICertificate, key string, routeBind string) (*tls.Certificate, bool) {
	entry, ok := sniCertMap[key]
	if !ok || entry.cert == nil {
		return nil, false
	}
	if routeBind != "" && entry.bind != routeBind {
		return nil, false
	}
	return entry.cert, true
}

func uniqueHTTP3SiteRuntimes(sn *snapshotpkg.Snapshot) []snapshotpkg.SiteRuntime {
	if sn == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(sn.Sites))
	items := make([]snapshotpkg.SiteRuntime, 0, len(sn.Sites))
	for _, rt := range sn.Sites {
		key := fmt.Sprintf("%d\x00%s", rt.Site.ID, rt.Bind)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		items = append(items, rt)
	}
	return items
}

func splitHTTP3Hosts(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func http3BindForSite(rt snapshotpkg.SiteRuntime) string {
	if bind := strings.TrimSpace(rt.NetworkDefaults.HTTP3Bind); bind != "" {
		return bind
	}
	return strings.TrimSpace(rt.Bind)
}

func http3ListenerName(bind string) string {
	return "h3:" + bind
}

func http3ListenerFingerprint(udpBind string, runtimes []snapshotpkg.SiteRuntime, routeTable http3RouteTable, sn *snapshotpkg.Snapshot) string {
	h := sha256.New()
	fmt.Fprintf(h, "udp_bind=%s default_tcp_bind=%s", udpBind, routeTable.defaultTCPBind)

	exactHosts := make([]string, 0, len(routeTable.exact))
	for host := range routeTable.exact {
		exactHosts = append(exactHosts, host)
	}
	sort.Strings(exactHosts)
	for _, host := range exactHosts {
		fmt.Fprintf(h, " exact=%s->%s", host, routeTable.exact[host])
	}

	wildcardHosts := make([]string, 0, len(routeTable.wildcard))
	for host := range routeTable.wildcard {
		wildcardHosts = append(wildcardHosts, host)
	}
	sort.Strings(wildcardHosts)
	for _, host := range wildcardHosts {
		fmt.Fprintf(h, " wildcard=%s->%s", host, routeTable.wildcard[host])
	}

	for _, rt := range runtimes {
		site := rt.Site
		effectiveNetwork, effectiveALPN := snapshotpkg.EffectiveSiteNetwork(site.ALPN, site.Network, rt.NetworkDefaults, rt.TLSDefaults)
		effectiveMinTLS, effectiveMaxTLS, effectiveCiphers := snapshotpkg.EffectiveSiteTLS(site.MinTLSVersion, site.MaxTLSVersion, site.CipherSuites, rt.TLSDefaults)
		fmt.Fprintf(h, " site=%d bind=%s host=%s tls=%v network=%s min=%s max=%s alpn=%s",
			site.ID,
			rt.Bind,
			strings.TrimSpace(site.Host),
			site.TLSEnabled,
			effectiveNetwork,
			effectiveMinTLS,
			effectiveMaxTLS,
			effectiveALPN,
		)
		fmt.Fprintf(h, " http3_enabled=%v http3_bind=%s ciphers=%s curves=%s prefer_server_cipher_suites=%v session_tickets_enabled=%v self_signed_on_ip=%v",
			rt.NetworkDefaults.HTTP3Enabled,
			strings.TrimSpace(rt.NetworkDefaults.HTTP3Bind),
			effectiveCiphers,
			strings.TrimSpace(rt.TLSDefaults.CurvePreferences),
			rt.TLSDefaults.PreferServerCipherSuites,
			rt.TLSDefaults.SessionTicketsEnabled,
			rt.TLSDefaults.SelfSignedOnIP,
		)
		if rt.Certificate != nil {
			cert, err := tls.X509KeyPair([]byte(rt.Certificate.CertPEM), []byte(rt.Certificate.KeyPEM))
			if err == nil {
				if staple, ok := snapshotpkg.ParseOCSPStaple(rt.Certificate.OCSPStaplePEM); ok {
					cert.OCSPStaple = staple
				}
				fmt.Fprintf(h, " cert_material=%s", tlsCertificateFingerprintMaterial(cert))
			}
		}
	}

	if sn != nil {
		relevantSNIKeys := make([]string, 0)
		allowedPrefixes := make([]string, 0, len(runtimes))
		seenPrefixes := make(map[string]struct{}, len(runtimes))
		for _, rt := range runtimes {
			prefix := "sni:" + rt.Bind + "\x00"
			if _, exists := seenPrefixes[prefix]; exists {
				continue
			}
			seenPrefixes[prefix] = struct{}{}
			allowedPrefixes = append(allowedPrefixes, prefix)
		}
		sort.Strings(allowedPrefixes)
		for sniKey := range sn.SiteTLSCertBySNI {
			for _, prefix := range allowedPrefixes {
				if strings.HasPrefix(sniKey, prefix) {
					relevantSNIKeys = append(relevantSNIKeys, sniKey)
					break
				}
			}
		}
		sort.Strings(relevantSNIKeys)
		for _, sniKey := range relevantSNIKeys {
			cert := sn.SiteTLSCertBySNI[sniKey]
			if len(cert.Certificate) > 0 {
				fmt.Fprintf(h, " sni=%s:material=%s", sniKey, tlsCertificateFingerprintMaterial(cert))
			} else {
				fmt.Fprintf(h, " sni=%s:material=%s", sniKey, tlsCertificateFingerprintMaterial(cert))
			}
		}
	}

	return hex.EncodeToString(h.Sum(nil))[:16]
}

func loopbackTargetHost(bind string) string {
	host, port, err := net.SplitHostPort(bind)
	if err == nil {
		host = strings.TrimSpace(host)
		switch host {
		case "", "0.0.0.0", "::":
			host = "127.0.0.1"
		}
		return net.JoinHostPort(host, port)
	}
	if strings.HasPrefix(bind, ":") {
		return "127.0.0.1" + bind
	}
	return bind
}

func extractPort(bind string) string {
	_, port, err := net.SplitHostPort(bind)
	if err != nil {
		if strings.HasPrefix(bind, ":") {
			return bind[1:]
		}
		return "443"
	}
	return port
}

func shouldEnableHTTP3(alpnStr string, defaults ...snapshotpkg.NetworkDefaults) bool {
	if len(defaults) > 0 && !defaults[0].HTTP3Enabled {
		return false
	}
	if strings.TrimSpace(alpnStr) == "" {
		if len(defaults) == 0 {
			alpnStr = snapshotpkg.DefaultTLSDefaults().DefaultALPN
		} else {
			alpnStr = defaults[0].DefaultALPN
			if strings.TrimSpace(alpnStr) == "" {
				alpnStr = snapshotpkg.DefaultTLSDefaults().DefaultALPN
			}
		}
	}
	return alpnIncludes(alpnStr, "h3")
}

func effectiveHTTP3Enabled(siteRT snapshotpkg.SiteRuntime) bool {
	if !siteRT.Site.TLSEnabled {
		return false
	}
	defaults := siteRT.NetworkDefaults
	if defaults == (snapshotpkg.NetworkDefaults{}) {
		defaults = snapshotpkg.DefaultNetworkDefaults()
	}
	_, effectiveALPN := snapshotpkg.EffectiveSiteNetwork(siteRT.Site.ALPN, siteRT.Site.Network, defaults, siteRT.TLSDefaults)
	return shouldEnableHTTP3(effectiveALPN, defaults)
}
