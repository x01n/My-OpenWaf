package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	hertzclient "github.com/cloudwego/hertz/pkg/app/client"
	hertzprotocol "github.com/cloudwego/hertz/pkg/protocol"
	http2config "github.com/hertz-contrib/http2/config"
	http2factory "github.com/hertz-contrib/http2/factory"
	"github.com/quic-go/quic-go/http3"

	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/security"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/dynamic"
)

type byteSliceReadCloser struct {
	data []byte
	pos  int
}

func (r *byteSliceReadCloser) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *byteSliceReadCloser) Close() error {
	return nil
}

// transportKey identifies a unique upstream TLS configuration.
type transportKey struct {
	tlsServerName string
	tlsSkipVerify bool
	isHTTPS       bool
	h2cPrior      bool
}

var (
	transportMu   sync.RWMutex
	transportPool = make(map[transportKey]*http.Transport)
)

// SharedTransport returns a cached http.Transport for the given site runtime.
// Transports are keyed by TLS config so connections are reused across requests.
func SharedTransport(rt snapshot.SiteRuntime) *http.Transport {
	base := ""
	if len(rt.UpstreamURLs) > 0 {
		base = rt.UpstreamURLs[0]
	}
	return SharedTransportForUpstream(rt, base)
}

// SharedTransportForUpstream keys the pool by the selected upstream scheme.
func SharedTransportForUpstream(rt snapshot.SiteRuntime, base string) *http.Transport {
	isHTTPS := isHTTPSUpstreamBase(base)
	key := transportKey{
		isHTTPS: isHTTPS,
	}
	if isHTTPS {
		key.tlsServerName = rt.Site.UpstreamTLSServerName
		key.tlsSkipVerify = rt.Site.UpstreamTLSSkipVerify
	}

	transportMu.RLock()
	if tr, ok := transportPool[key]; ok {
		transportMu.RUnlock()
		return tr
	}
	transportMu.RUnlock()

	tr := &http.Transport{
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   128,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
	}
	if isHTTPS {
		tr.TLSClientConfig = &tls.Config{
			ServerName:         rt.Site.UpstreamTLSServerName,
			InsecureSkipVerify: rt.Site.UpstreamTLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
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

// clientPool caches http.Client instances keyed by transport to avoid repeated allocation.
var (
	clientPoolMu sync.RWMutex
	clientCache  = make(map[*http.Transport]*http.Client)
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

type hertzClientKey struct {
	tlsServerName string
	tlsSkipVerify bool
	h2c           bool
}

var (
	hertzClientMu    sync.RWMutex
	hertzClientCache = make(map[hertzClientKey]*hertzclient.Client)
)

func sharedHertzH2CClient() (*hertzclient.Client, error) {
	key := hertzClientKey{h2c: true}
	hertzClientMu.RLock()
	if cli, ok := hertzClientCache[key]; ok {
		hertzClientMu.RUnlock()
		return cli, nil
	}
	hertzClientMu.RUnlock()
	cli, err := hertzclient.NewClient(
		hertzclient.WithResponseBodyStream(true),
		hertzclient.WithDisablePathNormalizing(true),
		hertzclient.WithNoDefaultUserAgentHeader(true),
		hertzclient.WithDialTimeout(30*time.Second),
		hertzclient.WithMaxConnsPerHost(128),
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
	lower := strings.ToLower(base)
	return strings.HasPrefix(lower, "h2c://")
}

const upstreamHTTPProtocolContextKey = "owaf.upstream_http_protocol"

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

func releaseHertzUpstreamRequest(req *hertzprotocol.Request) {
	if req == nil {
		return
	}
	_ = req.CloseBodyStream()
	hertzprotocol.ReleaseRequest(req)
}

func hertzHeaderToHTTPHeader(src interface{ VisitAll(func(key, value []byte)) }) http.Header {
	dst := make(http.Header)
	src.VisitAll(func(key, value []byte) {
		dst.Add(string(key), string(value))
	})
	return dst
}

func hertzTrailerToHTTPHeader(src *hertzprotocol.Trailer) http.Header {
	dst := make(http.Header)
	if src == nil {
		return dst
	}
	src.VisitAll(func(key, value []byte) {
		dst.Add(string(key), string(value))
	})
	return dst
}

type hertzResponseBody struct {
	reader  io.Reader
	resp    *hertzprotocol.Response
	trailer http.Header
	closed  bool
}

func (b *hertzResponseBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	if err != nil {
		b.syncTrailer()
	}
	return n, err
}

func (b *hertzResponseBody) Close() error {
	if b.closed {
		return nil
	}
	b.closed = true
	b.syncTrailer()
	var closeErr error
	if b.resp != nil {
		closeErr = b.resp.CloseBodyStream()
		hertzprotocol.ReleaseResponse(b.resp)
		b.resp = nil
	}
	return closeErr
}

func (b *hertzResponseBody) syncTrailer() {
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

func hertzResponseToHTTPResponse(base string, hresp *hertzprotocol.Response) *http.Response {
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
		Body:          &hertzResponseBody{reader: body, resp: hresp, trailer: trailer},
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

func doHertzUpstream(ctx context.Context, rt snapshot.SiteRuntime, base string, req *http.Request) (*hertzprotocol.Response, error) {
	if req == nil {
		return nil, errors.New("nil upstream request")
	}
	var (
		clientInst *hertzclient.Client
		err        error
	)
	clientInst, err = sharedHertzH2CClient()
	if err != nil {
		return nil, err
	}
	hreq := hertzprotocol.AcquireRequest()
	hreq.SetRequestURI(req.URL.String())
	hreq.Header.SetMethod(req.Method)
	hreq.URI().DisablePathNormalizing = true
	copyHTTPRequestHeadersToHertz(hreq, req)
	resp := hertzprotocol.AcquireResponse()
	if err := clientInst.Do(ctx, hreq, resp); err != nil {
		releaseHertzUpstreamRequest(hreq)
		hertzprotocol.ReleaseResponse(resp)
		return nil, err
	}
	return resp, nil
}

// NormalizeUpstreamURL converts h2c:// and h3:// URLs to http:// and https://
// so standard Go http.Client can process them.
func NormalizeUpstreamURL(raw string) string {
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "h2c://") {
		return "http://" + raw[6:]
	}
	if strings.HasPrefix(lower, "h3://") {
		return "https://" + raw[5:]
	}
	return raw
}

// UpstreamRoundTripperForBase returns an appropriate http.RoundTripper and
// normalized base URL for the given upstream URL scheme.
func UpstreamRoundTripperForBase(rt snapshot.SiteRuntime, base string) (http.RoundTripper, string) {
	lower := strings.ToLower(base)
	if strings.HasPrefix(lower, "h2c://") {
		normalizedBase := "http://" + base[6:]
		tr := h2cTransportForUpstream()
		return tr, normalizedBase
	}
	if strings.HasPrefix(lower, "h3://") {
		normalizedBase := "https://" + base[5:]
		tr := http3TransportForUpstream(rt)
		return tr, normalizedBase
	}
	return SharedTransportForUpstream(rt, base), base
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

func http3TransportForUpstream(rt snapshot.SiteRuntime) *http3.Transport {
	key := http3TransportKey{
		tlsServerName: rt.Site.UpstreamTLSServerName,
		tlsSkipVerify: rt.Site.UpstreamTLSSkipVerify,
	}
	http3TransportMu.RLock()
	if tr, ok := http3TransportPool[key]; ok {
		http3TransportMu.RUnlock()
		return tr
	}
	http3TransportMu.RUnlock()

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         rt.Site.UpstreamTLSServerName,
			InsecureSkipVerify: rt.Site.UpstreamTLSSkipVerify,
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{http3.NextProtoH3},
		},
		DisableCompression: true,
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

// HTTPResponse is a buffered upstream response used by the cache path.
type HTTPResponse struct {
	StatusCode           int
	ContentType          string
	Body                 []byte
	Header               http.Header
	UpstreamHTTPProtocol string
}

var upstreamErrorLogCounter atomic.Uint64

// shouldLogUpstreamErrorCount keeps initial evidence and samples repeated failures.
func shouldLogUpstreamErrorCount(count uint64) bool {
	return count <= 16 || count%1024 == 0
}

func upstreamErrorReason(err error) string {
	if err == nil {
		return ""
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err.Error()
	}
	return err.Error()
}

func upstreamLogPath(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	const limit = 160
	if len(path) <= limit {
		return path
	}
	return path[:limit] + "..."
}

func logUpstreamRequestError(ctx context.Context, mode string, req *http.Request, origHost string, err error) {
	logger := slog.Default()
	if !logger.Enabled(ctx, slog.LevelWarn) {
		return
	}
	count := upstreamErrorLogCounter.Add(1)
	if !shouldLogUpstreamErrorCount(count) {
		return
	}

	method := ""
	scheme := ""
	upstreamHost := ""
	queryLen := 0
	if req != nil {
		method = req.Method
		if req.URL != nil {
			scheme = req.URL.Scheme
			upstreamHost = req.URL.Host
			queryLen = len(req.URL.RawQuery)
		}
	}
	logger.LogAttrs(ctx, slog.LevelWarn, "upstream "+mode+" request failed",
		slog.String("method", method),
		slog.String("scheme", scheme),
		slog.String("upstream_host", upstreamHost),
		slog.String("path", upstreamLogPath(req)),
		slog.Int("query_len", queryLen),
		slog.String("host", origHost),
		slog.String("upstream_protocol", upstreamProtocolFromScheme(scheme)),
		slog.Uint64("failure_count", count),
		slog.String("err", upstreamErrorReason(err)),
	)
}

func upstreamProtocolFromScheme(scheme string) string {
	switch strings.ToLower(scheme) {
	case "https":
		return "h3"
	case "h2c":
		return "h2c"
	case "h3":
		return "h3"
	default:
		return scheme
	}
}

func requestPath(c *app.RequestContext) string {
	if rawPath := c.Request.URI().PathOriginal(); len(rawPath) > 0 {
		return string(rawPath)
	}
	path := string(c.Path())
	if path == "" {
		return "/"
	}
	return path
}

func upstreamRequestURL(c *app.RequestContext, base string) string {
	base = NormalizeUpstreamURL(base)
	path := c.Request.URI().PathOriginal()
	if len(path) == 0 {
		path = c.Path()
	}
	pathLen := len(path)
	if pathLen == 0 {
		pathLen = 1
	}
	q := c.URI().QueryString()
	baseLen := len(base)
	for baseLen > 0 && base[baseLen-1] == '/' {
		baseLen--
	}

	var b strings.Builder
	b.Grow(baseLen + pathLen + querySuffixLen(q))
	b.WriteString(base[:baseLen])
	if len(path) > 0 {
		b.Write(path)
	} else {
		b.WriteByte('/')
	}
	if len(q) > 0 {
		b.WriteByte('?')
		b.Write(q)
	}
	return b.String()
}

func querySuffixLen(q []byte) int {
	if len(q) == 0 {
		return 0
	}
	return 1 + len(q)
}

func requestMethod(c *app.RequestContext) string {
	method := c.Method()
	switch len(method) {
	case len("GET"):
		if bytes.Equal(method, []byte("GET")) {
			return "GET"
		}
		if bytes.Equal(method, []byte("PUT")) {
			return "PUT"
		}
	case len("POST"):
		if bytes.Equal(method, []byte("POST")) {
			return "POST"
		}
		if bytes.Equal(method, []byte("HEAD")) {
			return "HEAD"
		}
	case len("PATCH"):
		if bytes.Equal(method, []byte("PATCH")) {
			return "PATCH"
		}
		if bytes.Equal(method, []byte("TRACE")) {
			return "TRACE"
		}
	case len("DELETE"):
		if bytes.Equal(method, []byte("DELETE")) {
			return "DELETE"
		}
	case len("OPTIONS"):
		if bytes.Equal(method, []byte("OPTIONS")) {
			return "OPTIONS"
		}
		if bytes.Equal(method, []byte("CONNECT")) {
			return "CONNECT"
		}
	}
	return string(method)
}

func inboundProto(c *app.RequestContext) string {
	if v := forwardedProtoFromHeader(c.GetHeader("X-Forwarded-Proto")); v != "" {
		return v
	}
	if bytes.EqualFold(c.Request.Header.Peek("Upgrade"), []byte("websocket")) {
		if bytes.HasPrefix(bytes.ToLower(c.Request.Header.Peek("Origin")), []byte("https://")) {
			return "https"
		}
		return "http"
	}
	if string(c.Request.Scheme()) == "https" {
		return "https"
	}
	return "http"
}

func buildUpstreamRequest(ctx context.Context, c *app.RequestContext, base string, clientIP net.IP, origHost string, preserveOriginalHost bool) (*http.Request, error) {
	full := upstreamRequestURL(c, base)

	isStream := c.Request.IsBodyStream()
	hertzContentLength := c.Request.Header.ContentLength()
	var rdr io.Reader
	var bodyBytes []byte
	var bodyLen int64

	if isStream {
		stream := c.Request.BodyStream()
		if stream != nil {
			rdr = stream
			bodyLen = int64(c.Request.Header.ContentLength())
			if bodyLen < 0 {
				bodyLen = -1
			}
		}
	} else {
		bodyBytes = c.Request.Body()
		if len(bodyBytes) > 0 {
			rdr = &byteSliceReadCloser{data: bodyBytes}
			bodyLen = int64(len(bodyBytes))
		}
	}

	req, err := http.NewRequestWithContext(ctx, requestMethod(c), full, rdr)
	if err != nil {
		return nil, err
	}
	if rdr != nil {
		req.ContentLength = bodyLen
		if !isStream && len(bodyBytes) > 0 && hertzContentLength >= 0 {
			snap := append([]byte(nil), bodyBytes...)
			req.GetBody = func() (io.ReadCloser, error) {
				return &byteSliceReadCloser{data: snap}, nil
			}
		}
	}

	connStripper := NewRequestConnectionHeaderStripper(c)
	var rawTE string
	c.Request.Header.VisitAll(func(k, v []byte) {
		if isHopByHopBytes(k) {
			if asciiEqualFoldBytes(k, "te") {
				rawTE = string(v)
			}
			return
		}
		if asciiEqualFoldBytes(k, "host") {
			return
		}
		if connStripper.ShouldStrip(k) {
			return
		}
		addUpstreamHeader(req.Header, k, v)
	})

	if te := forwardableTEValue(rawTE); te != "" {
		req.Header.Set("TE", te)
	}

	ce := req.Header.Get("Content-Encoding")
	if ce != "" && rdr != nil {
		if isStream {
			decoded, didDecode, decErr := decodeUpstreamRequestBodyStream(req.Body, ce)
			if decErr != nil {
				return nil, decErr
			}
			if didDecode {
				req.Header.Del("Content-Encoding")
				req.Header.Del("Content-Length")
				req.Body = decoded
				req.ContentLength = -1
				req.GetBody = nil
			}
		} else if len(bodyBytes) > 0 {
			decoded, didDecode, decErr := decodeUpstreamRequestBody(bodyBytes, ce)
			if decErr != nil {
				return nil, decErr
			}
			if didDecode {
				req.Header.Del("Content-Encoding")
				req.Header.Del("Content-Length")
				req.Body = io.NopCloser(bytes.NewReader(decoded))
				req.ContentLength = int64(len(decoded))
				req.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(decoded)), nil
				}
			}
		}
	}

	if trailer := hertzRequestTrailer(c); trailer != nil {
		req.Trailer = trailer
		if req.ContentLength >= 0 {
			req.ContentLength = -1
			req.GetBody = nil
		}
		if req.Body != nil {
			req.Body = io.NopCloser(&trailerSyncBody{
				inner:   req.Body,
				hertz:   c,
				trailer: trailer,
			})
		}
	}

	security.ApplyOutboundForwarding(req, clientIP, origHost, preserveOriginalHost, "", inboundProto(c))
	return req, nil
}

func forwardableTEValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	for _, token := range strings.Split(raw, ",") {
		part := strings.TrimSpace(token)
		if part == "" {
			continue
		}
		name := part
		if semi := strings.IndexByte(part, ';'); semi >= 0 {
			name = strings.TrimSpace(part[:semi])
		}
		if strings.EqualFold(name, "trailers") {
			return "trailers"
		}
	}
	return ""
}

func hertzRequestTrailer(c *app.RequestContext) http.Header {
	ht := c.Request.Header.Trailer()
	if ht == nil {
		return nil
	}
	trailer := make(http.Header)
	ht.VisitAll(func(k, v []byte) {
		key := http.CanonicalHeaderKey(string(k))
		trailer[key] = append(trailer[key], string(v))
	})
	if len(trailer) == 0 {
		return nil
	}
	return trailer
}

type trailerSyncBody struct {
	inner   io.Reader
	hertz   *app.RequestContext
	trailer http.Header
	synced  bool
}

func (b *trailerSyncBody) Read(p []byte) (int, error) {
	n, err := b.inner.Read(p)
	if err == io.EOF && !b.synced {
		b.synced = true
		syncHertzTrailerToHTTP(b.hertz, b.trailer)
	}
	return n, err
}

func syncHertzTrailerToHTTP(c *app.RequestContext, dst http.Header) {
	ht := c.Request.Header.Trailer()
	if ht == nil {
		return
	}
	ht.VisitAll(func(k, v []byte) {
		key := http.CanonicalHeaderKey(string(k))
		dst[key] = []string{string(v)}
	})
}

func addUpstreamHeader(header http.Header, key, value []byte) {
	switch len(key) {
	case len("Accept"):
		if bytes.Equal(key, []byte("Accept")) {
			header["Accept"] = append(header["Accept"], string(value))
			return
		}
		if bytes.Equal(key, []byte("Origin")) {
			header["Origin"] = append(header["Origin"], string(value))
			return
		}
		if bytes.Equal(key, []byte("Pragma")) {
			header["Pragma"] = append(header["Pragma"], string(value))
			return
		}
		if bytes.Equal(key, []byte("Cookie")) {
			header["Cookie"] = append(header["Cookie"], string(value))
			return
		}
	case len("Referer"):
		if bytes.Equal(key, []byte("Referer")) {
			header["Referer"] = append(header["Referer"], string(value))
			return
		}
	case len("Sec-Ch-Ua"):
		if bytes.Equal(key, []byte("Sec-Ch-Ua")) {
			header["Sec-Ch-Ua"] = append(header["Sec-Ch-Ua"], string(value))
			return
		}
	case len("User-Agent"):
		if bytes.Equal(key, []byte("User-Agent")) {
			header["User-Agent"] = append(header["User-Agent"], string(value))
			return
		}
	case len("Content-Type"):
		if bytes.Equal(key, []byte("Content-Type")) {
			header["Content-Type"] = append(header["Content-Type"], string(value))
			return
		}
		if bytes.Equal(key, []byte("X-Tingyun-Id")) {
			header["X-Tingyun-Id"] = append(header["X-Tingyun-Id"], string(value))
			return
		}
	case len("Cache-Control"):
		if bytes.Equal(key, []byte("Cache-Control")) {
			header["Cache-Control"] = append(header["Cache-Control"], string(value))
			return
		}
		if bytes.Equal(key, []byte("X-Client-Data")) {
			header["X-Client-Data"] = append(header["X-Client-Data"], string(value))
			return
		}
	case len("Content-Length"):
		if bytes.Equal(key, []byte("Content-Length")) {
			header["Content-Length"] = append(header["Content-Length"], string(value))
			return
		}
		if bytes.Equal(key, []byte("Sec-Fetch-Site")) {
			header["Sec-Fetch-Site"] = append(header["Sec-Fetch-Site"], string(value))
			return
		}
		if bytes.Equal(key, []byte("Sec-Fetch-Mode")) {
			header["Sec-Fetch-Mode"] = append(header["Sec-Fetch-Mode"], string(value))
			return
		}
		if bytes.Equal(key, []byte("Sec-Fetch-Dest")) {
			header["Sec-Fetch-Dest"] = append(header["Sec-Fetch-Dest"], string(value))
			return
		}
	case len("Accept-Encoding"):
		if bytes.Equal(key, []byte("Accept-Encoding")) {
			header["Accept-Encoding"] = append(header["Accept-Encoding"], string(value))
			return
		}
		if bytes.Equal(key, []byte("Accept-Language")) {
			header["Accept-Language"] = append(header["Accept-Language"], string(value))
			return
		}
	case len("Sec-Ch-Ua-Mobile"):
		if bytes.Equal(key, []byte("Sec-Ch-Ua-Mobile")) {
			header["Sec-Ch-Ua-Mobile"] = append(header["Sec-Ch-Ua-Mobile"], string(value))
			return
		}
		if bytes.Equal(key, []byte("X-Requested-With")) {
			header["X-Requested-With"] = append(header["X-Requested-With"], string(value))
			return
		}
	case len("If-Modified-Since"):
		if bytes.Equal(key, []byte("If-Modified-Since")) {
			header["If-Modified-Since"] = append(header["If-Modified-Since"], string(value))
			return
		}
	case len("Sec-Ch-Ua-Platform"):
		if bytes.Equal(key, []byte("Sec-Ch-Ua-Platform")) {
			header["Sec-Ch-Ua-Platform"] = append(header["Sec-Ch-Ua-Platform"], string(value))
			return
		}
	case len("Upgrade-Insecure-Requests"):
		if bytes.Equal(key, []byte("Upgrade-Insecure-Requests")) {
			header["Upgrade-Insecure-Requests"] = append(header["Upgrade-Insecure-Requests"], string(value))
			return
		}
	}
	header.Add(string(key), string(value))
}

func copyResponseHeaders(dst *app.RequestContext, src http.Header) {
	debugEnabled := slog.Default().Enabled(context.Background(), slog.LevelDebug)
	var removed []string
	connTokens := responseConnectionTokens(src)
	for k, vv := range src {
		lk := strings.ToLower(k)
		if isHopByHop(lk) || connTokens[lk] {
			if debugEnabled {
				removed = append(removed, k)
			}
			continue
		}
		for _, v := range vv {
			dst.Response.Header.Add(k, v)
		}
	}
	if src.Get("Server") == "" {
		dst.Response.Header.Del("Server")
	}
	if len(removed) > 0 {
		slog.Debug("upstream hop-by-hop response headers stripped", slog.Any("headers", removed))
	}
}

// AddResponseTrailerHeaders re-adds the Trailer declaration header after copyResponseHeaders
// strips it.  This tells the downstream HTTP client which trailer fields to expect.
func AddResponseTrailerHeaders(dst *app.RequestContext, trailers http.Header) {
	if len(trailers) == 0 {
		return
	}
	for k := range trailers {
		dst.Response.Header.Add("Trailer", k)
	}
}

func responseConnectionTokens(h http.Header) map[string]bool {
	conn := h.Get("Connection")
	if conn == "" {
		return nil
	}
	tokens := make(map[string]bool)
	for _, tok := range strings.Split(conn, ",") {
		tok = strings.TrimSpace(tok)
		if tok != "" {
			tokens[strings.ToLower(tok)] = true
		}
	}
	return tokens
}

// FetchHTTP performs the upstream request and returns a buffered response.
func FetchHTTP(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string) (*HTTPResponse, error) {
	req, err := buildUpstreamRequest(ctx, c, base, clientIP, origHost, rt.PreserveOriginalHost)
	if err != nil {
		return nil, err
	}

	debugEnabled := slog.Default().Enabled(ctx, slog.LevelDebug)
	var start time.Time
	if debugEnabled {
		start = time.Now()
	}

	if shouldUseHertzUpstream(base) {
		hresp, err := doHertzUpstream(ctx, rt, base, req)
		if err != nil {
			logUpstreamRequestError(ctx, "buffered", req, origHost, err)
			return nil, err
		}
		defer hertzprotocol.ReleaseResponse(hresp)
		defer hresp.CloseBodyStream()
		if debugEnabled {
			slog.Debug("upstream buffered response received",
				slog.String("method", req.Method),
				slog.String("url", req.URL.String()),
				slog.String("host", origHost),
				slog.Int("status", hresp.StatusCode()),
				slog.Duration("latency", time.Since(start)),
			)
		}
		respBody, err := io.ReadAll(hresp.BodyStream())
		if err != nil {
			return nil, err
		}
		headers := hertzHeaderToHTTPHeader(&hresp.Header)
		return &HTTPResponse{
			StatusCode:           hresp.StatusCode(),
			ContentType:          string(hresp.Header.ContentType()),
			Body:                 respBody,
			Header:               headers,
			UpstreamHTTPProtocol: httpProtoForBase(base),
		}, nil
	}

	transport, _ := UpstreamRoundTripperForBase(rt, base)
	hc := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		logUpstreamRequestError(ctx, "buffered", req, origHost, err)
		return nil, err
	}
	defer resp.Body.Close()
	if debugEnabled {
		slog.Debug("upstream buffered response received",
			slog.String("method", req.Method),
			slog.String("url", req.URL.String()),
			slog.String("host", origHost),
			slog.Int("status", resp.StatusCode),
			slog.String("proto", resp.Proto),
			slog.Duration("latency", time.Since(start)),
		)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	headers := resp.Header.Clone()
	for k, vv := range resp.Trailer {
		for _, v := range vv {
			headers.Add(k, v)
		}
	}

	return &HTTPResponse{
		StatusCode:           resp.StatusCode,
		ContentType:          resp.Header.Get("Content-Type"),
		Body:                 respBody,
		Header:               headers,
		UpstreamHTTPProtocol: resp.Proto,
	}, nil
}

func ForwardBufferedResponse(c *app.RequestContext, resp *HTTPResponse) {
	if resp == nil {
		return
	}
	SetUpstreamHTTPProtocol(c, resp.UpstreamHTTPProtocol)
	if resp.Header != nil {
		copyResponseHeaders(c, resp.Header)
	}
	if resp.ContentType != "" && (resp.Header == nil || resp.Header.Get("Content-Type") == "") {
		c.SetContentType(resp.ContentType)
	}
	c.Status(resp.StatusCode)

	body := resp.Body
	opts := DefaultResponseCompressionOptions(true)
	body = applyClientResponseCompressionWithOptions(c, resp.StatusCode, body, opts)

	method := strings.ToUpper(string(c.Request.Method()))
	if method == "HEAD" {
		if len(body) > 0 {
			c.Response.Header.Set("Content-Length", strconv.Itoa(len(body)))
		}
		c.Response.SetBodyRaw(nil)
		return
	}
	c.Response.SetBodyRaw(body)
}

// ForwardBufferedResponseAsStream writes a buffered response as a body stream
// so Content-Length is omitted (chunked transfer).
func ForwardBufferedResponseAsStream(c *app.RequestContext, resp *HTTPResponse) {
	if resp == nil {
		return
	}
	SetUpstreamHTTPProtocol(c, resp.UpstreamHTTPProtocol)
	if resp.Header != nil {
		copyResponseHeaders(c, resp.Header)
	}
	if resp.ContentType != "" && (resp.Header == nil || resp.Header.Get("Content-Type") == "") {
		c.SetContentType(resp.ContentType)
	}
	c.Response.Header.Del("Content-Length")
	c.Status(resp.StatusCode)
	c.Response.SetBodyStream(bytes.NewReader(resp.Body), -1)
}

// SanitizeHeadersForEdgeCache strips hop-by-hop headers and Content-Length before persisting
// upstream metadata with the body. Keeps Content-Encoding (e.g. br) so cache hits decode correctly.
func SanitizeHeadersForEdgeCache(src http.Header) http.Header {
	if src == nil {
		return nil
	}
	connTokens := responseConnectionTokens(src)
	dst := src.Clone()
	for k := range dst {
		lk := strings.ToLower(k)
		if isHopByHop(lk) || connTokens[lk] {
			dst.Del(k)
		}
	}
	dst.Del("Content-Length")
	if len(dst) == 0 {
		return nil
	}
	return dst
}

// WriteCachedResponse replays a cache.ResponseEntry, including stored headers when present.
func WriteCachedResponse(c *app.RequestContext, method string, e *cache.ResponseEntry) {
	if e == nil {
		return
	}
	isHead := strings.EqualFold(strings.TrimSpace(method), "HEAD")

	if e.Header != nil && len(e.Header) > 0 {
		copyResponseHeaders(c, e.Header)
	}
	if e.ContentType != "" {
		c.SetContentType(e.ContentType)
	}
	c.Status(e.StatusCode)

	body := e.Body
	opts := DefaultResponseCompressionOptions(false)
	body = applyClientResponseCompressionWithOptions(c, e.StatusCode, body, opts)

	if isHead {
		if len(body) > 0 {
			c.Response.Header.Set("Content-Length", strconv.Itoa(len(body)))
		}
		c.Response.SetBodyRaw(nil)
		return
	}
	c.Response.SetBodyRaw(body)
}

func ShouldCacheResponse(method string, statusCode int, body []byte) bool {
	return strings.EqualFold(method, "GET") && statusCode == 200 && len(body) > 0
}

// varyDisallowsCaching reports true when Vary implies dimensions we do not key on.
// Many origins send only "Accept-Encoding"; Go's http.Client already decodes gzip bodies,
// so a single buffered variant is safe for our in-process cache.
func varyDisallowsCaching(vary string) bool {
	vary = strings.TrimSpace(vary)
	if vary == "" {
		return false
	}
	for _, p := range strings.Split(vary, ",") {
		t := strings.ToLower(strings.TrimSpace(p))
		if t == "" {
			continue
		}
		if t != "accept-encoding" {
			return true
		}
	}
	return false
}

// ShouldCacheHTTPResponse decides whether to store the upstream response in the edge cache.
// When ignoreUpstreamCacheControl is true (path matched an explicit site cache rule), upstream
// Cache-Control private/no-store is ignored so CDNs/framework defaults do not disable caching;
// Set-Cookie and unsafe Vary are still respected.
func ShouldCacheHTTPResponse(method string, resp *HTTPResponse, ignoreUpstreamCacheControl bool) bool {
	if resp == nil || !ShouldCacheResponse(method, resp.StatusCode, resp.Body) {
		return false
	}
	if resp.Header.Get("Set-Cookie") != "" {
		return false
	}
	if !ignoreUpstreamCacheControl {
		cacheControl := strings.ToLower(resp.Header.Get("Cache-Control"))
		if strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "private") {
			return false
		}
	}
	if varyDisallowsCaching(resp.Header.Get("Vary")) {
		return false
	}
	return true
}

// SiteCacheTTL returns the configured TTL in seconds for the given rule match key (path with optional "?query").
func SiteCacheTTL(rt snapshot.SiteRuntime, matchKey string) int64 {
	ttl, _ := SiteCacheTTLDetails(rt, matchKey)
	return ttl
}

// siteCacheFirstMatch returns the first matching cache rule's TTL and key-shaping flags.
func siteCacheFirstMatch(rt snapshot.SiteRuntime, matchKey string) (ttl int64, stripQueryKey bool, lowerPathKey bool, matched bool) {
	if !rt.CacheEnabled {
		return 0, false, false, false
	}
	for _, rule := range rt.CacheRules {
		pat := cacheRulePattern(rule)
		if pat == "" {
			continue
		}
		ruleType := strings.ToLower(strings.TrimSpace(rule.Type))
		if ruleType == "" {
			ruleType = "prefix"
		}
		keyFor := matchKey
		if rule.IgnoreQuery {
			keyFor = pathOnlyFromRuleMatchKey(matchKey)
		}
		var matches bool
		switch ruleType {
		case "regex":
			if rule.Regex != nil {
				matches = rule.Regex.MatchString(keyFor)
			}
		default:
			keyCmp, patCmp := keyFor, pat
			if rule.CaseInsensitive {
				keyCmp = strings.ToLower(keyCmp)
				patCmp = strings.ToLower(patCmp)
			}
			switch ruleType {
			case "exact":
				matches = keyCmp == patCmp
			case "suffix":
				matches = cacheSuffixPatternMatch(keyCmp, patCmp)
			case "contains":
				matches = strings.Contains(keyCmp, patCmp)
			default:
				matches = strings.HasPrefix(keyCmp, patCmp)
			}
		}
		if !matches {
			continue
		}
		t := int64(rule.TTL)
		if t <= 0 {
			t = int64(rt.CacheDefaultTTL)
		}
		if t > 0 {
			return t, rule.IgnoreQuery, rule.CaseInsensitive, true
		}
	}
	return 0, false, false, false
}

// SiteCacheTTLDetails returns TTL and whether a cache_rules row matched (pattern hit).
// cache_default_ttl is applied only as the TTL for a matching rule whose own ttl is <= 0;
// it does not enable caching for paths that do not match any rule.
func SiteCacheTTLDetails(rt snapshot.SiteRuntime, matchKey string) (ttl int64, matchedExplicitRule bool) {
	t, _, _, ok := siteCacheFirstMatch(rt, matchKey)
	return t, ok
}

// RuleMatchKey is path plus optional raw query string, used to evaluate cache path rules.
func RuleMatchKey(c *app.RequestContext) string {
	return ruleMatchKeyFromPathQuery(requestPath(c), c.URI().QueryString())
}

func ruleMatchKeyFromPathQuery(path string, query []byte) string {
	qs := strings.TrimSpace(string(query))
	if qs == "" {
		return path
	}
	return path + "?" + qs
}

func cacheRulePattern(r store.SiteCacheRule) string {
	v := strings.TrimSpace(r.Value)
	if v != "" {
		return v
	}
	return strings.TrimSpace(r.Path)
}

func pathOnlyFromRuleMatchKey(matchKey string) string {
	if i := strings.IndexByte(matchKey, '?'); i >= 0 {
		return matchKey[:i]
	}
	return matchKey
}

// cacheSuffixPatternMatch matches suffix rules without mid-token false positives, e.g. pattern
// "ig" must not match ".../config". File extensions (".js") and explicit path tails ("a/b.js")
// keep standard suffix semantics.
func cacheSuffixPatternMatch(matchKey, pat string) bool {
	if pat == "" {
		return false
	}
	if strings.Contains(pat, "?") {
		return strings.HasSuffix(matchKey, pat)
	}
	pathOnly := pathOnlyFromRuleMatchKey(matchKey)
	if !strings.HasSuffix(pathOnly, pat) {
		return false
	}
	if strings.HasPrefix(pat, ".") || strings.Contains(pat, "/") {
		return true
	}
	idx := len(pathOnly) - len(pat)
	if idx < 0 {
		return false
	}
	if idx == 0 {
		return true
	}
	switch pathOnly[idx-1] {
	case '/', '.', '_', '-':
		return true
	default:
		return false
	}
}

// BuildSiteCacheStorageKey builds the in-process cache key; stripQuery drops the query from the key,
// lowerPath lowercases only the path segment (not the host key) when case-insensitive rules matched.
func BuildSiteCacheStorageKey(rt snapshot.SiteRuntime, c *app.RequestContext, stripQuery, lowerPath bool) string {
	return buildSiteCacheStorageKeyFromParts(rt, c, requestPath(c), c.URI().QueryString(), stripQuery, lowerPath)
}

func buildSiteCacheStorageKeyFromParts(rt snapshot.SiteRuntime, c *app.RequestContext, path string, query []byte, stripQuery, lowerPath bool) string {
	method := string(c.Method())
	if strings.EqualFold(method, "HEAD") {
		method = "GET"
	}
	p := path
	if lowerPath {
		p = strings.ToLower(p)
	}
	q := string(query)
	if stripQuery {
		q = ""
	}
	hostKey := strings.TrimSpace(rt.Bind) + "|" + strconv.FormatUint(uint64(rt.Site.ID), 10) + "|" + snapshot.NormalizeMatchHost(string(c.Host()))
	return cache.CacheKey(method, hostKey, p, q)
}

// SiteCacheKey builds the default cache key (full query, original path casing).
func SiteCacheKey(rt snapshot.SiteRuntime, c *app.RequestContext) string {
	return BuildSiteCacheStorageKey(rt, c, false, false)
}

// SiteCacheEligible reports whether this request may use the edge response cache.
// The third return is true when a cache_rules row matched: upstream Cache-Control private/no-store
// may be ignored for storing (still never caches Set-Cookie responses).
func SiteCacheEligible(rt snapshot.SiteRuntime, c *app.RequestContext) (key string, ttl int64, ignoreUpstreamCacheControl bool) {
	if !rt.CacheEnabled {
		return "", 0, false
	}
	if !isCacheableRequestMethod(c.Method()) {
		return "", 0, false
	}
	if c.Request.Header.Get("Authorization") != "" {
		return "", 0, false
	}
	// Do not disable edge caching based on the client's Cache-Control/Pragma. Browsers and
	// devtools often send no-cache while operators still want stale shielding when upstream
	// is down. Storage eligibility remains governed by ShouldCacheHTTPResponse (upstream CC,
	// Set-Cookie, Vary, etc.).
	path := requestPath(c)
	query := c.URI().QueryString()
	full := ruleMatchKeyFromPathQuery(path, query)
	ttlVal, stripQ, lowerP, ok := siteCacheFirstMatch(rt, full)
	if !ok || ttlVal <= 0 {
		return "", 0, false
	}
	return buildSiteCacheStorageKeyFromParts(rt, c, path, query, stripQ, lowerP), ttlVal, true
}

func isCacheableRequestMethod(method []byte) bool {
	switch len(method) {
	case len("GET"):
		return asciiEqualFoldBytes(method, "get")
	case len("HEAD"):
		return asciiEqualFoldBytes(method, "head")
	}
	return false
}

// streamProbeSize is the buffer used to attempt a single Read on unknown-length
// responses. If the entire body fits in one Read (EOF returned), ForwardHTTP
// serves it buffered without compression. Otherwise it switches to streaming
// compression. 32 KiB balances memory per request with typical small-body sizes.
const streamProbeSize = 32768
const completeUnknownLengthCompressMaxBytes = 5 * snapshot.DefaultResponseCompressionMinBytes

// ForwardHTTP copies the incoming request to upstream and streams the response.
func ForwardHTTP(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string) error {
	req, err := buildUpstreamRequest(ctx, c, base, clientIP, origHost, rt.PreserveOriginalHost)
	if err != nil {
		return err
	}

	debugEnabled := slog.Default().Enabled(ctx, slog.LevelDebug)
	var start time.Time
	if debugEnabled {
		start = time.Now()
	}
	var resp *http.Response
	if shouldUseHertzUpstream(base) {
		hresp, err := doHertzUpstream(ctx, rt, base, req)
		if err != nil {
			logUpstreamRequestError(ctx, "streaming", req, origHost, err)
			return err
		}
		resp = hertzResponseToHTTPResponse(base, hresp)
	} else {
		transport, _ := UpstreamRoundTripperForBase(rt, base)
		hc := &http.Client{Transport: transport, Timeout: 0}
		var err error
		resp, err = hc.Do(req)
		if err != nil {
			logUpstreamRequestError(ctx, "streaming", req, origHost, err)
			return err
		}
	}
	SetUpstreamHTTPProtocol(c, resp.Proto)
	if debugEnabled {
		slog.Debug("upstream streaming response received",
			slog.String("method", req.Method),
			slog.String("url", req.URL.String()),
			slog.String("host", origHost),
			slog.Int("status", resp.StatusCode),
			slog.String("proto", resp.Proto),
			slog.Duration("latency", time.Since(start)),
		)
	}

	copyResponseHeaders(c, resp.Header)
	if len(resp.Trailer) > 0 {
		AddResponseTrailerHeaders(c, resp.Trailer)
	}

	// 动态防护处理：根据配置对响应内容进行加密/混淆/水印
	dp := rt.DynamicProtection
	if dp.HTMLObfuscationEnabled || dp.JSObfuscationEnabled || dp.ImageWatermarkEnabled {
		ct := resp.Header.Get("Content-Type")
		if kind := dynamic.ShouldProcessContentType(ct); kind != "" {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				return readErr
			}
			processor := dynamic.NewProcessor(dp)
			processed, procErr := processor.Process(requestPath(c), ct, body)
			if procErr != nil {
				processed = body
			}
			c.Status(resp.StatusCode)
			c.Response.SetBodyRaw(processed)
			return nil
		}
	}

	c.Status(resp.StatusCode)

	if responseStatusDisallowsBody(resp.StatusCode) {
		resp.Body.Close()
		return nil
	}
	method := strings.ToUpper(string(c.Method()))
	if method == "HEAD" {
		resp.Body.Close()
		return nil
	}

	bodyReader, closeFn, decoded, decErr := upstreamResponseReader(resp)
	if decErr != nil {
		resp.Body.Close()
		return decErr
	}

	bodySize := int(resp.ContentLength)
	if decoded {
		bodySize = -1
		c.Response.Header.Del("Content-Encoding")
		c.Response.Header.Del("Content-Length")
	}

	compOpts := defaultStreamCompressionOptions()
	effectiveCE := resp.Header.Get("Content-Encoding")
	if decoded {
		effectiveCE = ""
	}

	encoding := responseEncodingIdentity
	canCompress := false

	if bodySize >= 0 {
		canCompress = shouldTransformStreamingResponseBody(
			resp.StatusCode,
			resp.Header.Get("Content-Type"),
			effectiveCE,
			resp.Header.Get("Cache-Control"),
			resp.Header.Get("Content-Range"),
			bodySize,
			compOpts.MinBytes,
		)
	} else {
		canCompress = shouldTransformResponseMetadata(
			resp.StatusCode,
			resp.Header.Get("Content-Type"),
			effectiveCE,
			resp.Header.Get("Cache-Control"),
			resp.Header.Get("Content-Range"),
		)
	}

	if canCompress {
		encoding = selectClientResponseEncodingBytes(c.GetHeader("Accept-Encoding"), compOpts.BrotliEnabled, compOpts.GzipEnabled)
	}

	if decoded && encoding != responseEncodingIdentity {
		return streamRecompressedResponse(ctx, c, bodyReader, closeFn, resp, encoding)
	}

	if encoding != responseEncodingIdentity && bodySize >= 0 {
		return streamCompressedResponseFromReader(ctx, c, bodyReader, closeFn, resp, encoding, bodySize)
	}

	if encoding != responseEncodingIdentity && bodySize < 0 {
		probeBuf := make([]byte, streamProbeSize)
		n, readErr := bodyReader.Read(probeBuf)
		if readErr == io.EOF {
			if closeFn != nil {
				_ = closeFn()
			}
			copyResponseTrailers(c, resp)
			if n >= compOpts.MinBytes && n <= completeUnknownLengthCompressMaxBytes {
				encodedBody, encErr := compressResponseBody(probeBuf[:n], encoding)
				if encErr == nil {
					ensureVaryAcceptEncoding(c)
					c.Response.Header.Set("Content-Encoding", string(encoding))
					c.Response.Header.Del("Content-Length")
					c.Response.SetBodyRaw(encodedBody)
					return nil
				}
			}
			c.Response.SetBodyRaw(probeBuf[:n])
			return nil
		}
		if readErr != nil {
			if closeFn != nil {
				_ = closeFn()
			}
			resp.Body.Close()
			return readErr
		}
		if n < compOpts.MinBytes {
			n2, err2 := bodyReader.Read(probeBuf[n:])
			n += n2
			if err2 == io.EOF {
				if closeFn != nil {
					_ = closeFn()
				}
				copyResponseTrailers(c, resp)
				c.Response.SetBodyRaw(probeBuf[:n])
				return nil
			}
			if err2 != nil {
				if closeFn != nil {
					_ = closeFn()
				}
				resp.Body.Close()
				return err2
			}
		}
		probedReader, isComplete, probeErr := probeStreamEOF(bodyReader)
		if probeErr != nil {
			if closeFn != nil {
				_ = closeFn()
			}
			resp.Body.Close()
			return probeErr
		}
		if isComplete {
			if closeFn != nil {
				_ = closeFn()
			}
			copyResponseTrailers(c, resp)
			c.Response.SetBodyRaw(probeBuf[:n])
			return nil
		}
		bodyReader = probedReader
		combined := io.MultiReader(bytes.NewReader(probeBuf[:n]), bodyReader)
		return streamRecompressedResponse(ctx, c, combined, closeFn, resp, encoding)
	}

	c.Response.ImmediateHeaderFlush = true
	stream := newProxyBodyStream(ctx, bodyReader, closeFn, resp, c)
	c.Response.SetBodyStream(stream, bodySize)
	return nil
}

func defaultStreamCompressionOptions() ResponseCompressionOptions {
	return ResponseCompressionOptions{
		Enabled:       true,
		BrotliEnabled: true,
		GzipEnabled:   true,
		MinBytes:      snapshot.DefaultResponseCompressionMinBytes,
	}
}

// streamRecompressedResponse sets up a non-blocking streaming compression
// pipeline: a goroutine reads from src, compresses, and writes into a pipe;
// the pipe reader is handed to Hertz via SetBodyStream so ForwardHTTP returns
// immediately.
func streamRecompressedResponse(ctx context.Context, c *app.RequestContext, src io.Reader, closeFn func() error, resp *http.Response, encoding responseEncoding) error {
	ensureVaryAcceptEncoding(c)
	c.Response.Header.Set("Content-Encoding", string(encoding))
	c.Response.Header.Del("Content-Length")

	pr, pw := io.Pipe()
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		compWriter, closeComp := newStreamCompressWriter(pw, encoding)
		_, copyErr := io.Copy(compWriter, src)
		closeComp()
		copyResponseTrailers(c, resp)
		if closeFn != nil {
			_ = closeFn()
		}
		if copyErr != nil {
			_ = pw.CloseWithError(copyErr)
		} else {
			_ = pw.Close()
		}
	}()

	go func() {
		select {
		case <-ctx.Done():
			resp.Body.Close()
		case <-streamDone:
		}
	}()

	c.Response.ImmediateHeaderFlush = true
	c.Response.SetBodyStream(pr, -1)
	return nil
}

// streamCompressedResponseFromReader sets up streaming compression for a
// known-length response body.
func streamCompressedResponseFromReader(ctx context.Context, c *app.RequestContext, src io.Reader, closeFn func() error, resp *http.Response, encoding responseEncoding, bodySize int) error {
	return streamRecompressedResponse(ctx, c, src, closeFn, resp, encoding)
}

// proxyBodyStream wraps an upstream body reader for SetBodyStream. It closes
// the underlying resources and copies trailers on EOF or Close, and monitors
// the request context for cancellation.
type proxyBodyStream struct {
	reader   io.Reader
	closeFn  func() error
	resp     *http.Response
	hertzCtx *app.RequestContext
	done     chan struct{}
	closed   bool
}

func newProxyBodyStream(ctx context.Context, reader io.Reader, closeFn func() error, resp *http.Response, hertzCtx *app.RequestContext) *proxyBodyStream {
	s := &proxyBodyStream{
		reader:   reader,
		closeFn:  closeFn,
		resp:     resp,
		hertzCtx: hertzCtx,
		done:     make(chan struct{}),
	}
	go func() {
		select {
		case <-ctx.Done():
			resp.Body.Close()
		case <-s.done:
		}
	}()
	return s
}

func (s *proxyBodyStream) Read(p []byte) (int, error) {
	n, err := s.reader.Read(p)
	if err != nil && !s.closed {
		s.cleanup()
	}
	return n, err
}

func (s *proxyBodyStream) Close() error {
	if s.closed {
		return nil
	}
	s.cleanup()
	return nil
}

func (s *proxyBodyStream) cleanup() {
	s.closed = true
	close(s.done)
	copyResponseTrailers(s.hertzCtx, s.resp)
	if s.closeFn != nil {
		_ = s.closeFn()
	}
}

const probeEOFTimeout = 5 * time.Millisecond

// probeStreamEOF attempts a short non-blocking read to detect whether the
// upstream body is already complete. For chunked responses the first Read may
// return all data bytes without EOF because the zero-length terminator chunk
// has not arrived yet. This helper spawns a brief goroutine read: if EOF
// arrives within probeEOFTimeout the body is fully buffered; otherwise
// bodyReader remains usable for streaming.
func probeStreamEOF(bodyReader io.Reader) (io.Reader, bool, error) {
	type probeResult struct {
		data []byte
		err  error
	}
	ch := make(chan probeResult, 1)
	go func() {
		var one [1]byte
		n, err := bodyReader.Read(one[:])
		res := probeResult{err: err}
		if n > 0 {
			res.data = append(res.data, one[:n]...)
		}
		ch <- res
	}()

	timer := time.NewTimer(probeEOFTimeout)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()

	select {
	case r := <-ch:
		if r.err == io.EOF && len(r.data) == 0 {
			return bytes.NewReader(nil), true, nil
		}
		if r.err != nil && r.err != io.EOF {
			return nil, false, r.err
		}
		if len(r.data) == 0 {
			return bodyReader, false, nil
		}
		if r.err == io.EOF {
			return bytes.NewReader(r.data), false, nil
		}
		return io.MultiReader(bytes.NewReader(r.data), bodyReader), false, nil
	case <-timer.C:
		pr, pw := io.Pipe()
		go func() {
			r := <-ch
			if len(r.data) > 0 {
				if _, err := pw.Write(r.data); err != nil {
					_ = pw.CloseWithError(err)
					return
				}
			}
			if r.err != nil && r.err != io.EOF {
				_ = pw.CloseWithError(r.err)
				return
			}
			_ = pw.Close()
		}()
		return io.MultiReader(pr, bodyReader), false, nil
	}
}

func copyResponseTrailers(c *app.RequestContext, resp *http.Response) {
	for k, vv := range resp.Trailer {
		lk := strings.ToLower(k)
		if isHopByHop(lk) {
			continue
		}
		for _, v := range vv {
			c.Response.Header.Trailer().Set(k, v)
		}
	}
}

var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"proxy-connection":    {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

func forwardedProtoFromHeader(raw []byte) string {
	start := 0
	end := len(raw)
	for start < end && isASCIISpace(raw[start]) {
		start++
	}
	for end > start && isASCIISpace(raw[end-1]) {
		end--
	}
	if start == end {
		return ""
	}
	trimmed := raw[start:end]
	switch len(trimmed) {
	case len("h3"):
		if asciiEqualFoldBytes(trimmed, "h3") {
			return "h3"
		}
	case len("http"):
		if asciiEqualFoldBytes(trimmed, "http") {
			return "http"
		}
	case len("https"):
		if asciiEqualFoldBytes(trimmed, "https") {
			return "https"
		}
	}
	return strings.ToLower(string(trimmed))
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

func isHopByHopBytes(name []byte) bool {
	switch len(name) {
	case len("te"):
		return asciiEqualFoldBytes(name, "te")
	case len("trailer"):
		return asciiEqualFoldBytes(name, "trailer") || asciiEqualFoldBytes(name, "upgrade")
	case len("connection"):
		return asciiEqualFoldBytes(name, "connection") || asciiEqualFoldBytes(name, "keep-alive")
	case len("proxy-connection"):
		return asciiEqualFoldBytes(name, "proxy-connection")
	case len("transfer-encoding"):
		return asciiEqualFoldBytes(name, "transfer-encoding")
	case len("proxy-authenticate"):
		return asciiEqualFoldBytes(name, "proxy-authenticate")
	case len("proxy-authorization"):
		return asciiEqualFoldBytes(name, "proxy-authorization")
	}
	return false
}

func asciiEqualFoldBytes(got []byte, want string) bool {
	if len(got) != len(want) {
		return false
	}
	for i, b := range got {
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if b != want[i] {
			return false
		}
	}
	return true
}

func isHopByHop(name string) bool {
	_, ok := hopByHopHeaders[strings.ToLower(name)]
	return ok
}

// IsHopByHop returns whether the given header name is a hop-by-hop header
// that should be stripped when forwarding responses.
func IsHopByHop(name string) bool { return isHopByHop(name) }

// RequestConnectionHeaderStripper strips tokens listed in the Connection header.
type RequestConnectionHeaderStripper struct {
	tokens map[string]struct{}
}

// NewRequestConnectionHeaderStripper creates a stripper from the Connection header of a request.
func NewRequestConnectionHeaderStripper(c *app.RequestContext) *RequestConnectionHeaderStripper {
	s := &RequestConnectionHeaderStripper{tokens: make(map[string]struct{})}
	for _, val := range c.Request.Header.PeekAll("Connection") {
		parseConnectionTokensInto(val, s.tokens)
	}
	parseRawHeaderConnectionTokens(c.Request.Header.RawHeaders(), s.tokens)
	return s
}

func parseConnectionTokensInto(val []byte, tokens map[string]struct{}) {
	for len(val) > 0 {
		part := val
		if comma := bytes.IndexByte(val, ','); comma >= 0 {
			part = val[:comma]
			val = val[comma+1:]
		} else {
			val = nil
		}
		part = bytes.TrimSpace(part)
		if len(part) > 0 {
			tokens[strings.ToLower(string(part))] = struct{}{}
		}
	}
}

func parseRawHeaderConnectionTokens(raw []byte, tokens map[string]struct{}) {
	for len(raw) > 0 {
		var line []byte
		if idx := bytes.Index(raw, []byte("\r\n")); idx >= 0 {
			line = raw[:idx]
			raw = raw[idx+2:]
		} else {
			line = raw
			raw = nil
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := bytes.TrimSpace(line[:colon])
		if asciiEqualFoldBytes(key, "connection") {
			parseConnectionTokensInto(bytes.TrimSpace(line[colon+1:]), tokens)
		}
	}
}

// ShouldStrip returns whether the given header key should be stripped.
func (s *RequestConnectionHeaderStripper) ShouldStrip(key []byte) bool {
	if s == nil || s.tokens == nil {
		return false
	}
	_, ok := s.tokens[strings.ToLower(string(key))]
	return ok
}

// trimASCIIHeaderSpaceBytes trims ASCII space characters from both ends of a byte slice.
func trimASCIIHeaderSpaceBytes(raw []byte) []byte {
	start := 0
	end := len(raw)
	for start < end && isASCIISpace(raw[start]) {
		start++
	}
	for end > start && isASCIISpace(raw[end-1]) {
		end--
	}
	return raw[start:end]
}

// PruneStats records the number of pruned upstream transports and clients.
type PruneStats struct {
	HTTPTransports           int
	HTTP2CleartextTransports int
	HTTPClients              int
	HTTPNoTimeoutClients     int
	HTTP3Transports          int
	HTTP3Clients             int
	HTTP3NoTimeoutClients    int
}

// Changed returns whether any transports or clients were pruned.
func (s PruneStats) Changed() bool {
	return s.HTTPTransports > 0 || s.HTTP2CleartextTransports > 0 || s.HTTPClients > 0 || s.HTTPNoTimeoutClients > 0 ||
		s.HTTP3Transports > 0 || s.HTTP3Clients > 0 || s.HTTP3NoTimeoutClients > 0
}

// PruneInactiveUpstreamTransports removes transports and clients that are not referenced by any site in the snapshot.
func PruneInactiveUpstreamTransports(sn *snapshot.Snapshot) PruneStats {
	if sn == nil || len(sn.Sites) == 0 {
		return PruneStats{}
	}
	// Build set of active transport keys from current snapshot.
	active := make(map[transportKey]struct{})
	for _, rt := range sn.Sites {
		base := ""
		if len(rt.UpstreamURLs) > 0 {
			base = rt.UpstreamURLs[0]
		}
		key := transportKeyForUpstream(base, rt)
		active[key] = struct{}{}
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
			// Remove associated clients.
			clientPoolMu.Lock()
			if hc, ok := clientCache[tr]; ok {
				delete(clientCache, tr)
				if hc.Timeout == 0 {
					stats.HTTPNoTimeoutClients++
				} else {
					stats.HTTPClients++
				}
			}
			clientPoolMu.Unlock()
		}
	}
	transportMu.Unlock()
	return stats
}

// CloseIdleUpstreamTransports closes idle connections on all cached transports.
// Returns counts of closed HTTP, H2C, and HTTP/3 transports.
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
	http3TransportMu.RLock()
	h3Count = len(http3TransportPool)
	http3TransportMu.RUnlock()
	for _, tr := range http3TransportPool {
		tr.CloseIdleConnections()
	}
	return httpCount, h2cCount, h3Count
}

// transportKeyForUpstream builds a transport key from the upstream base URL and site runtime.
func transportKeyForUpstream(base string, rt snapshot.SiteRuntime) transportKey {
	key := transportKey{}
	if base != "" {
		u, err := url.Parse(base)
		if err == nil {
			key.isHTTPS = u.Scheme == "https" || u.Scheme == "wss"
			key.h2cPrior = u.Scheme == "h2c"
		}
	}
	key.tlsServerName = rt.Site.UpstreamTLSServerName
	key.tlsSkipVerify = rt.Site.UpstreamTLSSkipVerify
	return key
}

// HTTP/3 transport pool for upstream connections.
type http3TransportKey struct {
	tlsServerName string
	tlsSkipVerify bool
}

var (
	http3TransportMu   sync.RWMutex
	http3TransportPool = make(map[http3TransportKey]*http3.Transport)
)

// UpstreamTransportPoolStats holds snapshot statistics for upstream transport pools.
type UpstreamTransportPoolStats struct {
	HTTPTransports           int
	HTTP2CleartextTransports int
	HTTP3Transports          int
	HTTPClients              int
	HTTPNoTimeoutClients     int
	HTTP3Clients             int
	HTTP3NoTimeoutClients    int
}

// UpstreamTransportPoolStatsSnapshot returns current pool statistics.
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
	noTimeoutClients := 0
	for _, hc := range clientCache {
		if hc.Timeout == 0 {
			noTimeoutClients++
		}
	}
	clientPoolMu.RUnlock()

	http3TransportMu.RLock()
	http3Transports := len(http3TransportPool)
	http3TransportMu.RUnlock()

	return UpstreamTransportPoolStats{
		HTTPTransports:           httpTransports,
		HTTP2CleartextTransports: h2cTransports,
		HTTP3Transports:          http3Transports,
		HTTPClients:              httpClients,
		HTTPNoTimeoutClients:     noTimeoutClients,
		HTTP3Clients:             0, // placeholder
		HTTP3NoTimeoutClients:    0, // placeholder
	}
}
