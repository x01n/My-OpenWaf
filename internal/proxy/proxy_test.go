package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/klauspost/compress/zstd"
	"github.com/quic-go/quic-go/http3"

	"My-OpenWaf/internal/acme"
	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

var benchmarkProxyBoolSink bool
var benchmarkProxyEncodingSink responseEncoding
var benchmarkProxyStringSink string
var benchmarkProxyStringsSink []string

type trackingReadCloser struct {
	reader io.Reader
	reads  int
	bytes  int
	closed bool
}

func (r *trackingReadCloser) Read(p []byte) (int, error) {
	r.reads++
	n, err := r.reader.Read(p)
	r.bytes += n
	return n, err
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

type gatedReadCloser struct {
	first   []byte
	second  []byte
	release <-chan struct{}
	stage   int
	pos     int
	closed  bool
}

func (r *gatedReadCloser) Read(p []byte) (int, error) {
	for {
		switch r.stage {
		case 0:
			if r.pos >= len(r.first) {
				r.stage = 1
				r.pos = 0
				continue
			}
			n := copy(p, r.first[r.pos:])
			r.pos += n
			return n, nil
		case 1:
			<-r.release
			r.stage = 2
		case 2:
			if r.pos >= len(r.second) {
				r.stage = 3
				return 0, io.EOF
			}
			n := copy(p, r.second[r.pos:])
			r.pos += n
			return n, nil
		default:
			return 0, io.EOF
		}
	}
}

func (r *gatedReadCloser) Close() error {
	r.closed = true
	return nil
}

func mustGzipBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		t.Fatalf("create gzip writer: %v", err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("write gzip body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}

func mustBrotliBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := brotli.NewWriterLevel(&buf, brotliCompressionLevel)
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("write brotli body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close brotli writer: %v", err)
	}
	return buf.Bytes()
}

func mustDeflateBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("write deflate body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close deflate writer: %v", err)
	}
	return buf.Bytes()
}

func mustZstdBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("create zstd writer: %v", err)
	}
	if _, err := writer.Write(body); err != nil {
		_ = writer.Close()
		t.Fatalf("write zstd body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zstd writer: %v", err)
	}
	return buf.Bytes()
}

func mustEncodeBodyWithContentEncodings(t *testing.T, body []byte, encodings ...string) []byte {
	t.Helper()
	encoded := body
	for _, encoding := range encodings {
		switch encoding {
		case "gzip", "x-gzip":
			encoded = mustGzipBytes(t, encoded)
		case "br":
			encoded = mustBrotliBytes(t, encoded)
		case "deflate":
			encoded = mustDeflateBytes(t, encoded)
		case "zstd":
			encoded = mustZstdBytes(t, encoded)
		case "", "identity":
		default:
			t.Fatalf("unsupported encoding for test helper: %s", encoding)
		}
	}
	return encoded
}

func TestReadUpstreamResponseBodyDecodesGzip(t *testing.T) {
	original := []byte(strings.Repeat("decoded-upstream-body-", 128))
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
	if err != nil {
		t.Fatalf("create gzip writer: %v", err)
	}
	if _, err := writer.Write(original); err != nil {
		t.Fatalf("write gzip body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Encoding": []string{"gzip"},
			"Content-Type":     []string{"text/plain; charset=utf-8"},
			"Content-Length":   []string{strconv.Itoa(compressed.Len())},
		},
		Body: io.NopCloser(bytes.NewReader(compressed.Bytes())),
	}

	body, headers, err := readUpstreamResponseBody(resp)
	if err != nil {
		t.Fatalf("readUpstreamResponseBody returned error: %v", err)
	}
	if !bytes.Equal(body, original) {
		t.Fatalf("decoded body mismatch: got %d bytes want %d bytes", len(body), len(original))
	}
	if got := headers.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding after decode = %q, want empty", got)
	}
	if got := headers.Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length after decode = %q, want empty", got)
	}
}

func TestReadUpstreamResponseBodyDecodesMultipleContentEncodings(t *testing.T) {
	original := []byte(strings.Repeat("decoded-upstream-body-", 128))
	encoded := mustEncodeBodyWithContentEncodings(t, original, "gzip", "br")

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Encoding": []string{"gzip, br"},
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
		t.Fatalf("decoded body mismatch: got %d bytes want %d bytes", len(body), len(original))
	}
	if got := headers.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding after decode = %q, want empty", got)
	}
	if got := headers.Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length after decode = %q, want empty", got)
	}
}

func TestReadUpstreamResponseBodyDecodesZstd(t *testing.T) {
	original := []byte(strings.Repeat("decoded-upstream-zstd-body-", 128))
	compressed := mustZstdBytes(t, original)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Encoding": []string{"zstd"},
			"Content-Type":     []string{"text/plain; charset=utf-8"},
			"Content-Length":   []string{strconv.Itoa(len(compressed))},
		},
		Body: io.NopCloser(bytes.NewReader(compressed)),
	}

	body, headers, err := readUpstreamResponseBody(resp)
	if err != nil {
		t.Fatalf("readUpstreamResponseBody returned error: %v", err)
	}
	if !bytes.Equal(body, original) {
		t.Fatalf("decoded body mismatch: got %d bytes want %d bytes", len(body), len(original))
	}
	if got := headers.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding after decode = %q, want empty", got)
	}
	if got := headers.Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length after decode = %q, want empty", got)
	}
}

func BenchmarkReadUpstreamResponseBodyPlain(b *testing.B) {
	body := []byte(strings.Repeat("plain-upstream-body-", 256))
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":   []string{"text/plain; charset=utf-8"},
			"Content-Length": []string{strconv.Itoa(len(body))},
		},
	}

	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		gotBody, headers, err := readUpstreamResponseBody(resp)
		if err != nil {
			b.Fatal(err)
		}
		if len(gotBody) != len(body) {
			b.Fatalf("body len = %d, want %d", len(gotBody), len(body))
		}
		if headers.Get("Content-Type") != "text/plain; charset=utf-8" {
			b.Fatal("missing content type")
		}
	}
}

func BenchmarkReadUpstreamResponseBodyLimitedPlain(b *testing.B) {
	body := []byte(strings.Repeat("plain-limited-upstream-body-", 256))
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":   []string{"text/plain; charset=utf-8"},
			"Content-Length": []string{strconv.Itoa(len(body))},
		},
	}

	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		gotBody, headers, _, closeFn, decoded, truncated, err := readUpstreamResponseBodyLimited(resp, int64(len(body)))
		if err != nil {
			b.Fatal(err)
		}
		if decoded {
			b.Fatal("unexpected decoded body")
		}
		if truncated {
			b.Fatal("unexpected truncation")
		}
		if closeFn != nil {
			if err := closeFn(); err != nil {
				b.Fatal(err)
			}
		}
		if len(gotBody) != len(body) {
			b.Fatalf("body len = %d, want %d", len(gotBody), len(body))
		}
		if headers.Get("Content-Type") != "text/plain; charset=utf-8" {
			b.Fatal("missing content type")
		}
	}
}

func BenchmarkCopyResponseHeadersBrowserLike(b *testing.B) {
	ctx := app.NewContext(0)
	src := http.Header{
		"Content-Type": []string{"text/plain; charset=utf-8"},
		"Connection":   []string{"keep-alive, X-Hop"},
		"Server":       []string{"upstream"},
		"Vary":         []string{"Accept-Encoding"},
		"X-Keep":       []string{"kept"},
		"X-Hop":        []string{"drop"},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ctx.Response.Header.Reset()
		copyResponseHeaders(ctx, src)
	}
}

func TestParseContentEncodingsBytesMatchesStringSemantics(t *testing.T) {
	tests := []string{
		"",
		"gzip",
		" GZip ",
		"x-gzip",
		"br",
		"deflate",
		"zstd",
		"identity",
		"gzip, br",
		" gzip ; level=1 , BR ; q=1 ",
		"gzip, unknown",
		"unknown",
		"gzip, , br",
		"gzip;",
		"gzip ; ;",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			want, wantOK := parseContentEncodingsStringForTest(raw)
			got, gotOK := parseContentEncodingsBytes([]byte(raw))
			if gotOK != wantOK {
				t.Fatalf("supported = %v, want %v", gotOK, wantOK)
			}
			if strings.Join(got, "|") != strings.Join(want, "|") {
				t.Fatalf("encodings = %#v, want %#v", got, want)
			}
		})
	}
}

func TestNormalizedContentEncodingBytesMatchesStringSemantics(t *testing.T) {
	tests := []string{
		"",
		"gzip",
		" GZip ",
		"gzip; level=1",
		" GZip ; level=1 ",
		"identity",
		"IDENTITY",
		"gzip, br",
		" GZip , BR ",
		"unknown",
		" Unknown ; param=1 ",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			want := normalizedContentEncodingStringForTest(raw)
			got := normalizedContentEncodingBytes([]byte(raw))
			if got != want {
				t.Fatalf("normalizedContentEncodingBytes(%q) = %q, want %q", raw, got, want)
			}
		})
	}
}

func TestIsCompressibleContentTypeBytesMatchesStringSemantics(t *testing.T) {
	tests := []string{
		"",
		"text/plain",
		"Text/Plain",
		"text/plain; charset=utf-8",
		" application/json ",
		"APPLICATION/JSON; charset=UTF-8",
		"application/javascript",
		"application/x-javascript",
		"application/xml",
		"application/xhtml+xml",
		"application/rss+xml",
		"application/atom+xml",
		"application/x-www-form-urlencoded",
		"image/svg+xml",
		"application/octet-stream",
		"application/json; charset=\"utf-8\"",
		"application/json; charset = utf-8",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			want := isCompressibleContentType(raw)
			got := isCompressibleContentTypeBytes([]byte(raw))
			if got != want {
				t.Fatalf("isCompressibleContentTypeBytes(%q) = %v, want %v", raw, got, want)
			}
		})
	}
}

func TestCacheControlHasNoTransformBytesMatchesStringSemantics(t *testing.T) {
	tests := []string{
		"",
		"public, max-age=60",
		"no-transform",
		"public, NO-TRANSFORM",
		"max-age=60, no-transform, public",
		"x-no-transform",
		"notransform",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			want := strings.Contains(strings.ToLower(raw), "no-transform")
			got := cacheControlHasNoTransformBytes([]byte(raw))
			if got != want {
				t.Fatalf("cacheControlHasNoTransformBytes(%q) = %v, want %v", raw, got, want)
			}
		})
	}
}

func parseContentEncodingsStringForTest(raw string) ([]string, bool) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return nil, true
	}

	parts := strings.Split(raw, ",")
	encodings := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if semi := strings.IndexByte(part, ';'); semi >= 0 {
			part = strings.TrimSpace(part[:semi])
		}
		if part == "" {
			continue
		}
		encodings = append(encodings, part)
		if !isSupportedContentEncoding(part) {
			return nil, false
		}
	}
	return encodings, true
}

func normalizedContentEncodingStringForTest(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, ",") {
		return raw
	}
	if semi := strings.IndexByte(raw, ';'); semi >= 0 {
		raw = strings.TrimSpace(raw[:semi])
	}
	return raw
}

func TestSharedTransportForUpstreamEnablesExpectContinueTimeout(t *testing.T) {
	rt := snapshot.SiteRuntime{}
	tr := SharedTransportForUpstream(rt, "http://127.0.0.1:8080")
	if tr.ExpectContinueTimeout != time.Second {
		t.Fatalf("ExpectContinueTimeout = %s, want %s", tr.ExpectContinueTimeout, time.Second)
	}
}

func TestSharedTransportForUpstreamUsesBoundedDialAndTLSHandshake(t *testing.T) {
	rt := snapshot.SiteRuntime{}
	tr := SharedTransportForUpstream(rt, "https://127.0.0.1:8443")
	if tr.IdleConnTimeout != 90*time.Second {
		t.Fatalf("IdleConnTimeout = %s, want %s", tr.IdleConnTimeout, 90*time.Second)
	}
	if tr.MaxIdleConns != 512 {
		t.Fatalf("MaxIdleConns = %d, want 512", tr.MaxIdleConns)
	}
	if tr.MaxIdleConnsPerHost != 128 {
		t.Fatalf("MaxIdleConnsPerHost = %d, want 128", tr.MaxIdleConnsPerHost)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 should be enabled")
	}
	if !tr.DisableCompression {
		t.Fatal("DisableCompression should be enabled so upstream response decoding stays explicit")
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("HTTPS upstream TLS config is nil")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("HTTPS upstream MinVersion = %#x, want %#x", tr.TLSClientConfig.MinVersion, tls.VersionTLS12)
	}
}

func TestSharedTransportForUpstreamKeysTLSFieldsOnlyForHTTPS(t *testing.T) {
	rtA := snapshot.SiteRuntime{
		Site: store.Site{
			UpstreamTLSServerName: "transport-key-a.example.test",
			UpstreamTLSSkipVerify: true,
		},
	}
	rtB := snapshot.SiteRuntime{
		Site: store.Site{
			UpstreamTLSServerName: "transport-key-b.example.test",
			UpstreamTLSSkipVerify: false,
		},
	}

	httpA := SharedTransportForUpstream(rtA, "http://127.0.0.1:8080")
	httpB := SharedTransportForUpstream(rtB, "http://127.0.0.1:8080")
	if httpA != httpB {
		t.Fatal("plain HTTP upstream transport should ignore upstream TLS fields")
	}

	httpsA := SharedTransportForUpstream(rtA, "https://127.0.0.1:8443")
	httpsB := SharedTransportForUpstream(rtB, "https://127.0.0.1:8443")
	if httpsA == httpsB {
		t.Fatal("HTTPS upstream transport must keep TLS fields in the cache key")
	}
	if httpsA.TLSClientConfig == nil || httpsA.TLSClientConfig.ServerName != rtA.Site.UpstreamTLSServerName || !httpsA.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("HTTPS A TLS config = %#v, want SNI %q and skip verify", httpsA.TLSClientConfig, rtA.Site.UpstreamTLSServerName)
	}
	if httpsB.TLSClientConfig == nil || httpsB.TLSClientConfig.ServerName != rtB.Site.UpstreamTLSServerName || httpsB.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("HTTPS B TLS config = %#v, want SNI %q and verified upstream", httpsB.TLSClientConfig, rtB.Site.UpstreamTLSServerName)
	}
}

type cancelableBlockingReader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *cancelableBlockingReader) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	return 0, context.Canceled
}

func TestHertzResponseBodyCloseIsIdempotent(t *testing.T) {
	req := protocol.AcquireRequest()
	resp := protocol.AcquireResponse()
	body := &hertzResponseBody{req: req, resp: resp}

	if err := body.Close(); err != nil {
		t.Fatalf("first Close returned error: %v", err)
	}
	if err := body.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
}

type closeSignalBody struct {
	closed chan struct{}
	once   sync.Once
}

func (b *closeSignalBody) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (b *closeSignalBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

func TestReleaseHertzUpstreamRequestWhenDoneDefersReset(t *testing.T) {
	req := protocol.AcquireRequest()
	body := &closeSignalBody{closed: make(chan struct{})}
	req.SetBodyStream(body, -1)
	done := make(chan struct{})

	releaseHertzUpstreamRequestWhenDone(req, []<-chan struct{}{done})
	select {
	case <-body.closed:
		t.Fatal("request body closed before write completion")
	default:
	}

	close(done)
	select {
	case <-body.closed:
	case <-time.After(time.Second):
		t.Fatal("request body was not closed after write completion")
	}
}

func TestReleaseHertzUpstreamRequestWhenDoneReleasesCompletedRequest(t *testing.T) {
	req := protocol.AcquireRequest()
	body := &closeSignalBody{closed: make(chan struct{})}
	req.SetBodyStream(body, -1)
	done := make(chan struct{})
	close(done)

	releaseHertzUpstreamRequestWhenDone(req, []<-chan struct{}{done})
	select {
	case <-body.closed:
	default:
		t.Fatal("completed request body was not closed synchronously")
	}
}

func TestReleaseHertzUpstreamRequestWhenDoneWaitsForEveryAttempt(t *testing.T) {
	req := protocol.AcquireRequest()
	body := &closeSignalBody{closed: make(chan struct{})}
	req.SetBodyStream(body, -1)
	firstDone := make(chan struct{})
	secondDone := make(chan struct{})

	releaseHertzUpstreamRequestWhenDone(req, []<-chan struct{}{firstDone, secondDone})
	close(firstDone)
	select {
	case <-body.closed:
		t.Fatal("request body closed before every write attempt completed")
	default:
	}

	close(secondDone)
	select {
	case <-body.closed:
	case <-time.After(time.Second):
		t.Fatal("request body was not closed after every write attempt completed")
	}
}

func TestReleaseHertzUpstreamRequestWhenDoneReleasesWithoutAttempt(t *testing.T) {
	req := protocol.AcquireRequest()
	body := &closeSignalBody{closed: make(chan struct{})}
	req.SetBodyStream(body, -1)

	releaseHertzUpstreamRequestWhenDone(req, nil)
	select {
	case <-body.closed:
	default:
		t.Fatal("request body was not closed when no write attempt was created")
	}
}

func TestHertzResponseBodyCloseCancelsBlockedReadAndWaits(t *testing.T) {
	reader := &cancelableBlockingReader{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	var cancelCount int
	var cancelMu sync.Mutex
	body := &hertzResponseBody{
		reader: reader,
		cancel: func() {
			cancelMu.Lock()
			cancelCount++
			cancelMu.Unlock()
			close(reader.release)
		},
	}

	readDone := make(chan error, 1)
	go func() {
		_, err := body.Read(make([]byte, 1))
		readDone <- err
	}()
	<-reader.started

	closeDone := make(chan error, 2)
	go func() { closeDone <- body.Close() }()
	go func() { closeDone <- body.Close() }()

	select {
	case err := <-readDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Read error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked Read was not released by Close cancellation")
	}
	for range 2 {
		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatalf("Close returned error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent Close did not finish after Read exited")
		}
	}

	cancelMu.Lock()
	gotCancelCount := cancelCount
	cancelMu.Unlock()
	if gotCancelCount != 1 {
		t.Fatalf("cancel calls = %d, want 1", gotCancelCount)
	}
}

func TestHertzResponseBodySyncsTrailerBeforeRelease(t *testing.T) {
	resp := protocol.AcquireResponse()
	if err := resp.Header.Trailer().Set("X-Upstream-Trailer", "done"); err != nil {
		protocol.ReleaseResponse(resp)
		t.Fatalf("set response trailer: %v", err)
	}
	trailer := make(http.Header)
	body := &hertzResponseBody{
		reader:  bytes.NewReader(nil),
		resp:    resp,
		trailer: trailer,
	}

	if err := body.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if got := trailer.Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("trailer X-Upstream-Trailer = %q, want %q", got, "done")
	}
}

func TestProxyBodyStreamCloseWaitsForActiveReader(t *testing.T) {
	reader := &cancelableBlockingReader{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	var closeCount int
	var closeMu sync.Mutex
	stream := newProxyBodyStream(
		context.Background(),
		reader,
		func() error {
			closeMu.Lock()
			closeCount++
			closeMu.Unlock()
			return nil
		},
		&http.Response{},
		app.NewContext(0),
		func() { close(reader.release) },
	)

	readDone := make(chan error, 1)
	go func() {
		_, err := stream.Read(make([]byte, 1))
		readDone <- err
	}()
	<-reader.started

	closeDone := make(chan struct{})
	go func() {
		_ = stream.Close()
		close(closeDone)
	}()

	select {
	case err := <-readDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Read error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy stream Read was not released by Close cancellation")
	}
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy stream Close did not finish after Read exited")
	}

	closeMu.Lock()
	gotCloseCount := closeCount
	closeMu.Unlock()
	if gotCloseCount != 1 {
		t.Fatalf("close function calls = %d, want 1", gotCloseCount)
	}
}

func TestBuildUpstreamRequestForwardsRequestTrailers(t *testing.T) {
	payload := `{"ok":true}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("upstream read body: %v", err)
		}
		if string(body) != payload {
			t.Fatalf("upstream body = %q, want %q", string(body), payload)
		}
		if got := r.Header.Get("TE"); got != "trailers" {
			t.Fatalf("upstream TE = %q, want %q", got, "trailers")
		}
		if got := r.Trailer.Get("X-Trace"); got != "done" {
			t.Fatalf("upstream trailer X-Trace = %q, want %q", got, "done")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/upload")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("TE", "gzip, trailers")
	ctx.Request.SetBody([]byte(payload))
	if err := ctx.Request.Header.Trailer().Set("X-Trace", "done"); err != nil {
		t.Fatalf("set request trailer: %v", err)
	}

	req, err := buildUpstreamRequest(context.Background(), ctx, upstream.URL, nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if got := req.Trailer.Get("X-Trace"); got != "done" {
		t.Fatalf("request trailer X-Trace = %q, want %q", got, "done")
	}
	if got := req.Header.Get("TE"); got != "trailers" {
		t.Fatalf("request TE = %q, want %q", got, "trailers")
	}
	if req.ContentLength != -1 {
		t.Fatalf("ContentLength = %d, want -1 for trailer-capable request", req.ContentLength)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http client Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

func TestBuildUpstreamRequestReaddsForwardableTEWhenConnectionDeclaresTE(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("Connection", "TE, X-Hop")
	ctx.Request.Header.Set("TE", "gzip, trailers; q=1.0")
	ctx.Request.Header.Set("X-Hop", "drop")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if got := req.Header.Get("Connection"); got != "" {
		t.Fatalf("Connection = %q, want empty", got)
	}
	if got := req.Header.Get("X-Hop"); got != "" {
		t.Fatalf("X-Hop = %q, want empty", got)
	}
	if got := req.Header.Get("TE"); got != "trailers" {
		t.Fatalf("TE = %q, want trailers", got)
	}
}

func TestBuildUpstreamRequestStreamsRequestTrailersAtEOF(t *testing.T) {
	trailerBody := []byte(strings.Repeat(`{"stream":"trailers"}`, 2048))
	stream := &trackingReadCloser{reader: bytes.NewReader(trailerBody)}

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/upload-stream-trailer")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("TE", "trailers")
	ctx.Request.Header.Set("Trailer", "X-Trace")
	ctx.Request.SetBodyStream(stream, -1)
	if err := ctx.Request.Header.Trailer().Set("X-Trace", ""); err != nil {
		t.Fatalf("set trailer placeholder: %v", err)
	}

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if req.Trailer == nil {
		t.Fatal("expected request trailer map")
	}
	if got := req.Trailer.Get("X-Trace"); got != "" {
		t.Fatalf("initial request trailer X-Trace = %q, want empty placeholder", got)
	}

	if err := ctx.Request.Header.Trailer().Set("X-Trace", "done"); err != nil {
		t.Fatalf("update trailer final value: %v", err)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	if !bytes.Equal(body, trailerBody) {
		t.Fatalf("streamed body mismatch: got %d bytes want %d bytes", len(body), len(trailerBody))
	}
	if got := req.Trailer.Get("X-Trace"); got != "done" {
		t.Fatalf("final request trailer X-Trace = %q, want %q", got, "done")
	}
}

func BenchmarkForwardableTEValueStringSplitTrailers(b *testing.B) {
	raw := "gzip, trailers; q=1.0"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if forwardableTEValueStringSplitForBenchmark(raw) != "trailers" {
			b.Fatal("unexpected TE value")
		}
	}
}

func forwardableTEValueStringSplitForBenchmark(raw string) string {
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
		q := 1.0
		if semi := strings.IndexByte(part, ';'); semi >= 0 {
			name = strings.TrimSpace(part[:semi])
			params := strings.Split(part[semi+1:], ";")
			for _, param := range params {
				kv := strings.SplitN(strings.TrimSpace(param), "=", 2)
				if len(kv) != 2 || !strings.EqualFold(kv[0], "q") {
					continue
				}
				if parsed, err := strconv.ParseFloat(strings.TrimSpace(kv[1]), 64); err == nil {
					q = parsed
				}
			}
		}
		if q > 0 && strings.EqualFold(name, "trailers") {
			return "trailers"
		}
	}
	return ""
}

func TestForwardHTTPHonorsExpectContinueBeforeSendingBody(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw upstream: %v", err)
	}
	defer ln.Close()

	type observation struct {
		expectHeader      string
		bodyReceivedEarly bool
		headerReadErr     error
		earlyBodyProbeErr error
	}
	resultCh := make(chan observation, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resultCh <- observation{headerReadErr: err}
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		var headerLines []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				resultCh <- observation{headerReadErr: err}
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			headerLines = append(headerLines, line)
		}

		expectHeader := ""
		for _, line := range headerLines {
			if strings.HasPrefix(strings.ToLower(line), "expect:") {
				expectHeader = strings.TrimSpace(line[len("expect:"):])
				break
			}
		}

		bodyReceivedEarly := reader.Buffered() > 0
		var probeErr error
		if !bodyReceivedEarly {
			if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
				resultCh <- observation{expectHeader: expectHeader, headerReadErr: err}
				return
			}
			_, err := reader.Peek(1)
			if err == nil {
				bodyReceivedEarly = true
			} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				probeErr = err
			}
			_ = conn.SetReadDeadline(time.Time{})
		}

		_, writeErr := io.WriteString(conn, "HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		if writeErr != nil {
			resultCh <- observation{
				expectHeader:      expectHeader,
				bodyReceivedEarly: bodyReceivedEarly,
				headerReadErr:     writeErr,
				earlyBodyProbeErr: probeErr,
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
		resultCh <- observation{
			expectHeader:      expectHeader,
			bodyReceivedEarly: bodyReceivedEarly,
			earlyBodyProbeErr: probeErr,
		}
	}()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/expect")
	ctx.Request.Header.SetHost("proxy.example.com")
	ctx.Request.Header.Set("Content-Type", "application/octet-stream")
	ctx.Request.Header.Set("Expect", "100-continue")
	ctx.Request.SetBody([]byte(strings.Repeat("expect-continue-body-", 512)))

	err = ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, "http://"+ln.Addr().String(), nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := ctx.Response.StatusCode(); got != http.StatusExpectationFailed {
		t.Fatalf("status = %d, want %d", got, http.StatusExpectationFailed)
	}

	result := <-resultCh
	if result.headerReadErr != nil {
		t.Fatalf("raw upstream observation error: %v", result.headerReadErr)
	}
	if result.earlyBodyProbeErr != nil {
		t.Fatalf("raw upstream early body probe error: %v", result.earlyBodyProbeErr)
	}
	if result.expectHeader != "100-continue" {
		t.Fatalf("Expect header = %q, want %q", result.expectHeader, "100-continue")
	}
	if result.bodyReceivedEarly {
		t.Fatal("request body was sent before upstream accepted Expect: 100-continue")
	}
}

func TestForwardHTTPDecodesCompressedRequestBodyAfterExpectContinue(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw upstream: %v", err)
	}
	defer ln.Close()

	originalBody := []byte(strings.Repeat(`{"ok":true,"message":"expect-compressed"}`, 16))
	compressedBody := mustGzipBytes(t, originalBody)

	type observation struct {
		expectHeader      string
		contentEncoding   string
		contentLength     string
		bodyReceivedEarly bool
		headerReadErr     error
		earlyBodyProbeErr error
		bodyReadErr       error
		body              []byte
	}
	resultCh := make(chan observation, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resultCh <- observation{headerReadErr: err}
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		var headerLines []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				resultCh <- observation{headerReadErr: err}
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			headerLines = append(headerLines, line)
		}

		expectHeader := ""
		contentEncoding := ""
		contentLength := ""
		for _, line := range headerLines {
			lowerLine := strings.ToLower(line)
			switch {
			case strings.HasPrefix(lowerLine, "expect:"):
				expectHeader = strings.TrimSpace(line[len("expect:"):])
			case strings.HasPrefix(lowerLine, "content-encoding:"):
				contentEncoding = strings.TrimSpace(line[len("content-encoding:"):])
			case strings.HasPrefix(lowerLine, "content-length:"):
				contentLength = strings.TrimSpace(line[len("content-length:"):])
			}
		}

		bodyReceivedEarly := reader.Buffered() > 0
		var probeErr error
		if !bodyReceivedEarly {
			if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
				resultCh <- observation{
					expectHeader:    expectHeader,
					contentEncoding: contentEncoding,
					contentLength:   contentLength,
					headerReadErr:   err,
				}
				return
			}
			_, err := reader.Peek(1)
			if err == nil {
				bodyReceivedEarly = true
			} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				probeErr = err
			}
			_ = conn.SetReadDeadline(time.Time{})
		}

		if _, err := io.WriteString(conn, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
			resultCh <- observation{
				expectHeader:      expectHeader,
				contentEncoding:   contentEncoding,
				contentLength:     contentLength,
				bodyReceivedEarly: bodyReceivedEarly,
				headerReadErr:     err,
				earlyBodyProbeErr: probeErr,
			}
			return
		}

		body := make([]byte, len(originalBody))
		if _, err := io.ReadFull(reader, body); err != nil {
			resultCh <- observation{
				expectHeader:      expectHeader,
				contentEncoding:   contentEncoding,
				contentLength:     contentLength,
				bodyReceivedEarly: bodyReceivedEarly,
				earlyBodyProbeErr: probeErr,
				bodyReadErr:       err,
			}
			return
		}

		if _, err := io.WriteString(conn, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); err != nil {
			resultCh <- observation{
				expectHeader:      expectHeader,
				contentEncoding:   contentEncoding,
				contentLength:     contentLength,
				bodyReceivedEarly: bodyReceivedEarly,
				earlyBodyProbeErr: probeErr,
				bodyReadErr:       err,
				body:              body,
			}
			return
		}

		resultCh <- observation{
			expectHeader:      expectHeader,
			contentEncoding:   contentEncoding,
			contentLength:     contentLength,
			bodyReceivedEarly: bodyReceivedEarly,
			earlyBodyProbeErr: probeErr,
			body:              body,
		}
	}()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/expect-compressed")
	ctx.Request.Header.SetHost("proxy.example.com")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("Content-Encoding", "gzip")
	ctx.Request.Header.Set("Expect", "100-continue")
	ctx.Request.SetBody(compressedBody)

	err = ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, "http://"+ln.Addr().String(), nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := ctx.Response.StatusCode(); got != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", got, http.StatusNoContent)
	}

	result := <-resultCh
	if result.headerReadErr != nil {
		t.Fatalf("raw upstream observation error: %v", result.headerReadErr)
	}
	if result.earlyBodyProbeErr != nil {
		t.Fatalf("raw upstream early body probe error: %v", result.earlyBodyProbeErr)
	}
	if result.bodyReadErr != nil {
		t.Fatalf("raw upstream body read error: %v", result.bodyReadErr)
	}
	if result.expectHeader != "100-continue" {
		t.Fatalf("Expect header = %q, want %q", result.expectHeader, "100-continue")
	}
	if result.contentEncoding != "" {
		t.Fatalf("Content-Encoding header = %q, want empty", result.contentEncoding)
	}
	if result.contentLength != strconv.Itoa(len(originalBody)) {
		t.Fatalf("Content-Length header = %q, want %d", result.contentLength, len(originalBody))
	}
	if result.bodyReceivedEarly {
		t.Fatal("compressed request body was sent before upstream accepted Expect: 100-continue")
	}
	if !bytes.Equal(result.body, originalBody) {
		t.Fatalf("forwarded body mismatch: got %d bytes want %d bytes", len(result.body), len(originalBody))
	}
}

func TestFetchHTTPBuffersResponseTrailers(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Add("Trailer", "X-Upstream-Trailer")
		_, _ = io.WriteString(w, "buffered trailer payload")
		w.Header().Set("X-Upstream-Trailer", "done")
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/trailers")

	resp, err := FetchHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "example.test")
	if err != nil {
		t.Fatalf("FetchHTTP returned error: %v", err)
	}
	if string(resp.Body) != "buffered trailer payload" {
		t.Fatalf("buffered body = %q", string(resp.Body))
	}
	if got := resp.Header.Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("buffered trailer X-Upstream-Trailer = %q, want %q", got, "done")
	}
}

func TestFetchHTTPDecodesCompressedBufferedResponse(t *testing.T) {
	upstreamBody := strings.Repeat("decoded buffered upstream gzip response.", 64)
	upstreamEncodedBody := mustGzipBytes(t, []byte(upstreamBody))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(upstreamEncodedBody)))
		_, _ = w.Write(upstreamEncodedBody)
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/compressed-buffered")
	ctx.Request.Header.Set("Accept-Encoding", "br, gzip")

	resp, err := FetchHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "example.test")
	if err != nil {
		t.Fatalf("FetchHTTP returned error: %v", err)
	}
	if got := string(resp.Body); got != upstreamBody {
		t.Fatalf("buffered body = %q, want decoded upstream body", got)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("buffered Content-Encoding = %q, want empty", got)
	}
	if got := resp.Header.Get("Content-Length"); got != "" {
		t.Fatalf("buffered Content-Length = %q, want empty", got)
	}
}

func TestFetchHTTPReturnsHTTP2ProtocolForHTTPSUpstream(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/2.0" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "h2-upstream")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/h2-upstream")

	rt := snapshot.SiteRuntime{
		Site: store.Site{
			UpstreamTLSSkipVerify: true,
		},
	}

	resp, err := FetchHTTP(context.Background(), ctx, rt, upstream.URL, nil, "example.test")
	if err != nil {
		t.Fatalf("FetchHTTP returned error: %v", err)
	}
	if got := string(resp.Body); got != "h2-upstream" {
		t.Fatalf("buffered body = %q, want %q", got, "h2-upstream")
	}
}

func TestFetchHTTPReturnsHTTP2ProtocolForExplicitH2CUpstream(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/2.0" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "h2c-upstream")
	}))
	upstream.Config.Protocols = new(http.Protocols)
	upstream.Config.Protocols.SetHTTP1(true)
	upstream.Config.Protocols.SetUnencryptedHTTP2(true)
	upstream.Start()
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/h2c-upstream")

	base := strings.Replace(upstream.URL, "http://", "h2c://", 1)
	resp, err := FetchHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, base, nil, "example.test")
	if err != nil {
		t.Fatalf("FetchHTTP returned error: %v", err)
	}
	if got := string(resp.Body); got != "h2c-upstream" {
		t.Fatalf("buffered body = %q, want %q", got, "h2c-upstream")
	}
}

func TestFetchHTTPReturnsHTTP3ProtocolForExplicitH3Upstream(t *testing.T) {
	upstream, base := startTestHTTP3UpstreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/3.0" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/3.0")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "h3-upstream")
	}))
	defer closeTestHTTP3UpstreamServer(t, upstream)

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/h3-upstream")

	rt := snapshot.SiteRuntime{
		Site: store.Site{
			UpstreamTLSSkipVerify: true,
		},
	}

	resp, err := FetchHTTP(context.Background(), ctx, rt, base, nil, "example.test")
	if err != nil {
		t.Fatalf("FetchHTTP returned error: %v", err)
	}
	if got := string(resp.Body); got != "h3-upstream" {
		t.Fatalf("buffered body = %q, want %q", got, "h3-upstream")
	}
}

func TestFetchHTTPPreservesExplicitProtocolBasePathAndQuery(t *testing.T) {
	assertRequest := func(t *testing.T, r *http.Request, wantProto string) {
		t.Helper()
		if r.Proto != wantProto {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, wantProto)
		}
		if r.URL.Path != "/base/resource" {
			t.Fatalf("upstream request path = %q, want %q", r.URL.Path, "/base/resource")
		}
		if r.URL.RawQuery != "x=1&y=two" {
			t.Fatalf("upstream request query = %q, want %q", r.URL.RawQuery, "x=1&y=two")
		}
	}

	t.Run("h2c", func(t *testing.T) {
		upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertRequest(t, r, "HTTP/2.0")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "h2c-base-query")
		}))
		upstream.Config.Protocols = new(http.Protocols)
		upstream.Config.Protocols.SetHTTP1(true)
		upstream.Config.Protocols.SetUnencryptedHTTP2(true)
		upstream.Start()
		defer upstream.Close()

		ctx := app.NewContext(0)
		ctx.Request.SetMethod("GET")
		ctx.Request.SetRequestURI("/resource?x=1&y=two")

		base := strings.Replace(upstream.URL, "http://", "h2c://", 1) + "/base"
		resp, err := FetchHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, base, nil, "example.test")
		if err != nil {
			t.Fatalf("FetchHTTP returned error: %v", err)
		}
		if got := string(resp.Body); got != "h2c-base-query" {
			t.Fatalf("buffered body = %q, want %q", got, "h2c-base-query")
		}
	})

	t.Run("h3", func(t *testing.T) {
		upstream, base := startTestHTTP3UpstreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertRequest(t, r, "HTTP/3.0")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "h3-base-query")
		}))
		defer closeTestHTTP3UpstreamServer(t, upstream)

		ctx := app.NewContext(0)
		ctx.Request.SetMethod("GET")
		ctx.Request.SetRequestURI("/resource?x=1&y=two")

		rt := snapshot.SiteRuntime{
			Site: store.Site{
				UpstreamTLSSkipVerify: true,
			},
		}

		resp, err := FetchHTTP(context.Background(), ctx, rt, base+"/base", nil, "example.test")
		if err != nil {
			t.Fatalf("FetchHTTP returned error: %v", err)
		}
		if got := string(resp.Body); got != "h3-base-query" {
			t.Fatalf("buffered body = %q, want %q", got, "h3-base-query")
		}
	})
}

func TestFetchHTTPUsesCustomSNIForExplicitH3Upstream(t *testing.T) {
	const wantSNI = "origin-h3.example.test"

	seenSNI := make(chan string, 1)
	upstream, base := startTestHTTP3UpstreamServerWithTLSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/3.0" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/3.0")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "h3-upstream-sni")
	}), func(cfg *tls.Config) {
		cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case seenSNI <- hello.ServerName:
			default:
			}
			return nil, nil
		}
	})
	defer closeTestHTTP3UpstreamServer(t, upstream)

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/h3-upstream-sni")

	rt := snapshot.SiteRuntime{
		Site: store.Site{
			UpstreamTLSServerName: wantSNI,
			UpstreamTLSSkipVerify: true,
		},
	}

	resp, err := FetchHTTP(context.Background(), ctx, rt, base, nil, "example.test")
	if err != nil {
		t.Fatalf("FetchHTTP returned error: %v", err)
	}
	if got := string(resp.Body); got != "h3-upstream-sni" {
		t.Fatalf("buffered body = %q, want %q", got, "h3-upstream-sni")
	}

	select {
	case got := <-seenSNI:
		if got != wantSNI {
			t.Fatalf("HTTP/3 upstream SNI = %q, want %q", got, wantSNI)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP/3 upstream did not observe ClientHello SNI")
	}
}

func TestFetchHTTPBuffersHTTP3ResponseTrailers(t *testing.T) {
	upstream, base := startTestHTTP3UpstreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/3.0" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/3.0")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Add("Trailer", "X-Upstream-Trailer")
		_, _ = io.WriteString(w, "h3 buffered trailer payload")
		w.Header().Set("X-Upstream-Trailer", "done")
	}))
	defer closeTestHTTP3UpstreamServer(t, upstream)

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/h3-buffered-trailers")

	rt := snapshot.SiteRuntime{
		Site: store.Site{
			UpstreamTLSSkipVerify: true,
		},
	}

	resp, err := FetchHTTP(context.Background(), ctx, rt, base, nil, "example.test")
	if err != nil {
		t.Fatalf("FetchHTTP returned error: %v", err)
	}
	if got := string(resp.Body); got != "h3 buffered trailer payload" {
		t.Fatalf("buffered body = %q, want %q", got, "h3 buffered trailer payload")
	}
	if got := resp.Header.Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("buffered trailer X-Upstream-Trailer = %q, want %q", got, "done")
	}
}

func TestFetchHTTPReturnsHTTP11ProtocolForPlainHTTPUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/1.1" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/1.1")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "http11-upstream")
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/http11-upstream")

	resp, err := FetchHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "example.test")
	if err != nil {
		t.Fatalf("FetchHTTP returned error: %v", err)
	}
	if got := string(resp.Body); got != "http11-upstream" {
		t.Fatalf("buffered body = %q, want %q", got, "http11-upstream")
	}
}

func TestForwardHTTPReturnsHTTP2ProtocolForExplicitH2CUpstream(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/2.0" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "h2c-stream")
	}))
	upstream.Config.Protocols = new(http.Protocols)
	upstream.Config.Protocols.SetHTTP1(true)
	upstream.Config.Protocols.SetUnencryptedHTTP2(true)
	upstream.Start()
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/h2c-stream")
	ctx.Request.Header.SetHost("proxy.example.com")

	base := strings.Replace(upstream.URL, "http://", "h2c://", 1)
	err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, base, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	if got := string(ctx.Response.Body()); got != "h2c-stream" {
		t.Fatalf("response body = %q, want %q", got, "h2c-stream")
	}
}

func TestForwardHTTPExplicitH2CWithoutBody(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/2.0" {
			t.Errorf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
		}
		switch r.URL.Path {
		case "/head":
			if r.Method != http.MethodHead {
				t.Errorf("upstream method = %q, want %q", r.Method, http.MethodHead)
			}
			w.Header().Set("Content-Length", "128")
			w.Header().Set("X-Upstream", "head")
		case "/no-content":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	upstream.Config.Protocols = new(http.Protocols)
	upstream.Config.Protocols.SetHTTP1(true)
	upstream.Config.Protocols.SetUnencryptedHTTP2(true)
	upstream.Start()
	defer upstream.Close()

	base := strings.Replace(upstream.URL, "http://", "h2c://", 1)
	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{name: "head", method: http.MethodHead, path: "/head", wantStatus: http.StatusOK},
		{name: "no content", method: http.MethodGet, path: "/no-content", wantStatus: http.StatusNoContent},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := app.NewContext(0)
			ctx.Request.SetMethod(tc.method)
			ctx.Request.SetRequestURI(tc.path)
			ctx.Request.Header.SetHost("proxy.example.com")

			if err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, base, nil, "proxy.example.com"); err != nil {
				t.Fatalf("ForwardHTTP returned error: %v", err)
			}
			if got := ctx.Response.StatusCode(); got != tc.wantStatus {
				t.Fatalf("status = %d, want %d", got, tc.wantStatus)
			}
			if got := len(ctx.Response.Body()); got != 0 {
				t.Fatalf("response body length = %d, want 0", got)
			}
			if ctx.Response.IsBodyStream() {
				t.Fatal("response is still marked as body stream")
			}
		})
	}
}

func TestForwardHTTPReturnsHTTP3ProtocolForExplicitH3Upstream(t *testing.T) {
	upstream, base := startTestHTTP3UpstreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/3.0" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/3.0")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "h3-stream")
	}))
	defer closeTestHTTP3UpstreamServer(t, upstream)

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/h3-stream")
	ctx.Request.Header.SetHost("proxy.example.com")

	rt := snapshot.SiteRuntime{
		Site: store.Site{
			UpstreamTLSSkipVerify: true,
		},
	}

	err := ForwardHTTP(context.Background(), ctx, rt, base, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	if got := string(ctx.Response.Body()); got != "h3-stream" {
		t.Fatalf("response body = %q, want %q", got, "h3-stream")
	}
}

func TestForwardHTTPPreservesExplicitProtocolBasePathAndQuery(t *testing.T) {
	assertRequest := func(t *testing.T, r *http.Request, wantProto string) {
		t.Helper()
		if r.Proto != wantProto {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, wantProto)
		}
		if r.URL.Path != "/base/resource" {
			t.Fatalf("upstream request path = %q, want %q", r.URL.Path, "/base/resource")
		}
		if r.URL.RawQuery != "x=1&y=two" {
			t.Fatalf("upstream request query = %q, want %q", r.URL.RawQuery, "x=1&y=two")
		}
	}

	t.Run("h2c", func(t *testing.T) {
		upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertRequest(t, r, "HTTP/2.0")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "h2c-stream-base-query")
		}))
		upstream.Config.Protocols = new(http.Protocols)
		upstream.Config.Protocols.SetHTTP1(true)
		upstream.Config.Protocols.SetUnencryptedHTTP2(true)
		upstream.Start()
		defer upstream.Close()

		ctx := app.NewContext(0)
		ctx.Request.SetMethod("GET")
		ctx.Request.SetRequestURI("/resource?x=1&y=two")
		ctx.Request.Header.SetHost("proxy.example.com")

		base := strings.Replace(upstream.URL, "http://", "h2c://", 1) + "/base"
		err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, base, nil, "proxy.example.com")
		if err != nil {
			t.Fatalf("ForwardHTTP returned error: %v", err)
		}
		if got := ctx.Response.StatusCode(); got != http.StatusOK {
			t.Fatalf("status = %d, want %d", got, http.StatusOK)
		}
		if got := string(ctx.Response.Body()); got != "h2c-stream-base-query" {
			t.Fatalf("response body = %q, want %q", got, "h2c-stream-base-query")
		}
	})

	t.Run("h3", func(t *testing.T) {
		upstream, base := startTestHTTP3UpstreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertRequest(t, r, "HTTP/3.0")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "h3-stream-base-query")
		}))
		defer closeTestHTTP3UpstreamServer(t, upstream)

		ctx := app.NewContext(0)
		ctx.Request.SetMethod("GET")
		ctx.Request.SetRequestURI("/resource?x=1&y=two")
		ctx.Request.Header.SetHost("proxy.example.com")

		rt := snapshot.SiteRuntime{
			Site: store.Site{
				UpstreamTLSSkipVerify: true,
			},
		}

		err := ForwardHTTP(context.Background(), ctx, rt, base+"/base", nil, "proxy.example.com")
		if err != nil {
			t.Fatalf("ForwardHTTP returned error: %v", err)
		}
		if got := ctx.Response.StatusCode(); got != http.StatusOK {
			t.Fatalf("status = %d, want %d", got, http.StatusOK)
		}
		if got := string(ctx.Response.Body()); got != "h3-stream-base-query" {
			t.Fatalf("response body = %q, want %q", got, "h3-stream-base-query")
		}
	})
}

func TestForwardHTTPStreamsExplicitProtocolDecodedUpstreamWithoutStaleEncoding(t *testing.T) {
	body := []byte(strings.Repeat("streaming-explicit-protocol-decoded-upstream-", 128))
	encodedBody := mustGzipBytes(t, body)

	assertDecoded := func(t *testing.T, ctx *app.RequestContext) {
		t.Helper()
		if got := ctx.Response.StatusCode(); got != http.StatusOK {
			t.Fatalf("status = %d, want %d", got, http.StatusOK)
		}
		if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "" {
			t.Fatalf("Content-Encoding = %q, want empty", got)
		}
		if got := string(ctx.Response.Header.Peek("Content-Length")); got != "" {
			t.Fatalf("Content-Length = %q, want empty", got)
		}
		if !ctx.Response.ImmediateHeaderFlush {
			t.Fatal("ImmediateHeaderFlush = false, want true")
		}
		if !bytes.Equal(ctx.Response.Body(), body) {
			t.Fatalf("decoded body mismatch: got %d bytes want %d bytes", len(ctx.Response.Body()), len(body))
		}
	}

	t.Run("h2c", func(t *testing.T) {
		upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Proto != "HTTP/2.0" {
				t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", strconv.Itoa(len(encodedBody)))
			_, _ = w.Write(encodedBody)
		}))
		upstream.Config.Protocols = new(http.Protocols)
		upstream.Config.Protocols.SetHTTP1(true)
		upstream.Config.Protocols.SetUnencryptedHTTP2(true)
		upstream.Start()
		defer upstream.Close()

		ctx := app.NewContext(0)
		ctx.Request.SetMethod("GET")
		ctx.Request.SetRequestURI("/h2c-decoded-stream")
		ctx.Request.Header.SetHost("proxy.example.com")

		base := strings.Replace(upstream.URL, "http://", "h2c://", 1)
		err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, base, nil, "proxy.example.com")
		if err != nil {
			t.Fatalf("ForwardHTTP returned error: %v", err)
		}
		assertDecoded(t, ctx)
	})

	t.Run("h3", func(t *testing.T) {
		upstream, base := startTestHTTP3UpstreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Proto != "HTTP/3.0" {
				t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/3.0")
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", strconv.Itoa(len(encodedBody)))
			_, _ = w.Write(encodedBody)
		}))
		defer closeTestHTTP3UpstreamServer(t, upstream)

		ctx := app.NewContext(0)
		ctx.Request.SetMethod("GET")
		ctx.Request.SetRequestURI("/h3-decoded-stream")
		ctx.Request.Header.SetHost("proxy.example.com")

		rt := snapshot.SiteRuntime{
			Site: store.Site{
				UpstreamTLSSkipVerify: true,
			},
		}
		err := ForwardHTTP(context.Background(), ctx, rt, base, nil, "proxy.example.com")
		if err != nil {
			t.Fatalf("ForwardHTTP returned error: %v", err)
		}
		assertDecoded(t, ctx)
	})
}

func TestForwardHTTPStreamsExplicitProtocolEncodedUpstreamSkipsCompression(t *testing.T) {
	body := []byte(strings.Repeat("streaming-explicit-protocol-custom-encoded-upstream-", 128))

	assertEncoded := func(t *testing.T, ctx *app.RequestContext) {
		t.Helper()
		if got := ctx.Response.StatusCode(); got != http.StatusOK {
			t.Fatalf("status = %d, want %d", got, http.StatusOK)
		}
		if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "custom" {
			t.Fatalf("Content-Encoding = %q, want custom", got)
		}
		if got := string(ctx.Response.Header.Peek("Content-Length")); got != strconv.Itoa(len(body)) {
			t.Fatalf("Content-Length = %q, want %d", got, len(body))
		}
		if got := string(ctx.Response.Header.Peek("Vary")); got != "" {
			t.Fatalf("Vary = %q, want empty when upstream body is already encoded", got)
		}
		if !ctx.Response.ImmediateHeaderFlush {
			t.Fatal("ImmediateHeaderFlush = false, want true")
		}
		if !bytes.Equal(ctx.Response.Body(), body) {
			t.Fatalf("encoded body changed: got %d bytes want %d bytes", len(ctx.Response.Body()), len(body))
		}
	}

	t.Run("h2c", func(t *testing.T) {
		upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Proto != "HTTP/2.0" {
				t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Encoding", "custom")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_, _ = w.Write(body)
		}))
		upstream.Config.Protocols = new(http.Protocols)
		upstream.Config.Protocols.SetHTTP1(true)
		upstream.Config.Protocols.SetUnencryptedHTTP2(true)
		upstream.Start()
		defer upstream.Close()

		ctx := app.NewContext(0)
		ctx.Request.SetMethod("GET")
		ctx.Request.SetRequestURI("/h2c-encoded-stream")
		ctx.Request.Header.SetHost("proxy.example.com")
		ctx.Request.Header.Set("Accept-Encoding", "gzip")

		base := strings.Replace(upstream.URL, "http://", "h2c://", 1)
		err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, base, nil, "proxy.example.com")
		if err != nil {
			t.Fatalf("ForwardHTTP returned error: %v", err)
		}
		assertEncoded(t, ctx)
	})

	t.Run("h3", func(t *testing.T) {
		upstream, base := startTestHTTP3UpstreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Proto != "HTTP/3.0" {
				t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/3.0")
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Encoding", "custom")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_, _ = w.Write(body)
		}))
		defer closeTestHTTP3UpstreamServer(t, upstream)

		ctx := app.NewContext(0)
		ctx.Request.SetMethod("GET")
		ctx.Request.SetRequestURI("/h3-encoded-stream")
		ctx.Request.Header.SetHost("proxy.example.com")
		ctx.Request.Header.Set("Accept-Encoding", "gzip")

		rt := snapshot.SiteRuntime{
			Site: store.Site{
				UpstreamTLSSkipVerify: true,
			},
		}
		err := ForwardHTTP(context.Background(), ctx, rt, base, nil, "proxy.example.com")
		if err != nil {
			t.Fatalf("ForwardHTTP returned error: %v", err)
		}
		assertEncoded(t, ctx)
	})
}

func TestForwardHTTPWritesH2CResponseTrailers(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/2.0" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Add("Trailer", "X-Upstream-Trailer")
		_, _ = io.WriteString(w, "h2c streamed trailer payload")
		w.Header().Set("X-Upstream-Trailer", "done")
	}))
	upstream.Config.Protocols = new(http.Protocols)
	upstream.Config.Protocols.SetHTTP1(true)
	upstream.Config.Protocols.SetUnencryptedHTTP2(true)
	upstream.Start()
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/h2c-streamed-trailers")
	ctx.Request.Header.SetHost("proxy.example.com")

	base := strings.Replace(upstream.URL, "http://", "h2c://", 1)
	err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, base, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	if got := string(ctx.Response.Body()); got != "h2c streamed trailer payload" {
		t.Fatalf("response body = %q, want %q", got, "h2c streamed trailer payload")
	}
	if got := ctx.Response.Header.Trailer().Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("response trailer X-Upstream-Trailer = %q, want %q", got, "done")
	}
}

func TestForwardHTTPWritesHTTP3ResponseTrailers(t *testing.T) {
	upstream, base := startTestHTTP3UpstreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/3.0" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/3.0")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Add("Trailer", "X-Upstream-Trailer")
		_, _ = io.WriteString(w, "h3 streamed trailer payload")
		w.Header().Set("X-Upstream-Trailer", "done")
	}))
	defer closeTestHTTP3UpstreamServer(t, upstream)

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/h3-streamed-trailers")
	ctx.Request.Header.SetHost("proxy.example.com")

	rt := snapshot.SiteRuntime{
		Site: store.Site{
			UpstreamTLSSkipVerify: true,
		},
	}

	err := ForwardHTTP(context.Background(), ctx, rt, base, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	if got := string(ctx.Response.Body()); got != "h3 streamed trailer payload" {
		t.Fatalf("response body = %q, want %q", got, "h3 streamed trailer payload")
	}
	if got := ctx.Response.Header.Trailer().Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("response trailer X-Upstream-Trailer = %q, want %q", got, "done")
	}
}

func TestForwardHTTPStripsConnectionTokenHeadersWhileForwardingResponseTrailers(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/1.1" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/1.1")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Connection", "X-Hop, X-Trace-Hop")
		w.Header().Set("X-Hop", "drop")
		w.Header().Set("X-Trace-Hop", "drop")
		w.Header().Set("X-End-To-End", "kept")
		w.Header().Add("Trailer", "X-Upstream-Trailer")
		_, _ = io.WriteString(w, "streamed trailer payload with connection tokens")
		w.Header().Set("X-Upstream-Trailer", "done")
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/streamed-trailers-connection-tokens")
	ctx.Request.Header.SetHost("proxy.example.com")

	err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	if got := string(ctx.Response.Body()); got != "streamed trailer payload with connection tokens" {
		t.Fatalf("response body = %q, want streamed trailer payload with connection tokens", got)
	}
	if got := string(ctx.Response.Header.Peek("Connection")); got != "" {
		t.Fatalf("Connection response header = %q, want empty", got)
	}
	if got := string(ctx.Response.Header.Peek("X-Hop")); got != "" {
		t.Fatalf("X-Hop response header = %q, want empty", got)
	}
	if got := string(ctx.Response.Header.Peek("X-Trace-Hop")); got != "" {
		t.Fatalf("X-Trace-Hop response header = %q, want empty", got)
	}
	if got := string(ctx.Response.Header.Peek("X-End-To-End")); got != "kept" {
		t.Fatalf("X-End-To-End response header = %q, want kept", got)
	}
	if got := ctx.Response.Header.Trailer().Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("response trailer X-Upstream-Trailer = %q, want %q", got, "done")
	}
}

func TestForwardHTTPCompressesHTTP3ResponseWithTrailers(t *testing.T) {
	body := []byte(strings.Repeat("h3-compressed-trailer-payload-", 160))
	upstream, base := startTestHTTP3UpstreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/3.0" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/3.0")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Add("Trailer", "X-Upstream-Trailer")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
		w.Header().Set("X-Upstream-Trailer", "done")
	}))
	defer closeTestHTTP3UpstreamServer(t, upstream)

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/h3-compressed-trailers")
	ctx.Request.Header.SetHost("proxy.example.com")
	ctx.Request.Header.Set("Accept-Encoding", "gzip")

	rt := snapshot.SiteRuntime{
		Site: store.Site{
			UpstreamTLSSkipVerify: true,
		},
	}

	err := ForwardHTTP(context.Background(), ctx, rt, base, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := string(ctx.Response.Header.Peek("Vary")); !strings.Contains(strings.ToLower(got), "accept-encoding") {
		t.Fatalf("Vary = %q, want Accept-Encoding", got)
	}
	reader, err := gzip.NewReader(bytes.NewReader(ctx.Response.Body()))
	if err != nil {
		t.Fatalf("create gzip reader: %v", err)
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("decode gzip response: %v", err)
	}
	if !bytes.Equal(decoded, body) {
		t.Fatalf("gzip decoded body mismatch")
	}
	if got := ctx.Response.Header.Trailer().Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("response trailer X-Upstream-Trailer = %q, want %q", got, "done")
	}
}

func TestForwardBufferedResponseUsesBrotliWhenEnabled(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.Header.Set("Accept-Encoding", "br, gzip")

	body := []byte(strings.Repeat("brotli-response-body-", 128))
	resp := &HTTPResponse{
		StatusCode:  http.StatusOK,
		ContentType: "text/plain; charset=utf-8",
		Body:        body,
		Header: http.Header{
			"Content-Type": []string{"text/plain; charset=utf-8"},
		},
	}

	ForwardBufferedResponse(ctx, resp)

	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "br" {
		t.Fatalf("Content-Encoding = %q, want br", got)
	}
	if got := string(ctx.Response.Header.Peek("Vary")); !strings.Contains(strings.ToLower(got), "accept-encoding") {
		t.Fatalf("Vary = %q, want Accept-Encoding", got)
	}
	decoded, err := io.ReadAll(brotli.NewReader(bytes.NewReader(ctx.Response.Body())))
	if err != nil {
		t.Fatalf("decode brotli response: %v", err)
	}
	if !bytes.Equal(decoded, body) {
		t.Fatalf("brotli decoded body mismatch")
	}
}

func TestForwardBufferedResponseHonorsAcceptEncodingQPreference(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.Header.Set("Accept-Encoding", "br;q=0.1, gzip;q=1")

	body := []byte(strings.Repeat("gzip-preferred-response-body-", 128))
	resp := &HTTPResponse{
		StatusCode:  http.StatusOK,
		ContentType: "text/plain; charset=utf-8",
		Body:        body,
		Header: http.Header{
			"Content-Type": []string{"text/plain; charset=utf-8"},
		},
	}

	ForwardBufferedResponse(ctx, resp)

	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	reader, err := gzip.NewReader(bytes.NewReader(ctx.Response.Body()))
	if err != nil {
		t.Fatalf("create gzip reader: %v", err)
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("decode gzip response: %v", err)
	}
	if !bytes.Equal(decoded, body) {
		t.Fatalf("gzip decoded body mismatch")
	}
}

func TestVaryContainsAcceptEncodingBytesMatchesStringSemantics(t *testing.T) {
	tests := []string{
		"",
		"Accept-Encoding",
		"accept-encoding",
		" Accept-Encoding ",
		"Origin, Accept-Encoding",
		"Origin,Accept-Encoding,User-Agent",
		"Origin, accept-encoding ",
		"X-Accept-Encoding",
		"Accept",
		"Accept-Encoding-Extra",
		"Accept, Encoding",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			want := varyContainsAcceptEncodingString(raw)
			if got := varyContainsAcceptEncodingBytes([]byte(raw)); got != want {
				t.Fatalf("varyContainsAcceptEncodingBytes(%q) = %v, want %v", raw, got, want)
			}
		})
	}
}

func varyContainsAcceptEncodingString(raw string) bool {
	for _, token := range strings.Split(raw, ",") {
		if strings.EqualFold(strings.TrimSpace(token), "Accept-Encoding") {
			return true
		}
	}
	return false
}

func TestParseAcceptEncodingOffersClampsQValues(t *testing.T) {
	offers := parseAcceptEncodingOffers("gzip;q=2, br;q=-0.5, deflate;q=0.75, zstd;q=bad")
	if len(offers) != 4 {
		t.Fatalf("offer count = %d, want 4", len(offers))
	}

	want := map[string]float64{
		"gzip":    1,
		"br":      0,
		"deflate": 0.75,
		"zstd":    1,
	}
	for _, offer := range offers {
		if got := offer.q; got != want[offer.name] {
			t.Fatalf("q for %s = %v, want %v", offer.name, got, want[offer.name])
		}
	}
}

func TestSelectClientResponseEncodingBytesMatchesStringSemantics(t *testing.T) {
	tests := []struct {
		name          string
		raw           string
		brotliEnabled bool
		gzipEnabled   bool
	}{
		{name: "empty", raw: "", brotliEnabled: true, gzipEnabled: true},
		{name: "browser default", raw: "gzip, deflate, br, zstd", brotliEnabled: true, gzipEnabled: true},
		{name: "gzip q preferred", raw: "br;q=0.1, gzip;q=1", brotliEnabled: true, gzipEnabled: true},
		{name: "explicit gzip zero over wildcard", raw: "gzip;q=0, *;q=0.8", brotliEnabled: false, gzipEnabled: true},
		{name: "clamped q values", raw: "gzip;q=2, br;q=-0.5, deflate;q=0.75, zstd;q=bad", brotliEnabled: true, gzipEnabled: true},
		{name: "duplicate exact takes max", raw: "gzip;q=0.5, gzip;q=0.9", brotliEnabled: true, gzipEnabled: true},
		{name: "bad q keeps default", raw: "gzip;q=bad, br;q=0.5", brotliEnabled: true, gzipEnabled: true},
		{name: "mixed case token and q key", raw: " GZip ; q = 0.4 , Br ; Q=0.9 ", brotliEnabled: true, gzipEnabled: true},
		{name: "brotli disabled", raw: "br, gzip;q=0.7", brotliEnabled: false, gzipEnabled: true},
		{name: "gzip disabled", raw: "gzip, deflate;q=0.4", brotliEnabled: false, gzipEnabled: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := selectClientResponseEncoding(tt.raw, tt.brotliEnabled, tt.gzipEnabled)
			got := selectClientResponseEncodingBytes([]byte(tt.raw), tt.brotliEnabled, tt.gzipEnabled)
			if got != want {
				t.Fatalf("selectClientResponseEncodingBytes(%q) = %q, want %q", tt.raw, got, want)
			}
		})
	}
}

func TestParseAcceptEncodingQValueBytesMatchesParseFloatSemantics(t *testing.T) {
	values := []string{
		"0",
		"0.001",
		"0.75",
		"1",
		"1.5",
		"-0.5",
		"+0.4",
		"1e0",
		"NaN",
		"Inf",
		"bad",
		".5",
	}
	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			got, gotOK := parseAcceptEncodingQValueBytes([]byte(value))
			want, err := strconv.ParseFloat(value, 64)
			wantOK := err == nil && !math.IsNaN(want)
			if gotOK != wantOK {
				t.Fatalf("parseAcceptEncodingQValueBytes(%q) ok = %v, want %v", value, gotOK, wantOK)
			}
			if gotOK && got != want {
				t.Fatalf("parseAcceptEncodingQValueBytes(%q) = %v, want %v", value, got, want)
			}
		})
	}
}

func BenchmarkSelectClientResponseEncodingBytesBrowser(b *testing.B) {
	raw := []byte("gzip, deflate, br, zstd")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyEncodingSink = selectClientResponseEncodingBytes(raw, true, true)
	}
}

func BenchmarkSelectClientResponseEncodingStringBrowser(b *testing.B) {
	raw := "gzip, deflate, br, zstd"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyEncodingSink = selectClientResponseEncoding(raw, true, true)
	}
}

func BenchmarkSelectClientResponseEncodingBytesQValues(b *testing.B) {
	raw := []byte("br;q=0.1, gzip;q=1, deflate;q=0.75, zstd;q=bad")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyEncodingSink = selectClientResponseEncodingBytes(raw, true, true)
	}
}

func BenchmarkSelectClientResponseEncodingStringQValues(b *testing.B) {
	raw := "br;q=0.1, gzip;q=1, deflate;q=0.75, zstd;q=bad"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyEncodingSink = selectClientResponseEncoding(raw, true, true)
	}
}

func BenchmarkVaryContainsAcceptEncodingBytes(b *testing.B) {
	raw := []byte("Origin, Accept-Encoding, User-Agent")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = varyContainsAcceptEncodingBytes(raw)
	}
}

func BenchmarkVaryContainsAcceptEncodingString(b *testing.B) {
	raw := "Origin, Accept-Encoding, User-Agent"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = varyContainsAcceptEncodingString(raw)
	}
}

func BenchmarkParseContentEncodingsBytes(b *testing.B) {
	raw := []byte("gzip, br, deflate, zstd")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyStringsSink, benchmarkProxyBoolSink = parseContentEncodingsBytes(raw)
	}
}

func BenchmarkParseContentEncodingsString(b *testing.B) {
	raw := "gzip, br, deflate, zstd"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyStringsSink, benchmarkProxyBoolSink = parseContentEncodingsStringForTest(raw)
	}
}

func BenchmarkNormalizedContentEncodingBytes(b *testing.B) {
	raw := []byte(" GZip ; level=1 ")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyStringSink = normalizedContentEncodingBytes(raw)
	}
}

func BenchmarkNormalizedContentEncodingString(b *testing.B) {
	raw := " GZip ; level=1 "

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyStringSink = normalizedContentEncodingStringForTest(raw)
	}
}

func BenchmarkShouldTransformResponseMetadataBytes(b *testing.B) {
	contentType := []byte("application/json; charset=utf-8")
	contentEncoding := []byte("identity")
	cacheControl := []byte("public, max-age=60")
	contentRange := []byte("")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = shouldTransformResponseMetadataBytes(http.StatusOK, contentType, contentEncoding, cacheControl, contentRange)
	}
}

func BenchmarkShouldTransformResponseMetadataString(b *testing.B) {
	contentType := "application/json; charset=utf-8"
	contentEncoding := "identity"
	cacheControl := "public, max-age=60"
	contentRange := ""

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = shouldTransformResponseMetadata(http.StatusOK, contentType, contentEncoding, cacheControl, contentRange)
	}
}

func BenchmarkIsCompressibleContentTypeBytes(b *testing.B) {
	raw := []byte("application/json; charset=utf-8")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = isCompressibleContentTypeBytes(raw)
	}
}

func BenchmarkIsCompressibleContentTypeString(b *testing.B) {
	raw := "application/json; charset=utf-8"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = isCompressibleContentType(raw)
	}
}

func BenchmarkCacheControlHasNoTransformBytes(b *testing.B) {
	raw := []byte("PUBLIC, MAX-AGE=60, MUST-REVALIDATE")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = cacheControlHasNoTransformBytes(raw)
	}
}

func BenchmarkCacheControlHasNoTransformString(b *testing.B) {
	raw := "PUBLIC, MAX-AGE=60, MUST-REVALIDATE"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = strings.Contains(strings.ToLower(raw), "no-transform")
	}
}

func TestForwardBufferedResponseStripsConnectionTokenHeaders(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")

	resp := &HTTPResponse{
		StatusCode:  http.StatusOK,
		ContentType: "text/plain; charset=utf-8",
		Body:        []byte("buffered-response"),
		Header: http.Header{
			"Content-Type":  []string{"text/plain; charset=utf-8"},
			"Connection":    []string{"X-Hop, X-Trace-Hop"},
			"X-Hop":         []string{"drop"},
			"X-Trace-Hop":   []string{"drop"},
			"X-End-To-End":  []string{"kept"},
			"Cache-Control": []string{"public"},
		},
	}

	ForwardBufferedResponse(ctx, resp)

	if got := string(ctx.Response.Header.Peek("X-Hop")); got != "" {
		t.Fatalf("X-Hop response header = %q, want empty", got)
	}
	if got := string(ctx.Response.Header.Peek("X-Trace-Hop")); got != "" {
		t.Fatalf("X-Trace-Hop response header = %q, want empty", got)
	}
	if got := string(ctx.Response.Header.Peek("Connection")); got != "" {
		t.Fatalf("Connection response header = %q, want empty", got)
	}
	if got := string(ctx.Response.Header.Peek("X-End-To-End")); got != "kept" {
		t.Fatalf("X-End-To-End response header = %q, want kept", got)
	}
}

func TestWriteCachedResponseFallsBackToGzipWhenBrotliDisabled(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.Header.Set("Accept-Encoding", "br, gzip")

	body := []byte(strings.Repeat("{\"ok\":true}", 256))
	entry := &cache.ResponseEntry{
		StatusCode:  http.StatusOK,
		ContentType: "application/json",
		Body:        body,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	WriteCachedResponse(ctx, "GET", entry)

	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	reader, err := gzip.NewReader(bytes.NewReader(ctx.Response.Body()))
	if err != nil {
		t.Fatalf("create gzip reader: %v", err)
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("decode gzip response: %v", err)
	}
	if !bytes.Equal(decoded, body) {
		t.Fatalf("gzip decoded body mismatch")
	}
}

func TestForwardBufferedResponseSkipsCompressionForSmallBody(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.Header.Set("Accept-Encoding", "br, gzip")

	body := []byte("small body should stay identity")
	resp := &HTTPResponse{
		StatusCode:  http.StatusOK,
		ContentType: "text/plain; charset=utf-8",
		Body:        body,
		Header: http.Header{
			"Content-Type": []string{"text/plain; charset=utf-8"},
		},
	}

	ForwardBufferedResponse(ctx, resp)

	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if !bytes.Equal(ctx.Response.Body(), body) {
		t.Fatalf("response body changed for small identity response")
	}
}

func TestForwardBufferedResponseHEADWritesCompressedMetadataOnly(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("HEAD")
	ctx.Request.Header.Set("Accept-Encoding", "gzip")

	body := []byte(strings.Repeat("head-buffered-response-", 256))
	wantBody, err := compressResponseBody(body, responseEncodingGzip)
	if err != nil {
		t.Fatalf("compressResponseBody returned error: %v", err)
	}
	resp := &HTTPResponse{
		StatusCode:  http.StatusOK,
		ContentType: "text/plain; charset=utf-8",
		Body:        body,
		Header: http.Header{
			"Content-Type": []string{"text/plain; charset=utf-8"},
		},
	}

	ForwardBufferedResponse(ctx, resp)

	if got := len(ctx.Response.Body()); got != 0 {
		t.Fatalf("HEAD response body length = %d, want 0", got)
	}
	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := string(ctx.Response.Header.Peek("Content-Length")); got != strconv.Itoa(len(wantBody)) {
		t.Fatalf("Content-Length = %q, want %d", got, len(wantBody))
	}
	if got := string(ctx.Response.Header.Peek("Vary")); !strings.Contains(strings.ToLower(got), "accept-encoding") {
		t.Fatalf("Vary = %q, want Accept-Encoding", got)
	}
}

func TestWriteCachedResponseHEADWritesCompressedMetadataOnly(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("HEAD")
	ctx.Request.Header.Set("Accept-Encoding", "gzip")

	body := []byte(strings.Repeat("{\"cached\":true}", 256))
	wantBody, err := compressResponseBody(body, responseEncodingGzip)
	if err != nil {
		t.Fatalf("compressResponseBody returned error: %v", err)
	}
	entry := &cache.ResponseEntry{
		StatusCode:  http.StatusOK,
		ContentType: "application/json",
		Body:        body,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	WriteCachedResponse(ctx, "HEAD", entry)

	if got := len(ctx.Response.Body()); got != 0 {
		t.Fatalf("HEAD response body length = %d, want 0", got)
	}
	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := string(ctx.Response.Header.Peek("Content-Length")); got != strconv.Itoa(len(wantBody)) {
		t.Fatalf("Content-Length = %q, want %d", got, len(wantBody))
	}
	if got := string(ctx.Response.Header.Peek("Vary")); !strings.Contains(strings.ToLower(got), "accept-encoding") {
		t.Fatalf("Vary = %q, want Accept-Encoding", got)
	}
}

func TestForwardHTTPHEADPassesThroughHeadersWithoutBody(t *testing.T) {
	payload := []byte(strings.Repeat("upstream-head-body-", 128))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("upstream method = %s, want HEAD", r.Method)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.Header().Set("X-Upstream", "head")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("HEAD")
	ctx.Request.SetRequestURI("/compressed-head?x=1")
	ctx.Request.Header.SetHost("proxy.example.com")

	err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	if got := len(ctx.Response.Body()); got != 0 {
		t.Fatalf("HEAD response body length = %d, want 0", got)
	}
	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := string(ctx.Response.Header.Peek("Content-Length")); got != strconv.Itoa(len(payload)) {
		t.Fatalf("Content-Length = %q, want %d", got, len(payload))
	}
	if got := string(ctx.Response.Header.Peek("X-Upstream")); got != "head" {
		t.Fatalf("X-Upstream = %q, want head", got)
	}
}

func TestForwardHTTPSkipsBodyStreamForNoBodyStatus(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", "128")
		w.Header().Add("Trailer", "X-Upstream-Trailer")
		w.WriteHeader(http.StatusNoContent)
		w.Header().Set("X-Upstream-Trailer", "done")
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/no-body")
	ctx.Request.Header.SetHost("proxy.example.com")

	err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := ctx.Response.StatusCode(); got != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", got, http.StatusNoContent)
	}
	if got := len(ctx.Response.Body()); got != 0 {
		t.Fatalf("no-body response body length = %d, want 0", got)
	}
	if ctx.Response.IsBodyStream() {
		t.Fatal("no-body response is still marked as body stream")
	}
	if got := string(ctx.Response.Header.Peek("Content-Length")); got != "" {
		t.Fatalf("Content-Length = %q, want empty", got)
	}
	if got := ctx.Response.Header.Trailer().Get("X-Upstream-Trailer"); got != "" {
		t.Fatalf("response trailer X-Upstream-Trailer = %q, want empty", got)
	}
}

func TestForwardHTTPHonorsCustomCompressionMinBytes(t *testing.T) {
	body := []byte(strings.Repeat("streaming-custom-threshold-", 160))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("upstream writer does not support flushing")
		}
		midpoint := len(body) / 2
		_, _ = w.Write(body[:midpoint])
		flusher.Flush()
		_, _ = w.Write(body[midpoint:])
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/stream-custom-threshold")
	ctx.Request.Header.SetHost("proxy.example.com")
	ctx.Request.Header.Set("Accept-Encoding", "gzip")

	err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	reader, err := gzip.NewReader(bytes.NewReader(ctx.Response.Body()))
	if err != nil {
		t.Fatalf("create gzip reader: %v", err)
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("decode gzip response: %v", err)
	}
	if !bytes.Equal(decoded, body) {
		t.Fatalf("streaming gzip decoded body mismatch")
	}
}

func TestForwardHTTPStreamsUnknownLengthCompressionWithoutReadAll(t *testing.T) {
	first := []byte(strings.Repeat("unknown-length-first-", 64))
	second := []byte(strings.Repeat("unknown-length-second-", 64))
	release := make(chan struct{})
	firstFlushed := make(chan struct{})
	var releaseOnce sync.Once
	releaseUpstream := func() {
		releaseOnce.Do(func() { close(release) })
	}
	t.Cleanup(releaseUpstream)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream writer does not support flushing")
			return
		}
		_, _ = w.Write(first)
		flusher.Flush()
		close(firstFlushed)
		<-release
		_, _ = w.Write(second)
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/unknown-length-stream")
	ctx.Request.Header.SetHost("proxy.example.com")
	ctx.Request.Header.Set("Accept-Encoding", "gzip")

	type result struct {
		err error
	}
	done := make(chan result, 1)
	go func() {
		err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "proxy.example.com")
		done <- result{err: err}
	}()

	select {
	case <-firstFlushed:
	case <-time.After(2 * time.Second):
		releaseUpstream()
		t.Fatal("timed out waiting for upstream first chunk")
	}

	select {
	case got := <-done:
		if got.err != nil {
			releaseUpstream()
			t.Fatalf("ForwardHTTP returned error: %v", got.err)
		}
	case <-time.After(200 * time.Millisecond):
		releaseUpstream()
		t.Fatal("ForwardHTTP blocked reading the full unknown-length response before returning")
	}

	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "gzip" {
		releaseUpstream()
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	releaseUpstream()

	reader, err := gzip.NewReader(bytes.NewReader(ctx.Response.Body()))
	if err != nil {
		t.Fatalf("create gzip reader: %v", err)
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("decode gzip response: %v", err)
	}
	if !bytes.Equal(decoded, append(append([]byte(nil), first...), second...)) {
		t.Fatalf("streaming gzip decoded body mismatch")
	}
}

func TestForwardHTTPSkipsUnknownLengthCompressionBelowMinBytes(t *testing.T) {
	body := []byte("small unknown length")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Add("Trailer", "X-Upstream-Trailer")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("upstream writer does not support flushing")
		}
		_, _ = w.Write(body)
		flusher.Flush()
		w.Header().Set("X-Upstream-Trailer", "done")
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/small-unknown-length-stream")
	ctx.Request.Header.SetHost("proxy.example.com")
	ctx.Request.Header.Set("Accept-Encoding", "gzip")

	err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if !bytes.Equal(ctx.Response.Body(), body) {
		t.Fatalf("response body = %q, want %q", string(ctx.Response.Body()), string(body))
	}
	if got := ctx.Response.Header.Trailer().Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("response trailer X-Upstream-Trailer = %q, want done", got)
	}
}

func TestForwardHTTPSkipsUnknownLengthCompressionBelowLargeMinBytes(t *testing.T) {
	body := []byte(strings.Repeat("unknown-length-large-threshold-", 220))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("upstream writer does not support flushing")
		}
		_, _ = w.Write(body)
		flusher.Flush()
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/large-threshold-unknown-length-stream")
	ctx.Request.Header.SetHost("proxy.example.com")
	ctx.Request.Header.Set("Accept-Encoding", "gzip")

	err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if !bytes.Equal(ctx.Response.Body(), body) {
		t.Fatalf("response body = %q, want %q", string(ctx.Response.Body()), string(body))
	}
}

func TestForwardHTTPUsesStreamingZstdWhenRequested(t *testing.T) {
	body := []byte(strings.Repeat("streaming-zstd-response-", 160))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("upstream writer does not support flushing")
		}
		midpoint := len(body) / 2
		_, _ = w.Write(body[:midpoint])
		flusher.Flush()
		_, _ = w.Write(body[midpoint:])
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/stream-zstd")
	ctx.Request.Header.SetHost("proxy.example.com")
	ctx.Request.Header.Set("Accept-Encoding", "zstd")

	err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "zstd" {
		t.Fatalf("Content-Encoding = %q, want zstd", got)
	}
	reader, err := zstd.NewReader(bytes.NewReader(ctx.Response.Body()))
	if err != nil {
		t.Fatalf("create zstd reader: %v", err)
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader.IOReadCloser())
	if err != nil {
		t.Fatalf("decode zstd response: %v", err)
	}
	if !bytes.Equal(decoded, body) {
		t.Fatalf("streaming zstd decoded body mismatch")
	}
}

func TestForwardHTTPUsesStreamingDeflateWhenRequested(t *testing.T) {
	body := []byte(strings.Repeat("streaming-deflate-response-", 160))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/stream-deflate")
	ctx.Request.Header.SetHost("proxy.example.com")
	ctx.Request.Header.Set("Accept-Encoding", "deflate")

	err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "deflate" {
		t.Fatalf("Content-Encoding = %q, want deflate", got)
	}
	reader, err := zlib.NewReader(bytes.NewReader(ctx.Response.Body()))
	if err != nil {
		t.Fatalf("create deflate reader: %v", err)
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("decode deflate response: %v", err)
	}
	if !bytes.Equal(decoded, body) {
		t.Fatalf("streaming deflate decoded body mismatch")
	}
}

func TestForwardHTTPSkipsStreamingGzipWhenGzipCompressionDisabled(t *testing.T) {
	body := []byte(strings.Repeat("streaming-gzip-disabled-", 24))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/stream-gzip-disabled")
	ctx.Request.Header.SetHost("proxy.example.com")
	ctx.Request.Header.Set("Accept-Encoding", "gzip")

	err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if !bytes.Equal(ctx.Response.Body(), body) {
		t.Fatalf("streaming body changed when gzip compression is disabled")
	}
}

func TestForwardHTTPWritesResponseTrailers(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Add("Trailer", "X-Upstream-Trailer")
		_, _ = io.WriteString(w, "streamed trailer payload")
		w.Header().Set("X-Upstream-Trailer", "done")
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/trailers")
	ctx.Request.Header.SetHost("proxy.example.com")

	err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if string(ctx.Response.Body()) != "streamed trailer payload" {
		t.Fatalf("streamed body = %q", string(ctx.Response.Body()))
	}
	if got := ctx.Response.Header.Trailer().Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("response trailer X-Upstream-Trailer = %q, want %q", got, "done")
	}
}

func TestVaryDisallowsCaching(t *testing.T) {
	if varyDisallowsCaching("") {
		t.Fatal("empty Vary should not block")
	}
	if varyDisallowsCaching("Accept-Encoding") {
		t.Fatal("Accept-Encoding only should not block")
	}
	if varyDisallowsCaching("accept-encoding, Accept-Encoding") {
		t.Fatal("duplicate accept-encoding should not block")
	}
	if !varyDisallowsCaching("Accept-Encoding, User-Agent") {
		t.Fatal("multi-axis Vary should block")
	}
	if !varyDisallowsCaching("User-Agent") {
		t.Fatal("non-encoding Vary should block")
	}
}

func TestVaryDisallowsCachingMatchesPreviousStringSemantics(t *testing.T) {
	tests := []string{
		"",
		" ",
		"Accept-Encoding",
		" ACCEPT-ENCODING ",
		"accept-encoding, Accept-Encoding",
		"Accept-Encoding, , ACCEPT-ENCODING",
		"Accept-Encoding, User-Agent",
		"User-Agent",
		"X-Accept-Encoding",
		"accept-encoding-extra",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			want := varyDisallowsCachingStringForTest(raw)
			got := varyDisallowsCaching(raw)
			if got != want {
				t.Fatalf("varyDisallowsCaching(%q) = %v, want %v", raw, got, want)
			}
		})
	}
}

func varyDisallowsCachingStringForTest(vary string) bool {
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

func cacheControlDisallowsCachingStringForTest(cacheControl string) bool {
	cacheControl = strings.ToLower(cacheControl)
	return strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "private")
}

func TestUpstreamErrorLoggingHelpers(t *testing.T) {
	for _, n := range []uint64{1, 16, 1024, 2048} {
		if !shouldLogUpstreamErrorCount(n) {
			t.Fatalf("expected count %d to be logged", n)
		}
	}
	for _, n := range []uint64{17, 1023, 1025} {
		if shouldLogUpstreamErrorCount(n) {
			t.Fatalf("expected count %d to be sampled out", n)
		}
	}

	err := &url.Error{Op: "Get", URL: "http://127.0.0.1:8800/secret?token=value", Err: errors.New("dial tcp 127.0.0.1:8800: connectex")}
	reason := upstreamErrorReason(err)
	if strings.Contains(reason, "token=value") || strings.Contains(reason, "/secret") {
		t.Fatalf("upstream error reason leaked request URL: %q", reason)
	}
}

func TestLogUpstreamRequestErrorIncludesConfiguredProtocol(t *testing.T) {
	var buf bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(oldLogger)
	upstreamErrorLogCounter.Store(0)
	defer upstreamErrorLogCounter.Store(0)

	req, err := http.NewRequest(http.MethodGet, "https://origin.example.test/events?token=secret", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	logUpstreamRequestError(context.Background(), "streaming", req, "client.example", errors.New("dial failed"))

	logLine := buf.String()
	if !strings.Contains(logLine, `"upstream_protocol":"h3"`) {
		t.Fatalf("log line = %s, want upstream_protocol h3", logLine)
	}
	if !strings.Contains(logLine, `"scheme":"https"`) {
		t.Fatalf("log line = %s, want normalized request scheme https", logLine)
	}
	if strings.Contains(logLine, "token=secret") {
		t.Fatalf("log line leaked raw query: %s", logLine)
	}
}

func TestIsHTTPSUpstreamBase(t *testing.T) {
	cases := map[string]bool{
		"":                          false,
		"http://127.0.0.1:8800":     false,
		"https://example.test":      true,
		"HTTPS://example.test":      true,
		"HtTpS://example.test/path": true,
		"ftp://example.test":        false,
	}
	for input, want := range cases {
		if got := isHTTPSUpstreamBase(input); got != want {
			t.Fatalf("isHTTPSUpstreamBase(%q) = %v, want %v", input, got, want)
		}
	}
}

func startTestHTTP3UpstreamServer(t *testing.T, handler http.Handler) (*http3.Server, string) {
	t.Helper()

	return startTestHTTP3UpstreamServerWithTLSConfig(t, handler, nil)
}

func startTestHTTP3UpstreamServerWithTLSConfig(t *testing.T, handler http.Handler, configureTLS func(*tls.Config)) (*http3.Server, string) {
	t.Helper()

	cert, err := acme.GenerateSelfSigned("127.0.0.1:0")
	if err != nil {
		t.Fatalf("generate self-signed cert: %v", err)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h3"},
	}
	if configureTLS != nil {
		configureTLS(tlsCfg)
	}

	server := &http3.Server{
		Handler:   handler,
		TLSConfig: tlsCfg,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(pc)
	}()
	t.Cleanup(func() {
		closeTestHTTP3UpstreamServer(t, server)
		select {
		case serveErr := <-errCh:
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !strings.Contains(serveErr.Error(), "closed network connection") {
				t.Fatalf("http3 serve returned error: %v", serveErr)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("http3 server did not stop in time")
		}
	})

	return server, "h3://" + pc.LocalAddr().String()
}

func closeTestHTTP3UpstreamServer(t *testing.T, server *http3.Server) {
	t.Helper()
	if server == nil {
		return
	}
	if err := server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("close http3 server: %v", err)
	}
}

func BenchmarkIsHTTPSUpstreamBase(b *testing.B) {
	base := "HTTPS://127.0.0.1:8800/api/v1/example/path?alpha=1&beta=2"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = isHTTPSUpstreamBase(base)
	}
}

func BenchmarkIsHTTPSUpstreamBaseToLower(b *testing.B) {
	base := "HTTPS://127.0.0.1:8800/api/v1/example/path?alpha=1&beta=2"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = strings.HasPrefix(strings.ToLower(base), "https://")
	}
}

func BenchmarkVaryDisallowsCaching(b *testing.B) {
	raw := "Accept-Encoding, ACCEPT-ENCODING, accept-encoding"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = varyDisallowsCaching(raw)
	}
}

func BenchmarkVaryDisallowsCachingStringForTest(b *testing.B) {
	raw := "Accept-Encoding, ACCEPT-ENCODING, accept-encoding"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = varyDisallowsCachingStringForTest(raw)
	}
}

func BenchmarkCacheControlDisallowsCachingStringForTest(b *testing.B) {
	raw := "PUBLIC, MAX-AGE=60, MUST-REVALIDATE"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = cacheControlDisallowsCachingStringForTest(raw)
	}
}

func TestShouldCacheHTTPResponse_VaryAcceptEncoding(t *testing.T) {
	h := http.Header{}
	h.Set("Vary", "Accept-Encoding")
	resp := &HTTPResponse{StatusCode: 200, Body: []byte("ok"), Header: h}
	if !ShouldCacheHTTPResponse("GET", resp, false) {
		t.Fatal("expected cacheable with Vary: Accept-Encoding")
	}
	h.Set("Vary", "User-Agent")
	if ShouldCacheHTTPResponse("GET", resp, false) {
		t.Fatal("should not cache with Vary: User-Agent")
	}
}

func TestShouldCacheHTTPResponse_BypassUpstreamPrivate(t *testing.T) {
	h := http.Header{}
	h.Set("Cache-Control", "private, no-cache, no-store, max-age=0, must-revalidate")
	resp := &HTTPResponse{StatusCode: 200, Body: []byte("x"), Header: h}
	if ShouldCacheHTTPResponse("GET", resp, false) {
		t.Fatal("should block without bypass")
	}
	if !ShouldCacheHTTPResponse("GET", resp, true) {
		t.Fatal("expected cacheable with bypass")
	}
	h.Set("Set-Cookie", "a=b")
	if ShouldCacheHTTPResponse("GET", resp, true) {
		t.Fatal("set-cookie must still block")
	}
}

func TestSiteCacheTTLDetails_QueryAware(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "exact", Value: "/x?q=1", TTL: 10},
		},
	}
	if ttl, explicit := SiteCacheTTLDetails(rt, "/x?q=1"); ttl != 10 || !explicit {
		t.Fatalf("exact+query: ttl=%d explicit=%v", ttl, explicit)
	}
	if ttl, _ := SiteCacheTTLDetails(rt, "/x"); ttl != 0 {
		t.Fatalf("exact should not match path without query, got %d", ttl)
	}
	rt2 := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/a", TTL: 5},
		},
	}
	if ttl, explicit := SiteCacheTTLDetails(rt2, "/a/b?r=1"); ttl != 5 || !explicit {
		t.Fatalf("prefix+query: ttl=%d explicit=%v", ttl, explicit)
	}
}

func TestSiteCacheTTLDetails_DefaultNotExplicit(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled:    true,
		CacheDefaultTTL: 60,
	}
	if ttl, explicit := SiteCacheTTLDetails(rt, "/anything"); ttl != 0 || explicit {
		t.Fatalf("default TTL must not apply without a matching rule, got ttl=%d explicit=%v", ttl, explicit)
	}
}

func TestSiteCacheTTLDetails_RuleTTLZeroUsesDefault(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled:    true,
		CacheDefaultTTL: 120,
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/static", TTL: 0},
		},
	}
	if ttl, ex := SiteCacheTTLDetails(rt, "/static/a.js"); ttl != 120 || !ex {
		t.Fatalf("rule ttl 0 should inherit cache_default_ttl, got ttl=%d explicit=%v", ttl, ex)
	}
}

func TestSanitizeHeadersForEdgeCache(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Encoding", "br")
	h.Set("Content-Type", "application/javascript")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("Content-Length", "999")
	h.Set("Cache-Control", "public")
	out := SanitizeHeadersForEdgeCache(h)
	if out.Get("Content-Encoding") != "br" {
		t.Fatalf("want br, got %q", out.Get("Content-Encoding"))
	}
	if out.Get("Transfer-Encoding") != "" {
		t.Fatal("expected Transfer-Encoding removed")
	}
	if out.Get("Content-Length") != "" {
		t.Fatal("expected Content-Length removed")
	}
}

func TestSanitizeHeadersForEdgeCacheStripsConnectionTokenHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "X-Hop, X-Trace-Hop")
	h.Set("X-Hop", "drop")
	h.Set("X-Trace-Hop", "drop")
	h.Set("X-Keep", "kept")

	out := SanitizeHeadersForEdgeCache(h)
	if out.Get("X-Hop") != "" || out.Get("X-Trace-Hop") != "" {
		t.Fatalf("expected Connection token headers removed, got %#v", out)
	}
	if out.Get("Connection") != "" {
		t.Fatalf("expected Connection removed, got %q", out.Get("Connection"))
	}
	if out.Get("X-Keep") != "kept" {
		t.Fatalf("expected X-Keep kept, got %q", out.Get("X-Keep"))
	}
}

func TestBuildUpstreamRequestStripsHopByHopHeadersCaseInsensitive(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("CoNnEcTiOn", "close")
	ctx.Request.Header.Set("Proxy-Connection", "keep-alive")
	ctx.Request.Header.Set("Transfer-Encoding", "chunked")
	ctx.Request.Header.Set("X-Test", "kept")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if got := req.Header.Get("Connection"); got != "" {
		t.Fatalf("expected Connection stripped, got %q", got)
	}
	if got := req.Header.Get("Proxy-Connection"); got != "" {
		t.Fatalf("expected Proxy-Connection stripped, got %q", got)
	}
	if got := req.Header.Get("Transfer-Encoding"); got != "" {
		t.Fatalf("expected Transfer-Encoding stripped, got %q", got)
	}
	if got := req.Header.Get("X-Test"); got != "kept" {
		t.Fatalf("expected X-Test kept, got %q", got)
	}
}

func TestBuildUpstreamRequestStripsConnectionTokenHeaders(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("Connection", "X-Second-Hop")
	ctx.Request.Header.SetRawHeaders([]byte("Connection: X-Hop\r\nConnection: X-Trace-Hop\r\n"))
	ctx.Request.Header.Set("X-Hop", "drop")
	ctx.Request.Header.Set("X-Trace-Hop", "drop")
	ctx.Request.Header.Set("X-Second-Hop", "drop")
	ctx.Request.Header.Set("X-Keep", "kept")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if got := req.Header.Get("X-Hop"); got != "" {
		t.Fatalf("expected X-Hop stripped, got %q", got)
	}
	if got := req.Header.Get("X-Trace-Hop"); got != "" {
		t.Fatalf("expected X-Trace-Hop stripped, got %q", got)
	}
	if got := req.Header.Get("X-Second-Hop"); got != "" {
		t.Fatalf("expected X-Second-Hop stripped, got %q", got)
	}
	if got := req.Header.Get("X-Keep"); got != "kept" {
		t.Fatalf("expected X-Keep kept, got %q", got)
	}
}

func TestBuildUpstreamRequestPreservesRepeatedCanonicalHeaders(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Add("x-repeat", "one")
	ctx.Request.Header.Add("X-Repeat", "two")
	ctx.Request.Header.Set("x-test", "kept")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if got := req.Header.Get("X-Test"); got != "kept" {
		t.Fatalf("expected X-Test kept, got %q", got)
	}
	values := req.Header.Values("X-Repeat")
	if len(values) != 2 || values[0] != "one" || values[1] != "two" {
		t.Fatalf("expected repeated X-Repeat values preserved, got %#v", values)
	}
}

func TestBuildUpstreamRequestPreservesRepeatedForwardedForValues(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Add("X-Forwarded-For", " 198.51.100.7 ")
	ctx.Request.Header.Add("X-Forwarded-For", "")
	ctx.Request.Header.Add("X-Forwarded-For", " 198.51.100.8, 198.51.100.9 ")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", net.ParseIP("203.0.113.10"), "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if got := req.Header.Get("X-Forwarded-For"); got != "198.51.100.7, 198.51.100.8, 198.51.100.9, 203.0.113.10" {
		t.Fatalf("X-Forwarded-For = %q", got)
	}
}

func TestBuildUpstreamRequestCanonicalHeaderStorage(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("User-Agent", "bench-agent")
	ctx.Request.Header.Set("Accept", "application/json")
	ctx.Request.Header.Set("x-test", "kept")
	ctx.Request.Header.Add("x-repeat", "one")
	ctx.Request.Header.Add("X-Repeat", "two")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if got := req.Header["User-Agent"]; len(got) != 1 || got[0] != "bench-agent" {
		t.Fatalf("expected canonical User-Agent storage, got %#v", got)
	}
	if got := req.Header["Accept"]; len(got) != 1 || got[0] != "application/json" {
		t.Fatalf("expected canonical Accept storage, got %#v", got)
	}
	if got := req.Header.Get("X-Test"); got != "kept" {
		t.Fatalf("expected X-Test kept, got %q", got)
	}
	values := req.Header.Values("X-Repeat")
	if len(values) != 2 || values[0] != "one" || values[1] != "two" {
		t.Fatalf("expected repeated X-Repeat values preserved, got %#v", values)
	}
}

func TestBuildUpstreamRequestCopiesHeaderValues(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("X-Test", "kept")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	ctx.Request.Header.Set("X-Test", "mutated")

	if got := req.Header.Get("X-Test"); got != "kept" {
		t.Fatalf("X-Test after source mutation = %q, want kept", got)
	}
}

func TestAddUpstreamHeader(t *testing.T) {
	header := http.Header{}
	addUpstreamHeader(header, []byte("Accept"), []byte("application/json"))
	addUpstreamHeader(header, []byte("User-Agent"), []byte("bench-agent"))
	addUpstreamHeader(header, []byte("Content-Type"), []byte("application/json"))
	addUpstreamHeader(header, []byte("x-test"), []byte("kept"))
	addUpstreamHeader(header, []byte("x-repeat"), []byte("one"))
	addUpstreamHeader(header, []byte("X-Repeat"), []byte("two"))

	if got := header["Accept"]; len(got) != 1 || got[0] != "application/json" {
		t.Fatalf("Accept = %#v", got)
	}
	if got := header["User-Agent"]; len(got) != 1 || got[0] != "bench-agent" {
		t.Fatalf("User-Agent = %#v", got)
	}
	if got := header["Content-Type"]; len(got) != 1 || got[0] != "application/json" {
		t.Fatalf("Content-Type = %#v", got)
	}
	if got := header.Get("X-Test"); got != "kept" {
		t.Fatalf("X-Test = %q", got)
	}
	values := header.Values("X-Repeat")
	if len(values) != 2 || values[0] != "one" || values[1] != "two" {
		t.Fatalf("X-Repeat = %#v", values)
	}
}

func TestAddUpstreamHeaderBrowserCanonicalFastPaths(t *testing.T) {
	header := http.Header{}
	keys := []string{
		"Accept-Encoding",
		"Accept-Language",
		"Referer",
		"Origin",
		"Sec-Ch-Ua",
		"Sec-Ch-Ua-Mobile",
		"Sec-Ch-Ua-Platform",
		"Sec-Fetch-Site",
		"Sec-Fetch-Mode",
		"Sec-Fetch-Dest",
		"Cache-Control",
		"Pragma",
		"Upgrade-Insecure-Requests",
		"X-Client-Data",
		"X-Requested-With",
		"If-Modified-Since",
		"X-Tingyun-Id",
		"Cookie",
		"Content-Length",
	}
	for _, key := range keys {
		addUpstreamHeader(header, []byte(key), []byte("kept"))
	}

	for _, key := range keys {
		values := header[key]
		if len(values) != 1 || values[0] != "kept" {
			t.Fatalf("%s = %#v", key, values)
		}
	}
}

func TestBuildUpstreamRequestPOSTBodySemantics(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.SetBody([]byte(`{"ok":true}`))

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if req.ContentLength != int64(len(`{"ok":true}`)) {
		t.Fatalf("ContentLength = %d", req.ContentLength)
	}
	if req.Body == nil || req.Body == http.NoBody {
		t.Fatalf("expected readable Body, got %#v", req.Body)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("Body = %q", string(body))
	}
	if req.GetBody == nil {
		t.Fatalf("GetBody is nil")
	}
	second, err := req.GetBody()
	if err != nil {
		t.Fatalf("GetBody returned error: %v", err)
	}
	defer second.Close()
	replayed, err := io.ReadAll(second)
	if err != nil {
		t.Fatalf("read replay body: %v", err)
	}
	if string(replayed) != `{"ok":true}` {
		t.Fatalf("GetBody replay = %q", string(replayed))
	}
}

func TestBuildUpstreamRequestDecodesCompressedRequestBody(t *testing.T) {
	originalBody := []byte(strings.Repeat(`{"ok":true,"message":"decoded"}`, 8))
	tests := []struct {
		name            string
		contentEncoding string
		encode          func(*testing.T, []byte) []byte
	}{
		{
			name:            "gzip",
			contentEncoding: "gzip",
			encode:          mustGzipBytes,
		},
		{
			name:            "brotli",
			contentEncoding: "br",
			encode:          mustBrotliBytes,
		},
		{
			name:            "deflate",
			contentEncoding: "deflate",
			encode:          mustDeflateBytes,
		},
		{
			name:            "zstd",
			contentEncoding: "zstd",
			encode:          mustZstdBytes,
		},
		{
			name:            "gzip_then_brotli",
			contentEncoding: "gzip, br",
			encode: func(t *testing.T, body []byte) []byte {
				return mustEncodeBodyWithContentEncodings(t, body, "gzip", "br")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressedBody := tt.encode(t, originalBody)

			ctx := app.NewContext(0)
			ctx.Request.SetMethod("POST")
			ctx.Request.SetRequestURI("/resource?x=1")
			ctx.Request.Header.Set("Content-Type", "application/json")
			ctx.Request.Header.Set("Content-Encoding", tt.contentEncoding)
			ctx.Request.Header.Set("Content-Length", strconv.Itoa(len(compressedBody)))
			ctx.Request.SetBody(compressedBody)

			req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
			if err != nil {
				t.Fatalf("buildUpstreamRequest returned error: %v", err)
			}
			if got := req.Header.Get("Content-Encoding"); got != "" {
				t.Fatalf("Content-Encoding = %q, want empty", got)
			}
			if got := req.Header.Get("Content-Length"); got != "" {
				t.Fatalf("Content-Length header = %q, want empty", got)
			}
			if req.ContentLength != int64(len(originalBody)) {
				t.Fatalf("ContentLength = %d, want %d", req.ContentLength, len(originalBody))
			}
			if req.Body == nil || req.Body == http.NoBody {
				t.Fatalf("expected readable Body, got %#v", req.Body)
			}
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if !bytes.Equal(body, originalBody) {
				t.Fatalf("decoded body mismatch: got %d bytes want %d bytes", len(body), len(originalBody))
			}
			if req.GetBody == nil {
				t.Fatalf("GetBody is nil")
			}
			second, err := req.GetBody()
			if err != nil {
				t.Fatalf("GetBody returned error: %v", err)
			}
			defer second.Close()
			replayed, err := io.ReadAll(second)
			if err != nil {
				t.Fatalf("read replay body: %v", err)
			}
			if !bytes.Equal(replayed, originalBody) {
				t.Fatalf("GetBody replay mismatch: got %d bytes want %d bytes", len(replayed), len(originalBody))
			}
		})
	}
}

func TestBuildUpstreamRequestRejectsInvalidCompressedRequestBody(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("Content-Encoding", "gzip")
	ctx.Request.SetBody([]byte("not-a-valid-gzip-stream"))

	if _, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false); err == nil {
		t.Fatalf("expected invalid compressed body error")
	}
}

func TestBuildUpstreamRequestDecodesCompressedRequestBodyWithTrailers(t *testing.T) {
	originalBody := []byte(strings.Repeat(`{"ok":true,"message":"decoded-with-trailer"}`, 8))
	compressedBody := mustGzipBytes(t, originalBody)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Encoding"); got != "" {
			t.Fatalf("upstream Content-Encoding = %q, want empty", got)
		}
		if got := r.Header.Get("TE"); got != "trailers" {
			t.Fatalf("upstream TE = %q, want %q", got, "trailers")
		}
		if r.ContentLength != -1 {
			t.Fatalf("upstream ContentLength = %d, want -1 for trailer-capable request", r.ContentLength)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("upstream read body: %v", err)
		}
		if !bytes.Equal(body, originalBody) {
			t.Fatalf("upstream decoded body mismatch: got %d bytes want %d bytes", len(body), len(originalBody))
		}
		if got := r.Trailer.Get("X-Trace"); got != "done" {
			t.Fatalf("upstream trailer X-Trace = %q, want %q", got, "done")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("Content-Encoding", "gzip")
	ctx.Request.Header.Set("Content-Length", strconv.Itoa(len(compressedBody)))
	ctx.Request.Header.Set("TE", "trailers")
	ctx.Request.SetBody(compressedBody)
	if err := ctx.Request.Header.Trailer().Set("X-Trace", "done"); err != nil {
		t.Fatalf("set request trailer: %v", err)
	}

	req, err := buildUpstreamRequest(context.Background(), ctx, upstream.URL, nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if got := req.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if got := req.Header.Get("TE"); got != "trailers" {
		t.Fatalf("TE = %q, want %q", got, "trailers")
	}
	if got := req.Trailer.Get("X-Trace"); got != "done" {
		t.Fatalf("request trailer X-Trace = %q, want %q", got, "done")
	}
	if req.ContentLength != -1 {
		t.Fatalf("ContentLength = %d, want -1 for trailer-capable request", req.ContentLength)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http client Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

func TestBuildUpstreamRequestDecodesCompressedChunkedBody(t *testing.T) {
	originalBody := []byte(strings.Repeat(`{"ok":true,"message":"decoded-chunked"}`, 8))
	compressedBody := mustGzipBytes(t, originalBody)

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("Content-Encoding", "gzip")
	ctx.Request.Header.Set("Transfer-Encoding", "chunked")
	ctx.Request.SetBody(compressedBody)

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if got := req.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if got := req.Header.Get("Transfer-Encoding"); got != "" {
		t.Fatalf("Transfer-Encoding = %q, want empty", got)
	}
	if req.ContentLength != int64(len(originalBody)) {
		t.Fatalf("ContentLength = %d, want %d", req.ContentLength, len(originalBody))
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(body, originalBody) {
		t.Fatalf("decoded body mismatch: got %d bytes want %d bytes", len(body), len(originalBody))
	}
}

func TestBuildUpstreamRequestEmptyPOSTBodySemantics(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/resource?x=1")

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if req.Body != nil {
		t.Fatalf("Body = %#v", req.Body)
	}
	if req.GetBody != nil {
		t.Fatalf("GetBody is not nil")
	}
	if req.ContentLength != 0 {
		t.Fatalf("ContentLength = %d", req.ContentLength)
	}
}

func TestBuildUpstreamRequestPOSTBodySendsToUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength != int64(len(`{"ok":true}`)) {
			t.Fatalf("upstream ContentLength = %d", r.ContentLength)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("upstream read body: %v", err)
		}
		if string(body) != `{"ok":true}` {
			t.Fatalf("upstream body = %q", string(body))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.SetBody([]byte(`{"ok":true}`))

	req, err := buildUpstreamRequest(context.Background(), ctx, upstream.URL, nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http client Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("StatusCode = %d", resp.StatusCode)
	}
}

func TestBuildUpstreamRequestStreamsPlainRequestBody(t *testing.T) {
	body := []byte(strings.Repeat(`{"stream":"plain-body"}`, 2048))

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("Content-Type", "application/json")
	stream := &trackingReadCloser{reader: bytes.NewReader(body)}
	ctx.Request.SetBodyStream(stream, len(body))

	req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if stream.reads != 0 {
		t.Fatalf("stream reads after build = %d, want 0", stream.reads)
	}
	if req.ContentLength != int64(len(body)) {
		t.Fatalf("ContentLength = %d, want %d", req.ContentLength, len(body))
	}
	if req.GetBody != nil {
		t.Fatal("GetBody should be nil for streamed request body")
	}
	if req.Body == nil || req.Body == http.NoBody {
		t.Fatalf("expected streamed request body, got %#v", req.Body)
	}

	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read streamed request body: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("streamed body mismatch: got %d bytes want %d bytes", len(got), len(body))
	}
	if stream.reads == 0 {
		t.Fatal("expected body stream to be consumed during read")
	}
	if err := req.Body.Close(); err != nil {
		t.Fatalf("close streamed request body: %v", err)
	}
	if !stream.closed {
		t.Fatal("expected original body stream to be closed")
	}
}

func TestBuildUpstreamRequestStreamsDecodedCompressedBody(t *testing.T) {
	originalBody := []byte(strings.Repeat(`{"ok":true,"message":"stream-decoded"}`, 256))
	compressedBody := mustGzipBytes(t, originalBody)
	releaseBody := make(chan struct{})

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("Content-Encoding", "gzip")
	stream := &gatedReadCloser{
		first:   compressedBody[:16],
		second:  compressedBody[16:],
		release: releaseBody,
	}
	ctx.Request.SetBodyStream(stream, len(compressedBody))

	type buildResult struct {
		req *http.Request
		err error
	}
	resultCh := make(chan buildResult, 1)
	go func() {
		req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
		resultCh <- buildResult{req: req, err: err}
	}()

	var req *http.Request
	select {
	case result := <-resultCh:
		req = result.req
		if result.err != nil {
			t.Fatalf("buildUpstreamRequest returned error: %v", result.err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("buildUpstreamRequest blocked waiting for the rest of the compressed body")
	}

	if got := req.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if req.ContentLength != -1 {
		t.Fatalf("ContentLength = %d, want -1", req.ContentLength)
	}
	if req.GetBody != nil {
		t.Fatal("GetBody should be nil for decoded streamed request body")
	}

	close(releaseBody)
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read decoded streamed request body: %v", err)
	}
	if !bytes.Equal(got, originalBody) {
		t.Fatalf("decoded streamed body mismatch: got %d bytes want %d bytes", len(got), len(originalBody))
	}
	if err := req.Body.Close(); err != nil {
		t.Fatalf("close decoded streamed request body: %v", err)
	}
	if !stream.closed {
		t.Fatal("expected original compressed body stream to be closed")
	}
}

func TestForwardHTTPDecodesCompressedRequestBodyBeforeUpstream(t *testing.T) {
	originalBody := []byte(strings.Repeat(`{"ok":true,"message":"forwarded"}`, 8))
	compressedBody := mustGzipBytes(t, originalBody)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Encoding"); got != "" {
			t.Fatalf("upstream Content-Encoding = %q, want empty", got)
		}
		if r.ContentLength != int64(len(originalBody)) {
			t.Fatalf("upstream ContentLength = %d, want %d", r.ContentLength, len(originalBody))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("upstream read body: %v", err)
		}
		if !bytes.Equal(body, originalBody) {
			t.Fatalf("upstream decoded body mismatch: got %d bytes want %d bytes", len(body), len(originalBody))
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "decoded-ok")
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/compressed")
	ctx.Request.Header.SetHost("proxy.example.com")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("Content-Encoding", "gzip")
	ctx.Request.Header.Set("Content-Length", strconv.Itoa(len(compressedBody)))
	ctx.Request.SetBody(compressedBody)

	err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	if got := string(ctx.Response.Body()); got != "decoded-ok" {
		t.Fatalf("response body = %q, want %q", got, "decoded-ok")
	}
}

func TestForwardHTTPDecodesMultipleContentEncodingsFromUpstream(t *testing.T) {
	originalBody := []byte(strings.Repeat("decoded-upstream-streaming-body-", 64))
	encodedBody := mustEncodeBodyWithContentEncodings(t, originalBody, "gzip", "br")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip, br")
		w.Header().Set("Content-Length", strconv.Itoa(len(encodedBody)))
		_, _ = w.Write(encodedBody)
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/streaming-multi-encoding")
	ctx.Request.Header.SetHost("proxy.example.com")

	err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if got := string(ctx.Response.Header.Peek("Content-Length")); got != "" {
		t.Fatalf("Content-Length = %q, want empty", got)
	}
	if !bytes.Equal(ctx.Response.Body(), originalBody) {
		t.Fatalf("decoded body mismatch: got %d bytes want %d bytes", len(ctx.Response.Body()), len(originalBody))
	}
}

func TestForwardHTTPRecompressesDecodedUpstreamGzipResponse(t *testing.T) {
	originalBody := []byte(strings.Repeat("decoded-upstream-recompressed-body-", 96))
	encodedBody := mustGzipBytes(t, originalBody)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(encodedBody)))
		_, _ = w.Write(encodedBody)
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/streaming-recompress")
	ctx.Request.Header.SetHost("proxy.example.com")
	ctx.Request.Header.Set("Accept-Encoding", "gzip")

	err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "proxy.example.com")
	if err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	reader, err := gzip.NewReader(bytes.NewReader(ctx.Response.Body()))
	if err != nil {
		t.Fatalf("create gzip reader: %v", err)
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("decode gzip response: %v", err)
	}
	if !bytes.Equal(decoded, originalBody) {
		t.Fatalf("recompressed gzip decoded body mismatch")
	}
	if got := string(ctx.Response.Header.Peek("Vary")); !strings.Contains(strings.ToLower(got), "accept-encoding") {
		t.Fatalf("Vary = %q, want Accept-Encoding", got)
	}
}

func TestForwardHTTPAppliesDynamicProtectionWhenEnabled(t *testing.T) {
	originalBody := []byte("<!doctype html><html><body><script>const value = 1;</script></body></html>")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(originalBody)
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/dynamic-protected")
	ctx.Request.Header.SetHost("proxy.example.com")

	rt := snapshot.SiteRuntime{}
	rt.DynamicProtection.HTMLObfuscationEnabled = true
	rt.DynamicProtection.JSObfuscationEnabled = true

	if err := ForwardHTTP(context.Background(), ctx, rt, upstream.URL, nil, "proxy.example.com"); err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	got := ctx.Response.Body()
	if bytes.Equal(got, originalBody) {
		t.Fatalf("expected dynamic protection to transform the body, but got original unchanged")
	}
	if !bytes.Contains(got, []byte("owaf")) {
		t.Fatalf("transformed body does not contain expected owaf marker: %q", got[:min(len(got), 200)])
	}
}

func TestForwardHTTPSkipsDynamicProtectionWhenDisabled(t *testing.T) {
	originalBody := []byte("<!doctype html><html><body><p>hello</p></body></html>")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(originalBody)
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/no-dynamic")
	ctx.Request.Header.SetHost("proxy.example.com")

	rt := snapshot.SiteRuntime{}

	if err := ForwardHTTP(context.Background(), ctx, rt, upstream.URL, nil, "proxy.example.com"); err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := ctx.Response.Body(); !bytes.Equal(got, originalBody) {
		t.Fatalf("expected original body when dynamic protection disabled, got: %q", got[:min(len(got), 200)])
	}
}

func TestForwardHTTPStreamsDecodedUpstreamRecompressionWithoutReadAll(t *testing.T) {
	first := []byte(strings.Repeat("decoded-upstream-recompress-first-", 96))
	second := []byte(strings.Repeat("decoded-upstream-recompress-second-", 96))
	release := make(chan struct{})
	firstFlushed := make(chan struct{})
	var releaseOnce sync.Once
	releaseUpstream := func() {
		releaseOnce.Do(func() { close(release) })
	}
	t.Cleanup(releaseUpstream)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream writer does not support flushing")
			return
		}
		writer, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
		if err != nil {
			t.Errorf("create gzip writer: %v", err)
			return
		}
		if _, err := writer.Write(first); err != nil {
			_ = writer.Close()
			t.Errorf("write first gzip chunk: %v", err)
			return
		}
		if err := writer.Flush(); err != nil {
			_ = writer.Close()
			t.Errorf("flush first gzip chunk: %v", err)
			return
		}
		flusher.Flush()
		close(firstFlushed)
		<-release
		if _, err := writer.Write(second); err != nil {
			_ = writer.Close()
			t.Errorf("write second gzip chunk: %v", err)
			return
		}
		if err := writer.Close(); err != nil {
			t.Errorf("close gzip writer: %v", err)
		}
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/streaming-recompress-without-readall")
	ctx.Request.Header.SetHost("proxy.example.com")
	ctx.Request.Header.Set("Accept-Encoding", "gzip")

	type result struct {
		err error
	}
	done := make(chan result, 1)
	go func() {
		err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "proxy.example.com")
		done <- result{err: err}
	}()

	select {
	case <-firstFlushed:
	case <-time.After(2 * time.Second):
		releaseUpstream()
		t.Fatal("timed out waiting for upstream first compressed chunk")
	}

	select {
	case got := <-done:
		if got.err != nil {
			releaseUpstream()
			t.Fatalf("ForwardHTTP returned error: %v", got.err)
		}
	case <-time.After(200 * time.Millisecond):
		releaseUpstream()
		t.Fatal("ForwardHTTP blocked reading the full decoded upstream response before returning")
	}

	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "gzip" {
		releaseUpstream()
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := string(ctx.Response.Header.Peek("Vary")); !strings.Contains(strings.ToLower(got), "accept-encoding") {
		releaseUpstream()
		t.Fatalf("Vary = %q, want Accept-Encoding", got)
	}

	releaseUpstream()
	reader, err := gzip.NewReader(bytes.NewReader(ctx.Response.Body()))
	if err != nil {
		t.Fatalf("create gzip reader: %v", err)
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("decode gzip response: %v", err)
	}
	want := append(append([]byte(nil), first...), second...)
	if !bytes.Equal(decoded, want) {
		t.Fatalf("streaming recompressed gzip decoded body mismatch: got %d bytes want %d bytes", len(decoded), len(want))
	}
}

func TestForwardHTTPClosesUpstreamResponseBodyOnContextCancel(t *testing.T) {
	tests := []struct {
		name           string
		acceptEncoding string
		wantEncoding   string
	}{
		{
			name: "plain",
		},
		{
			name:           "gzip",
			acceptEncoding: "gzip",
			wantEncoding:   "gzip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte(strings.Repeat("downstream-cancel-closes-upstream-", 64))
			upstreamStarted := make(chan struct{})
			upstreamCanceled := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				flusher, ok := w.(http.Flusher)
				if !ok {
					t.Error("upstream writer does not support flushing")
					return
				}
				midpoint := len(body) / 2
				_, _ = w.Write(body[:midpoint])
				flusher.Flush()
				close(upstreamStarted)
				<-r.Context().Done()
				close(upstreamCanceled)
			}))
			defer upstream.Close()

			ctx := app.NewContext(0)
			ctx.Request.SetMethod("GET")
			ctx.Request.SetRequestURI("/downstream-cancel")
			ctx.Request.Header.SetHost("proxy.example.com")
			if tt.acceptEncoding != "" {
				ctx.Request.Header.Set("Accept-Encoding", tt.acceptEncoding)
			}
			t.Cleanup(func() {
				if ctx.Response.IsBodyStream() {
					_ = ctx.Response.CloseBodyStream()
				}
			})

			reqCtx, cancel := context.WithCancel(context.Background())
			defer cancel()

			type result struct {
				err error
			}
			done := make(chan result, 1)
			go func() {
				err := ForwardHTTP(reqCtx, ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "proxy.example.com")
				done <- result{err: err}
			}()

			var res result
			select {
			case res = <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("ForwardHTTP blocked before returning the response stream")
			}
			if res.err != nil {
				t.Fatalf("ForwardHTTP returned error: %v", res.err)
			}
			if !ctx.Response.IsBodyStream() {
				t.Fatal("expected downstream response body stream")
			}
			if tt.wantEncoding != "" {
				if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != tt.wantEncoding {
					t.Fatalf("Content-Encoding = %q, want %q", got, tt.wantEncoding)
				}
			}

			select {
			case <-upstreamStarted:
			case <-time.After(2 * time.Second):
				t.Fatal("upstream did not start streaming before context cancellation")
			}

			cancel()

			select {
			case <-upstreamCanceled:
			case <-time.After(2 * time.Second):
				t.Fatal("upstream response body was not closed after context cancellation")
			}
		})
	}
}

func TestForwardHTTPReusesHTTP1ConnectionAfterCompleteResponse(t *testing.T) {
	var mu sync.Mutex
	newConnections := 0

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", "2")
		_, _ = io.WriteString(w, "ok")
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state != http.StateNew {
			return
		}
		mu.Lock()
		newConnections++
		mu.Unlock()
	}
	upstream.Start()
	defer upstream.Close()

	forward := func(path string) {
		ctx := app.NewContext(0)
		ctx.Request.SetMethod("GET")
		ctx.Request.SetRequestURI(path)
		ctx.Request.Header.SetHost("proxy.example.com")

		if err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, upstream.URL, nil, "proxy.example.com"); err != nil {
			t.Fatalf("ForwardHTTP(%q) returned error: %v", path, err)
		}
		if got := string(ctx.Response.Body()); got != "ok" {
			t.Fatalf("ForwardHTTP(%q) body = %q, want %q", path, got, "ok")
		}
		if ctx.Response.IsBodyStream() {
			_ = ctx.Response.CloseBodyStream()
		}
	}

	forward("/first")
	forward("/second")

	mu.Lock()
	gotConnections := newConnections
	mu.Unlock()
	if gotConnections != 1 {
		t.Fatalf("HTTP/1.1 upstream connections = %d, want 1", gotConnections)
	}
}

func TestBuildUpstreamRequestURLAndHostSemantics(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource/sub?x=1&y=two")
	ctx.Request.Header.SetHost("client.example")

	req, err := buildUpstreamRequest(context.Background(), ctx, "https://origin.example:9443/base", net.ParseIP("203.0.113.10"), "client.example", true)
	if err != nil {
		t.Fatalf("buildUpstreamRequest returned error: %v", err)
	}
	if req.Method != http.MethodGet {
		t.Fatalf("Method = %q", req.Method)
	}
	if req.URL.Scheme != "https" {
		t.Fatalf("URL.Scheme = %q", req.URL.Scheme)
	}
	if req.URL.Host != "origin.example:9443" {
		t.Fatalf("URL.Host = %q", req.URL.Host)
	}
	if req.URL.Path != "/base/resource/sub" {
		t.Fatalf("URL.Path = %q", req.URL.Path)
	}
	if req.URL.RawQuery != "x=1&y=two" {
		t.Fatalf("URL.RawQuery = %q", req.URL.RawQuery)
	}
	if req.Host != "client.example" {
		t.Fatalf("Host = %q", req.Host)
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "client.example" {
		t.Fatalf("X-Forwarded-Host = %q", got)
	}
	if got := req.Header.Get("X-Forwarded-For"); got != "203.0.113.10" {
		t.Fatalf("X-Forwarded-For = %q", got)
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("X-Forwarded-Proto = %q", got)
	}
	if got := req.Header.Get("Host"); got != "" {
		t.Fatalf("Host header = %q, want empty because net/http uses Request.Host", got)
	}
}

func TestBuildUpstreamRequestPreservesEscapedPathForExplicitProtocols(t *testing.T) {
	tests := []struct {
		name       string
		base       string
		wantScheme string
		wantHost   string
	}{
		{
			name:       "h2c escaped path",
			base:       "h2c://origin.example:8080/base",
			wantScheme: "http",
			wantHost:   "origin.example:8080",
		},
		{
			name:       "h3 escaped path",
			base:       "h3://origin.example:8443/base",
			wantScheme: "https",
			wantHost:   "origin.example:8443",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := app.NewContext(0)
			ctx.Request.SetMethod("GET")
			ctx.Request.SetRequestURI("/assets/a%2Fb%20c.js?x=a%2Fb&y=two")
			ctx.Request.Header.SetHost("client.example")

			req, err := buildUpstreamRequest(context.Background(), ctx, tt.base, nil, "client.example", false)
			if err != nil {
				t.Fatalf("buildUpstreamRequest returned error: %v", err)
			}
			if req.URL.Scheme != tt.wantScheme {
				t.Fatalf("URL.Scheme = %q, want %q", req.URL.Scheme, tt.wantScheme)
			}
			if req.URL.Host != tt.wantHost {
				t.Fatalf("URL.Host = %q, want %q", req.URL.Host, tt.wantHost)
			}
			if got := req.URL.EscapedPath(); got != "/base/assets/a%2Fb%20c.js" {
				t.Fatalf("EscapedPath = %q, want escaped upstream path", got)
			}
			if req.URL.RawQuery != "x=a%2Fb&y=two" {
				t.Fatalf("RawQuery = %q, want raw encoded query", req.URL.RawQuery)
			}
			if got := req.Header.Get("Host"); got != "" {
				t.Fatalf("Host header = %q, want empty because net/http uses Request.Host", got)
			}
		})
	}
}

func TestBuildUpstreamRequestRejectsInvalidUpstreamBase(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")

	if _, err := buildUpstreamRequest(context.Background(), ctx, "http://[::1", nil, "example.test", false); err == nil {
		t.Fatalf("expected invalid upstream base error")
	}
}

func TestBuildUpstreamRequestMatchesNewRequestCoreSemantics(t *testing.T) {
	t.Run("nil context rejected", func(t *testing.T) {
		ctx := app.NewContext(0)
		ctx.Request.SetMethod("GET")
		ctx.Request.SetRequestURI("/resource")
		nilContextForTest := func() context.Context { return nil }
		if _, err := buildUpstreamRequest(nilContextForTest(), ctx, "http://127.0.0.1:8800", nil, "example.test", false); err == nil {
			t.Fatalf("expected nil context error")
		}
	})

	t.Run("empty method defaults to get", func(t *testing.T) {
		ctx := app.NewContext(0)
		ctx.Request.SetMethod("")
		ctx.Request.SetRequestURI("/resource")
		req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
		if err != nil {
			t.Fatalf("buildUpstreamRequest returned error: %v", err)
		}
		if req.Method != http.MethodGet {
			t.Fatalf("Method = %q", req.Method)
		}
	})

	t.Run("invalid method rejected", func(t *testing.T) {
		ctx := app.NewContext(0)
		ctx.Request.SetMethod("BAD METHOD")
		ctx.Request.SetRequestURI("/resource")
		if _, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false); err == nil {
			t.Fatalf("expected invalid method error")
		}
	})

	t.Run("empty port normalized", func(t *testing.T) {
		ctx := app.NewContext(0)
		ctx.Request.SetMethod("GET")
		ctx.Request.SetRequestURI("/resource")
		req, err := buildUpstreamRequest(context.Background(), ctx, "http://origin.example:", nil, "example.test", false)
		if err != nil {
			t.Fatalf("buildUpstreamRequest returned error: %v", err)
		}
		if req.URL.Host != "origin.example" {
			t.Fatalf("URL.Host = %q", req.URL.Host)
		}
		if req.Host != "origin.example" {
			t.Fatalf("Host = %q", req.Host)
		}
	})
}

func TestUpstreamRequestURL(t *testing.T) {
	tests := []struct {
		name string
		base string
		uri  string
		want string
	}{
		{name: "query", base: "http://127.0.0.1:8800", uri: "/resource?x=1", want: "http://127.0.0.1:8800/resource?x=1"},
		{name: "base trailing slash", base: "http://127.0.0.1:8800/", uri: "/resource?x=1", want: "http://127.0.0.1:8800/resource?x=1"},
		{name: "no query", base: "http://127.0.0.1:8800", uri: "/resource", want: "http://127.0.0.1:8800/resource"},
		{name: "empty path", base: "http://127.0.0.1:8800", uri: "", want: "http://127.0.0.1:8800/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := app.NewContext(0)
			ctx.Request.SetMethod("GET")
			ctx.Request.SetRequestURI(tt.uri)
			if got := upstreamRequestURL(ctx, tt.base); got != tt.want {
				t.Fatalf("upstreamRequestURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUpstreamRequestURLPreservesExplicitProtocolBasePathAndQuery(t *testing.T) {
	tests := []struct {
		name string
		base string
		want string
	}{
		{
			name: "explicit h2c",
			base: "h2c://127.0.0.1:8080/base",
			want: "http://127.0.0.1:8080/base/resource?x=1&y=two",
		},
		{
			name: "explicit h3",
			base: "h3://127.0.0.1:8443/base",
			want: "https://127.0.0.1:8443/base/resource?x=1&y=two",
		},
		{
			name: "explicit h2c escaped path",
			base: "h2c://127.0.0.1:8080/base",
			want: "http://127.0.0.1:8080/base/assets/a%2Fb%20c.js?x=a%2Fb&y=two",
		},
		{
			name: "explicit h3 escaped path",
			base: "h3://127.0.0.1:8443/base",
			want: "https://127.0.0.1:8443/base/assets/a%2Fb%20c.js?x=a%2Fb&y=two",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := app.NewContext(0)
			ctx.Request.SetMethod("GET")
			if strings.Contains(tt.name, "escaped path") {
				ctx.Request.SetRequestURI("/assets/a%2Fb%20c.js?x=a%2Fb&y=two")
			} else {
				ctx.Request.SetRequestURI("/resource?x=1&y=two")
			}
			if got := upstreamRequestURL(ctx, tt.base); got != tt.want {
				t.Fatalf("upstreamRequestURL(%q) = %q, want %q", tt.base, got, tt.want)
			}
		})
	}
}

func TestRequestMethod(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "GET", want: "GET"},
		{input: "POST", want: "POST"},
		{input: "HEAD", want: "HEAD"},
		{input: "PUT", want: "PUT"},
		{input: "PATCH", want: "PATCH"},
		{input: "TRACE", want: "TRACE"},
		{input: "DELETE", want: "DELETE"},
		{input: "OPTIONS", want: "OPTIONS"},
		{input: "CONNECT", want: "CONNECT"},
		{input: "post", want: "post"},
		{input: "Head", want: "Head"},
		{input: "custom", want: "custom"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ctx := app.NewContext(0)
			ctx.Request.SetMethod(tt.input)
			if got := requestMethod(ctx); got != tt.want {
				t.Fatalf("requestMethod() = %q, want %q", got, tt.want)
			}
		})
	}
}

func BenchmarkRequestMethodGET(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if requestMethod(ctx) == "" {
			b.Fatal("empty method")
		}
	}
}

func BenchmarkRequestMethodStringGET(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if string(ctx.Method()) == "" {
			b.Fatal("empty method")
		}
	}
}

func TestForwardedProtoFromHeader(t *testing.T) {
	cases := map[string]string{
		"":            "",
		"   ":         "",
		"http":        "http",
		" HtTp ":      "http",
		"HTTPS":       "https",
		" h3 ":        "h3",
		"CustomProto": "customproto",
	}
	for input, want := range cases {
		if got := forwardedProtoFromHeader([]byte(input)); got != want {
			t.Fatalf("forwardedProtoFromHeader(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestInboundProtoWebSocketOriginScheme(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		want   string
	}{
		{name: "https uppercase scheme", origin: "HTTPS://app.example.test", want: "https"},
		{name: "https mixed case scheme", origin: "HtTpS://app.example.test", want: "https"},
		{name: "http scheme", origin: "http://app.example.test", want: "http"},
		{name: "empty origin", origin: "", want: "http"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := app.NewContext(0)
			ctx.Request.SetMethod("GET")
			ctx.Request.SetRequestURI("/ws")
			ctx.Request.Header.Set("Upgrade", "websocket")
			if tt.origin != "" {
				ctx.Request.Header.Set("Origin", tt.origin)
			}

			if got := inboundProto(ctx); got != tt.want {
				t.Fatalf("inboundProto origin %q = %q, want %q", tt.origin, got, tt.want)
			}
		})
	}

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/ws")
	ctx.Request.Header.Set("Upgrade", "websocket")
	ctx.Request.Header.Set("Origin", "http://app.example.test")
	ctx.Request.Header.Set("X-Forwarded-Proto", " h3 ")
	if got := inboundProto(ctx); got != "h3" {
		t.Fatalf("inboundProto with X-Forwarded-Proto = %q, want h3", got)
	}
}

func BenchmarkIsHopByHopBytesMixedCase(b *testing.B) {
	name := []byte("TrAnSfEr-EnCoDiNg")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = isHopByHopBytes(name)
	}
}

func BenchmarkIsHopByHopStringMixedCase(b *testing.B) {
	name := "TrAnSfEr-EnCoDiNg"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = isHopByHop(name)
	}
}

func BenchmarkInboundProtoDefaultHTTP(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if inboundProto(ctx) == "" {
			b.Fatal("empty proto")
		}
	}
}

func BenchmarkInboundProtoForwardedMixedCase(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("X-Forwarded-Proto", " HtTpS ")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if inboundProto(ctx) != "https" {
			b.Fatal("unexpected proto")
		}
	}
}

func BenchmarkInboundProtoWebSocketHTTPSOrigin(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/ws")
	ctx.Request.Header.Set("Upgrade", "websocket")
	ctx.Request.Header.Set("Origin", "HTTPS://bench.example.test/ws")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if inboundProto(ctx) != "https" {
			b.Fatal("unexpected proto")
		}
	}
}

func BenchmarkInboundProtoWebSocketHTTPSOriginToLower(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/ws")
	ctx.Request.Header.Set("Upgrade", "websocket")
	ctx.Request.Header.Set("Origin", "HTTPS://bench.example.test/ws")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if inboundProtoOriginLowerForBenchmark(ctx) != "https" {
			b.Fatal("unexpected proto")
		}
	}
}

func inboundProtoOriginLowerForBenchmark(c *app.RequestContext) string {
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

func BenchmarkBuildUpstreamRequestSmallGET(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("User-Agent", "bench-agent")
	ctx.Request.Header.Set("Accept", "application/json")
	ctx.Request.Header.Set("X-Test", "kept")
	ctx.Request.Header.Set("Connection", "close")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
		if err != nil {
			b.Fatal(err)
		}
		if req.URL.Path == "" {
			b.Fatal("empty path")
		}
	}
}

func BenchmarkBuildUpstreamRequestSmallGETNoConnectionHeader(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("User-Agent", "bench-agent")
	ctx.Request.Header.Set("Accept", "application/json")
	ctx.Request.Header.Set("X-Test", "kept")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
		if err != nil {
			b.Fatal(err)
		}
		if req.URL.Path == "" {
			b.Fatal("empty path")
		}
	}
}

func BenchmarkBuildUpstreamRequestSmallPOST(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("User-Agent", "bench-agent")
	ctx.Request.Header.Set("Accept", "application/json")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("X-Test", "kept")
	ctx.Request.SetBody([]byte(`{"ok":true}`))

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
		if err != nil {
			b.Fatal(err)
		}
		if req.Body == nil {
			b.Fatal("empty body reader")
		}
	}
}

func BenchmarkBuildUpstreamRequestBrowserHeadersGET(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("Host", "127.0.0.1:80")
	ctx.Request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	ctx.Request.Header.Set("Sec-Ch-Ua", `"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"`)
	ctx.Request.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	ctx.Request.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	ctx.Request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	ctx.Request.Header.Set("Sec-Fetch-Site", "same-origin")
	ctx.Request.Header.Set("Sec-Fetch-Mode", "navigate")
	ctx.Request.Header.Set("Sec-Fetch-Dest", "document")
	ctx.Request.Header.Set("Referer", "http://127.0.0.1:80/")
	ctx.Request.Header.Set("Accept-Encoding", "gzip, deflate, br")
	ctx.Request.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	ctx.Request.Header.Set("Connection", "close")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
		if err != nil {
			b.Fatal(err)
		}
		if req.Header.Get("Sec-Fetch-Dest") == "" {
			b.Fatal("missing browser header")
		}
	}
}

func BenchmarkBuildUpstreamRequestExplicitH3EscapedPath(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/assets/a%2Fb%20c.js?x=a%2Fb&y=two")
	ctx.Request.Header.SetHost("proxy.example.com")
	ctx.Request.Header.Set("User-Agent", "bench-agent")
	ctx.Request.Header.Set("Accept", "application/json")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, err := buildUpstreamRequest(context.Background(), ctx, "h3://127.0.0.1:8443/base", nil, "proxy.example.com", false)
		if err != nil {
			b.Fatal(err)
		}
		if req.URL.EscapedPath() != "/base/assets/a%2Fb%20c.js" {
			b.Fatal("unexpected escaped path")
		}
	}
}

func BenchmarkBuildUpstreamRequestWithTrailers(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/resource?x=1")
	ctx.Request.Header.Set("User-Agent", "bench-agent")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("TE", "gzip, trailers; q=1.0")
	if err := ctx.Request.Header.Trailer().Set("X-Trace", "done"); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, err := buildUpstreamRequest(context.Background(), ctx, "http://127.0.0.1:8800", nil, "example.test", false)
		if err != nil {
			b.Fatal(err)
		}
		if req.Header.Get("TE") != "trailers" || req.Trailer.Get("X-Trace") != "done" {
			b.Fatal("missing trailer forwarding metadata")
		}
	}
}

func BenchmarkRequestPathOriginal(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if requestPath(ctx) == "" {
			b.Fatal("empty path")
		}
	}
}

func BenchmarkUpstreamRequestURLWithQuery(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource?x=1")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if upstreamRequestURL(ctx, "http://127.0.0.1:8800") == "" {
			b.Fatal("empty url")
		}
	}
}

func BenchmarkUpstreamRequestURLNoQuery(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if upstreamRequestURL(ctx, "http://127.0.0.1:8800") == "" {
			b.Fatal("empty url")
		}
	}
}

func BenchmarkUpstreamRequestURLExplicitH3EscapedPath(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/assets/a%2Fb%20c.js?x=a%2Fb&y=two")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if upstreamRequestURL(ctx, "h3://127.0.0.1:8443/base") == "" {
			b.Fatal("empty url")
		}
	}
}

func TestSiteCacheTTLDetails_SuffixMidTokenRejected(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: "ig", TTL: 10},
		},
	}
	if ttl, _ := SiteCacheTTLDetails(rt, "/v1/api/config"); ttl != 0 {
		t.Fatalf("suffix ig must not match inside config, got ttl=%d", ttl)
	}
}

func TestSiteCacheTTLDetails_SuffixJSWithQuery(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: ".js", TTL: 10},
		},
	}
	if ttl, _ := SiteCacheTTLDetails(rt, "/a/b.js?v=1"); ttl != 10 {
		t.Fatalf("want .js match with query ignored for suffix, got %d", ttl)
	}
}

func TestSiteCacheTTLDetails_SuffixPageTxt(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: "__PAGE__.txt", TTL: 10},
		},
	}
	k := "/blog/archive/__next.blog.archive.__PAGE__.txt"
	if ttl, _ := SiteCacheTTLDetails(rt, k); ttl != 10 {
		t.Fatalf("want __PAGE__.txt match, got %d for %q", ttl, k)
	}
}

func TestSiteCacheTTLDetails_CaseInsensitivePrefix(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/api", TTL: 10, CaseInsensitive: true},
		},
	}
	if ttl, _ := SiteCacheTTLDetails(rt, "/API/v1/config"); ttl != 10 {
		t.Fatalf("want case-insensitive prefix match, got %d", ttl)
	}
}

func TestSiteCacheFirstMatchTypeAndPatternNormalization(t *testing.T) {
	tests := []struct {
		name     string
		rule     store.SiteCacheRule
		matchKey string
		wantTTL  int64
	}{
		{
			name:     "normalized prefix",
			rule:     store.SiteCacheRule{Type: "prefix", Value: "/api", TTL: 10},
			matchKey: "/api/v1/config",
			wantTTL:  10,
		},
		{
			name:     "manual mixed type and padded value",
			rule:     store.SiteCacheRule{Type: " SuFfIx ", Value: " .js ", TTL: 20},
			matchKey: "/assets/app.js?v=1",
			wantTTL:  20,
		},
		{
			name:     "blank type defaults to prefix",
			rule:     store.SiteCacheRule{Type: "  ", Path: " /static ", TTL: 30},
			matchKey: "/static/app.css",
			wantTTL:  30,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := snapshot.SiteRuntime{
				CacheEnabled: true,
				CacheRules:   []store.SiteCacheRule{tt.rule},
			}
			got, matched := SiteCacheTTLDetails(rt, tt.matchKey)
			if got != tt.wantTTL || !matched {
				t.Fatalf("SiteCacheTTLDetails() ttl=%d matched=%v, want ttl=%d matched=true", got, matched, tt.wantTTL)
			}
		})
	}
}

func siteCacheRuleMatchesPreviousLowerForTest(ruleType, matchKey, pat string) bool {
	keyCmp := strings.ToLower(matchKey)
	patCmp := strings.ToLower(pat)
	switch ruleType {
	case "exact":
		return keyCmp == patCmp
	case "suffix":
		return cacheSuffixPatternMatch(keyCmp, patCmp)
	case "contains":
		return strings.Contains(keyCmp, patCmp)
	default:
		return strings.HasPrefix(keyCmp, patCmp)
	}
}

func cacheRulePatternStringForTest(r store.SiteCacheRule) string {
	v := strings.TrimSpace(r.Value)
	if v != "" {
		return v
	}
	return strings.TrimSpace(r.Path)
}

func cacheRuleTypeStringForTest(raw string) string {
	ruleType := strings.ToLower(strings.TrimSpace(raw))
	if ruleType == "" {
		return "prefix"
	}
	return ruleType
}

func TestSiteCacheTTLDetails_IgnoreQueryForSuffix(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: ".js", TTL: 10, IgnoreQuery: true},
		},
	}
	if ttl, _ := SiteCacheTTLDetails(rt, "/a/b.js?v=1&x=2"); ttl != 10 {
		t.Fatalf("want suffix match ignoring query comparison, got %d", ttl)
	}
}

func TestSiteCacheTTLDetails_Contains(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "contains", Value: "/cdn/", TTL: 10},
		},
	}
	if ttl, _ := SiteCacheTTLDetails(rt, "/x/cdn/foo"); ttl != 10 {
		t.Fatalf("contains path: want ttl 10, got %d", ttl)
	}
}

func TestSiteCacheTTLDetails_Regex(t *testing.T) {
	re := regexp.MustCompile(`\.(js|mjs)$`)
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "regex", Value: `\.(js|mjs)$`, TTL: 10, Regex: re},
		},
	}
	if ttl, _ := SiteCacheTTLDetails(rt, "/a.X"); ttl != 0 {
		t.Fatalf("regex should not match, got %d", ttl)
	}
	if ttl, _ := SiteCacheTTLDetails(rt, "/a/b.mjs"); ttl != 10 {
		t.Fatalf("regex mjs: want ttl 10, got %d", ttl)
	}
	rt2 := snapshot.SiteRuntime{
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "regex", Value: `\.(js|mjs)$`, TTL: 10, Regex: re, IgnoreQuery: true},
		},
	}
	if ttl, _ := SiteCacheTTLDetails(rt2, "/a/b.mjs?x=1"); ttl != 10 {
		t.Fatalf("regex+ignore query: want ttl 10, got %d", ttl)
	}
}

func TestSiteCacheEligible_AllowedWithClientNoCache(t *testing.T) {
	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI("/favicon.ico")
	req.SetHost("127.0.0.1")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)

	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		Site:         store.Site{ID: 1, Bind: ":80"},
		Bind:         ":80",
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: ".ico", TTL: 60},
		},
	}
	key, ttl, _ := SiteCacheEligible(rt, ctx)
	if key == "" || ttl != 60 {
		t.Fatalf("expected cache eligible with client no-cache, got key=%q ttl=%d", key, ttl)
	}
}

func TestSiteCacheEligibleAllowsRangeRequests(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		Site:         store.Site{ID: 1, Bind: ":80"},
		Bind:         ":80",
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: ".mp4", TTL: 60},
		},
	}

	for _, method := range []string{"GET", "HEAD"} {
		t.Run(method, func(t *testing.T) {
			var req protocol.Request
			req.SetMethod(method)
			req.SetRequestURI("/video.mp4")
			req.SetHost("127.0.0.1")
			req.Header.Set("Range", "bytes=0-99")
			ctx := app.NewContext(0)
			req.CopyTo(&ctx.Request)

			key, ttl, _ := SiteCacheEligible(rt, ctx)
			if key == "" || ttl == 0 {
				t.Fatalf("Range request should be cache eligible: key=%q ttl=%d", key, ttl)
			}
		})
	}
}

func TestSiteCacheEligibleAllowsConditionalRequests(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		Site:         store.Site{ID: 1, Bind: ":80"},
		Bind:         ":80",
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: ".json", TTL: 60},
		},
	}
	tests := []struct {
		name  string
		value string
	}{
		{name: "If-Range", value: `"etag-range"`},
		{name: "If-Match", value: `"etag-match"`},
		{name: "If-None-Match", value: `"etag-none"`},
		{name: "If-Modified-Since", value: "Wed, 21 Oct 2015 07:28:00 GMT"},
		{name: "If-Unmodified-Since", value: "Wed, 21 Oct 2015 07:28:00 GMT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req protocol.Request
			req.SetMethod("GET")
			req.SetRequestURI("/api/data.json")
			req.SetHost("127.0.0.1")
			req.Header.Set(tt.name, tt.value)
			ctx := app.NewContext(0)
			req.CopyTo(&ctx.Request)

			key, ttl, _ := SiteCacheEligible(rt, ctx)
			if key == "" || ttl == 0 {
				t.Fatalf("%s request should be cache eligible: key=%q ttl=%d", tt.name, key, ttl)
			}
		})
	}
}

func cacheAuthorizationHeaderPresentStringForTest(c *app.RequestContext) bool {
	return c.Request.Header.Get("Authorization") != ""
}

func TestSiteCacheEligibleRejectsAuthorizationRequests(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		Site:         store.Site{ID: 1, Bind: ":80"},
		Bind:         ":80",
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: ".ico", TTL: 60},
		},
	}
	tests := []struct {
		name   string
		header string
		value  string
	}{
		{name: "authorization", header: "Authorization", value: "Bearer token"},
		{name: "lowercase authorization", header: "authorization", value: "Bearer token"},
		{name: "whitespace authorization", header: "Authorization", value: " \t "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req protocol.Request
			req.SetMethod("GET")
			req.SetRequestURI("/favicon.ico")
			req.SetHost("127.0.0.1")
			req.Header.Set(tt.header, tt.value)
			ctx := app.NewContext(0)
			req.CopyTo(&ctx.Request)

			key, ttl, _ := SiteCacheEligible(rt, ctx)
			if key != "" || ttl != 0 {
				t.Fatalf("Authorization request entered cache path: key=%q ttl=%d", key, ttl)
			}
		})
	}
}

func TestSiteCacheEligible_Methods(t *testing.T) {
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		Site:         store.Site{ID: 1, Bind: ":80"},
		Bind:         ":80",
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: ".ico", TTL: 60},
		},
	}
	tests := []struct {
		method string
		want   bool
	}{
		{method: "GET", want: true},
		{method: "get", want: true},
		{method: "HEAD", want: true},
		{method: "head", want: true},
		{method: "POST", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			var req protocol.Request
			req.SetMethod(tt.method)
			req.SetRequestURI("/favicon.ico")
			req.SetHost("127.0.0.1")
			ctx := app.NewContext(0)
			req.CopyTo(&ctx.Request)

			key, ttl, _ := SiteCacheEligible(rt, ctx)
			got := key != "" && ttl == 60
			if got != tt.want {
				t.Fatalf("SiteCacheEligible() cacheable = %v, want %v, key=%q ttl=%d", got, tt.want, key, ttl)
			}
		})
	}
}

func TestBuildSiteCacheStorageKeyNormalizesHEADToGET(t *testing.T) {
	rt := snapshot.SiteRuntime{
		Site: store.Site{ID: 7, Bind: ":80"},
		Bind: ":80",
	}

	getCtx := app.NewContext(0)
	getCtx.Request.SetMethod("GET")
	getCtx.Request.SetRequestURI("/favicon.ico?x=1")
	getCtx.Request.SetHost("cache.example.com")

	headCtx := app.NewContext(0)
	headCtx.Request.SetMethod("HEAD")
	headCtx.Request.SetRequestURI("/favicon.ico?x=1")
	headCtx.Request.SetHost("cache.example.com")

	getKey := BuildSiteCacheStorageKey(rt, getCtx, false, false)
	headKey := BuildSiteCacheStorageKey(rt, headCtx, false, false)
	if getKey == "" {
		t.Fatal("GET cache key is empty")
	}
	if headKey != getKey {
		t.Fatalf("HEAD cache key = %q, want GET key %q", headKey, getKey)
	}
}

func TestRuleMatchKeyFromPathQueryMatchesPreviousStringSemantics(t *testing.T) {
	tests := []struct {
		path  string
		query []byte
	}{
		{path: "/favicon.ico"},
		{path: "/favicon.ico", query: []byte("x=1")},
		{path: "/favicon.ico", query: []byte(" x=1 ")},
		{path: "/favicon.ico", query: []byte("\t x=1&y=2 \n")},
		{path: "/favicon.ico", query: []byte("   ")},
		{path: "/favicon.ico", query: []byte("\u00a0x=1\u00a0")},
	}
	for _, tt := range tests {
		t.Run(tt.path+"?"+string(tt.query), func(t *testing.T) {
			want := ruleMatchKeyFromPathQueryStringForTest(tt.path, tt.query)
			got := ruleMatchKeyFromPathQuery(tt.path, tt.query)
			if got != want {
				t.Fatalf("ruleMatchKeyFromPathQuery(%q, %q) = %q, want %q", tt.path, tt.query, got, want)
			}
		})
	}
}

func ruleMatchKeyFromPathQueryStringForTest(path string, query []byte) string {
	qs := strings.TrimSpace(string(query))
	if qs == "" {
		return path
	}
	return path + "?" + qs
}

func BenchmarkIsCacheableRequestMethodGET(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	method := ctx.Method()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = isCacheableRequestMethod(method)
	}
}

func BenchmarkIsCacheableRequestMethodPOST(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	method := ctx.Method()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = isCacheableRequestMethod(method)
	}
}

func BenchmarkIsCacheableRequestMethodStringGET(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	method := ctx.Method()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m := string(method)
		benchmarkProxyBoolSink = strings.EqualFold(m, "GET") || strings.EqualFold(m, "HEAD")
	}
}

func BenchmarkIsCacheableRequestMethodStringPOST(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	method := ctx.Method()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m := string(method)
		benchmarkProxyBoolSink = strings.EqualFold(m, "GET") || strings.EqualFold(m, "HEAD")
	}
}

func BenchmarkSiteCacheEligibleGET(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/favicon.ico")
	ctx.Request.SetHost("127.0.0.1")
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		Site:         store.Site{ID: 1, Bind: ":80"},
		Bind:         ":80",
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: ".ico", TTL: 60},
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key, ttl, _ := SiteCacheEligible(rt, ctx)
		if key == "" || ttl != 60 {
			b.Fatal("not cache eligible")
		}
	}
}

func BenchmarkSiteCacheRuleMatchesCaseInsensitivePrefixPreviousLowerForTest(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = siteCacheRuleMatchesPreviousLowerForTest("prefix", "/API/v1/config", "/api")
	}
}

func BenchmarkSiteCacheRuleMatchesCaseInsensitiveContainsPreviousLowerForTest(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = siteCacheRuleMatchesPreviousLowerForTest("contains", "/v1/CDN/App.JS", "/cdn/")
	}
}

func BenchmarkSiteCacheRuleMatchesCaseInsensitiveSuffixPreviousLowerForTest(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = siteCacheRuleMatchesPreviousLowerForTest("suffix", "/assets/APP.JS?v=1", ".js")
	}
}

func BenchmarkSiteCacheEligibleCaseInsensitivePrefix(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/API/v1/config")
	ctx.Request.SetHost("127.0.0.1")
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		Site:         store.Site{ID: 1, Bind: ":80"},
		Bind:         ":80",
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/api", TTL: 60, CaseInsensitive: true},
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key, ttl, _ := SiteCacheEligible(rt, ctx)
		if key == "" || ttl != 60 {
			b.Fatal("not cache eligible")
		}
	}
}

func BenchmarkCacheRuleTypePreviousStringForTestNormalized(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchmarkProxyStringSink = cacheRuleTypeStringForTest("suffix")
	}
}

func BenchmarkCacheRulePatternNormalizedValue(b *testing.B) {
	rule := store.SiteCacheRule{Type: "suffix", Value: ".js", TTL: 60}

	for i := 0; i < b.N; i++ {
		benchmarkProxyStringSink = cacheRulePattern(rule)
	}
}

func BenchmarkCacheRulePatternPreviousStringForTestNormalizedValue(b *testing.B) {
	rule := store.SiteCacheRule{Type: "suffix", Value: ".js", TTL: 60}

	for i := 0; i < b.N; i++ {
		benchmarkProxyStringSink = cacheRulePatternStringForTest(rule)
	}
}

func BenchmarkBuildSiteCacheStorageKeyGET(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/favicon.ico?x=1")
	ctx.Request.SetHost("127.0.0.1")
	rt := snapshot.SiteRuntime{
		Site: store.Site{ID: 1, Bind: ":80"},
		Bind: ":80",
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if BuildSiteCacheStorageKey(rt, ctx, false, false) == "" {
			b.Fatal("empty key")
		}
	}
}

func BenchmarkBuildSiteCacheStorageKeyHEAD(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("HEAD")
	ctx.Request.SetRequestURI("/favicon.ico?x=1")
	ctx.Request.SetHost("127.0.0.1")
	rt := snapshot.SiteRuntime{
		Site: store.Site{ID: 1, Bind: ":80"},
		Bind: ":80",
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if BuildSiteCacheStorageKey(rt, ctx, false, false) == "" {
			b.Fatal("empty key")
		}
	}
}

func BenchmarkBuildSiteCacheStorageKeyBytesForTestGET(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/favicon.ico?x=1")
	ctx.Request.SetHost("127.0.0.1")
	rt := snapshot.SiteRuntime{
		Site: store.Site{ID: 1, Bind: ":80"},
		Bind: ":80",
	}
	path := requestPath(ctx)
	query := ctx.URI().QueryString()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if buildSiteCacheStorageKeyFromParts(rt, ctx, path, query, false, false) == "" {
			b.Fatal("empty key")
		}
	}
}

func BenchmarkNormalizeMatchHostStringASCII(b *testing.B) {
	host := " Cache.Example.COM:443 "

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyStringSink = snapshot.NormalizeMatchHost(host)
	}
}

func BenchmarkRuleMatchKeyFromPathQuery(b *testing.B) {
	path := "/assets/app.js"
	query := []byte(" v=123&lang=zh ")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyStringSink = ruleMatchKeyFromPathQuery(path, query)
	}
}

func BenchmarkRuleMatchKeyFromPathQueryStringForTest(b *testing.B) {
	path := "/assets/app.js"
	query := []byte(" v=123&lang=zh ")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyStringSink = ruleMatchKeyFromPathQueryStringForTest(path, query)
	}
}

func BenchmarkRuleMatchKeyFromPathQueryBlankQuery(b *testing.B) {
	path := "/assets/app.js"
	query := []byte(" \t\n ")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyStringSink = ruleMatchKeyFromPathQuery(path, query)
	}
}

func BenchmarkRuleMatchKeyFromPathQueryStringForTestBlankQuery(b *testing.B) {
	path := "/assets/app.js"
	query := []byte(" \t\n ")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyStringSink = ruleMatchKeyFromPathQueryStringForTest(path, query)
	}
}

func BenchmarkRuleMatchKey(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/assets/app.js?v=123&lang=zh")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyStringSink = RuleMatchKey(ctx)
	}
}

func BenchmarkRuleMatchKeyPreviousStringForTest(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/assets/app.js?v=123&lang=zh")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyStringSink = ruleMatchKeyFromPathQueryStringForTest(requestPath(ctx), ctx.URI().QueryString())
	}
}

func BenchmarkSiteCacheEligiblePOST(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("POST")
	ctx.Request.SetRequestURI("/favicon.ico")
	ctx.Request.SetHost("127.0.0.1")
	rt := snapshot.SiteRuntime{
		CacheEnabled: true,
		Site:         store.Site{ID: 1, Bind: ":80"},
		Bind:         ":80",
		CacheRules: []store.SiteCacheRule{
			{Type: "suffix", Value: ".ico", TTL: 60},
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key, ttl, _ := SiteCacheEligible(rt, ctx)
		if key != "" || ttl != 0 {
			b.Fatal("post should not be cache eligible")
		}
	}
}

func BenchmarkCacheAuthorizationHeaderPresentStringForTestNone(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/favicon.ico")
	ctx.Request.SetHost("127.0.0.1")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = cacheAuthorizationHeaderPresentStringForTest(ctx)
	}
}

func BenchmarkCacheAuthorizationHeaderPresentStringForTestBearer(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/favicon.ico")
	ctx.Request.SetHost("127.0.0.1")
	ctx.Request.Header.Set("Authorization", "Bearer token")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkProxyBoolSink = cacheAuthorizationHeaderPresentStringForTest(ctx)
	}
}
