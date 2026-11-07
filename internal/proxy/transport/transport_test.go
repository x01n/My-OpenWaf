package transport

// 本文件白盒测试上游连接层的内部符号，必须与实现同包 —— Go 的白盒测试不能跨包访问
// 非导出符号。测试自 internal/proxy/proxy_test.go 按测试函数整体切出，断言逐字未改。
import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/protocol"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

// cancelableBlockingReader 模拟一个被 Close 取消的阻塞读。
//
// 该夹具同时被父包（TestProxyBodyStreamCloseWaitsForActiveReader）与子包
// （TestHertzResponseBodyCloseCancelsBlockedReadAndWaits）使用。Go 的两个包不共享
// 测试符号，故两侧各持一份逐字相同的副本 —— 与实现层的 cancelableBlockingReader
// 语义一致，切包未改动任何断言。
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

// benchmarkProxyBoolSink 是 benchmark 的落地变量，防止编译器消除被测调用。
// 与父包 proxy_test.go 中的同名变量各自独立：两个包不共享测试符号。
var benchmarkProxyBoolSink bool

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
	if tr.IdleConnTimeout != 30*time.Second {
		t.Fatalf("IdleConnTimeout = %s, want %s", tr.IdleConnTimeout, 30*time.Second)
	}
	if tr.MaxIdleConns != 1024 {
		t.Fatalf("MaxIdleConns = %d, want 1024", tr.MaxIdleConns)
	}
	if tr.MaxIdleConnsPerHost != 512 {
		t.Fatalf("MaxIdleConnsPerHost = %d, want 512", tr.MaxIdleConnsPerHost)
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
