package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/snapshot"
)

// grpcWebDataFrame builds a gRPC-Web DATA frame: the one-byte frame flag
// (0x00 for data, 0x80 for trailers) followed by a big-endian uint32 payload
// length and the payload. The message length prefix inside a message payload
// is added by grpcMessagePayload.
func grpcWebDataFrame(flag byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

// grpcMessagePayload wraps an unary message with the gRPC length prefix:
// one compressed flag byte, a big-endian uint32 message length, the message.
func grpcMessagePayload(payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

// grpcWebTrailersFrame builds the in-body trailers frame of the Envoy-style
// server form of gRPC-Web: flag 0x80, payload "grpc-status:<code>", then an
// optional "grpc-message:<message>" and any extra "key:value" entries. The
// grpc-status never travels in the HTTP Trailer segment in this form.
func grpcWebTrailersFrame(status int, message string, extra map[string]string) []byte {
	payload := fmt.Sprintf("grpc-status:%d", status)
	if message != "" {
		payload += "\r\ngrpc-message:" + message
	}
	for key, value := range extra {
		payload += "\r\n" + key + ":" + value
	}
	return grpcWebDataFrame(0x80, []byte(payload))
}

// h2GRPCWebUnaryUpstream serves one message frame plus the in-body trailers
// frame over HTTP/2 with content type application/grpc-web+proto.
func h2GRPCWebUnaryUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/grpc.web.Echo/Echo" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		_, _ = w.Write(grpcWebDataFrame(0, grpcMessagePayload([]byte("payload-web-unary"))))
		_, _ = w.Write(grpcWebTrailersFrame(0, "", nil))
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	return upstream
}

// compressionRT returns runtime flags with a 1-byte compression threshold so
// any compressible response qualifies for re-encoding.
func compressionRT() snapshot.SiteRuntime {
	return snapshot.SiteRuntime{
		ResponseCompressionConfigured:  true,
		ResponseCompressionEnabled:     true,
		ResponseCompressionGzipEnabled: true,
		ResponseCompressionMinBytes:    1,
	}
}

// TestForwardHTTPSkipsCompressionForGRPCWebAndGRPCJSONFamilies drives the
// streaming ForwardHTTP path for every grpc-family content type and asserts
// no Content-Encoding is applied, while the compressible text/plain control
// response is gzip-encoded by the same runtime flags.
func TestForwardHTTPSkipsCompressionForGRPCWebAndGRPCJSONFamilies(t *testing.T) {
	grpcTypes := []string{
		"application/grpc",
		"application/grpc+proto",
		"application/grpc+json",
		"application/grpc-web",
		"application/grpc-web+proto",
		"application/grpc-web+json",
	}
	payload := strings.Repeat("grpc-compression-border-", 64)
	for _, contentType := range grpcTypes {
		t.Run(contentType, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", contentType)
				_, _ = io.WriteString(w, payload)
			}))
			defer upstream.Close()

			ctx := app.NewContext(0)
			ctx.Request.SetMethod("GET")
			ctx.Request.SetRequestURI("/grpc-compression-border")
			ctx.Request.Header.SetHost("proxy.example.com")
			ctx.Request.Header.Set("Accept-Encoding", "gzip, br")
			if err := ForwardHTTP(context.Background(), ctx, compressionRT(), upstream.URL, nil, "proxy.example.com"); err != nil {
				t.Fatalf("ForwardHTTP returned error: %v", err)
			}
			if got := ctx.Response.Header.Peek("Content-Encoding"); len(got) != 0 {
				t.Fatalf("Content-Encoding = %q, want empty for %s", got, contentType)
			}
			if got := ctx.Response.Body(); !bytes.Equal(got, []byte(payload)) {
				t.Fatalf("body mismatch for %s: got %d bytes, want %d", contentType, len(got), len(payload))
			}
		})
	}

	// Control: the same runtime must still compress an ordinary text response.
	t.Run("control-text-plain", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, payload)
		}))
		defer upstream.Close()

		ctx := app.NewContext(0)
		ctx.Request.SetMethod("GET")
		ctx.Request.SetRequestURI("/control-text-plain")
		ctx.Request.Header.SetHost("proxy.example.com")
		ctx.Request.Header.Set("Accept-Encoding", "gzip")
		if err := ForwardHTTP(context.Background(), ctx, compressionRT(), upstream.URL, nil, "proxy.example.com"); err != nil {
			t.Fatalf("ForwardHTTP returned error: %v", err)
		}
		if got := ctx.Response.Header.Peek("Content-Encoding"); !bytes.Equal(got, []byte("gzip")) {
			t.Fatalf("Content-Encoding = %q, want gzip", got)
		}
		setRaw := ctx.Response.Body()
		reader, err := gzip.NewReader(bytes.NewReader(setRaw))
		if err != nil {
			t.Fatalf("create gzip reader: %v", err)
		}
		decoded, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil || !bytes.Equal(decoded, []byte(payload)) {
			t.Fatalf("control decoded body mismatch: err=%v len=%d", err, len(decoded))
		}
	})
}

// TestForwardBufferedResponseSkipsCompressionForGRPCWebFamilies covers the
// buffered forwarding path used by the cache and app-route capture flows.
func TestForwardBufferedResponseSkipsCompressionForGRPCWebFamilies(t *testing.T) {
	payload := strings.Repeat("buffered-grpc-border-", 64)
	for _, contentType := range []string{"application/grpc", "application/grpc+json", "application/grpc-web", "application/grpc-web+proto", "application/grpc-web+json"} {
		t.Run(contentType, func(t *testing.T) {
			resp := &HTTPResponse{
				StatusCode:  http.StatusOK,
				ContentType: contentType,
				Body:        []byte(payload),
				Header:      http.Header{"Content-Type": []string{contentType}},
			}
			ctx := app.NewContext(0)
			ctx.Request.SetMethod("GET")
			ctx.Request.SetRequestURI("/buffered-grpc-border")
			ctx.Request.Header.SetHost("proxy.example.com")
			ctx.Request.Header.Set("Accept-Encoding", "gzip")
			ForwardBufferedResponseForSiteWithClientIP(ctx, resp, compressionRT(), nil)
			if got := ctx.Response.Header.Peek("Content-Encoding"); len(got) != 0 {
				t.Fatalf("Content-Encoding = %q, want empty for %s", got, contentType)
			}
			if got := ctx.Response.Body(); !bytes.Equal(got, []byte(payload)) {
				t.Fatalf("body mismatch for %s: got %d bytes, want %d", contentType, len(got), len(payload))
			}
		})
	}
}

// TestForwardHTTPSkipsCompressionForGRPCWebTrailerBody forwards the Envoy
// gRPC-Web body form (message frame + in-body trailers frame with
// grpc-status) and requires the exact frame bytes with no Content-Encoding.
func TestForwardHTTPSkipsCompressionForGRPCWebTrailerBody(t *testing.T) {
	payload := []byte(strings.Repeat("zx-body-payload", 512))
	messageFrame := grpcWebDataFrame(0, grpcMessagePayload(payload))
	trailersFrame := grpcWebTrailersFrame(0, "", nil)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		_, _ = w.Write(messageFrame)
		_, _ = w.Write(trailersFrame)
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/grpc.web.Echo/Echo")
	ctx.Request.Header.SetHost("proxy.example.com")
	ctx.Request.Header.Set("Accept-Encoding", "gzip")
	if err := ForwardHTTP(context.Background(), ctx, compressionRT(), upstream.URL, nil, "proxy.example.com"); err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := ctx.Response.Header.Peek("Content-Encoding"); len(got) != 0 {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	want := append(append([]byte{}, messageFrame...), trailersFrame...)
	if got := ctx.Response.Body(); !bytes.Equal(got, want) {
		t.Fatalf("grpc-web body mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

// TestShouldCacheHTTPResponseRejectsGRPCFamilies verifies the shared edge
// cache never stores RPC response streams: every application/grpc family
// (grpc, grpc+proto, grpc-web, grpc-web+proto) is excluded regardless of
// upstream cache directives, because replaying one caller's stream to another
// breaks RPC semantics (per-call trailers, status and payload continuity).
func TestShouldCacheHTTPResponseRejectsGRPCFamilies(t *testing.T) {
	for _, contentType := range []string{"application/grpc", "application/grpc+proto", "application/grpc-web", "application/grpc-web+proto", "application/grpc+json"} {
		t.Run(contentType, func(t *testing.T) {
			resp := &HTTPResponse{
				StatusCode:  http.StatusOK,
				ContentType: contentType,
				Header: http.Header{
					"Content-Type":  []string{contentType},
					"Cache-Control": []string{"public, max-age=60"},
				},
				Body: grpcWebDataFrame(0, grpcMessagePayload([]byte("cache-border-payload"))),
			}
			if ShouldCacheHTTPResponse(http.MethodGet, resp) {
				t.Fatalf("ShouldCacheHTTPResponse = true, gRPC family %s must stay uncacheable", contentType)
			}
		})
	}
}

// TestForwardHTTPWritesH2CGRPCTrailerFrame verifies h2c gRPC classic
// semantics through the streaming path: the message body frame and the
// grpc-status response trailer both survive the proxy.
func TestForwardHTTPWritesH2CGRPCTrailerFrame(t *testing.T) {
	messageFrame := grpcWebDataFrame(0, grpcMessagePayload([]byte("h2c-grpc-echo")))
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/2.0" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
		}
		w.Header().Set("Content-Type", "application/grpc+proto")
		w.Header().Add("Trailer", "grpc-status")
		_, _ = w.Write(messageFrame)
		w.Header().Set("grpc-status", "0")
	}))
	upstream.Config.Protocols = new(http.Protocols)
	upstream.Config.Protocols.SetHTTP1(true)
	upstream.Config.Protocols.SetUnencryptedHTTP2(true)
	upstream.Start()
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/grpc.Echo/Echo")
	ctx.Request.Header.SetHost("proxy.example.com")
	base := strings.Replace(upstream.URL, "http://", "h2c://", 1)
	if err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, base, nil, "proxy.example.com"); err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	if got := ctx.Response.Body(); !bytes.Equal(got, messageFrame) {
		t.Fatalf("body mismatch: got %d bytes, want %d", len(got), len(messageFrame))
	}
	if got := ctx.Response.Header.Trailer().Get("grpc-status"); got != "0" {
		t.Fatalf("grpc-status trailer = %q, want %q", got, "0")
	}
}
