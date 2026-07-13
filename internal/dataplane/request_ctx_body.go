package dataplane

import (
	"bytes"
	"io"
	"sync"

	"My-OpenWaf/internal/snapshot"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
)

const (
	requestInspectionBodyLimit     = snapshot.WAFBodyScanLimit
	requestBodySnapshotContextKey  = "openwaf_request_body_snapshot"
	requestBodySnapshotReadMaxSize = requestInspectionBodyLimit + 1
)

type requestBodySnapshot struct {
	prefetched []byte
	original   io.Reader
	forward    *prefetchedRequestBodyStream
	size       int64
	hasMore    bool
	readErr    error
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

func requestBodySample(c *app.RequestContext) ([]byte, bool, int64) {
	if c == nil {
		return nil, false, 0
	}
	if c.Request.IsBodyStream() {
		snap := ensureRequestBodySnapshot(c)
		body := snap.prefetched
		if len(body) > requestInspectionBodyLimit {
			body = body[:requestInspectionBodyLimit]
		}
		return body, snap.hasMore, snap.size
	}

	body := c.Request.Body()
	size := int64(len(body))
	if len(body) <= requestInspectionBodyLimit {
		return body, false, size
	}
	return body[:requestInspectionBodyLimit], true, size
}

func ensureRequestBodySnapshot(c *app.RequestContext) requestBodySnapshot {
	if snap, ok := requestBodySnapshotFromContext(c); ok {
		return snap
	}
	if c == nil {
		return requestBodySnapshot{}
	}

	stream := c.Request.BodyStream()
	contentLength := c.Request.Header.ContentLength()
	snap := requestBodySnapshot{}
	if stream == nil || stream == protocol.NoBody {
		if contentLength >= 0 {
			snap.size = int64(contentLength)
		}
		c.Set(requestBodySnapshotContextKey, snap)
		return snap
	}

	prefetched, readErr := io.ReadAll(io.LimitReader(stream, requestBodySnapshotReadMaxSize))
	snap.prefetched = prefetched
	snap.original = stream
	snap.hasMore = len(prefetched) > requestInspectionBodyLimit
	snap.readErr = readErr
	if contentLength >= 0 {
		snap.size = int64(contentLength)
	} else if !snap.hasMore {
		snap.size = int64(len(prefetched))
	}

	// Rebinding a request body stream must not call SetBodyStream here.
	// Hertz SetBodyStream() resets and closes the current body stream first,
	// which breaks HTTP/2 requestBody pipes before the proxy can continue
	// streaming the unread remainder upstream.
	forward := &prefetchedRequestBodyStream{
		reader: io.MultiReader(bytes.NewReader(prefetched), stream),
	}
	snap.forward = forward
	c.Request.ConstructBodyStream(nil, forward)
	c.Set(requestBodySnapshotContextKey, snap)
	return snap
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
