package dataplane

import (
	"bytes"
	"io"

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
	size       int64
	hasMore    bool
	readErr    error
}

type prefetchedRequestBodyStream struct {
	reader io.Reader
	closer io.Closer
}

func (s *prefetchedRequestBodyStream) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

func (s *prefetchedRequestBodyStream) Close() error {
	if s.closer == nil {
		return nil
	}
	return s.closer.Close()
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
	c.Request.ConstructBodyStream(nil, &prefetchedRequestBodyStream{
		reader: io.MultiReader(bytes.NewReader(prefetched), stream),
		closer: requestBodyStreamCloser(stream),
	})
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

func requestBodyStreamCloser(reader io.Reader) io.Closer {
	closer, _ := reader.(io.Closer)
	return closer
}
