package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/klauspost/compress/zstd"

	"My-OpenWaf/internal/snapshot"
)

const (
	brotliCompressionLevel = 4
)

type responseEncoding string

type ResponseCompressionOptions struct {
	Enabled       bool
	BrotliEnabled bool
	GzipEnabled   bool
	MinBytes      int
}

const (
	responseEncodingIdentity responseEncoding = ""
	responseEncodingGzip     responseEncoding = "gzip"
	responseEncodingBrotli   responseEncoding = "br"
	responseEncodingDeflate  responseEncoding = "deflate"
	responseEncodingZstd     responseEncoding = "zstd"
)

func DefaultResponseCompressionOptions(brotliEnabled bool) ResponseCompressionOptions {
	return normalizeResponseCompressionOptions(ResponseCompressionOptions{
		Enabled:       snapshot.DefaultResponseCompressionEnabled,
		BrotliEnabled: brotliEnabled,
		GzipEnabled:   snapshot.DefaultResponseCompressionGzipEnabled,
		MinBytes:      snapshot.DefaultResponseCompressionMinBytes,
	})
}

func normalizeResponseCompressionOptions(opts ResponseCompressionOptions) ResponseCompressionOptions {
	if opts.MinBytes <= 0 {
		opts.MinBytes = snapshot.DefaultResponseCompressionMinBytes
	}
	return opts
}

func responseCompressionMinBytes(minBytes int) int {
	if minBytes <= 0 {
		return snapshot.DefaultResponseCompressionMinBytes
	}
	return minBytes
}

func readUpstreamResponseBody(resp *http.Response) ([]byte, http.Header, error) {
	reader, closeFn, decoded, err := upstreamResponseReader(resp)
	if err != nil {
		return nil, nil, err
	}
	if closeFn != nil {
		defer closeFn()
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, err
	}

	headers := http.Header(nil)
	if resp != nil {
		headers = resp.Header
	}
	if decoded && headers != nil {
		headers = headers.Clone()
		headers.Del("Content-Encoding")
		headers.Del("Content-Length")
	}
	return body, headers, nil
}

func readUpstreamResponseBodyLimited(resp *http.Response, maxBodyBytes int64) ([]byte, http.Header, io.Reader, func() error, bool, bool, error) {
	reader, closeFn, decoded, err := upstreamResponseReader(resp)
	if err != nil {
		return nil, nil, nil, nil, false, false, err
	}

	headers := http.Header(nil)
	if resp != nil {
		headers = resp.Header
	}
	if decoded && headers != nil {
		headers = headers.Clone()
		headers.Del("Content-Encoding")
		headers.Del("Content-Length")
	}
	if maxBodyBytes < 0 {
		maxBodyBytes = 0
	}
	if maxBodyBytes > int64(math.MaxInt) {
		maxBodyBytes = int64(math.MaxInt)
	}
	if resp != nil && !decoded && resp.ContentLength > maxBodyBytes {
		return nil, headers, reader, closeFn, decoded, true, nil
	}
	limited := io.LimitReader(reader, maxBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		if closeFn != nil {
			_ = closeFn()
		}
		return nil, nil, nil, nil, false, false, err
	}
	if int64(len(body)) <= maxBodyBytes {
		if closeFn != nil {
			if err := closeFn(); err != nil {
				return nil, nil, nil, nil, false, false, err
			}
		}
		return body, headers, nil, nil, decoded, false, nil
	}

	prefixLen := int(maxBodyBytes)
	prefix := append([]byte(nil), body[:prefixLen]...)
	remaining := io.MultiReader(bytes.NewReader(body[prefixLen:]), reader)
	return prefix, headers, remaining, closeFn, decoded, true, nil
}

func upstreamResponseReader(resp *http.Response) (io.Reader, func() error, bool, error) {
	if resp == nil || resp.Body == nil {
		return bytes.NewReader(nil), nil, false, nil
	}

	closeBody := func() error { return resp.Body.Close() }
	encodings, supported := parseContentEncodings(resp.Header.Get("Content-Encoding"))
	if len(encodings) == 0 {
		return resp.Body, closeBody, false, nil
	}
	if !supported {
		return resp.Body, closeBody, false, nil
	}

	current := io.Reader(resp.Body)
	closers := make([]io.Closer, 0, len(encodings))
	decoded := false
	for i := len(encodings) - 1; i >= 0; i-- {
		reader, closer, used, err := newContentDecoderReader(current, encodings[i])
		if err != nil {
			_ = closeContentDecoderClosers(closers)
			_ = resp.Body.Close()
			return nil, nil, false, err
		}
		if !used {
			continue
		}
		current = reader
		decoded = true
		if closer != nil {
			closers = append(closers, closer)
		}
	}
	if !decoded {
		return resp.Body, closeBody, false, nil
	}
	return current, func() error {
		closeErr := closeContentDecoderClosers(closers)
		bodyErr := resp.Body.Close()
		if closeErr != nil {
			return closeErr
		}
		return bodyErr
	}, true, nil
}

func decodeUpstreamRequestBody(body []byte, contentEncoding string) ([]byte, bool, error) {
	return decodeUpstreamRequestBodyBytes(body, []byte(contentEncoding))
}

func decodeUpstreamRequestBodyBytes(body []byte, contentEncoding []byte) ([]byte, bool, error) {
	if len(body) == 0 {
		return body, false, nil
	}

	encodings, supported := parseContentEncodingsBytes(contentEncoding)
	if len(encodings) == 0 {
		return body, false, nil
	}
	if !supported {
		return body, false, nil
	}

	decoded := false
	for i := len(encodings) - 1; i >= 0; i-- {
		reader, closer, used, err := newContentDecoderReader(bytes.NewReader(body), encodings[i])
		if err != nil {
			return nil, false, err
		}
		if !used {
			continue
		}
		decodedBody, readErr := io.ReadAll(reader)
		closeErr := closeContentDecoder(closer)
		if readErr != nil {
			return nil, false, readErr
		}
		if closeErr != nil {
			return nil, false, closeErr
		}
		body = decodedBody
		decoded = true
	}
	return body, decoded, nil
}

type readerReadCloser struct {
	io.Reader
}

func (r readerReadCloser) Close() error {
	return nil
}

type decodedBodyReadCloser struct {
	reader     io.Reader
	bodyCloser io.Closer
	closers    []io.Closer
}

func (r *decodedBodyReadCloser) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *decodedBodyReadCloser) Close() error {
	closeErr := closeContentDecoderClosers(r.closers)
	bodyErr := closeContentDecoder(r.bodyCloser)
	if closeErr != nil {
		return closeErr
	}
	return bodyErr
}

func decodeUpstreamRequestBodyStream(body io.Reader, contentEncoding string) (io.ReadCloser, bool, error) {
	return decodeUpstreamRequestBodyStreamBytes(body, []byte(contentEncoding))
}

func decodeUpstreamRequestBodyStreamBytes(body io.Reader, contentEncoding []byte) (io.ReadCloser, bool, error) {
	if body == nil {
		return nil, false, nil
	}

	encodings, supported := parseContentEncodingsBytes(contentEncoding)
	if len(encodings) == 0 || !supported {
		return readerAsReadCloser(body), false, nil
	}

	current := body
	bodyCloser, _ := body.(io.Closer)
	closers := make([]io.Closer, 0, len(encodings))
	decoded := false
	for i := len(encodings) - 1; i >= 0; i-- {
		reader, closer, used, err := newContentDecoderReader(current, encodings[i])
		if err != nil {
			_ = closeContentDecoderClosers(closers)
			_ = closeContentDecoder(bodyCloser)
			return nil, false, err
		}
		if !used {
			continue
		}
		current = reader
		decoded = true
		if closer != nil {
			closers = append(closers, closer)
		}
	}
	if !decoded {
		return readerAsReadCloser(body), false, nil
	}
	return &decodedBodyReadCloser{
		reader:     current,
		bodyCloser: bodyCloser,
		closers:    closers,
	}, true, nil
}

func readerAsReadCloser(reader io.Reader) io.ReadCloser {
	if reader == nil {
		return nil
	}
	if closer, ok := reader.(io.ReadCloser); ok {
		return closer
	}
	return readerReadCloser{Reader: reader}
}

func parseContentEncodings(raw string) ([]string, bool) {
	return parseContentEncodingsBytes([]byte(raw))
}

func parseContentEncodingsBytes(raw []byte) ([]string, bool) {
	raw = trimASCIIHeaderSpaceBytes(raw)
	if len(raw) == 0 {
		return nil, true
	}

	encodings := make([]string, 0, 4)
	for len(raw) > 0 {
		part := raw
		if comma := bytes.IndexByte(raw, ','); comma >= 0 {
			part = raw[:comma]
			raw = raw[comma+1:]
		} else {
			raw = nil
		}
		part = trimASCIIHeaderSpaceBytes(part)
		if len(part) == 0 {
			continue
		}
		if semi := bytes.IndexByte(part, ';'); semi >= 0 {
			part = trimASCIIHeaderSpaceBytes(part[:semi])
		}
		if len(part) == 0 {
			continue
		}
		encoding, ok := canonicalContentEncodingBytes(part)
		if !ok {
			return nil, false
		}
		encodings = append(encodings, encoding)
	}
	return encodings, true
}

func isSupportedContentEncoding(encoding string) bool {
	switch encoding {
	case "", "identity", "gzip", "x-gzip", "br", "deflate", "zstd":
		return true
	default:
		return false
	}
}

func canonicalContentEncodingBytes(raw []byte) (string, bool) {
	switch len(raw) {
	case 0:
		return "", true
	case len("br"):
		if asciiEqualFoldBytes(raw, "br") {
			return "br", true
		}
	case len("gzip"):
		if asciiEqualFoldBytes(raw, "gzip") {
			return "gzip", true
		}
		if asciiEqualFoldBytes(raw, "zstd") {
			return "zstd", true
		}
	case len("x-gzip"):
		if asciiEqualFoldBytes(raw, "x-gzip") {
			return "x-gzip", true
		}
	case len("deflate"):
		if asciiEqualFoldBytes(raw, "deflate") {
			return "deflate", true
		}
	case len("identity"):
		if asciiEqualFoldBytes(raw, "identity") {
			return "identity", true
		}
	}
	return "", false
}

func newContentDecoderReader(reader io.Reader, encoding string) (io.Reader, io.Closer, bool, error) {
	switch encoding {
	case "", "identity":
		return reader, nil, false, nil
	case "gzip", "x-gzip":
		gzReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, nil, false, err
		}
		return gzReader, gzReader, true, nil
	case "br":
		return brotli.NewReader(reader), nil, true, nil
	case "deflate":
		zlibReader, err := zlib.NewReader(reader)
		if err != nil {
			return nil, nil, false, err
		}
		return zlibReader, zlibReader, true, nil
	case "zstd":
		zstdReader, err := zstd.NewReader(reader)
		if err != nil {
			return nil, nil, false, err
		}
		readCloser := zstdReader.IOReadCloser()
		return readCloser, readCloser, true, nil
	default:
		return nil, nil, false, nil
	}
}

func closeContentDecoderClosers(closers []io.Closer) error {
	var firstErr error
	for i := len(closers) - 1; i >= 0; i-- {
		if err := closers[i].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func closeContentDecoder(closer io.Closer) error {
	if closer == nil {
		return nil
	}
	return closer.Close()
}

func applyClientResponseCompressionWithOptions(c *app.RequestContext, statusCode int, body []byte, opts ResponseCompressionOptions) []byte {
	if c == nil {
		return body
	}
	opts = normalizeResponseCompressionOptions(opts)
	if !opts.Enabled {
		return body
	}
	if !shouldTransformResponseBodyWithMinBytesBytes(statusCode, c.Response.Header.Peek("Content-Type"), c.Response.Header.ContentEncoding(), c.Response.Header.Peek("Cache-Control"), c.Response.Header.Peek("Content-Range"), len(body), opts.MinBytes) {
		return body
	}

	encoding := selectClientResponseEncodingBytes(c.GetHeader("Accept-Encoding"), opts.BrotliEnabled, opts.GzipEnabled)
	if encoding == responseEncodingIdentity {
		return body
	}

	encodedBody, err := compressResponseBody(body, encoding)
	if err != nil || len(encodedBody) >= len(body) {
		return body
	}

	ensureVaryAcceptEncoding(c)
	c.Response.Header.Set("Content-Encoding", string(encoding))
	c.Response.Header.Del("Content-Length")
	return encodedBody
}

func responseStatusDisallowsBody(statusCode int) bool {
	return (statusCode >= 100 && statusCode < 200) || statusCode == http.StatusNoContent || statusCode == http.StatusNotModified
}

func selectClientResponseEncoding(raw string, brotliEnabled bool, gzipEnabled bool) responseEncoding {
	offers := parseAcceptEncodingOffers(raw)
	best := responseEncodingIdentity
	bestQ := 0.0
	for _, encoding := range []responseEncoding{responseEncodingBrotli, responseEncodingGzip, responseEncodingDeflate, responseEncodingZstd} {
		if encoding == responseEncodingBrotli && !brotliEnabled {
			continue
		}
		if encoding == responseEncodingGzip && !gzipEnabled {
			continue
		}
		q := acceptEncodingQ(offers, string(encoding))
		if q <= 0 {
			continue
		}
		if q > bestQ {
			best = encoding
			bestQ = q
		}
	}
	return best
}

type acceptEncodingScores struct {
	br       float64
	gzip     float64
	deflate  float64
	zstd     float64
	wildcard float64

	hasBR       bool
	hasGzip     bool
	hasDeflate  bool
	hasZstd     bool
	hasWildcard bool
}

func selectClientResponseEncodingBytes(raw []byte, brotliEnabled bool, gzipEnabled bool) responseEncoding {
	scores := parseAcceptEncodingScoresBytes(raw)
	best := responseEncodingIdentity
	bestQ := 0.0
	if brotliEnabled {
		if q := scores.q(responseEncodingBrotli); q > bestQ {
			best = responseEncodingBrotli
			bestQ = q
		}
	}
	if gzipEnabled {
		if q := scores.q(responseEncodingGzip); q > bestQ {
			best = responseEncodingGzip
			bestQ = q
		}
	}
	if q := scores.q(responseEncodingDeflate); q > bestQ {
		best = responseEncodingDeflate
		bestQ = q
	}
	if q := scores.q(responseEncodingZstd); q > bestQ {
		best = responseEncodingZstd
	}
	return best
}

func parseAcceptEncodingScoresBytes(raw []byte) acceptEncodingScores {
	var scores acceptEncodingScores
	raw = trimASCIIHeaderSpaceBytes(raw)
	for len(raw) > 0 {
		token := raw
		if comma := bytes.IndexByte(raw, ','); comma >= 0 {
			token = raw[:comma]
			raw = raw[comma+1:]
		} else {
			raw = nil
		}
		part := trimASCIIHeaderSpaceBytes(token)
		if len(part) == 0 {
			continue
		}
		name := part
		q := 1.0
		if semi := bytes.IndexByte(part, ';'); semi >= 0 {
			name = trimASCIIHeaderSpaceBytes(part[:semi])
			q = acceptEncodingQParamBytes(part[semi+1:])
		}
		scores.set(name, q)
	}
	return scores
}

func acceptEncodingQParamBytes(params []byte) float64 {
	q := 1.0
	for len(params) > 0 {
		param := params
		if semi := bytes.IndexByte(params, ';'); semi >= 0 {
			param = params[:semi]
			params = params[semi+1:]
		} else {
			params = nil
		}
		kv := trimASCIIHeaderSpaceBytes(param)
		if eq := bytes.IndexByte(kv, '='); eq >= 0 {
			key := trimASCIIHeaderSpaceBytes(kv[:eq])
			if !asciiEqualFoldBytes(key, "q") {
				continue
			}
			value := trimASCIIHeaderSpaceBytes(kv[eq+1:])
			parsed, ok := parseAcceptEncodingQValueBytes(value)
			if !ok {
				continue
			}
			switch {
			case parsed < 0:
				q = 0
			case parsed > 1:
				q = 1
			default:
				q = parsed
			}
		}
	}
	return q
}

func parseAcceptEncodingQValueBytes(value []byte) (float64, bool) {
	value = trimASCIIHeaderSpaceBytes(value)
	if len(value) == 0 {
		return 0, false
	}
	if acceptEncodingQValueNeedsFloatFallback(value) {
		parsed, err := strconv.ParseFloat(string(value), 64)
		return parsed, err == nil && !math.IsNaN(parsed)
	}

	negative := false
	i := 0
	switch value[0] {
	case '+':
		i++
	case '-':
		negative = true
		i++
	}
	if i >= len(value) {
		return 0, false
	}

	var whole int64
	digits := 0
	for i < len(value) && value[i] >= '0' && value[i] <= '9' {
		whole = whole*10 + int64(value[i]-'0')
		i++
		digits++
	}

	frac := 0.0
	scale := 1.0
	if i < len(value) && value[i] == '.' {
		i++
		for i < len(value) && value[i] >= '0' && value[i] <= '9' {
			scale *= 10
			frac += float64(value[i]-'0') / scale
			i++
			digits++
		}
	}
	if digits == 0 || i != len(value) {
		return 0, false
	}

	parsed := float64(whole) + frac
	if negative {
		parsed = -parsed
	}
	return parsed, true
}

func acceptEncodingQValueNeedsFloatFallback(value []byte) bool {
	for _, b := range value {
		switch b {
		case 'e', 'E', 'i', 'I', 'n', 'N':
			return true
		}
	}
	return false
}

func (s *acceptEncodingScores) set(name []byte, q float64) {
	name = trimASCIIHeaderSpaceBytes(name)
	if len(name) == 0 {
		return
	}
	switch len(name) {
	case len("*"):
		if name[0] == '*' {
			if !s.hasWildcard || q > s.wildcard {
				s.wildcard = q
			}
			s.hasWildcard = true
		}
	case len("br"):
		if asciiEqualFoldBytes(name, "br") {
			if !s.hasBR || q > s.br {
				s.br = q
			}
			s.hasBR = true
		}
	case len("gzip"):
		if asciiEqualFoldBytes(name, "gzip") {
			if !s.hasGzip || q > s.gzip {
				s.gzip = q
			}
			s.hasGzip = true
			return
		}
		if asciiEqualFoldBytes(name, "zstd") {
			if !s.hasZstd || q > s.zstd {
				s.zstd = q
			}
			s.hasZstd = true
		}
	case len("deflate"):
		if asciiEqualFoldBytes(name, "deflate") {
			if !s.hasDeflate || q > s.deflate {
				s.deflate = q
			}
			s.hasDeflate = true
		}
	}
}

func (s acceptEncodingScores) q(encoding responseEncoding) float64 {
	switch encoding {
	case responseEncodingBrotli:
		if s.hasBR {
			return s.br
		}
	case responseEncodingGzip:
		if s.hasGzip {
			return s.gzip
		}
	case responseEncodingDeflate:
		if s.hasDeflate {
			return s.deflate
		}
	case responseEncodingZstd:
		if s.hasZstd {
			return s.zstd
		}
	default:
		return 0
	}
	if s.hasWildcard {
		return s.wildcard
	}
	return 0
}

type acceptEncodingOffer struct {
	name string
	q    float64
}

func parseAcceptEncodingOffers(raw string) []acceptEncodingOffer {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	offers := make([]acceptEncodingOffer, 0, strings.Count(raw, ",")+1)
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
				if len(kv) != 2 || !strings.EqualFold(strings.TrimSpace(kv[0]), "q") {
					continue
				}
				if parsed, err := strconv.ParseFloat(strings.TrimSpace(kv[1]), 64); err == nil && !math.IsNaN(parsed) {
					switch {
					case parsed < 0:
						q = 0
					case parsed > 1:
						q = 1
					default:
						q = parsed
					}
				}
			}
		}
		name = strings.ToLower(name)
		if name == "" {
			continue
		}
		offers = append(offers, acceptEncodingOffer{name: name, q: q})
	}
	return offers
}

func acceptEncodingQ(offers []acceptEncodingOffer, target string) float64 {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return 0
	}
	best := 0.0
	hasExact := false
	for _, offer := range offers {
		if offer.name == target {
			hasExact = true
			if offer.q > best {
				best = offer.q
			}
		}
	}
	if hasExact {
		return best
	}
	for _, offer := range offers {
		if offer.name == "*" && offer.q > best {
			best = offer.q
		}
	}
	return best
}

func shouldTransformResponseBodyWithMinBytes(statusCode int, contentType string, contentEncoding string, cacheControl string, contentRange string, bodySize int, minBytes int) bool {
	minBytes = responseCompressionMinBytes(minBytes)
	if bodySize < minBytes {
		return false
	}
	return shouldTransformResponseMetadata(statusCode, contentType, contentEncoding, cacheControl, contentRange)
}

func shouldTransformResponseBodyWithMinBytesBytes(statusCode int, contentType []byte, contentEncoding []byte, cacheControl []byte, contentRange []byte, bodySize int, minBytes int) bool {
	minBytes = responseCompressionMinBytes(minBytes)
	if bodySize < minBytes {
		return false
	}
	return shouldTransformResponseMetadataBytes(statusCode, contentType, contentEncoding, cacheControl, contentRange)
}

func shouldTransformStreamingResponseBody(statusCode int, contentType string, contentEncoding string, cacheControl string, contentRange string, bodySize int, minBytes int) bool {
	if bodySize >= 0 {
		return shouldTransformResponseBodyWithMinBytes(statusCode, contentType, contentEncoding, cacheControl, contentRange, bodySize, minBytes)
	}
	return shouldTransformResponseMetadata(statusCode, contentType, contentEncoding, cacheControl, contentRange)
}

func shouldTransformStreamingResponseBodyBytes(statusCode int, contentType []byte, contentEncoding []byte, cacheControl []byte, contentRange []byte, bodySize int, minBytes int) bool {
	if bodySize >= 0 {
		return shouldTransformResponseBodyWithMinBytesBytes(statusCode, contentType, contentEncoding, cacheControl, contentRange, bodySize, minBytes)
	}
	return shouldTransformResponseMetadataBytes(statusCode, contentType, contentEncoding, cacheControl, contentRange)
}

func shouldTransformResponseMetadata(statusCode int, contentType string, contentEncoding string, cacheControl string, contentRange string) bool {
	return shouldTransformResponseMetadataBytes(statusCode, []byte(contentType), []byte(contentEncoding), []byte(cacheControl), []byte(contentRange))
}

func shouldTransformResponseMetadataBytes(statusCode int, contentType []byte, contentEncoding []byte, cacheControl []byte, contentRange []byte) bool {
	if statusCode >= 100 && statusCode < 200 {
		return false
	}
	if statusCode == http.StatusNoContent || statusCode == http.StatusNotModified {
		return false
	}
	if len(trimASCIIHeaderSpaceBytes(contentRange)) != 0 {
		return false
	}
	if cacheControlHasNoTransformBytes(cacheControl) {
		return false
	}
	encoding := normalizedContentEncodingBytes(contentEncoding)
	if encoding != "" && encoding != "identity" {
		return false
	}
	return isCompressibleContentTypeBytes(contentType)
}

func isCompressibleContentType(raw string) bool {
	mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(raw))
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(raw))
	}
	mediaType = strings.ToLower(mediaType)
	if strings.HasPrefix(mediaType, "text/") {
		return true
	}
	switch mediaType {
	case "application/json",
		"application/ld+json",
		"application/manifest+json",
		"application/problem+json",
		"application/javascript",
		"application/x-javascript",
		"application/xml",
		"application/xhtml+xml",
		"application/rss+xml",
		"application/atom+xml",
		"application/x-www-form-urlencoded",
		"image/svg+xml":
		return true
	default:
		return false
	}
}

func isCompressibleContentTypeBytes(raw []byte) bool {
	raw = trimASCIIHeaderSpaceBytes(raw)
	if len(raw) == 0 {
		return false
	}
	mediaType := raw
	if semi := bytes.IndexByte(raw, ';'); semi >= 0 {
		params := raw[semi+1:]
		if !contentTypeParamsAreSimpleBytes(params) {
			return isCompressibleContentType(string(raw))
		}
		mediaType = trimASCIIHeaderSpaceBytes(raw[:semi])
	}
	return isCompressibleMediaTypeBytes(mediaType)
}

func contentTypeParamsAreSimpleBytes(raw []byte) bool {
	for len(raw) > 0 {
		part := raw
		if semi := bytes.IndexByte(raw, ';'); semi >= 0 {
			part = raw[:semi]
			raw = raw[semi+1:]
		} else {
			raw = nil
		}
		part = trimASCIIHeaderSpaceBytes(part)
		if len(part) == 0 {
			return false
		}
		eq := bytes.IndexByte(part, '=')
		if eq <= 0 {
			return false
		}
		key := trimASCIIHeaderSpaceBytes(part[:eq])
		value := trimASCIIHeaderSpaceBytes(part[eq+1:])
		if len(key) == 0 || len(value) == 0 || !isHTTPTokenBytes(key) || !isHTTPTokenBytes(value) {
			return false
		}
	}
	return true
}

func isCompressibleMediaTypeBytes(mediaType []byte) bool {
	if len(mediaType) > len("text/") && asciiEqualFoldBytes(mediaType[:len("text/")], "text/") {
		return true
	}
	switch len(mediaType) {
	case len("image/svg+xml"):
		return asciiEqualFoldBytes(mediaType, "image/svg+xml")
	case len("application/json"):
		return asciiEqualFoldBytes(mediaType, "application/json")
	case len("application/xml"):
		return asciiEqualFoldBytes(mediaType, "application/xml")
	case len("application/ld+json"):
		return asciiEqualFoldBytes(mediaType, "application/ld+json") || asciiEqualFoldBytes(mediaType, "application/rss+xml")
	case len("application/atom+xml"):
		return asciiEqualFoldBytes(mediaType, "application/atom+xml")
	case len("application/xhtml+xml"):
		return asciiEqualFoldBytes(mediaType, "application/xhtml+xml")
	case len("application/javascript"):
		return asciiEqualFoldBytes(mediaType, "application/javascript")
	case len("application/problem+json"):
		return asciiEqualFoldBytes(mediaType, "application/problem+json") || asciiEqualFoldBytes(mediaType, "application/x-javascript")
	case len("application/manifest+json"):
		return asciiEqualFoldBytes(mediaType, "application/manifest+json")
	case len("application/x-www-form-urlencoded"):
		return asciiEqualFoldBytes(mediaType, "application/x-www-form-urlencoded")
	default:
		return false
	}
}

func cacheControlHasNoTransformBytes(raw []byte) bool {
	return asciiContainsFoldBytes(raw, "no-transform")
}

func asciiContainsFoldBytes(raw []byte, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(raw) < len(needle) {
		return false
	}
	for i := 0; i <= len(raw)-len(needle); i++ {
		if asciiEqualFoldBytes(raw[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

func isHTTPTokenBytes(raw []byte) bool {
	for _, b := range raw {
		if !isHTTPTokenByte(b) {
			return false
		}
	}
	return true
}

func isHTTPTokenByte(b byte) bool {
	if b >= '0' && b <= '9' {
		return true
	}
	if b >= 'A' && b <= 'Z' {
		return true
	}
	if b >= 'a' && b <= 'z' {
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

func compressResponseBody(body []byte, encoding responseEncoding) ([]byte, error) {
	var buf bytes.Buffer
	switch encoding {
	case responseEncodingBrotli:
		writer := brotli.NewWriterLevel(&buf, brotliCompressionLevel)
		if _, err := writer.Write(body); err != nil {
			_ = writer.Close()
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
	case responseEncodingGzip:
		writer, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
		if err != nil {
			return nil, err
		}
		if _, err := writer.Write(body); err != nil {
			_ = writer.Close()
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
	case responseEncodingDeflate:
		writer, err := zlib.NewWriterLevel(&buf, zlib.BestSpeed)
		if err != nil {
			return nil, err
		}
		if _, err := writer.Write(body); err != nil {
			_ = writer.Close()
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
	case responseEncodingZstd:
		writer, err := zstd.NewWriter(&buf)
		if err != nil {
			return nil, err
		}
		if _, err := writer.Write(body); err != nil {
			_ = writer.Close()
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
	default:
		return body, nil
	}
	return buf.Bytes(), nil
}

func ensureVaryAcceptEncoding(c *app.RequestContext) {
	current := c.Response.Header.Peek("Vary")
	if len(current) == 0 {
		c.Response.Header.Set("Vary", "Accept-Encoding")
		return
	}
	if varyContainsAcceptEncodingBytes(current) {
		return
	}
	next := make([]byte, 0, len(current)+len(", Accept-Encoding"))
	next = append(next, current...)
	next = append(next, ", Accept-Encoding"...)
	c.Response.Header.SetBytesV("Vary", next)
}

func varyContainsAcceptEncodingBytes(raw []byte) bool {
	for len(raw) > 0 {
		token := raw
		if comma := bytes.IndexByte(raw, ','); comma >= 0 {
			token = raw[:comma]
			raw = raw[comma+1:]
		} else {
			raw = nil
		}
		token = trimASCIIHeaderSpaceBytes(token)
		if len(token) == len("Accept-Encoding") && asciiEqualFoldBytes(token, "accept-encoding") {
			return true
		}
	}
	return false
}

func normalizedContentEncoding(raw string) string {
	return normalizedContentEncodingBytes([]byte(raw))
}

func newStreamCompressWriter(w io.Writer, encoding responseEncoding) (io.Writer, func()) {
	switch encoding {
	case responseEncodingGzip:
		gw, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
		return gw, func() { _ = gw.Close() }
	case responseEncodingBrotli:
		bw := brotli.NewWriterLevel(w, brotliCompressionLevel)
		return bw, func() { _ = bw.Close() }
	case responseEncodingDeflate:
		dw, _ := zlib.NewWriterLevel(w, zlib.BestSpeed)
		return dw, func() { _ = dw.Close() }
	case responseEncodingZstd:
		zw, _ := zstd.NewWriter(w)
		return zw, func() { _ = zw.Close() }
	default:
		return w, func() {}
	}
}

func normalizedContentEncodingBytes(raw []byte) string {
	raw = trimASCIIHeaderSpaceBytes(raw)
	if len(raw) == 0 {
		return ""
	}
	if bytes.IndexByte(raw, ',') >= 0 {
		return strings.ToLower(string(raw))
	}
	if semi := bytes.IndexByte(raw, ';'); semi >= 0 {
		raw = trimASCIIHeaderSpaceBytes(raw[:semi])
	}
	encoding, ok := canonicalContentEncodingBytes(raw)
	if ok {
		return encoding
	}
	return strings.ToLower(string(raw))
}
