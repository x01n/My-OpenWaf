package appresource

import (
	"net"
	"net/http"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
)

const (
	maxBodySnippet       = 4096
	maxHeadersJSON       = 8192
	maxFingerprintString = 1024
)

// Material holds extracted HTTP fields used for application-route matching and recording.
type Material struct {
	Method              string
	Path                string
	QueryString         string
	Host                string
	ClientIP            string
	RequestBody         string
	ResponseBody        string
	RequestHeadersFull  string
	ResponseHeadersFull string
	FullHTTPRequest     string
	FullHTTPResponse    string
	Fingerprint         string
	StatusCode          int
	ContentType         string
	UserAgent           string
	TLSVersion          string
	TLSSNI              string
	TLSALPN             string
	JA3Hash             string
	JA4                 string
	RequestHeadersJSON  string
	ResponseHeadersJSON string
	RequestBodySnippet  string
	ResponseBodySnippet string
}

// TLSMetadata captures the TLS fields used by application-route recording.
type TLSMetadata struct {
	TLSVersion string
	TLSSNI     string
	TLSALPN    string
	JA3Hash    string
	JA4        string
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func requestPath(c *app.RequestContext) string {
	if rawPath := c.Request.URI().PathOriginal(); len(rawPath) > 0 {
		return string(rawPath)
	}
	return string(c.Path())
}

// RequestHeaderLookup returns the concatenated values for a header (case-insensitive key).
func RequestHeaderLookup(c *app.RequestContext) func(string) string {
	var cached map[string]string
	var loaded bool
	return func(key string) string {
		if !loaded {
			grouped := make(map[string][]string)
			c.Request.Header.VisitAll(func(k, v []byte) {
				lower := strings.ToLower(strings.TrimSpace(string(k)))
				grouped[lower] = append(grouped[lower], string(v))
			})
			cached = make(map[string]string, len(grouped))
			for lower, values := range grouped {
				cached[lower] = strings.Join(values, ", ")
			}
			loaded = true
		}
		return cached[strings.ToLower(strings.TrimSpace(key))]
	}
}

// BuildMaterial extracts strings from the request context synchronously.
// tls is optional; pass a zero-value metadata struct when unavailable.
// If upstreamHeader is non-nil, response header fields prefer upstream headers;
// respBody should be upstream body bytes when available.
func BuildMaterial(c *app.RequestContext, clientIP net.IP, tls TLSMetadata, respBody []byte, upstreamHeader http.Header) *Material {
	reqBodyBytes, _ := c.Body()
	return BuildMaterialFromRequestBody(c, clientIP, tls, reqBodyBytes, respBody, upstreamHeader, true)
}

// BuildMaterialFromRequestBody builds material using a caller-supplied request
// body snapshot. Callers may pass nil to skip request-body capture without
// consuming an unread request stream.
// When captureResponse is false, the full response body and response header text
// are skipped to keep resource recording on the hot path lightweight.
func BuildMaterialFromRequestBody(c *app.RequestContext, clientIP net.IP, tls TLSMetadata, reqBody []byte, respBody []byte, upstreamHeader http.Header, captureResponse bool) *Material {
	if c == nil {
		return nil
	}
	if reqBody == nil && !c.Request.IsBodyStream() {
		reqBody = c.Request.Body()
	}
	m := &Material{}
	m.Method = string(c.Method())
	m.Path = requestPath(c)
	m.QueryString = sanitizeRecordedQueryString(string(c.URI().QueryString()))
	m.Host = string(c.Host())
	if clientIP != nil {
		m.ClientIP = clientIP.String()
	}
	m.TLSVersion = strings.TrimSpace(tls.TLSVersion)
	m.TLSSNI = strings.TrimSpace(tls.TLSSNI)
	m.TLSALPN = strings.TrimSpace(tls.TLSALPN)
	m.JA3Hash = strings.TrimSpace(tls.JA3Hash)
	m.JA4 = strings.TrimSpace(tls.JA4)
	m.UserAgent = string(c.UserAgent())

	reqBodyText := string(reqBody)
	m.RequestBody = reqBodyText
	m.RequestBodySnippet = truncate(sanitizeRecordedBodySnippet(reqBodyText, string(c.Request.Header.ContentType())), maxBodySnippet)
	requestHeaders := captureRecordedRequestHeaders(c, recordedHeaderCaptureText|recordedHeaderCaptureJSON)
	m.RequestHeadersFull = requestHeaders.text
	m.RequestHeadersJSON = requestHeaders.json

	responseContentType := ""
	responseMode := recordedHeaderCaptureJSON
	if captureResponse {
		responseMode |= recordedHeaderCaptureText
	}
	if upstreamHeader != nil {
		responseHeaders := captureRecordedHTTPHeaders(upstreamHeader, responseMode)
		m.ResponseHeadersJSON = responseHeaders.json
		if captureResponse {
			m.ResponseHeadersFull = responseHeaders.text
		}
		if vs := upstreamHeader.Values("Content-Type"); len(vs) > 0 {
			responseContentType = vs[0]
		}
	} else {
		responseHeaders := captureRecordedResponseHeaders(c, responseMode)
		m.ResponseHeadersJSON = responseHeaders.json
		if captureResponse {
			m.ResponseHeadersFull = responseHeaders.text
		}
		responseContentType = string(c.Response.Header.ContentType())
	}
	m.ContentType = responseContentType
	if captureResponse {
		rb := append([]byte(nil), respBody...)
		if len(rb) == 0 {
			rb = append([]byte(nil), c.Response.Body()...)
		}
		m.ResponseBody = string(rb)
		m.ResponseBodySnippet = truncate(sanitizeRecordedBodySnippet(m.ResponseBody, responseContentType), maxBodySnippet)
	} else {
		responseSample := respBody
		if len(responseSample) == 0 && !c.Response.IsBodyStream() {
			responseSample = c.Response.BodyBytes()
		}
		if len(responseSample) > maxBodySnippet {
			responseSample = responseSample[:maxBodySnippet]
		}
		m.ResponseBodySnippet = truncate(sanitizeRecordedBodySnippet(string(responseSample), responseContentType), maxBodySnippet)
	}

	m.StatusCode = c.Response.StatusCode()

	return m
}
