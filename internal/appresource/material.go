package appresource

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
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
	JA3Hash             string
	RequestHeadersJSON  string
	ResponseHeadersJSON string
	RequestBodySnippet  string
	ResponseBodySnippet string
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

func serializeRequestHeaders(c *app.RequestContext) string {
	var b strings.Builder
	c.Request.Header.VisitAll(func(k, v []byte) {
		b.Write(k)
		b.WriteString(": ")
		b.Write(v)
		b.WriteByte('\n')
	})
	return b.String()
}

func serializeResponseHeaders(c *app.RequestContext) string {
	var b strings.Builder
	c.Response.Header.VisitAll(func(k, v []byte) {
		b.Write(k)
		b.WriteString(": ")
		b.Write(v)
		b.WriteByte('\n')
	})
	return b.String()
}

func headersMapJSONFromRequest(c *app.RequestContext) string {
	m := make(map[string]string)
	c.Request.Header.VisitAll(func(k, v []byte) {
		m[string(k)] = string(v)
	})
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return truncate(string(b), maxHeadersJSON)
}

func headersMapJSONFromResponse(c *app.RequestContext) string {
	m := make(map[string]string)
	c.Response.Header.VisitAll(func(k, v []byte) {
		m[string(k)] = string(v)
	})
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return truncate(string(b), maxHeadersJSON)
}

func headersMapJSONFromHTTP(h http.Header) string {
	if h == nil {
		return ""
	}
	m := make(map[string]string)
	for k, vs := range h {
		m[k] = strings.Join(vs, ", ")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return truncate(string(b), maxHeadersJSON)
}

func headersTextFromHTTP(h http.Header) string {
	if h == nil {
		return ""
	}
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// RequestHeaderLookup returns the concatenated values for a header (case-insensitive key).
func RequestHeaderLookup(c *app.RequestContext) func(string) string {
	return func(key string) string {
		want := strings.ToLower(strings.TrimSpace(key))
		var out string
		c.Request.Header.VisitAll(func(k, v []byte) {
			if strings.ToLower(string(k)) == want {
				if out != "" {
					out += ", "
				}
				out += string(v)
			}
		})
		return out
	}
}

// BuildMaterial extracts strings from the request context synchronously.
// ja3 is optional (TLS fingerprint hash); pass empty when unavailable.
// If upstreamHeader is non-nil, response header fields prefer upstream headers;
// respBody should be upstream body bytes when available.
func BuildMaterial(c *app.RequestContext, clientIP net.IP, ja3 string, respBody []byte, upstreamHeader http.Header) *Material {
	m := &Material{}
	m.Method = string(c.Method())
	m.Path = requestPath(c)
	m.Host = string(c.Host())
	if clientIP != nil {
		m.ClientIP = clientIP.String()
	}
	m.JA3Hash = ja3
	m.UserAgent = string(c.UserAgent())
	var fp strings.Builder
	fp.WriteString(m.JA3Hash)
	fp.WriteByte('\t')
	fp.WriteString(m.UserAgent)
	m.Fingerprint = truncate(fp.String(), maxFingerprintString)

	reqBodyBytes, _ := c.Body()
	reqBody := string(reqBodyBytes)
	m.RequestBody = truncate(reqBody, maxBodySnippet)
	m.RequestBodySnippet = m.RequestBody
	m.RequestHeadersFull = serializeRequestHeaders(c)
	m.RequestHeadersJSON = headersMapJSONFromRequest(c)

	rb := append([]byte(nil), respBody...)
	if len(rb) == 0 {
		rb = append([]byte(nil), c.Response.Body()...)
	}
	m.ResponseBody = string(rb)
	m.ResponseBodySnippet = truncate(m.ResponseBody, maxBodySnippet)

	if upstreamHeader != nil {
		m.ResponseHeadersFull = headersTextFromHTTP(upstreamHeader)
		m.ResponseHeadersJSON = headersMapJSONFromHTTP(upstreamHeader)
		if vs := upstreamHeader.Values("Content-Type"); len(vs) > 0 {
			m.ContentType = vs[0]
		}
	} else {
		m.ResponseHeadersFull = serializeResponseHeaders(c)
		m.ResponseHeadersJSON = headersMapJSONFromResponse(c)
		m.ContentType = string(c.Response.Header.ContentType())
	}

	m.StatusCode = c.Response.StatusCode()
	st := m.StatusCode
	m.FullHTTPRequest = m.Method + " " + m.Path + "\n" + m.RequestHeadersFull + "\n\n" + m.RequestBodySnippet
	m.FullHTTPResponse = strconv.Itoa(st) + " " + http.StatusText(st) + "\n" + m.ResponseHeadersFull + "\n\n" + m.ResponseBodySnippet

	return m
}
