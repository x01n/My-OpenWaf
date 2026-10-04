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

// Material 保存应用路由匹配与记录所用的 HTTP 提取字段。
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

// TLSMetadata 保存应用路由记录所用的 TLS 字段。
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

/**
 * RequestHeaderLookup 返回按大小写不敏感键拼接同名多值后的取值函数。
 *
 * 首次调用时才遍历全部请求头并建缓存，避免对未用到的头付出构建成本。
 *
 * @param c 请求上下文。
 * @return 传入头名即可取得其拼接值的函数。
 */
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

/**
 * BuildMaterial 同步地从请求上下文提取各字段。
 *
 * @param c 请求上下文；为 nil 时返回 nil。
 * @param clientIP 客户端 IP。
 * @param tls TLS 元数据；不可用时传零值结构体。
 * @param respBody 上游响应体字节；可用时传入。
 * @param upstreamHeader 上游响应头；非 nil 时响应头字段优先取上游值。
 * @return 提取出的 material。
 */
func BuildMaterial(c *app.RequestContext, clientIP net.IP, tls TLSMetadata, respBody []byte, upstreamHeader http.Header) *Material {
	reqBodyBytes, _ := c.Body()
	return BuildMaterialFromRequestBody(c, clientIP, tls, reqBodyBytes, respBody, upstreamHeader, true)
}

/**
 * BuildMaterialFromRequestBody 用调用方提供的请求体快照构建 material。
 *
 * 调用方可传 nil 跳过请求体采集，从而不消费尚未读取的请求流。
 * captureResponse 为 false 时跳过完整响应体与响应头文本，让热路径上的资源记录保持轻量。
 *
 * @param c 请求上下文；为 nil 时返回 nil。
 * @param clientIP 客户端 IP。
 * @param tls TLS 元数据。
 * @param reqBody 请求体快照；nil 且请求体非流式时回退读取请求体。
 * @param respBody 上游响应体字节。
 * @param upstreamHeader 上游响应头。
 * @param captureResponse 是否采集完整响应体与响应头文本。
 * @return 提取出的 material。
 */
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
