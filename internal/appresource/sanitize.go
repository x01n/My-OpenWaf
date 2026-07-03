package appresource

import (
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
)

const (
	recordedHeaderValueLimit  = 2048
	recordedHeaderValuesLimit = 32
)

var sensitiveRecordedValuePattern = regexp.MustCompile(`(?i)(password|passwd|pwd|token|secret|session|api[_-]?key|auth[_-]?token|csrf|code)(["'\s:=]+)([^&\s,"'}]+)`)

type recordedHeaderCaptureMode uint8

const (
	recordedHeaderCaptureText recordedHeaderCaptureMode = 1 << iota
	recordedHeaderCaptureJSON
)

type recordedHeaderCapture struct {
	text string
	json string
}

func captureRecordedRequestHeaders(c *app.RequestContext, mode recordedHeaderCaptureMode) recordedHeaderCapture {
	var text strings.Builder
	var headers map[string][]string
	if mode&recordedHeaderCaptureJSON != 0 {
		headers = make(map[string][]string)
	}

	c.Request.Header.VisitAll(func(k, v []byte) {
		if mode&recordedHeaderCaptureText != 0 {
			text.Write(k)
			text.WriteString(": ")
			text.Write(v)
			text.WriteByte('\n')
		}
		if mode&recordedHeaderCaptureJSON == 0 {
			return
		}
		key := string(k)
		lower := strings.ToLower(key)
		if isSensitiveRecordedKey(lower) {
			headers[key] = []string{"[redacted]"}
			return
		}
		values := headers[key]
		if len(values) >= recordedHeaderValuesLimit {
			return
		}
		headers[key] = append(values, truncateRecordedValue(sanitizeRecordedText(string(v)), recordedHeaderValueLimit))
	})

	result := recordedHeaderCapture{}
	if mode&recordedHeaderCaptureText != 0 {
		result.text = text.String()
	}
	if mode&recordedHeaderCaptureJSON != 0 {
		data, err := json.Marshal(headers)
		if err != nil {
			result.json = "{}"
		} else {
			result.json = truncate(string(data), maxHeadersJSON)
		}
	}
	return result
}

func captureRecordedResponseHeaders(c *app.RequestContext, mode recordedHeaderCaptureMode) recordedHeaderCapture {
	var text strings.Builder
	var headers map[string][]string
	if mode&recordedHeaderCaptureJSON != 0 {
		headers = make(map[string][]string)
	}

	c.Response.Header.VisitAll(func(k, v []byte) {
		if mode&recordedHeaderCaptureText != 0 {
			text.Write(k)
			text.WriteString(": ")
			text.Write(v)
			text.WriteByte('\n')
		}
		if mode&recordedHeaderCaptureJSON == 0 {
			return
		}
		key := string(k)
		lower := strings.ToLower(key)
		if isSensitiveRecordedKey(lower) {
			headers[key] = []string{"[redacted]"}
			return
		}
		values := headers[key]
		if len(values) >= recordedHeaderValuesLimit {
			return
		}
		headers[key] = append(values, truncateRecordedValue(sanitizeRecordedText(string(v)), recordedHeaderValueLimit))
	})

	result := recordedHeaderCapture{}
	if mode&recordedHeaderCaptureText != 0 {
		result.text = text.String()
	}
	if mode&recordedHeaderCaptureJSON != 0 {
		data, err := json.Marshal(headers)
		if err != nil {
			result.json = "{}"
		} else {
			result.json = truncate(string(data), maxHeadersJSON)
		}
	}
	return result
}

func captureRecordedHTTPHeaders(h http.Header, mode recordedHeaderCaptureMode) recordedHeaderCapture {
	if h == nil {
		return recordedHeaderCapture{}
	}

	var text strings.Builder
	var headers map[string][]string
	if mode&recordedHeaderCaptureJSON != 0 {
		headers = make(map[string][]string)
	}

	for key, rawValues := range h {
		if mode&recordedHeaderCaptureText != 0 {
			for _, value := range rawValues {
				text.WriteString(key)
				text.WriteString(": ")
				text.WriteString(value)
				text.WriteByte('\n')
			}
		}
		if mode&recordedHeaderCaptureJSON == 0 {
			continue
		}
		lower := strings.ToLower(key)
		if isSensitiveRecordedKey(lower) {
			headers[key] = []string{"[redacted]"}
			continue
		}
		values := make([]string, 0, len(rawValues))
		for _, value := range rawValues {
			if len(values) >= recordedHeaderValuesLimit {
				break
			}
			values = append(values, truncateRecordedValue(sanitizeRecordedText(value), recordedHeaderValueLimit))
		}
		headers[key] = values
	}

	result := recordedHeaderCapture{}
	if mode&recordedHeaderCaptureText != 0 {
		result.text = text.String()
	}
	if mode&recordedHeaderCaptureJSON != 0 {
		data, err := json.Marshal(headers)
		if err != nil {
			result.json = "{}"
		} else {
			result.json = truncate(string(data), maxHeadersJSON)
		}
	}
	return result
}

func sanitizeRecordedQueryString(raw string) string {
	if raw == "" {
		return ""
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return sanitizeRecordedText(raw)
	}
	for key := range values {
		if isSensitiveRecordedKey(key) {
			values[key] = []string{"[redacted]"}
			continue
		}
		for i, value := range values[key] {
			values[key][i] = sanitizeRecordedText(value)
		}
	}
	return values.Encode()
}

func sanitizeRecordedBodySnippet(body, contentType string) string {
	if body == "" {
		return ""
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	switch mediaType {
	case "application/x-www-form-urlencoded":
		return sanitizeRecordedQueryString(body)
	case "application/json":
		var value any
		if json.Unmarshal([]byte(body), &value) == nil {
			return marshalSanitizedRecordedJSON(value)
		}
	}
	return sanitizeRecordedText(body)
}

func marshalSanitizedRecordedJSON(value any) string {
	data, err := json.Marshal(sanitizeRecordedJSONValue(value))
	if err != nil {
		return ""
	}
	return string(data)
}

func sanitizeRecordedJSONValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			if isSensitiveRecordedKey(key) {
				out[key] = "[redacted]"
			} else {
				out[key] = sanitizeRecordedJSONValue(item)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = sanitizeRecordedJSONValue(item)
		}
		return out
	case string:
		return sanitizeRecordedText(v)
	default:
		return value
	}
}

func sanitizeRecordedText(value string) string {
	return sensitiveRecordedValuePattern.ReplaceAllString(value, `${1}${2}[redacted]`)
}

func truncateRecordedValue(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "...[truncated]"
}

func isSensitiveRecordedKey(key string) bool {
	lower := strings.ToLower(key)
	for _, part := range []string{"authorization", "cookie", "token", "secret", "password", "passwd", "pwd", "session", "api-key", "apikey", "csrf", "credential", "key"} {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}
