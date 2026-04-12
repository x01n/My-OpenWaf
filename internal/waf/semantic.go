package waf

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
)

// SemanticViews holds lazily-built decoded fields for rules (decode-only; no decisions).
type SemanticViews struct {
	QueryKeys  map[string]string
	FormKeys   map[string]string
	JSONKeys   map[string]any
	BodyParsed bool
}

// LazyQuery parses query string once when needed.
func LazyQuery(c *app.RequestContext) *SemanticViews {
	v := &SemanticViews{}
	qs := c.URI().QueryString()
	if len(qs) == 0 {
		v.QueryKeys = map[string]string{}
		return v
	}
	v.QueryKeys = parseQueryString(string(qs))
	return v
}

// LazyBody parses body on demand based on Content-Type (form, JSON).
func (v *SemanticViews) LazyBody(c *app.RequestContext, maxBytes int64) {
	if v.BodyParsed {
		return
	}
	v.BodyParsed = true
	body := c.Request.Body()
	if len(body) == 0 {
		return
	}
	if maxBytes > 0 && int64(len(body)) > maxBytes {
		body = body[:maxBytes]
	}

	ct := strings.ToLower(string(c.ContentType()))
	switch {
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		v.FormKeys = parseQueryString(string(body))
	case strings.Contains(ct, "application/json"):
		var m map[string]any
		if json.Unmarshal(body, &m) == nil {
			v.JSONKeys = m
		}
	}
}

func parseQueryString(qs string) map[string]string {
	m := make(map[string]string)
	for qs != "" {
		key := qs
		if i := strings.IndexByte(key, '&'); i >= 0 {
			key, qs = key[:i], key[i+1:]
		} else {
			qs = ""
		}
		if key == "" {
			continue
		}
		value := ""
		if i := strings.IndexByte(key, '='); i >= 0 {
			key, value = key[:i], key[i+1:]
		}
		dk, _ := url.QueryUnescape(key)
		dv, _ := url.QueryUnescape(value)
		if dk == "" {
			dk = key
		}
		m[dk] = dv
	}
	return m
}
