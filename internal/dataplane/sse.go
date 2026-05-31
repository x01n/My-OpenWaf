package dataplane

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/proxy"
	"My-OpenWaf/internal/security"
	"My-OpenWaf/internal/snapshot"
)

// ForwardSSE streams a text/event-stream response from upstream to the client.
func ForwardSSE(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string) error {
	path := string(c.Path())
	if path == "" {
		path = "/"
	}
	q := c.URI().QueryString()
	full := strings.TrimRight(base, "/") + path
	if len(q) > 0 {
		full += "?" + string(q)
	}

	body := c.Request.Body()
	var rdr io.Reader
	if len(body) > 0 {
		rdr = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, string(c.Method()), full, rdr)
	if err != nil {
		return err
	}

	c.Request.Header.VisitAll(func(k, v []byte) {
		key := strings.ToLower(string(k))
		switch key {
		case "connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade":
			return
		}
		req.Header.Add(string(k), string(v))
	})
	security.ApplyOutboundForwarding(req, clientIP, origHost, rt.PreserveOriginalHost, inboundProto(c, rt.Site.TLSEnabled))

	hc := &http.Client{Transport: proxy.SharedTransportForUpstream(rt, base), Timeout: 0}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		if proxy.IsHopByHop(k) {
			continue
		}
		for _, v := range vv {
			c.Response.Header.Add(k, v)
		}
	}
	if resp.Header.Get("Server") == "" {
		c.Response.Header.Del("Server")
	}
	c.SetStatusCode(resp.StatusCode)

	c.Response.Header.Set("Cache-Control", "no-cache")
	c.Response.Header.Del("Connection")
	c.Response.Header.Del("Content-Length")
	c.Response.SetBodyStream(resp.Body, -1)
	return nil
}

func inboundProto(c *app.RequestContext, tlsEnabled bool) string {
	if v := strings.TrimSpace(string(c.GetHeader("X-Forwarded-Proto"))); v != "" {
		return strings.ToLower(v)
	}
	if tlsEnabled {
		return "https"
	}
	return "http"
}

// IsSSERequest checks if the client expects a text/event-stream response.
func IsSSERequest(c *app.RequestContext) bool {
	return strings.Contains(string(c.GetHeader("Accept")), "text/event-stream")
}
