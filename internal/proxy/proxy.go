package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/security"
	"My-OpenWaf/internal/snapshot"
)

func transportFor(rt snapshot.SiteRuntime) *http.Transport {
	tr := &http.Transport{
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	if len(rt.UpstreamURLs) > 0 && strings.HasPrefix(rt.UpstreamURLs[0], "https://") {
		tr.TLSClientConfig = &tls.Config{
			ServerName:         rt.Site.UpstreamTLSServerName,
			InsecureSkipVerify: rt.Site.UpstreamTLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}
	}
	return tr
}

// ForwardHTTP copies the incoming request to upstream and streams the response.
func ForwardHTTP(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string) error {
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
		case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
			return
		}
		req.Header.Add(string(k), string(v))
	})

	security.ApplyOutboundForwarding(req, clientIP, origHost, rt.Forwarding)

	hc := &http.Client{Transport: transportFor(rt), Timeout: 0}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			c.Response.Header.Add(k, v)
		}
	}
	c.Status(resp.StatusCode)
	_, err = io.Copy(c.Response.BodyWriter(), resp.Body)
	return err
}
