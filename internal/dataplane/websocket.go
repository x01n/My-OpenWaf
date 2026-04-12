package dataplane

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/snapshot"
)

// IsWebSocketUpgrade checks the request for a WebSocket upgrade handshake.
func IsWebSocketUpgrade(c *app.RequestContext) bool {
	return strings.EqualFold(string(c.GetHeader("Upgrade")), "websocket") &&
		strings.Contains(strings.ToLower(string(c.GetHeader("Connection"))), "upgrade")
}

// ForwardWebSocket tunnels the upgraded connection to upstream at raw TCP level.
func ForwardWebSocket(c *app.RequestContext, rt snapshot.SiteRuntime, base string) error {
	target := strings.TrimRight(base, "/") + string(c.Path())
	q := c.URI().QueryString()
	if len(q) > 0 {
		target += "?" + string(q)
	}
	target = strings.Replace(target, "http://", "ws://", 1)
	target = strings.Replace(target, "https://", "wss://", 1)

	dialer := net.Dialer{Timeout: 10 * time.Second}
	host := hostFromURL(target)
	var upConn net.Conn
	var err error

	if strings.HasPrefix(target, "wss://") {
		upConn, err = tls.DialWithDialer(&dialer, "tcp", host, &tls.Config{
			ServerName:         rt.Site.UpstreamTLSServerName,
			InsecureSkipVerify: rt.Site.UpstreamTLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
		})
	} else {
		upConn, err = dialer.Dial("tcp", host)
	}
	if err != nil {
		return err
	}
	defer upConn.Close()

	reqLine := string(c.Method()) + " " + pathAndQuery(target) + " HTTP/1.1\r\n"
	var hdr strings.Builder
	hdr.WriteString(reqLine)
	c.Request.Header.VisitAll(func(k, v []byte) {
		hdr.WriteString(string(k) + ": " + string(v) + "\r\n")
	})
	hdr.WriteString("\r\n")
	if _, err := io.WriteString(upConn, hdr.String()); err != nil {
		return err
	}

	clientConn := c.GetConn()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upConn, clientConn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(clientConn, upConn); done <- struct{}{} }()
	<-done
	return nil
}

func hostFromURL(u string) string {
	u = strings.TrimPrefix(u, "ws://")
	u = strings.TrimPrefix(u, "wss://")
	parts := strings.SplitN(u, "/", 2)
	host := parts[0]
	if !strings.Contains(host, ":") {
		if strings.HasPrefix(u, "wss://") {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	return host
}

func pathAndQuery(u string) string {
	for _, prefix := range []string{"ws://", "wss://", "http://", "https://"} {
		u = strings.TrimPrefix(u, prefix)
	}
	i := strings.Index(u, "/")
	if i < 0 {
		return "/"
	}
	return u[i:]
}

var _ http.Handler = (*wsPlaceholder)(nil)

type wsPlaceholder struct{}

func (w *wsPlaceholder) ServeHTTP(http.ResponseWriter, *http.Request) {}
