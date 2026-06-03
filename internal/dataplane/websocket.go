package dataplane

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/waf/bot"
)

const wsInspectFrameLimit = 4096

// IsWebSocketUpgrade checks the request for a WebSocket upgrade handshake.
func IsWebSocketUpgrade(c *app.RequestContext) bool {
	return strings.EqualFold(string(c.GetHeader("Upgrade")), "websocket") &&
		strings.Contains(strings.ToLower(string(c.GetHeader("Connection"))), "upgrade")
}

// ForwardWebSocket forwards the WS handshake and inspects text/binary frames.
func ForwardWebSocket(c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, eng *engine.Engine) error {
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

	if strings.HasPrefix(strings.ToLower(target), "wss://") {
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

	hdr := buildWebSocketHandshakeHeaders(c, pathAndQuery(target), host, strings.ToLower(strings.SplitN(target, "://", 2)[0]), rt, clientIP)
	if _, err := io.WriteString(upConn, hdr); err != nil {
		return err
	}

	upReader := bufio.NewReader(upConn)
	statusLine, respHeaders, err := readHTTPResponseHead(upReader)
	if err != nil {
		return err
	}
	clientConn := c.GetConn()
	if _, err := io.WriteString(clientConn, statusLine); err != nil {
		return err
	}
	if _, err := io.WriteString(clientConn, respHeaders); err != nil {
		return err
	}

	pipeClient, pipeUpstream := net.Pipe()
	defer pipeClient.Close()
	defer pipeUpstream.Close()

	copyErr := make(chan error, 3)
	go func() { _, e := io.Copy(pipeUpstream, clientConn); copyErr <- e }()
	go func() { _, e := io.Copy(clientConn, upReader); copyErr <- e }()
	go inspectWebSocketClientFrames(pipeClient, upConn, c, rt, eng, copyErr)

	for range 3 {
		if err := <-copyErr; err != nil && !errors.Is(err, io.EOF) && !isNetClosed(err) {
			return err
		}
	}
	return nil
}

func buildWebSocketHandshakeHeaders(c *app.RequestContext, requestTarget string, upstreamHost string, upstreamProto string, rt snapshot.SiteRuntime, clientIP net.IP) string {
	method := string(c.Method())
	if method == "" {
		method = http.MethodGet
	}

	var hdr strings.Builder
	hdr.WriteString(method + " " + requestTarget + " HTTP/1.1\r\n")
	c.Request.Header.VisitAll(func(k, v []byte) {
		key := strings.ToLower(string(k))
		switch key {
		case "host", "connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto":
			return
		}
		hdr.WriteString(string(k) + ": " + string(v) + "\r\n")
	})

	host := upstreamHost
	origHost := string(c.Host())
	if rt.PreserveOriginalHost && origHost != "" {
		host = origHost
	}
	hdr.WriteString("Host: " + host + "\r\n")
	hdr.WriteString("Connection: Upgrade\r\n")
	if clientIP != nil {
		hdr.WriteString("X-Forwarded-For: " + clientIP.String() + "\r\n")
	}
	if rt.PreserveOriginalHost && origHost != "" {
		hdr.WriteString("X-Forwarded-Host: " + origHost + "\r\n")
	}
	if v := strings.TrimSpace(string(c.GetHeader("X-Forwarded-Proto"))); v != "" {
		hdr.WriteString("X-Forwarded-Proto: " + strings.ToLower(v) + "\r\n")
	} else if upstreamProto == "wss" {
		hdr.WriteString("X-Forwarded-Proto: https\r\n")
	} else {
		hdr.WriteString("X-Forwarded-Proto: http\r\n")
	}
	hdr.WriteString("\r\n")
	return hdr.String()
}

func inspectWebSocketClientFrames(src net.Conn, dst net.Conn, c *app.RequestContext, rt snapshot.SiteRuntime, eng *engine.Engine, done chan<- error) {
	defer func() { done <- nil }()
	for {
		frame, err := readWSFrame(src, wsInspectFrameLimit)
		if err != nil {
			if !errors.Is(err, io.EOF) && !isNetClosed(err) {
				done <- err
			}
			return
		}
		if eng != nil && len(frame.Payload) > 0 && (frame.Opcode == 0x1 || frame.Opcode == 0x2) {
			if hit := inspectWebSocketPayload(c, rt, eng, frame.Payload); hit.IsTerminal() {
				_ = dst.Close()
				_ = src.Close()
				return
			}
		}
		if _, err := dst.Write(frame.Raw); err != nil {
			done <- err
			return
		}
	}
}

func inspectWebSocketPayload(c *app.RequestContext, rt snapshot.SiteRuntime, eng *engine.Engine, payload []byte) action.Result {
	reqCtx := &pipeline.RequestCtx{
		Bind:        rt.Bind,
		Method:      string(c.Method()),
		Path:        string(c.Path()),
		RawQuery:    string(c.URI().QueryString()),
		Host:        string(c.Host()),
		Headers:     make(map[string]string, 8),
		HeaderKeys:  make([]string, 0, 8),
		Body:        payload,
		ContentType: "application/octet-stream",
	}
	if fp, ok := bot.TLSFingerprintFromConn(c.GetConn()); ok {
		reqCtx.TLS = fp
	}
	c.Request.Header.VisitAll(func(k, v []byte) {
		key := string(k)
		reqCtx.Headers[key] = string(v)
		reqCtx.HeaderKeys = append(reqCtx.HeaderKeys, key)
	})
	return eng.Process(reqCtx).Action
}

type wsFrame struct {
	Raw     []byte
	Opcode  byte
	Payload []byte
}

func readWSFrame(r io.Reader, payloadLimit int) (wsFrame, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return wsFrame{}, err
	}
	finOpcode := header[0]
	maskLen := header[1]
	opcode := finOpcode & 0x0F
	masked := maskLen&0x80 != 0
	payloadLen := uint64(maskLen & 0x7F)

	raw := append([]byte{}, header[:]...)
	switch payloadLen {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return wsFrame{}, err
		}
		raw = append(raw, ext[:]...)
		payloadLen = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return wsFrame{}, err
		}
		raw = append(raw, ext[:]...)
		payloadLen = binary.BigEndian.Uint64(ext[:])
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return wsFrame{}, err
		}
		raw = append(raw, maskKey[:]...)
	}

	payload, decoded, err := readWSPayload(r, payloadLen, payloadLimit, maskKey, masked)
	if err != nil {
		return wsFrame{}, err
	}
	raw = append(raw, payload...)
	return wsFrame{Raw: raw, Opcode: opcode, Payload: decoded}, nil
}

func readWSPayload(r io.Reader, payloadLen uint64, payloadLimit int, maskKey [4]byte, masked bool) ([]byte, []byte, error) {
	if payloadLen > uint64(int(^uint(0)>>1)) {
		return nil, nil, errors.New("websocket frame too large")
	}
	payload := make([]byte, int(payloadLen))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, nil, err
	}
	decodedLen := len(payload)
	if decodedLen > payloadLimit {
		decodedLen = payloadLimit
	}
	decoded := append([]byte(nil), payload[:decodedLen]...)
	if masked {
		for i := range decoded {
			decoded[i] ^= maskKey[i%4]
		}
	}
	return payload, decoded, nil
}

func readHTTPResponseHead(r *bufio.Reader) (string, string, error) {
	statusLine, err := r.ReadString('\n')
	if err != nil {
		return "", "", err
	}
	var headers bytes.Buffer
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", "", err
		}
		headers.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	return statusLine, headers.String(), nil
}

func isNetClosed(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "closed") || strings.Contains(msg, "reset by peer")
}

func hostFromURL(u string) string {
	isWSS := strings.HasPrefix(u, "wss://")
	u = strings.TrimPrefix(u, "ws://")
	u = strings.TrimPrefix(u, "wss://")
	parts := strings.SplitN(u, "/", 2)
	host := parts[0]
	if !strings.Contains(host, ":") {
		if isWSS {
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
