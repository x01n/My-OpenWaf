package dataplane

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/proxy"
	"My-OpenWaf/internal/security"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/upstream"
)

const wsInspectFrameLimit = 4096
const websocketUpstreamResponseHeaderLimit = 1 << 20

// IsWebSocketUpgrade checks the request for a WebSocket upgrade handshake.
func IsWebSocketUpgrade(c *app.RequestContext) bool {
	return strings.EqualFold(string(c.GetHeader("Upgrade")), "websocket") &&
		headerContainsToken(c.GetHeader("Connection"), []byte("upgrade"))
}

// headerContainsToken checks whether comma-separated header value contains token.
func headerContainsToken(value []byte, token []byte) bool {
	for len(value) > 0 {
		part := value
		if comma := bytes.IndexByte(value, ','); comma >= 0 {
			part = value[:comma]
			value = value[comma+1:]
		} else {
			value = nil
		}
		part = bytes.TrimSpace(part)
		if asciiEqualFoldBytes(part, string(token)) {
			return true
		}
	}
	return false
}

// asciiEqualFoldBytes compares a byte slice with a string case-insensitively for ASCII.
func asciiEqualFoldBytes(got []byte, want string) bool {
	if len(got) != len(want) {
		return false
	}
	for i, b := range got {
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if b != want[i] {
			return false
		}
	}
	return true
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
		upConn, err = tlsDialWebSocketUpstream(&dialer, host, rt)
	} else {
		upConn, err = dialer.Dial("tcp", host)
	}
	if err != nil {
		return err
	}
	defer upConn.Close()

	hdr, err := buildWebSocketHandshakeHeaders(c, pathAndQuery(target), host, strings.ToLower(strings.SplitN(target, "://", 2)[0]), rt, clientIP)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(upConn, hdr); err != nil {
		return err
	}

	upReader := bufio.NewReader(upConn)
	statusLine, respHeaders, err := readHTTPResponseHead(upReader)
	if err != nil {
		return err
	}
	respHeaders, err = sanitizeWebSocketUpgradeResponseHeaders(respHeaders)
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
	go func() {
		_, e := io.Copy(pipeUpstream, clientConn)
		_ = pipeUpstream.Close()
		_ = upConn.Close()
		copyErr <- e
	}()
	go func() {
		_, e := io.Copy(clientConn, upReader)
		_ = clientConn.Close()
		_ = pipeUpstream.Close()
		copyErr <- e
	}()
	go inspectWebSocketClientFrames(pipeClient, upConn, c, rt, eng, copyErr)

	for range 3 {
		if err := <-copyErr; err != nil && !errors.Is(err, io.EOF) && !isNetClosed(err) {
			return err
		}
	}
	return nil
}

var tlsDialWebSocketUpstream = func(dialer *net.Dialer, host string, rt snapshot.SiteRuntime) (net.Conn, error) {
	return upstream.TLSDialWithDialer(dialer, host, rt.Site.UpstreamTLSServerName, rt.Site.UpstreamTLSSkipVerify)
}

func buildWebSocketHandshakeHeaders(c *app.RequestContext, requestTarget string, upstreamHost string, upstreamProto string, rt snapshot.SiteRuntime, clientIP net.IP) (string, error) {
	method := string(c.Method())
	if method == "" {
		method = http.MethodGet
	}

	var hdr strings.Builder
	hdr.WriteString(method)
	hdr.WriteByte(' ')
	hdr.WriteString(requestTarget)
	hdr.WriteString(" HTTP/1.1\r\n")
	connectionHeaderStripper := proxy.NewRequestConnectionHeaderStripper(c)
	c.Request.Header.VisitAll(func(k, v []byte) {
		key := strings.ToLower(string(k))
		switch key {
		case "host", "connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto":
			return
		}
		if connectionHeaderStripper.ShouldStrip(k) {
			return
		}
		hdr.Write(k)
		hdr.WriteString(": ")
		hdr.Write(v)
		hdr.WriteString("\r\n")
	})

	host, err := snapshot.ResolveOutboundHost(rt, upstreamHost, string(c.Host()))
	if err != nil {
		return "", err
	}
	origHost := string(c.Host())
	hdr.WriteString("Host: ")
	hdr.WriteString(host)
	hdr.WriteString("\r\n")
	hdr.WriteString("Connection: Upgrade\r\n")
	if clientIP != nil {
		hdr.WriteString("X-Forwarded-For: ")
		if prior := security.ForwardedForHeaderValueBytes(c.Request.Header.PeekAll("X-Forwarded-For")); prior != "" {
			hdr.WriteString(prior)
			hdr.WriteString(", ")
		}
		hdr.WriteString(clientIP.String())
		hdr.WriteString("\r\n")
	}
	if rt.PreserveOriginalHost && origHost != "" {
		hdr.WriteString("X-Forwarded-Host: ")
		hdr.WriteString(origHost)
		hdr.WriteString("\r\n")
	}
	hdr.WriteString("X-Forwarded-Proto: ")
	hdr.WriteString(webSocketForwardedProto(c, upstreamProto))
	hdr.WriteString("\r\n")
	hdr.WriteString("\r\n")
	return hdr.String(), nil
}

func webSocketForwardedProto(c *app.RequestContext, upstreamProto string) string {
	if v := trimRequestHeaderValue(c.GetHeader("X-Forwarded-Proto")); v != "" {
		return strings.ToLower(v)
	}
	if webSocketOriginHasHTTPSScheme(c.Request.Header.Peek("Origin")) {
		return "https"
	}
	if upstreamProto == "wss" {
		return "https"
	}
	return "http"
}

func webSocketOriginHasHTTPSScheme(raw []byte) bool {
	const httpsScheme = "https://"
	return len(raw) >= len(httpsScheme) && asciiEqualFoldBytes(raw[:len(httpsScheme)], httpsScheme)
}

func sanitizeWebSocketUpgradeResponseHeaders(raw string) (string, error) {
	var connectionHeaders connectionHeaderTokensForWebSocket
	var lines []string
	hasWebSocketUpgrade := false
	hasConnectionUpgrade := false
	for len(raw) > 0 {
		line := raw
		if idx := strings.IndexByte(raw, '\n'); idx >= 0 {
			line = raw[:idx+1]
			raw = raw[idx+1:]
		} else {
			raw = ""
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		name, value, ok := splitHTTPHeaderLine(line)
		if !ok {
			lines = append(lines, line)
			continue
		}
		if strings.EqualFold(name, "Connection") {
			if headerContainsToken([]byte(value), []byte("upgrade")) {
				hasConnectionUpgrade = true
			}
			connectionHeaders.add(value)
			continue
		}
		if strings.EqualFold(name, "Upgrade") && headerContainsToken([]byte(value), []byte("websocket")) {
			hasWebSocketUpgrade = true
		}
		lines = append(lines, line)
	}
	if !hasWebSocketUpgrade {
		return "", errors.New("websocket upstream handshake missing Upgrade: websocket")
	}
	if !hasConnectionUpgrade {
		return "", errors.New("websocket upstream handshake missing Connection: Upgrade")
	}

	var out strings.Builder
	for _, line := range lines {
		name, _, ok := splitHTTPHeaderLine(line)
		if ok && proxy.IsHopByHop(name) && !strings.EqualFold(name, "Upgrade") {
			continue
		}
		if ok && connectionHeaders.contains(name) && !strings.EqualFold(name, "Upgrade") {
			continue
		}
		out.WriteString(line)
	}
	out.WriteString("Connection: Upgrade\r\n\r\n")
	return out.String(), nil
}

type connectionHeaderTokensForWebSocket struct {
	inline [8]string
	extra  []string
	n      int
}

func (t *connectionHeaderTokensForWebSocket) add(raw string) {
	for len(raw) > 0 {
		part := raw
		if comma := strings.IndexByte(raw, ','); comma >= 0 {
			part = raw[:comma]
			raw = raw[comma+1:]
		} else {
			raw = ""
		}
		part = strings.Trim(part, " \t\r\n")
		if part == "" || t.contains(part) {
			continue
		}
		if t.n < len(t.inline) {
			t.inline[t.n] = part
			t.n++
			continue
		}
		t.extra = append(t.extra, part)
	}
}

func (t connectionHeaderTokensForWebSocket) contains(name string) bool {
	if name == "" || t.n == 0 && len(t.extra) == 0 {
		return false
	}
	for i := 0; i < t.n; i++ {
		if strings.EqualFold(name, t.inline[i]) {
			return true
		}
	}
	for _, token := range t.extra {
		if strings.EqualFold(name, token) {
			return true
		}
	}
	return false
}

func splitHTTPHeaderLine(line string) (string, string, bool) {
	idx := strings.IndexByte(line, ':')
	if idx <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]), true
}

func inspectWebSocketClientFrames(src net.Conn, dst net.Conn, c *app.RequestContext, rt snapshot.SiteRuntime, eng *engine.Engine, done chan<- error) {
	var result error
	defer func() { done <- result }()
	for {
		frame, err := readWSFrame(src, wsInspectFrameLimit)
		if err != nil {
			if !errors.Is(err, io.EOF) && !isNetClosed(err) {
				result = err
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
			result = err
			return
		}
		remainingPayloadLen := int64(frame.PayloadLen) - int64(frame.BufferedPayloadLen)
		if remainingPayloadLen > 0 {
			if _, err := io.CopyN(dst, src, remainingPayloadLen); err != nil {
				result = err
				return
			}
		}
	}
}

func inspectWebSocketPayload(c *app.RequestContext, rt snapshot.SiteRuntime, eng *engine.Engine, payload []byte) action.Result {
	reqCtx := pipeline.AcquireCtx()
	reqCtx.Bind = rt.Bind
	reqCtx.Method = string(c.Method())
	reqCtx.Path = string(c.Path())
	reqCtx.RawQuery = string(c.URI().QueryString())
	reqCtx.Host = string(c.Host())
	reqCtx.AntiReplayTTL = rt.Site.AntiReplayTTL
	reqCtx.Body = payload
	reqCtx.ContentType = "application/octet-stream"
	defer pipeline.ReleaseCtx(reqCtx)
	if fp, ok := tlsFingerprintFromRequestContext(c); ok {
		reqCtx.TLS = fp
	}
	populateRequestCtxHeaders(reqCtx, c)
	return eng.Process(reqCtx).Action
}

type wsFrame struct {
	Raw                []byte
	Opcode             byte
	Payload            []byte
	PayloadLen         uint64
	BufferedPayloadLen uint64
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
	var ext []byte
	var ext2 [2]byte
	var ext8 [8]byte

	switch payloadLen {
	case 126:
		if _, err := io.ReadFull(r, ext2[:]); err != nil {
			return wsFrame{}, err
		}
		ext = ext2[:]
		payloadLen = uint64(binary.BigEndian.Uint16(ext2[:]))
	case 127:
		if _, err := io.ReadFull(r, ext8[:]); err != nil {
			return wsFrame{}, err
		}
		ext = ext8[:]
		payloadLen = binary.BigEndian.Uint64(ext8[:])
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return wsFrame{}, err
		}
	}

	raw := make([]byte, 0, wsFrameRawPrefixCapacity(payloadLen, payloadLimit, masked, len(ext)))
	raw = append(raw, header[:]...)
	raw = append(raw, ext...)
	if masked {
		raw = append(raw, maskKey[:]...)
	}

	raw, decoded, bufferedPayloadLen, err := readWSPayloadPrefix(r, raw, payloadLen, payloadLimit, maskKey, masked)
	if err != nil {
		return wsFrame{}, err
	}
	return wsFrame{
		Raw:                raw,
		Opcode:             opcode,
		Payload:            decoded,
		PayloadLen:         payloadLen,
		BufferedPayloadLen: bufferedPayloadLen,
	}, nil
}

func wsFrameRawPrefixCapacity(payloadLen uint64, payloadLimit int, masked bool, extLen int) int {
	capHint := 2 + extLen
	if masked {
		capHint += 4
	}
	if payloadLimit < 0 {
		payloadLimit = 0
	}
	bufferedPayloadLen := payloadLen
	if bufferedPayloadLen > uint64(payloadLimit) {
		bufferedPayloadLen = uint64(payloadLimit)
	}
	if bufferedPayloadLen > uint64(int(^uint(0)>>1)-capHint) {
		return capHint
	}
	return capHint + int(bufferedPayloadLen)
}

func readWSPayloadPrefix(r io.Reader, raw []byte, payloadLen uint64, payloadLimit int, maskKey [4]byte, masked bool) ([]byte, []byte, uint64, error) {
	if payloadLen > uint64(1<<63-1) {
		return nil, nil, 0, errors.New("websocket frame too large")
	}
	if payloadLimit < 0 {
		payloadLimit = 0
	}
	bufferedPayloadLen := payloadLen
	if bufferedPayloadLen > uint64(payloadLimit) {
		bufferedPayloadLen = uint64(payloadLimit)
	}
	if bufferedPayloadLen > uint64(int(^uint(0)>>1)) {
		return nil, nil, 0, errors.New("websocket frame too large")
	}
	payloadStart := len(raw)
	raw = append(raw, make([]byte, int(bufferedPayloadLen))...)
	payload := raw[payloadStart:]
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, nil, 0, err
	}
	decodedLen := len(payload)
	if decodedLen > payloadLimit {
		decodedLen = payloadLimit
	}
	decoded := payload[:decodedLen]
	if masked && decodedLen > 0 {
		decoded = append([]byte(nil), decoded...)
		for i := range decoded {
			decoded[i] ^= maskKey[i%4]
		}
	}
	return raw, decoded, bufferedPayloadLen, nil
}

func readHTTPResponseHead(r *bufio.Reader) (string, string, error) {
	statusLine, err := readHTTPResponseLineLimited(r, websocketUpstreamResponseHeaderLimit)
	if err != nil {
		return "", "", err
	}
	if statusCode := httpStatusCodeFromLine(statusLine); statusCode != http.StatusSwitchingProtocols {
		return "", "", fmt.Errorf("websocket upstream handshake failed with status %d", statusCode)
	}
	remaining := websocketUpstreamResponseHeaderLimit - len(statusLine)
	var headers bytes.Buffer
	for {
		line, err := readHTTPResponseLineLimited(r, remaining)
		if err != nil {
			return "", "", err
		}
		remaining -= len(line)
		headers.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	return statusLine, headers.String(), nil
}

func httpStatusCodeFromLine(line string) int {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return 0
	}
	code, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0
	}
	return code
}

func readHTTPResponseLineLimited(r *bufio.Reader, remaining int) (string, error) {
	if remaining <= 0 {
		return "", errors.New("websocket upstream response headers too large")
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > remaining {
		return "", errors.New("websocket upstream response headers too large")
	}
	return line, nil
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
