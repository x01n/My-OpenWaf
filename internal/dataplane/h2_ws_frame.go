package dataplane

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/hertz-contrib/http2/hpack"
)

// h2c 帧类型（RFC 9113）。
const (
	h2FrameData         = 0x0
	h2FrameHeaders      = 0x1
	h2FrameRSTStream    = 0x3
	h2FrameSettings     = 0x4
	h2FramePing         = 0x6
	h2FrameGoAway       = 0x7
	h2FrameWindowUpdate = 0x8
	h2FrameContinuation = 0x9

	h2FlagAck        = 0x1
	h2FlagEndStream  = 0x1
	h2FlagEndHeaders = 0x4
)

const (
	// h2cUpstreamInitialWindow 是发送侧窗口初始值（RFC 9113 默认 64KB）。
	// h2cUpstreamRecvWindow / h2cUpstreamRecvRefill 控制接收侧窗口返还节奏。
	h2cUpstreamInitialWindow = 1 << 16
	h2cUpstreamRecvWindow    = 1 << 30
	h2cUpstreamRecvRefill    = 1 << 20
)

// h2cExtConnectStream 是到 h2c 上游一条扩展 CONNECT 流的全双工通道。
//
// readLoop 单协程解析上游帧并维护状态；Write 用 mutex 序列化并受上游
// 窗口约束。首响应头到达前 Write 阻塞（此时 DATA 不能被对端受理）。
type h2cExtConnectStream struct {
	conn net.Conn
	br   *bufio.Reader

	target   string      // CONNECT 请求绝对 URL（http://authority/path）
	protocol string      // ":protocol" 值
	headers  [][2]string // 透传常规头（已净化）
	host     string      // ":authority"

	mu            sync.Mutex
	maxFrameSize  uint32 // 对端 MAX_FRAME_SIZE（发送约束）
	initWinConn   int64  // 对端连接窗口剩余
	initWinStream int64  // 对端流窗口剩余
	respStatus    int    // 首响应 :status；收到前为 -1

	handshakeOnce sync.Once
	handshakeDone chan struct{}

	closeOnce sync.Once
	closed    chan struct{}

	writeOnce sync.Once
	writeDone chan struct{}

	dataCh  chan []byte
	readErr error

	// 接收侧窗口簿记。
	recvMu   sync.Mutex
	recvConn int64
	recvStrm int64

	// 响应头解码状态（CONTINUATION 拼接）。
	hdrMu       sync.Mutex
	hdrFragment bytes.Buffer
	hdrStarted  bool
}

// dialH2CExtendedConnect 拨号到 h2c 上游（prior knowledge）并发出扩展
// CONNECT 请求头。握手结果经 HandshakeDone/ResponseStatus 暴露；写入
// 在响应头到达前阻塞。
func dialH2CExtendedConnect(ctx context.Context, dialAddr string, target string, protocol string, passHeaders [][2]string) (*h2cExtConnectStream, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		return nil, err
	}

	s := &h2cExtConnectStream{
		conn:          conn,
		br:            bufio.NewReaderSize(conn, 8<<10),
		target:        target,
		protocol:      protocol,
		headers:       passHeaders,
		host:          hostFromURL(target),
		initWinConn:   h2cUpstreamInitialWindow,
		initWinStream: h2cUpstreamInitialWindow,
		respStatus:    -1,
		handshakeDone: make(chan struct{}),
		closed:        make(chan struct{}),
		writeDone:     make(chan struct{}),
		dataCh:        make(chan []byte, 8),
		recvConn:      h2cUpstreamRecvWindow,
		recvStrm:      h2cUpstreamRecvWindow,
	}
	if err := s.sendPrefaceAndHeaders(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	go s.readLoop(ctx)
	return s, nil
}

// HandshakeDone 在首个响应 HEADERS 到达（或流失败）时关闭。
func (s *h2cExtConnectStream) HandshakeDone() <-chan struct{} { return s.handshakeDone }

// ResponseStatus 返回首响应状态码；未收到响应头时为 -1。
func (s *h2cExtConnectStream) ResponseStatus() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.respStatus
}

// Read 从上游 DATA 净荷读取；上游 END_STREAM 后返回 io.EOF。
func (s *h2cExtConnectStream) Read(p []byte) (int, error) {
	for {
		select {
		case <-s.closed:
			return 0, s.currentErr()
		case data, ok := <-s.dataCh:
			if !ok {
				return 0, io.EOF
			}
			n := copy(p, data)
			if n < len(data) {
				select {
				case s.dataCh <- data[n:]:
				case <-s.closed:
				}
			}
			if n == 0 {
				continue
			}
			return n, nil
		}
	}
}

// Write 发送 DATA 帧净荷；在首响应头与 SETTINGS 到达前阻塞，随后受
// 上游窗口约束。引用语义与 net.Conn 相同。
func (s *h2cExtConnectStream) Write(p []byte) (int, error) {
	select {
	case <-s.closed:
		return 0, s.currentErr()
	case <-s.handshakeDone:
	}
	written := 0
	for len(p) > 0 {
		s.mu.Lock()
		limit := s.initWinStream
		if s.initWinConn < limit {
			limit = s.initWinConn
		}
		if mf := int64(s.maxFrameSize); mf > 0 && mf < limit {
			limit = mf
		}
		if limit <= 0 {
			s.mu.Unlock()
			select {
			case <-s.closed:
				return written, s.currentErr()
			case <-s.writeDone:
				return written, nil
			case <-time.After(25 * time.Millisecond):
			}
			continue
		}
		n := int(limit)
		if n > len(p) {
			n = len(p)
		}
		frame := make([]byte, 9+n)
		frame[0] = byte(n >> 16)
		frame[1] = byte(n >> 8)
		frame[2] = byte(n)
		frame[3] = h2FrameData
		binary.BigEndian.PutUint32(frame[5:9], 1) // 客户端流的 ID 为 1
		copy(frame[9:], p[:n])
		s.initWinConn -= int64(n)
		s.initWinStream -= int64(n)
		s.mu.Unlock()

		if _, err := s.conn.Write(frame); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// CloseWrite 发送 END_STREAM 空 DATA 半关写方向（幂等）。
func (s *h2cExtConnectStream) CloseWrite() error {
	s.writeOnce.Do(func() {
		close(s.writeDone)
		frame := make([]byte, 9)
		frame[3] = h2FrameData
		frame[4] = h2FlagEndStream
		binary.BigEndian.PutUint32(frame[5:9], 1)
		_, _ = s.conn.Write(frame)
	})
	return nil
}

// Close 关闭整条连接（幂等），唤醒所有等待方。
func (s *h2cExtConnectStream) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		_ = s.conn.Close()
	})
	return nil
}

func (s *h2cExtConnectStream) currentErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return s.readErr
	}
	return io.EOF
}

func (s *h2cExtConnectStream) signalHandshake() {
	s.handshakeOnce.Do(func() { close(s.handshakeDone) })
}

// sendPrefaceAndHeaders 写连接前缀、空 SETTINGS 与扩展 CONNECT HEADERS。
func (s *h2cExtConnectStream) sendPrefaceAndHeaders() error {
	var buf bytes.Buffer
	buf.WriteString("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	writeH2RawFrame(&buf, h2FrameSettings, 0, 0, nil)

	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	fields := [][2]string{
		{":method", "CONNECT"},
		{":protocol", s.protocol},
		{":scheme", "http"},
		{":authority", s.host},
		{":path", pathAndQuery(s.target)},
	}
	fields = append(fields, s.headers...)
	for _, f := range fields {
		_ = enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	// 扩展 CONNECT 请求流必须保持打开（RFC 8441 §4）：HEADERS 帧不设置
	// END_STREAM，DATA 双工在握手期间持续可用。
	writeH2RawFrame(&buf, h2FrameHeaders, h2FlagEndHeaders, 1, hb.Bytes())

	_, err := s.conn.Write(buf.Bytes())
	return err
}

// readLoop 串行解析上游帧直至错误或流终态。
func (s *h2cExtConnectStream) readLoop(ctx context.Context) {
	done := ctx.Done()
	defer s.signalHandshake()
	header := make([]byte, 9)
	for {
		if done != nil {
			select {
			case <-done:
				s.fail(fmt.Errorf("upstream context closed: %w", ctx.Err()))
				return
			default:
			}
		}
		if _, err := io.ReadFull(s.br, header); err != nil {
			s.fail(errors.Join(io.EOF, fmt.Errorf("read upstream frame: %w", err)))
			return
		}
		length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
		ftype := header[3]
		flags := header[4]
		streamID := binary.BigEndian.Uint32(header[5:9]) & 0x7fffffff

		if err := s.handleFrame(ftype, flags, streamID, length); err != nil {
			s.fail(err)
			return
		}
		if ftype == h2FrameData && flags&h2FlagEndStream != 0 && streamID == 1 {
			// 上游半关：读侧终结，写侧保持可用直至桥关闭。
			s.setReadErr(io.EOF)
			close(s.dataCh)
			return
		}
	}
}

// handleFrame 读净荷并分派；返回致命错误。帧头已消费。
func (s *h2cExtConnectStream) handleFrame(ftype uint8, flags uint8, streamID uint32, length int) error {
	switch ftype {
	case h2FrameSettings:
		payload, err := readH2Payload(s.br, length, 4096)
		if err != nil {
			return err
		}
		if flags&h2FlagAck != 0 {
			return nil
		}
		s.applySettings(payload)
		writeH2RawFrame(s.conn, h2FrameSettings, h2FlagAck, 0, nil)
		return nil
	case h2FrameHeaders, h2FrameContinuation:
		payload, err := readH2Payload(s.br, length, h2WSBridgeMaxUpgradeResponseHeaderSize)
		if err != nil {
			return err
		}
		if ftype == h2FrameContinuation && !s.hdrStarted {
			return errors.New("unexpected CONTINUATION frame")
		}
		s.hdrStarted = true
		s.hdrFragment.Write(payload)
		if flags&h2FlagEndHeaders == 0 {
			return nil
		}
		defer func() {
			s.hdrFragment.Reset()
			s.hdrStarted = false
		}()
		s.parseResponseHeaders(s.hdrFragment.Bytes())
		if flags&h2FlagEndStream != 0 {
			// 上游在响应头就关闭了流：握手即终态。
			return errors.New("upstream closed extended CONNECT at response headers")
		}
		s.signalHandshake()
		return nil
	case h2FrameData:
		payload, err := readH2Payload(s.br, length, h2cUpstreamRecvRefill)
		if err != nil {
			return err
		}
		if streamID == 1 && len(payload) > 0 {
			select {
			case s.dataCh <- payload:
			case <-s.closed:
				return io.EOF
			}
		}
		s.recvMu.Lock()
		s.recvStrm -= int64(length)
		s.recvConn -= int64(length)
		stLow := s.recvStrm < h2cUpstreamRecvRefill
		cnLow := s.recvConn < h2cUpstreamRecvRefill
		s.recvMu.Unlock()
		if stLow || cnLow {
			if err := s.refundRecvWindow(streamID); err != nil {
				return err
			}
		}
		return nil
	case h2FrameWindowUpdate:
		if length != 4 {
			return errors.New("malformed WINDOW_UPDATE frame")
		}
		var inc [4]byte
		if _, err := io.ReadFull(s.br, inc[:]); err != nil {
			return err
		}
		v := int64(binary.BigEndian.Uint32(inc[:]) & 0x7fffffff)
		s.mu.Lock()
		if streamID == 0 {
			s.initWinConn += v
		} else if streamID == 1 {
			s.initWinStream += v
		}
		s.mu.Unlock()
		return nil
	case h2FramePing:
		payload, err := readH2Payload(s.br, length, 8)
		if err != nil {
			return err
		}
		if flags&h2FlagAck != 0 {
			return nil
		}
		ack := prependH2FrameHeader(h2FramePing, h2FlagAck, 0, payload)
		_, err = s.conn.Write(ack)
		return err
	case h2FrameGoAway:
		if err := discardRead(s.br, length); err != nil {
			return err
		}
		return errors.New("upstream sent GOAWAY")
	case h2FrameRSTStream:
		if err := discardRead(s.br, length); err != nil {
			return err
		}
		return errors.New("upstream reset stream")
	default:
		return discardRead(s.br, length)
	}
}

// parseResponseHeaders 解码首响应头块；:status 记入 respStatus。
func (s *h2cExtConnectStream) parseResponseHeaders(block []byte) {
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if f.Name == ":status" {
			code, err := strconv.Atoi(f.Value)
			if err == nil {
				s.mu.Lock()
				s.respStatus = code
				s.mu.Unlock()
			}
		}
	})
	if _, err := dec.Write(block); err != nil {
		s.setReadErr(fmt.Errorf("decode upstream response headers: %w", err))
	}
}

// applySettings 应用上游 SETTINGS 中的窗口类参数。
func (s *h2cExtConnectStream) applySettings(payload []byte) {
	if len(payload)%6 != 0 {
		s.setReadErr(errors.New("malformed SETTINGS frame from upstream"))
		return
	}
	for i := 0; i+6 <= len(payload); i += 6 {
		id := binary.BigEndian.Uint16(payload[i : i+2])
		val := binary.BigEndian.Uint32(payload[i+2 : i+6])
		s.mu.Lock()
		switch id {
		case 0x4: // SETTINGS_INITIAL_WINDOW_SIZE
			s.initWinStream = int64(val)
		case 0x5: // SETTINGS_MAX_FRAME_SIZE
			if val >= 16384 {
				s.maxFrameSize = val
			}
		}
		s.mu.Unlock()
	}
}

// refundRecvWindow 向对端返还连接级与流级 WINDOW_UPDATE 额度。
func (s *h2cExtConnectStream) refundRecvWindow(streamID uint32) error {
	s.recvMu.Lock()
	inc := int64(h2cUpstreamRecvRefill)
	if deficit := h2cUpstreamRecvWindow - s.recvConn; deficit < inc {
		inc = deficit
	}
	if deficit := h2cUpstreamRecvWindow - s.recvStrm; deficit < inc {
		inc = deficit
	}
	if inc <= 0 {
		s.recvMu.Unlock()
		return nil
	}
	s.recvConn += inc
	s.recvStrm += inc
	s.recvMu.Unlock()

	var incBytes [4]byte
	binary.BigEndian.PutUint32(incBytes[:], uint32(inc))
	connFrame := prependH2FrameHeader(h2FrameWindowUpdate, 0, 0, incBytes[:])
	strmFrame := prependH2FrameHeader(h2FrameWindowUpdate, 0, streamID, incBytes[:])
	var buf bytes.Buffer
	buf.Write(connFrame)
	buf.Write(strmFrame)
	_, err := s.conn.Write(buf.Bytes())
	return err
}

func (s *h2cExtConnectStream) setReadErr(err error) {
	s.mu.Lock()
	if s.readErr == nil {
		s.readErr = err
	}
	s.mu.Unlock()
}

func (s *h2cExtConnectStream) fail(err error) {
	if err == nil {
		err = io.EOF
	}
	s.setReadErr(err)
	s.signalHandshake()
	s.Close()
}

// readH2Payload 读 length 字节净荷，超过 cap 视为畸形帧。
func readH2Payload(r *bufio.Reader, length int, capLimit int) ([]byte, error) {
	if length > capLimit {
		return nil, fmt.Errorf("h2 frame payload too large: %d", length)
	}
	p := make([]byte, length)
	if length == 0 {
		return p, nil
	}
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	return p, nil
}

func discardRead(r *bufio.Reader, length int) error {
	if length == 0 {
		return nil
	}
	_, err := r.Discard(length)
	return err
}

// prependH2FrameHeader 组出「帧头 + 净荷」的完整帧字节。
func prependH2FrameHeader(ftype uint8, flags uint8, streamID uint32, payload []byte) []byte {
	frame := make([]byte, 9+len(payload))
	n := len(payload)
	frame[0] = byte(n >> 16)
	frame[1] = byte(n >> 8)
	frame[2] = byte(n)
	frame[3] = ftype
	frame[4] = flags
	binary.BigEndian.PutUint32(frame[5:9], streamID)
	copy(frame[9:], payload)
	return frame
}

func writeH2RawFrame(w io.Writer, ftype uint8, flags uint8, streamID uint32, payload []byte) {
	frame := prependH2FrameHeader(ftype, flags, streamID, payload)
	_, _ = w.Write(frame)
}
