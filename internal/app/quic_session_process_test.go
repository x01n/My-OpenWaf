package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	adminsystem "My-OpenWaf/internal/admin/system"
	"My-OpenWaf/internal/store"

	quicgo "github.com/quic-go/quic-go"
	"gorm.io/gorm"
)

// TestQuicTransportLayerExploration 通过进程内探测观察进程级 h3 服务端
// 对「会话复用 + 0-RTT」的真实行为。
//
// 探测逻辑原位于 temp/_tls-exp/main.go（temp/ 被 gitignore，CI 拉不到该目录），
// 现作为 _test.go 内的辅助函数内联，与包内其它进程测试共用 harness。
//
// 证据来源：
//   - http3.go:763-765  服务端 Allow0RTT 透传自 TLSDefaults.SessionTicketsEnabled
//   - server.go:1024    初始快照 Allow0RTT 同源
//   - http3.go:1668     SessionTicketsDisabled 为 SessionTicketsEnabled 取反
//
// 断言全部基于 quic.ConnectionState（客户端真实握手状态）：
//   - 首次连接必须完整握手（resumed=false, used0rtt=false）
//   - 第二次 DialEarly 连接必须恢复会话（resumed=true）
//   - h1.1 keep-alive 复用连接不得重新握手，关闭空闲连接后新连接恢复会话
func TestQuicTransportLayerExploration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping quic transport layer exploration in -short mode")
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "quic transport layer exploration upstream:"+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	tcpBind := reserveAppProcessBind(t)
	udpBind := reserveAppProcessUDPBind(t)

	const siteHost = "tls-transport-quic.exp.test"

	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		networkCfgBytes, err := json.Marshal(adminsystem.NetworkConfig{
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		})
		if err != nil {
			return fmt.Errorf("marshal network_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(networkCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}

		tlsCfgBytes, err := json.Marshal(adminsystem.TLSDefaultConfig{
			MinVersion:            "TLS13",
			MaxVersion:            "TLS13",
			DefaultALPN:           "h2,h3,http/1.1",
			CurvePreferences:      "X25519,CurveP256,CurveP384",
			SessionTicketsEnabled: true,
			SelfSignedOnIP:        true,
		})
		if err != nil {
			return fmt.Errorf("marshal tls_default_config: %w", err)
		}
		if err := db.Create(&store.SystemSettings{
			Key:   "tls_default_config",
			Value: string(tlsCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create tls_default_config: %w", err)
		}

		site := store.Site{
			Host:         siteHost,
			UpstreamURLs: upstream.URL,
			Bind:         tcpBind,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}
		return nil
	})
	defer appProc.stop(t)

	// 等 h3 数据面真实可用。
	appProc.waitHTTP3Response(t, udpBind, siteHost, "/exp-warm", func(resp *http.Response, body string) bool {
		return resp.StatusCode == http.StatusOK && strings.Contains(body, "quic transport layer exploration")
	})

	runQuicTransportProbe(t, tcpBind, udpBind, siteHost)
}

// dialAppProcessQUICEarly 用 quic.DialAddrEarly 建立带 0-RTT 尝试的 QUIC 连接并等待握手完成。
func dialAppProcessQUICEarly(t *testing.T, addr, serverName string, cache tls.ClientSessionCache) (*quicgo.Conn, quicgo.ConnectionState) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	tlsCfg := &tls.Config{
		InsecureSkipVerify:     true,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		ServerName:             serverName,
		NextProtos:             []string{"h3"},
		ClientSessionCache:     cache,
		SessionTicketsDisabled: false,
	}
	conn, err := quicgo.DialAddrEarly(ctx, addr, tlsCfg, &quicgo.Config{})
	if err != nil {
		t.Fatalf("h3 DialAddrEarly to %s failed: %v", addr, err)
	}
	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		conn.CloseWithError(1, "handshake timeout")
		t.Fatalf("h3 handshake to %s timed out", addr)
	}
	return conn, conn.ConnectionState()
}

// runQuicTransportProbe 内联原 temp/_tls-exp 的探测与断言：
// h3 首次完整握手、复用会话、0-RTT 接受状态，以及 h1.1 keep-alive 与会话恢复。
func runQuicTransportProbe(t *testing.T, tcpBind, udpBind, serverName string) {
	// 阶段 A/B：h3 首次完整握手，随后用同一会话缓存 DialEarly 建立第二条连接。
	cache := tls.NewLRUClientSessionCache(8)
	firstConn, firstState := dialAppProcessQUICEarly(t, udpBind, serverName, cache)
	t.Logf("first h3 connection handshake done, resumed=%v used0rtt=%v",
		firstState.TLS.DidResume, firstState.Used0RTT)

	// 首次连接：必须完整握手，且不得误报 0-RTT。
	if firstState.TLS.DidResume {
		t.Fatalf("first h3 connection resumed without a session cache; state=%+v", firstState)
	}
	if firstState.Used0RTT {
		t.Fatalf("first h3 connection claims 0-RTT without a session cache; state=%+v", firstState)
	}

	time.Sleep(700 * time.Millisecond) // 等 NewSessionTicket 送达并入库
	firstConn.CloseWithError(0, "exp close first conn")

	// 第二次连接：会话必须恢复（resumed=true），且 ALPN 必须仍协商为 h3。
	secondConn, secondState := dialAppProcessQUICEarly(t, udpBind, serverName, cache)
	defer secondConn.CloseWithError(0, "exp close second conn")
	t.Logf("second h3 connection: resumed=%v used0rtt=%v tlsver=%#x negotiated=%v",
		secondState.TLS.DidResume, secondState.Used0RTT, secondState.TLS.Version, secondState.TLS.NegotiatedProtocol)
	if !secondState.TLS.DidResume {
		t.Fatalf("second h3 connection did not resume the session (session tickets enabled); state=%+v", secondState)
	}
	if secondState.TLS.Version != tls.VersionTLS13 || secondState.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("second h3 connection negotiated unexpected protocol: tlsver=%#x alpn=%q", secondState.TLS.Version, secondState.TLS.NegotiatedProtocol)
	}
	if !secondState.Used0RTT {
		t.Fatalf("h3 0-RTT not accepted by server even though http3.go wires Allow0RTT from SessionTicketsEnabled; state=%+v", secondState)
	}

	// 阶段 C：同一 https 连接上的 h1.1 keep-alive 行为，以及关闭空闲连接后的会话恢复。
	cacheD := tls.NewLRUClientSessionCache(8)
	transportD := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, tcpBind)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			NextProtos:         []string{"http/1.1"},
			ClientSessionCache: cacheD,
		},
		ForceAttemptHTTP2: false,
	}
	defer transportD.CloseIdleConnections()
	clientD := &http.Client{Timeout: 5 * time.Second, Transport: transportD}
	reqOnce := func(path string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+serverName+path, nil)
		if err != nil {
			t.Fatalf("build h1.1 request %s: %v", path, err)
		}
		resp, err := clientD.Do(req)
		if err != nil {
			t.Fatalf("h1.1 request %s failed: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Logf("h1.1 %s: status=%d did_resume=%v body=%q",
			path, resp.StatusCode, resp.TLS != nil && resp.TLS.DidResume, string(body))
		return resp
	}

	r1 := reqOnce("/exp-h11-first")
	r2 := reqOnce("/exp-h11-second")
	if r1.StatusCode != http.StatusOK || (r1.TLS != nil && r1.TLS.DidResume) {
		t.Fatalf("h1.1 first request was not a clean full handshake: status=%d did_resume=%v", r1.StatusCode, r1.TLS != nil && r1.TLS.DidResume)
	}
	if r2.StatusCode != http.StatusOK || (r2.TLS != nil && r2.TLS.DidResume) {
		t.Fatalf("h1.1 keep-alive did not reuse the transport connection as expected: status=%d did_resume=%v", r2.StatusCode, r2.TLS != nil && r2.TLS.DidResume)
	}
	transportD.CloseIdleConnections()

	// 关闭空闲连接后新连接必须恢复会话。
	r3 := reqOnce("/exp-h11-third")
	if r3.StatusCode != http.StatusOK || r3.TLS == nil || !r3.TLS.DidResume {
		t.Fatalf("h1.1 session resumption on a new connection did not work as expected: status=%d did_resume=%v", r3.StatusCode, r3.TLS != nil && r3.TLS.DidResume)
	}

	t.Logf("tcp=%s quic=%s (h1.1 keep-alive probe completed)", tcpBind, udpBind)
}
