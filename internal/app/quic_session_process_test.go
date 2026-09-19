package app

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	adminsystem "My-OpenWaf/internal/admin/system"
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

// TestQuicTransportLayerExploration 通过手写探测程序观察进程级 h3 服务端
// 对「会话复用 + 0-RTT」的真实行为。
//
// 证据来源：
//   - http3.go:763-765  服务端 Allow0RTT 透传自 TLSDefaults.SessionTicketsEnabled
//   - server.go:1024    初始快照 Allow0RTT 同源
//   - http3.go:1668     SessionTicketsDisabled 为 SessionTicketsEnabled 取反
//
// 探测程序位于 temp/_tls-exp/main.go（temp/ 被 gitignore，仅作取证工具）。
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

	cmd := exec.CommandContext(t.Context(), "go", "run", ".", tcpBind, udpBind)
	cmd.Dir = filepath.Join("..", "..", "temp", "_tls-exp")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tls-exp helper failed: %v\n%s\napp output:\n%s", err, out, appProc.output.String())
	}
	raw := string(out)
	t.Logf("tls-exp output:\n%s", raw)

	// 首次连接：必须完整握手，且不得误报 0-RTT。
	if !regexp.MustCompile(`first h3 connection handshake done, resumed=false used0rtt=false`).MatchString(raw) {
		t.Fatalf("first h3 connection did not do a full handshake as expected; output:\n%s", raw)
	}

	// 第二次连接：会话必须恢复（resumed=true）。
	if !regexp.MustCompile(`second h3 connection: resumed=true used0rtt=(true|false) tlsver=0x304 negotiated=h3`).MatchString(raw) {
		t.Fatalf("second h3 connection did not resume the session (session tickets enabled); output:\n%s", raw)
	}

	// 0-RTT 接受状态：探测程序如实打出 ACCEPTED/rejected 结论行，此处按真实证据断言。
	zeroRTTAccepted := regexp.MustCompile(`h3 0-RTT: ACCEPTED`).MatchString(raw)
	if !zeroRTTAccepted && !regexp.MustCompile(`h3 0-RTT: rejected`).MatchString(raw) {
		t.Fatalf("tls-exp did not report a 0-RTT verdict; output:\n%s", raw)
	}
	if !zeroRTTAccepted {
		t.Fatalf("h3 0-RTT not accepted by server even though http3.go wires Allow0RTT from SessionTicketsEnabled; output:\n%s", raw)
	}

	// h1.1 keep-alive：复用连接不得重新握手；关闭空闲连接后新连接必须恢复会话。
	if !regexp.MustCompile(`h1.1 keep-alive: WORKS`).MatchString(raw) {
		t.Fatalf("h1.1 keep-alive did not reuse the transport connection as expected; output:\n%s", raw)
	}
	if !regexp.MustCompile(`h1.1 new-connection resumption: WORKS`).MatchString(raw) {
		t.Fatalf("h1.1 session resumption on a new connection did not work as expected; output:\n%s", raw)
	}
}
