package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	snapshotpkg "My-OpenWaf/internal/snapshot"

	"github.com/quic-go/quic-go/http3"
)

// HTTP3Server 封装了基于 QUIC 协议的 HTTP/3 服务器。
// 它通过反向代理将 HTTP/3 请求转发到本地 TCP Hertz 监听器，
// 从而复用完整的 WAF 数据面处理链路。
type HTTP3Server struct {
	server   *http3.Server
	bind     string
	tcpBind  string
	log      *slog.Logger
	stopChan chan struct{}
}

// HTTP3ServerConfig 创建 HTTP/3 服务器所需的配置。
type HTTP3ServerConfig struct {
	// Bind 是 UDP 监听地址（通常与 TCP 同端口，如 :443）
	Bind string
	// TCPBind 是对应的本地 TCP Hertz 监听地址（用于反向代理目标）
	TCPBind string
	// TLSConfig 是 TLS 配置（与 TCP 侧共享证书）
	TLSConfig *tls.Config
	// Log 日志实例
	Log *slog.Logger
}

// NewHTTP3Server 创建一个新的 HTTP/3 QUIC 服务器。
func NewHTTP3Server(cfg HTTP3ServerConfig) *HTTP3Server {
	targetHost := cfg.TCPBind
	if strings.HasPrefix(targetHost, ":") {
		targetHost = "127.0.0.1" + targetHost
	}
	targetURL := &url.URL{
		Scheme: "https",
		Host:   targetHost,
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	defaultDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		originalHost := r.Host
		defaultDirector(r)
		r.URL.Scheme = targetURL.Scheme
		r.URL.Host = targetURL.Host
		r.Header.Del("X-Forwarded-Proto")
		r.Header.Del("X-OpenWaf-Internal-Proto")
		if originalHost != "" {
			r.Host = originalHost
			r.Header.Set("X-Forwarded-Host", originalHost)
		}
		r.Header.Set("X-Forwarded-Proto", "h3")
		r.Header.Set("X-OpenWaf-Internal-Proto", "h3")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(cfg.Bind)))
		proxy.ServeHTTP(w, r)
	})

	tlsCfg := cfg.TLSConfig.Clone()
	tlsCfg.NextProtos = []string{"h3"}
	if tlsCfg.MinVersion == 0 || tlsCfg.MinVersion < tls.VersionTLS13 {
		tlsCfg.MinVersion = tls.VersionTLS13
	}
	if tlsCfg.MaxVersion != 0 && tlsCfg.MaxVersion < tls.VersionTLS13 {
		tlsCfg.MaxVersion = tls.VersionTLS13
	}

	h3Server := &http3.Server{
		Addr:      cfg.Bind,
		Handler:   handler,
		TLSConfig: tlsCfg,
	}

	return &HTTP3Server{
		server:   h3Server,
		bind:     cfg.Bind,
		tcpBind:  cfg.TCPBind,
		log:      cfg.Log,
		stopChan: make(chan struct{}),
	}
}

// Spin 启动 HTTP/3 QUIC 服务器（阻塞）。
func (s *HTTP3Server) Spin() {
	s.log.Info("HTTP/3 QUIC server starting",
		slog.String("udp_bind", s.bind),
		slog.String("tcp_target", s.tcpBind),
	)
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		select {
		case <-s.stopChan:
			// 正常关闭
		default:
			s.log.Error("HTTP/3 server error", slog.Any("err", err))
		}
	}
}

// Shutdown 优雅关闭 HTTP/3 服务器。
func (s *HTTP3Server) Shutdown(ctx context.Context) error {
	close(s.stopChan)
	return s.server.Close()
}

// extractPort 从绑定地址中提取端口号。
func extractPort(bind string) string {
	_, port, err := net.SplitHostPort(bind)
	if err != nil {
		// 可能只是 ":443" 格式
		if strings.HasPrefix(bind, ":") {
			return bind[1:]
		}
		return "443"
	}
	return port
}

// shouldEnableHTTP3 判断站点是否应启用 HTTP/3。
// 条件：TLS 已启用 + ALPN 包含 "h3"
func shouldEnableHTTP3(alpnStr string, defaults ...snapshotpkg.NetworkDefaults) bool {
	if len(defaults) > 0 && !defaults[0].HTTP3Enabled {
		return false
	}
	if strings.TrimSpace(alpnStr) == "" {
		if len(defaults) == 0 {
			alpnStr = snapshotpkg.DefaultTLSDefaults().DefaultALPN
		} else {
			alpnStr = defaults[0].DefaultALPN
			if strings.TrimSpace(alpnStr) == "" {
				alpnStr = snapshotpkg.DefaultTLSDefaults().DefaultALPN
			}
		}
	}
	for _, p := range strings.Split(alpnStr, ",") {
		if strings.TrimSpace(p) == "h3" {
			return true
		}
	}
	return false
}
