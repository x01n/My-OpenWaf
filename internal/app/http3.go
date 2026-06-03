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

type HTTP3Server struct {
	server   *http3.Server
	bind     string
	tcpBind  string
	log      *slog.Logger
	stopChan chan struct{}
}

type HTTP3ServerConfig struct {
	Bind      string
	TCPBind   string
	TLSConfig *tls.Config
	Log       *slog.Logger
}

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

func (s *HTTP3Server) Shutdown(ctx context.Context) error {
	close(s.stopChan)
	return s.server.Close()
}

func extractPort(bind string) string {
	_, port, err := net.SplitHostPort(bind)
	if err != nil {
		if strings.HasPrefix(bind, ":") {
			return bind[1:]
		}
		return "443"
	}
	return port
}

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
