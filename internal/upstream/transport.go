package upstream

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"My-OpenWaf/internal/snapshot"
)

var legacyHTTPSClientCipherSuiteIDs = buildLegacyHTTPSClientCipherSuites()

// HTTPSClientTLSConfig returns TLS settings for regular HTTPS upstreams.
func HTTPSClientTLSConfig(serverName string, skipVerify bool) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: skipVerify,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       legacyHTTPSClientCipherSuites(),
	}
}

func legacyHTTPSClientCipherSuites() []uint16 {
	if len(legacyHTTPSClientCipherSuiteIDs) == 0 {
		return nil
	}
	suites := make([]uint16, len(legacyHTTPSClientCipherSuiteIDs))
	copy(suites, legacyHTTPSClientCipherSuiteIDs)
	return suites
}

func buildLegacyHTTPSClientCipherSuites() []uint16 {
	suites := make([]uint16, 0, len(tls.CipherSuites())+len(tls.InsecureCipherSuites()))
	for _, suite := range tls.CipherSuites() {
		if cipherSuiteSupportsTLS10ToTLS12(suite.SupportedVersions) {
			suites = append(suites, suite.ID)
		}
	}
	for _, suite := range tls.InsecureCipherSuites() {
		if cipherSuiteSupportsTLS10ToTLS12(suite.SupportedVersions) {
			suites = append(suites, suite.ID)
		}
	}
	return suites
}

func cipherSuiteSupportsTLS10ToTLS12(versions []uint16) bool {
	for _, version := range versions {
		switch version {
		case tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12:
			return true
		}
	}
	return false
}

// dialTLSConfigKey 隔离不同上游的会话缓存。
//
// skipVerify 必须参与键：否则跳过校验的连接所建立的会话，可能被要求校验证书的
// 连接复用，等于绕过证书校验。
//
// 键里不含实际拨号的 host 是有意为之：crypto/tls 的 clientSessionCacheKey 在
// ServerName 非空时用 ServerName 作会话键，为空时回退到远端地址，因此同一份
// ClientSessionCache 内部已按上游身份隔离，不会跨主机误用会话。
type dialTLSConfigKey struct {
	serverName string
	skipVerify bool
}

var (
	dialTLSConfigMu    sync.RWMutex
	dialTLSConfigCache = make(map[dialTLSConfigKey]*tls.Config)
)

// sharedDialTLSConfig 返回可跨连接复用的客户端 TLS 配置。
//
// 复用的目的是让 ClientSessionCache 真正生效：每次新建 tls.Config 会同时新建一个
// 空会话缓存，导致每条连接都做完整握手（含非对称密钥交换）。配置本身在放入缓存后
// 不再修改，crypto/tls 也不会修改传入的 Config，因此并发读取是安全的。
//
// 注意：HTTPSClientTLSConfig 仍然每次返回独立实例，因为它的调用方会就地修改
// NextProtos 等字段；此处不能改用共享实例。
func sharedDialTLSConfig(serverName string, skipVerify bool) *tls.Config {
	key := dialTLSConfigKey{serverName: serverName, skipVerify: skipVerify}

	dialTLSConfigMu.RLock()
	if cfg, ok := dialTLSConfigCache[key]; ok {
		dialTLSConfigMu.RUnlock()
		return cfg
	}
	dialTLSConfigMu.RUnlock()

	cfg := HTTPSClientTLSConfig(serverName, skipVerify)
	// 容量与 proxy 侧上游 transport 的 MaxIdleConnsPerHost 保持一致。
	cfg.ClientSessionCache = tls.NewLRUClientSessionCache(32)

	dialTLSConfigMu.Lock()
	defer dialTLSConfigMu.Unlock()
	if existing, ok := dialTLSConfigCache[key]; ok {
		return existing
	}
	dialTLSConfigCache[key] = cfg
	return cfg
}

func TLSDialWithDialer(dialer *net.Dialer, host string, serverName string, skipVerify bool) (net.Conn, error) {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	return tls.DialWithDialer(dialer, "tcp", host, sharedDialTLSConfig(serverName, skipVerify))
}

// HTTPTransport returns a pooled transport suitable for reverse-proxying to the site's first upstream scheme.
func HTTPTransport(rt snapshot.SiteRuntime) *http.Transport {
	tr := &http.Transport{
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	if len(rt.UpstreamURLs) > 0 && hasSchemePrefixFold(rt.UpstreamURLs[0], "https://") {
		tr.TLSClientConfig = HTTPSClientTLSConfig(rt.Site.UpstreamTLSServerName, rt.Site.UpstreamTLSSkipVerify)
	} else if len(rt.UpstreamURLs) > 0 && hasSchemePrefixFold(rt.UpstreamURLs[0], "h2c://") {
		tr.Protocols = new(http.Protocols)
		tr.Protocols.SetUnencryptedHTTP2(true)
	}
	return tr
}

func hasSchemePrefixFold(raw string, scheme string) bool {
	if len(raw) < len(scheme) {
		return false
	}
	for i := 0; i < len(scheme); i++ {
		b := raw[i]
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if b != scheme[i] {
			return false
		}
	}
	return true
}
