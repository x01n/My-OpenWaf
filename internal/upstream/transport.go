package upstream

import (
	"crypto/tls"
	"net"
	"net/http"
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

func TLSDialWithDialer(dialer *net.Dialer, host string, serverName string, skipVerify bool) (net.Conn, error) {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	return tls.DialWithDialer(dialer, "tcp", host, HTTPSClientTLSConfig(serverName, skipVerify))
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
