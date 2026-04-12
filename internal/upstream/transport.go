package upstream

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"My-OpenWaf/internal/snapshot"
)

// HTTPTransport returns a pooled transport suitable for reverse-proxying to the site's first upstream scheme.
func HTTPTransport(rt snapshot.SiteRuntime) *http.Transport {
	tr := &http.Transport{
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	if len(rt.UpstreamURLs) > 0 && strings.HasPrefix(rt.UpstreamURLs[0], "https://") {
		tr.TLSClientConfig = &tls.Config{
			ServerName:         rt.Site.UpstreamTLSServerName,
			InsecureSkipVerify: rt.Site.UpstreamTLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}
	}
	return tr
}
