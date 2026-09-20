package app

import (
	"os"

	snapshotpkg "My-OpenWaf/internal/snapshot"
)

// needsTLSClientHelloFingerprint enables ClientHello parsing for every TLS
// listener so normal access logs and visitor-fusion analysis retain real
// client fingerprints even when no fingerprint detector is configured.
//
// MY_OPENWAF_H2WS_PEEKER_OFF=1 gives the subprocess-only h2 WebSocket E2E an
// escape hatch: the raw h2 test client writes its preface right after the TLS
// handshake, and the prefix-peeking conn would consume those bytes. When the
// env is set the listener is wrapped in a plain FixURIConn instead; its h2
// zero-peek fast path keeps extended CONNECT semantics intact, and the
// unconditional onConnect setTLSHandshakeInfo compensation still populates
// tls_version/SNI/ALPN. JA3/JA4 stay empty under this exemption, which is
// expected. The env is never set in production binaries or in any existing
// test, so default behavior is byte-for-byte unchanged.
func needsTLSClientHelloFingerprint(snapshotpkg.SiteRuntime) bool {
	if os.Getenv("MY_OPENWAF_H2WS_PEEKER_OFF") == "1" {
		return false
	}
	return true
}
