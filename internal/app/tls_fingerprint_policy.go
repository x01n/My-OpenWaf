package app

import snapshotpkg "My-OpenWaf/internal/snapshot"

// needsTLSClientHelloFingerprint enables ClientHello parsing for every TLS
// listener so normal access logs and visitor-fusion analysis retain real
// client fingerprints even when no fingerprint detector is configured.
func needsTLSClientHelloFingerprint(snapshotpkg.SiteRuntime) bool {
	return true
}
