package app

import (
	snapshotpkg "My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

func needsTLSClientHelloFingerprint(rt snapshotpkg.SiteRuntime) bool {
	if rt.EffectiveProtection != nil {
		if rt.EffectiveProtection.BotDetectionEnabled {
			return true
		}
	} else if rt.BotProtection.Enabled {
		return true
	}

	for i := range rt.Rules {
		switch rt.Rules[i].Kind {
		case "tls_ja3", "tls_ja3_hash", "tls_ja4", "tls_cipher_suite", "tls_cipher_suites":
			return true
		}
	}

	for i := range rt.AppRouteRules {
		if rt.AppRouteRules[i].Target == store.AppRouteTargetFingerprint {
			return true
		}
	}

	return false
}
