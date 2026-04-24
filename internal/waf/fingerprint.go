package waf

import (
	"crypto/md5"
	"fmt"
	"strings"
)

// FingerprintInfo stores fingerprint information extracted from a request.
type FingerprintInfo struct {
	JA3Hash        string // JA3 TLS fingerprint hash
	JA4Hash        string // JA4 TLS fingerprint hash
	TLSVersion     uint16 // TLS version number
	HTTP2Settings  string // HTTP/2 SETTINGS frame fingerprint
	H2WindowSize   uint32 // HTTP/2 initial window size
	H2Priorities   string // HTTP/2 priority tree fingerprint
	ClaimedBrowser string // Browser claimed by User-Agent
	AcceptLang     string // Accept-Language header
	AcceptEnc      string // Accept-Encoding header
	HeaderOrder    string // Hash of request header order
}

// FingerprintResult holds the scoring result from fingerprint analysis.
type FingerprintResult struct {
	Score     int
	Reasons   []string
	MatchedDB string // Name of matched known fingerprint (if any)
}

// FingerprintScorer performs fingerprint-based bot scoring.
type FingerprintScorer struct {
	knownFingerprints *FingerprintDB
}

// NewFingerprintScorer creates a scorer with the default fingerprint database.
func NewFingerprintScorer() *FingerprintScorer {
	return &FingerprintScorer{
		knownFingerprints: DefaultFingerprintDB(),
	}
}

// ExtractFingerprint extracts fingerprint info from request headers and context.
// It first checks for native TLS fingerprints captured during TLS handshake,
// then falls back to X-JA3-Hash headers for external TLS terminators.
func ExtractFingerprint(headers map[string]string, headerKeys []string) FingerprintInfo {
	return ExtractFingerprintWithIP(headers, headerKeys, "")
}

// ExtractFingerprintWithIP extracts fingerprints with native TLS lookup by client IP.
func ExtractFingerprintWithIP(headers map[string]string, headerKeys []string, clientIP string) FingerprintInfo {
	info := FingerprintInfo{}

	// Try native TLS fingerprint first (captured from actual TLS handshake).
	if clientIP != "" {
		if nativeJA3 := LookupTLSFingerprint(clientIP); nativeJA3 != "" {
			info.JA3Hash = nativeJA3
			if fp := GetTLSFingerprinter(); fp != nil {
				if tlsInfo := fp.Lookup(clientIP); tlsInfo != nil {
					info.TLSVersion = tlsInfo.TLSVersion
				}
			}
		}
	}

	// Fall back to headers if no native fingerprint available.
	if info.JA3Hash == "" {
		if ja3, ok := headers["x-ja3-hash"]; ok {
			info.JA3Hash = ja3
		} else if ja3, ok := headers["X-JA3-Hash"]; ok {
			info.JA3Hash = ja3
		}
	}

	if ja4, ok := headers["x-ja4-hash"]; ok {
		info.JA4Hash = ja4
	} else if ja4, ok := headers["X-JA4-Hash"]; ok {
		info.JA4Hash = ja4
	}

	if info.TLSVersion == 0 {
		if tlsVer, ok := headers["x-tls-version"]; ok {
			info.TLSVersion = parseTLSVersion(tlsVer)
		} else if tlsVer, ok := headers["X-TLS-Version"]; ok {
			info.TLSVersion = parseTLSVersion(tlsVer)
		}
	}

	if h2s, ok := headers["x-h2-settings"]; ok {
		info.HTTP2Settings = h2s
	} else if h2s, ok := headers["X-H2-Settings"]; ok {
		info.HTTP2Settings = h2s
	}

	if ws, ok := headers["x-h2-window-size"]; ok {
		info.H2WindowSize = parseUint32(ws)
	} else if ws, ok := headers["X-H2-Window-Size"]; ok {
		info.H2WindowSize = parseUint32(ws)
	}

	ua := getHeaderCI(headers, "user-agent")
	info.ClaimedBrowser = BrowserFamilyFromUA(ua)

	info.AcceptLang = getHeaderCI(headers, "accept-language")
	info.AcceptEnc = getHeaderCI(headers, "accept-encoding")

	info.HeaderOrder = computeHeaderOrderHash(headerKeys)

	return info
}

// ScoreFingerprint evaluates a fingerprint and returns a risk score.
func (fs *FingerprintScorer) ScoreFingerprint(info FingerprintInfo) FingerprintResult {
	result := FingerprintResult{}

	// 1. Check JA3 against known databases
	if info.JA3Hash != "" {
		if name, ok := fs.knownFingerprints.MaliciousJA3[info.JA3Hash]; ok {
			result.Score += 40
			result.Reasons = append(result.Reasons, "known_malicious_ja3:"+name)
			result.MatchedDB = name
		} else if name, ok := fs.knownFingerprints.BrowserJA3[info.JA3Hash]; ok {
			// Known good fingerprint - check if it matches claimed browser
			result.MatchedDB = name
			if !ja3MatchesClaimed(name, info.ClaimedBrowser) {
				result.Score += 30
				result.Reasons = append(result.Reasons, "ja3_browser_mismatch")
			}
		} else if info.ClaimedBrowser != "unknown" {
			// Claims to be a browser but JA3 not in known browser list
			result.Score += 30
			result.Reasons = append(result.Reasons, "ja3_not_recognized_for_claimed_browser")
		}
	}

	// 2. Check JA4 similarly
	if info.JA4Hash != "" && info.JA3Hash == "" {
		// If we only have JA4 but no JA3, use JA4 for scoring
		if info.ClaimedBrowser != "unknown" {
			// JA4 present but can't verify against claimed browser
			result.Score += 15
			result.Reasons = append(result.Reasons, "ja4_unverified")
		}
	}

	// 3. TLS version check
	if info.TLSVersion > 0 && info.TLSVersion < 0x0303 { // < TLS 1.2
		result.Score += 15
		result.Reasons = append(result.Reasons, "tls_version_too_low")
	}

	// 4. HTTP/2 SETTINGS anomaly detection
	if info.ClaimedBrowser != "unknown" && info.HTTP2Settings != "" {
		if !fs.h2SettingsMatch(info.ClaimedBrowser, info.HTTP2Settings, info.H2WindowSize) {
			result.Score += 20
			result.Reasons = append(result.Reasons, "h2_settings_mismatch")
		}
	}

	// 5. Browser environment consistency check
	if info.ClaimedBrowser != "unknown" {
		if inconsistent, reason := checkBrowserConsistency(info); inconsistent {
			result.Score += 25
			result.Reasons = append(result.Reasons, "browser_env_inconsistent:"+reason)
		}
	}

	// 6. Header order anomaly check
	if info.HeaderOrder != "" && info.ClaimedBrowser != "unknown" {
		if !fs.headerOrderKnown(info.ClaimedBrowser, info.HeaderOrder) {
			result.Score += 10
			result.Reasons = append(result.Reasons, "header_order_anomaly")
		}
	}

	return result
}

// h2SettingsMatch checks if HTTP/2 settings match expected browser profile.
func (fs *FingerprintScorer) h2SettingsMatch(browser, settings string, windowSize uint32) bool {
	profile, ok := fs.knownFingerprints.BrowserH2Settings[browser]
	if !ok {
		return true // No profile to compare against
	}
	// If window size is available and significantly different from expected
	if windowSize > 0 && profile.InitialWindowSize > 0 {
		ratio := float64(windowSize) / float64(profile.InitialWindowSize)
		if ratio < 0.5 || ratio > 2.0 {
			return false
		}
	}
	// If settings string is provided, compare against expected pattern
	if settings != "" {
		expectedPattern := fmt.Sprintf("%d:%d:%d",
			profile.HeaderTableSize, profile.InitialWindowSize, profile.MaxHeaderListSize)
		if !strings.Contains(settings, expectedPattern) && settings != expectedPattern {
			return false
		}
	}
	return true
}

// headerOrderKnown checks if the header order hash is in known patterns.
func (fs *FingerprintScorer) headerOrderKnown(browser, orderHash string) bool {
	patterns, ok := fs.knownFingerprints.HeaderOrderPatterns[browser]
	if !ok {
		return true // No patterns to compare
	}
	for _, p := range patterns {
		if p == orderHash {
			return true
		}
	}
	return false
}

// checkBrowserConsistency verifies that browser environment claims are consistent.
func checkBrowserConsistency(info FingerprintInfo) (inconsistent bool, reason string) {
	switch info.ClaimedBrowser {
	case "chrome", "edge":
		// Chrome/Edge typically sends Accept-Language in format: en-US,en;q=0.9
		if info.AcceptLang != "" && !strings.Contains(info.AcceptLang, ";q=") && strings.Contains(info.AcceptLang, ",") {
			return true, "accept_lang_format"
		}
		// Chrome/Edge always supports gzip, deflate, br
		if info.AcceptEnc != "" && !strings.Contains(info.AcceptEnc, "br") {
			return true, "missing_brotli"
		}
	case "firefox":
		// Firefox also supports br in modern versions
		if info.AcceptEnc != "" && !strings.Contains(info.AcceptEnc, "gzip") {
			return true, "missing_gzip"
		}
	case "safari":
		// Safari supports gzip, deflate, br
		if info.AcceptEnc != "" && !strings.Contains(info.AcceptEnc, "gzip") {
			return true, "missing_gzip"
		}
	}
	return false, ""
}

// ja3MatchesClaimed checks if a JA3 database entry matches the claimed browser.
func ja3MatchesClaimed(ja3Name, claimedBrowser string) bool {
	if claimedBrowser == "unknown" {
		return true
	}
	ja3Lower := toLower(ja3Name)
	switch claimedBrowser {
	case "chrome":
		return strings.HasPrefix(ja3Lower, "chrome_")
	case "firefox":
		return strings.HasPrefix(ja3Lower, "firefox_")
	case "safari":
		return strings.HasPrefix(ja3Lower, "safari_")
	case "edge":
		// Edge is Chromium-based, so both edge_ and chrome_ are acceptable
		return strings.HasPrefix(ja3Lower, "edge_") || strings.HasPrefix(ja3Lower, "chrome_")
	}
	return false
}

// computeHeaderOrderHash computes an MD5 hash of the header key order.
func computeHeaderOrderHash(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	// Normalize: lowercase all keys, join with comma
	normalized := make([]string, len(keys))
	for i, k := range keys {
		normalized[i] = toLower(k)
	}
	joined := strings.Join(normalized, ",")
	hash := md5.Sum([]byte(joined))
	return fmt.Sprintf("%x", hash)
}

// parseTLSVersion parses TLS version from string representation.
func parseTLSVersion(s string) uint16 {
	switch s {
	case "1.0", "0x0301":
		return 0x0301
	case "1.1", "0x0302":
		return 0x0302
	case "1.2", "0x0303":
		return 0x0303
	case "1.3", "0x0304":
		return 0x0304
	}
	return 0
}

// parseUint32 parses a uint32 from string.
func parseUint32(s string) uint32 {
	var n uint32
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + uint32(c-'0')
		} else {
			break
		}
	}
	return n
}

// getHeaderCI retrieves a header value case-insensitively.
func getHeaderCI(headers map[string]string, key string) string {
	if v, ok := headers[key]; ok {
		return v
	}
	keyLower := toLower(key)
	for k, v := range headers {
		if toLower(k) == keyLower {
			return v
		}
	}
	return ""
}
