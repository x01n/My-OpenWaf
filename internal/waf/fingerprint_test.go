package waf

import (
	"testing"
)

func TestFingerprintScorer_MaliciousJA3(t *testing.T) {
	scorer := NewFingerprintScorer()

	// Known malicious JA3 (curl)
	info := FingerprintInfo{
		JA3Hash:        "456523fc94726331a4d5a2e1d40b2cd7",
		ClaimedBrowser: "unknown",
	}

	result := scorer.ScoreFingerprint(info)
	if result.Score < 40 {
		t.Errorf("expected score >= 40 for known malicious JA3, got %d", result.Score)
	}
	if result.MatchedDB != "curl_7_x" {
		t.Errorf("expected MatchedDB 'curl_7_x', got %q", result.MatchedDB)
	}

	found := false
	for _, r := range result.Reasons {
		if r == "known_malicious_ja3:curl_7_x" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected reason 'known_malicious_ja3:curl_7_x', got %v", result.Reasons)
	}
}

func TestFingerprintScorer_BrowserMismatch(t *testing.T) {
	scorer := NewFingerprintScorer()

	// Claims to be Firefox but has Chrome JA3
	info := FingerprintInfo{
		JA3Hash:        "cd08e31494f9531f560d64c695473da9", // chrome_120
		ClaimedBrowser: "firefox",
	}

	result := scorer.ScoreFingerprint(info)
	if result.Score < 30 {
		t.Errorf("expected score >= 30 for JA3/browser mismatch, got %d", result.Score)
	}

	found := false
	for _, r := range result.Reasons {
		if r == "ja3_browser_mismatch" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected reason 'ja3_browser_mismatch', got %v", result.Reasons)
	}
}

func TestFingerprintScorer_BrowserConsistency(t *testing.T) {
	scorer := NewFingerprintScorer()

	tests := []struct {
		name       string
		info       FingerprintInfo
		wantReason string
	}{
		{
			name: "chrome missing brotli",
			info: FingerprintInfo{
				ClaimedBrowser: "chrome",
				AcceptEnc:      "gzip, deflate",
			},
			wantReason: "browser_env_inconsistent:missing_brotli",
		},
		{
			name: "firefox missing gzip",
			info: FingerprintInfo{
				ClaimedBrowser: "firefox",
				AcceptEnc:      "deflate, br",
			},
			wantReason: "browser_env_inconsistent:missing_gzip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scorer.ScoreFingerprint(tt.info)
			found := false
			for _, r := range result.Reasons {
				if r == tt.wantReason {
					found = true
				}
			}
			if !found {
				t.Errorf("expected reason %q, got %v", tt.wantReason, result.Reasons)
			}
		})
	}
}

func TestFingerprintScorer_LegitBrowser(t *testing.T) {
	scorer := NewFingerprintScorer()

	// Legitimate Chrome with matching JA3
	info := FingerprintInfo{
		JA3Hash:        "cd08e31494f9531f560d64c695473da9", // chrome_120
		ClaimedBrowser: "chrome",
		AcceptEnc:      "gzip, deflate, br",
		AcceptLang:     "en-US,en;q=0.9",
	}

	result := scorer.ScoreFingerprint(info)
	if result.Score > 10 {
		t.Errorf("legitimate browser should have low score, got %d (reasons: %v)", result.Score, result.Reasons)
	}
}

func TestFingerprintScorer_ScoreCalculation(t *testing.T) {
	scorer := NewFingerprintScorer()

	// Multiple risk signals stacking
	info := FingerprintInfo{
		JA3Hash:        "456523fc94726331a4d5a2e1d40b2cd7", // curl - malicious
		ClaimedBrowser: "unknown",
		TLSVersion:     0x0301, // TLS 1.0 - very old
	}

	result := scorer.ScoreFingerprint(info)
	// Should have: 40 (malicious JA3) + 15 (old TLS) = 55 minimum
	if result.Score < 55 {
		t.Errorf("expected score >= 55 for malicious JA3 + old TLS, got %d", result.Score)
	}
}

func TestBrowserFamilyFromUA(t *testing.T) {
	tests := []struct {
		ua   string
		want string
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "chrome"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0", "firefox"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15", "safari"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", "edge"},
		{"curl/7.88.1", "unknown"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := BrowserFamilyFromUA(tt.ua)
			if got != tt.want {
				t.Errorf("BrowserFamilyFromUA(%q) = %q, want %q", tt.ua, got, tt.want)
			}
		})
	}
}
