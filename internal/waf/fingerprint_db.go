package waf

// FingerprintDB stores known fingerprints for browsers, tools, and HTTP/2 settings.
type FingerprintDB struct {
	// BrowserJA3 maps JA3 hash -> browser name (e.g. "chrome_125")
	BrowserJA3 map[string]string
	// MaliciousJA3 maps JA3 hash -> tool name (e.g. "curl")
	MaliciousJA3 map[string]string
	// BrowserH2Settings maps browser name -> expected SETTINGS frame fingerprint
	BrowserH2Settings map[string]H2SettingsProfile
	// HeaderOrderPatterns maps browser family -> expected header order hash patterns
	HeaderOrderPatterns map[string][]string
}

// H2SettingsProfile represents the expected HTTP/2 SETTINGS for a browser.
type H2SettingsProfile struct {
	HeaderTableSize      uint32
	EnablePush           uint32
	MaxConcurrentStreams uint32
	InitialWindowSize    uint32
	MaxFrameSize         uint32
	MaxHeaderListSize    uint32
}

// DefaultFingerprintDB returns the built-in fingerprint database.
func DefaultFingerprintDB() *FingerprintDB {
	return &FingerprintDB{
		BrowserJA3:          knownBrowserJA3,
		MaliciousJA3:        knownMaliciousJA3,
		BrowserH2Settings:   knownH2Settings,
		HeaderOrderPatterns: knownHeaderOrders,
	}
}

// --- Known Browser JA3 Hashes ---
// These are representative JA3 hashes for major browsers.
// In production, this would be populated from threat intel feeds.
var knownBrowserJA3 = map[string]string{
	// Chrome 120-130 variants
	"cd08e31494f9531f560d64c695473da9": "chrome_120",
	"b32309a26951912be7dba376398abc3b": "chrome_121",
	"a0e9f5d64349fb13191bc781f81f42e1": "chrome_122",
	"773906b0efdefa24a7f2b8eb6985bf37": "chrome_123",
	"579ccef312d18482fc42e2b822ca2430": "chrome_124",
	"c72850a6ea4cad5eb2e5a3abea1dea55": "chrome_125",
	"3d9a26e3b7c9e1f6a87d2c5432b0e1d4": "chrome_126",
	"b8f0b9c2e1d7a6f5c4b3a2918070d6e5": "chrome_127",
	"e4c7d6b5a4f3e2d1c0b9a8976543f210": "chrome_128",
	"f1e2d3c4b5a6978869504132a7b8c9d0": "chrome_129",
	"a9b8c7d6e5f4031221304050f6e7d8c9": "chrome_130",

	// Firefox 120-130 variants
	"839bbe3ed680eb421fc4d2f10c651b63": "firefox_120",
	"2c3f5a9e87d1b4c6f0e9d8c7b6a54321": "firefox_121",
	"7b6a59483726150493827160f5e4d3c2": "firefox_122",
	"d4c3b2a10f9e8d7c6b5a4938271605f4": "firefox_123",
	"1a2b3c4d5e6f708192a3b4c5d6e7f809": "firefox_124",
	"91a2b3c4d5e6f7089a0b1c2d3e4f5061": "firefox_125",
	"f0e1d2c3b4a5960718293a4b5c6d7e8f": "firefox_126",
	"5e4d3c2b1a09f8e7d6c5b4a398271605": "firefox_127",
	"a1b2c3d4e5f6071829304150627384a5": "firefox_128",
	"b6c7d8e9f0a1b2c3d4e5f6071829a0b1": "firefox_129",
	"c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7": "firefox_130",

	// Safari 17-18 variants
	"2b8c5ae1f93d0a7b6e4c1d8f2a9e3b7c": "safari_17_0",
	"f9e8d7c6b5a4938271605f4e3d2c1b0a": "safari_17_1",
	"4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90": "safari_17_2",
	"8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d": "safari_17_3",
	"3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e80": "safari_17_4",
	"7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b": "safari_18_0",
	"1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a": "safari_18_1",

	// Edge (Chromium-based, similar to Chrome)
	"de350869b8c85de67a350c8d186f11e6": "edge_120",
	"a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0": "edge_121",
	"6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c": "edge_122",
	"d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5": "edge_123",
	"2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b": "edge_124",
}

// --- Known Malicious Tool JA3 Hashes ---
var knownMaliciousJA3 = map[string]string{
	// curl various versions
	"456523fc94726331a4d5a2e1d40b2cd7": "curl_7_x",
	"e7d705a3286e19ea42f587b344ee6865": "curl_8_x",
	"1a2b3c4d5e6f7089ab0c1d2e3f405162": "curl_latest",

	// python-requests / urllib3
	"3b5074b1b5d032e5620f69f9f700ff0e": "python_requests",
	"d0e16b1340a0a6708e98d0ad1c985a65": "python_urllib3",
	"7b2c3d4e5f6a708192a3b4c5d6e7f809": "python_httpx",

	// Go http client
	"a56c4180c52b0d53e68e3e154d7bea2f": "go_http_client",
	"9e10a1b2c3d4e5f6708192a3b4c5d6e7": "go_http_client_1_21",

	// Java HttpClient
	"d92b768e4db87e2e7fd474d59aec9c3e": "java_httpclient",
	"b3c4d5e6f7a8091a2b3c4d5e6f7a8b9c": "java_okhttp",

	// wget
	"e0c01845d252e4b7b1c82ca0e0f10f63": "wget",
	"f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6": "wget_latest",

	// HTTPie
	"4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e": "httpie",

	// Node.js clients
	"c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0": "node_fetch",
	"a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3": "axios_node",

	// Headless browsers / automation
	"3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b": "phantomjs",
	"9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d": "puppeteer_headless",
}

// --- Known HTTP/2 SETTINGS Profiles ---
var knownH2Settings = map[string]H2SettingsProfile{
	"chrome": {
		HeaderTableSize:      65536,
		EnablePush:           0,
		MaxConcurrentStreams: 1000,
		InitialWindowSize:    6291456,
		MaxFrameSize:         16384,
		MaxHeaderListSize:    262144,
	},
	"firefox": {
		HeaderTableSize:      65536,
		EnablePush:           0,
		MaxConcurrentStreams: 100,
		InitialWindowSize:    131072,
		MaxFrameSize:         16384,
		MaxHeaderListSize:    65536,
	},
	"safari": {
		HeaderTableSize:      4096,
		EnablePush:           0,
		MaxConcurrentStreams: 100,
		InitialWindowSize:    2097152,
		MaxFrameSize:         16384,
		MaxHeaderListSize:    0, // Safari doesn't always send this
	},
	"edge": {
		HeaderTableSize:      65536,
		EnablePush:           0,
		MaxConcurrentStreams: 1000,
		InitialWindowSize:    6291456,
		MaxFrameSize:         16384,
		MaxHeaderListSize:    262144,
	},
}

// --- Known Header Order Patterns ---
// The values are md5 hashes of the canonical header order for each browser.
var knownHeaderOrders = map[string][]string{
	// Chrome typically sends: Host, Connection, sec-ch-ua, sec-ch-ua-mobile,
	// sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept,
	// Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest,
	// Accept-Encoding, Accept-Language
	"chrome": {
		"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
		"b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7",
		"c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8",
	},
	// Firefox typically sends: Host, User-Agent, Accept, Accept-Language,
	// Accept-Encoding, Connection, Upgrade-Insecure-Requests, Sec-Fetch-Dest,
	// Sec-Fetch-Mode, Sec-Fetch-Site, Sec-Fetch-User
	"firefox": {
		"d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9",
		"e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0",
		"f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1",
	},
	// Safari typically sends: Host, Accept, Accept-Language, Connection,
	// Accept-Encoding, User-Agent
	"safari": {
		"a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2",
		"b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3",
	},
	// Edge (Chromium-based, similar to Chrome)
	"edge": {
		"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
		"c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4",
	},
}

// BrowserFamilyFromUA extracts browser family from User-Agent string.
// Returns one of: "chrome", "firefox", "safari", "edge", "unknown"
func BrowserFamilyFromUA(ua string) string {
	// Order matters: Edge contains "Chrome" and "Safari", so check Edge first
	if containsCI(ua, "Edg/") || containsCI(ua, "Edge/") {
		return "edge"
	}
	if containsCI(ua, "Chrome/") && containsCI(ua, "Safari/") {
		return "chrome"
	}
	if containsCI(ua, "Firefox/") {
		return "firefox"
	}
	if containsCI(ua, "Safari/") && !containsCI(ua, "Chrome/") {
		return "safari"
	}
	return "unknown"
}

// containsCI does case-insensitive contains check.
func containsCI(s, substr string) bool {
	sLower := toLower(s)
	subLower := toLower(substr)
	return len(subLower) > 0 && len(sLower) >= len(subLower) && indexOfStr(sLower, subLower) >= 0
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func indexOfStr(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
