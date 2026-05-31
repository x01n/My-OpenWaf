package owasp

import (
	"fmt"
	"testing"
)

func TestJSFuckDebug(t *testing.T) {
	// Sample 8 raw query
	rawQ := `name=this%5B%28%2B%7B%7D%2B%5B%5D%29%5B%2B%21%21%5B%5D%5D%2B%28%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%21%5B%5D%5D%2B%28%5B%5D%5B%5B%5D%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%21%5B%5D%2B%21%21%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%21%21%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%5D%28%28%2B%7B%7D%2B%5B%5D%29%5B%2B%21%21%5B%5D%5D%29%3B%2F%2F`

	normalized := normalizeWithDecode(rawQ)
	t.Logf("normalized: %s", normalized)
	t.Logf("hasSuspicious: %v", hasSuspiciousContent(normalized))
	t.Logf("hasXSSIndicator: %v", hasXSSIndicator(normalized))

	hit, ok := checkXSS(normalized, 2)
	t.Logf("checkXSS hit: %v, ok: %v", hit, ok)

	// Test full CheckOWASP
	headers := map[string]string{
		"Host":       "10.10.3.128:2280",
		"User-Agent": "Mozilla/5.0",
		"Referer":    "http://10.10.3.128:2280/vulnerabilities/xss_r/?name=",
	}
	hits := CheckOWASP("high", "/vulnerabilities/xss_r/", rawQ, headers, nil)
	fmt.Printf("CheckOWASP hits: %v\n", hits)
	t.Logf("CheckOWASP hits count: %d", len(hits))
}
