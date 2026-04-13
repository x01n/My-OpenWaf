package waf

import "testing"

func TestBotFingerprint(t *testing.T) {
	// Empty request — no UA, no Accept, no Accept-Language, no Accept-Encoding
	br := BotRequest{Method: "GET", Path: "/"}
	v := CheckBot(br)
	if v.Category != "malicious" {
		t.Errorf("expected malicious for empty request, got %q (score=%d)", v.Category, v.Score)
	}

	// Known malicious tool
	br = BotRequest{UserAgent: "sqlmap/1.5"}
	v = CheckBot(br)
	if v.Category != "malicious" || v.Score != 100 {
		t.Errorf("expected malicious:100 for sqlmap, got %q:%d", v.Category, v.Score)
	}

	// Known good bot
	br = BotRequest{UserAgent: "Googlebot/2.1 (+http://www.google.com/bot.html)"}
	v = CheckBot(br)
	if v.Category != "good" {
		t.Errorf("expected good for Googlebot, got %q", v.Category)
	}

	// Normal browser-like request
	br = BotRequest{
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
		Method:         "GET",
		Path:           "/",
		AcceptHeader:   "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		AcceptLanguage: "en-US,en;q=0.5",
		AcceptEncoding: "gzip, deflate, br",
		Connection:     "keep-alive",
		HasCookie:      true,
	}
	v = CheckBot(br)
	if v.Category != "human" {
		t.Errorf("expected human for normal browser, got %q (score=%d)", v.Category, v.Score)
	}

	// Automation library (python-requests) with minimal headers
	br = BotRequest{
		UserAgent: "python-requests/2.28.1",
		Method:    "GET",
		Path:      "/api/data",
	}
	v = CheckBot(br)
	if v.Category != "malicious" && v.Category != "suspicious" {
		t.Errorf("expected suspicious/malicious for python-requests, got %q (score=%d)", v.Category, v.Score)
	}

	// curl with some headers
	br = BotRequest{
		UserAgent:      "curl/7.88.1",
		AcceptHeader:   "*/*",
		AcceptEncoding: "gzip",
	}
	v = CheckBot(br)
	if v.Score < 50 {
		t.Errorf("expected score>=50 for curl, got %d", v.Score)
	}
}

func TestBotFakeFirefox(t *testing.T) {
	// Fake Mozilla without parentheses
	br := BotRequest{
		UserAgent:      "Mozilla/5.0",
		AcceptHeader:   "text/html",
		AcceptLanguage: "en",
		AcceptEncoding: "gzip",
	}
	v := CheckBot(br)
	if v.Score < 25 {
		t.Errorf("expected score>=25 for fake mozilla, got %d", v.Score)
	}
}
