package challenge

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func init() {
	// 固定 secret 保证测试间确定性
	SetChallengeSecret([]byte("test-secret-key-for-unit-tests!!"))
}

// --- SetChallengeSecret ---

func TestSetChallengeSecretTooShort(t *testing.T) {
	before := append([]byte(nil), loadChallengeSecret()...)
	SetChallengeSecret([]byte("short"))
	after := loadChallengeSecret()
	if len(before) != len(after) {
		t.Fatal("secret length should not change when new secret is too short")
	}
	for i := range before {
		if before[i] != after[i] {
			t.Error("secret should not change when new secret is too short")
			return
		}
	}
}

// --- GenerateChallengeTokenPair / VerifyChallengeToken ---

func TestGenerateChallengeTokenPairAndVerify(t *testing.T) {
	ts, token := GenerateChallengeTokenPair("req-001")
	if ts == "" {
		t.Fatal("ts should not be empty")
	}
	if token == "" {
		t.Fatal("token should not be empty")
	}
	if !VerifyChallengeToken("req-001", ts, token, 5*time.Minute) {
		t.Fatal("freshly generated token should verify successfully")
	}
}

func TestVerifyChallengeTokenWrongReqID(t *testing.T) {
	ts, token := GenerateChallengeTokenPair("req-abc")
	if VerifyChallengeToken("req-xyz", ts, token, 5*time.Minute) {
		t.Error("token should not verify with different reqID")
	}
}

func TestVerifyChallengeTokenExpired(t *testing.T) {
	ts, token := GenerateChallengeTokenPair("req-002")
	// maxAge=1ns 立即过期
	if VerifyChallengeToken("req-002", ts, token, 1*time.Nanosecond) {
		t.Error("token should be expired with 1ns maxAge")
	}
}

func TestVerifyChallengeTokenInvalidTS(t *testing.T) {
	_, token := GenerateChallengeTokenPair("req-003")
	if VerifyChallengeToken("req-003", "not-a-timestamp", token, 5*time.Minute) {
		t.Error("invalid timestamp should fail verification")
	}
}

func TestVerifyChallengeTokenTamperedToken(t *testing.T) {
	ts, _ := GenerateChallengeTokenPair("req-004")
	if VerifyChallengeToken("req-004", ts, "deadbeefdeadbeef", 5*time.Minute) {
		t.Error("tampered token should fail verification")
	}
}

// --- normalizeChallengePassTTL ---

func TestNormalizeChallengePassTTL(t *testing.T) {
	if normalizeChallengePassTTL(0) != time.Hour {
		t.Errorf("zero TTL should default to 1h, got %v", normalizeChallengePassTTL(0))
	}
	if normalizeChallengePassTTL(-time.Minute) != time.Hour {
		t.Errorf("negative TTL should default to 1h, got %v", normalizeChallengePassTTL(-time.Minute))
	}
	if normalizeChallengePassTTL(30*time.Minute) != 30*time.Minute {
		t.Errorf("positive TTL should be preserved, got %v", normalizeChallengePassTTL(30*time.Minute))
	}
}

// --- challengeIPString ---

func TestChallengeIPString(t *testing.T) {
	if challengeIPString(nil) != "" {
		t.Error("nil IP should return empty string")
	}
	ip := net.ParseIP("1.2.3.4")
	got := challengeIPString(ip)
	if got != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %q", got)
	}
}

// --- challengeUserAgentHash ---

func TestChallengeUserAgentHash(t *testing.T) {
	h1 := challengeUserAgentHash("Mozilla/5.0 Chrome/125")
	h2 := challengeUserAgentHash("Mozilla/5.0 Chrome/125")
	h3 := challengeUserAgentHash("curl/8.0")
	if h1 != h2 {
		t.Error("same UA should produce same hash")
	}
	if h1 == h3 {
		t.Error("different UA should produce different hash")
	}
	if h1 == "" {
		t.Error("hash should not be empty")
	}
}

// --- SignChallengePassValue / VerifyChallengePassValue round-trip ---

func TestSignAndVerifyChallengePassValue(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	now := time.Now()
	value := SignChallengePassValue("example.com", ip, now, 5*time.Minute)
	if value == "" {
		t.Fatal("signed value should not be empty")
	}
	if !VerifyChallengePassValue(value, "example.com", ip, now) {
		t.Error("freshly signed value should verify")
	}
}

func TestVerifyChallengePassValueExpired(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	now := time.Now().Add(-2 * time.Hour)
	value := SignChallengePassValue("example.com", ip, now, time.Minute)
	if VerifyChallengePassValue(value, "example.com", ip, time.Now()) {
		t.Error("expired pass value should not verify")
	}
}

func TestVerifyChallengePassValueWrongHost(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	now := time.Now()
	value := SignChallengePassValue("example.com", ip, now, 5*time.Minute)
	if VerifyChallengePassValue(value, "other.com", ip, now) {
		t.Error("wrong host should not verify")
	}
}

func TestVerifyChallengePassValueWrongIP(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	otherIP := net.ParseIP("10.0.0.2")
	now := time.Now()
	value := SignChallengePassValue("example.com", ip, now, 5*time.Minute)
	if VerifyChallengePassValue(value, "example.com", otherIP, now) {
		t.Error("wrong IP should not verify")
	}
}

func TestVerifyChallengePassValueMalformed(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	if VerifyChallengePassValue("not-base64!!!", "example.com", ip, time.Now()) {
		t.Error("malformed value should not verify")
	}
	if VerifyChallengePassValue("", "example.com", ip, time.Now()) {
		t.Error("empty value should not verify")
	}
}

func TestVerifyChallengePassValueHostCaseInsensitive(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	now := time.Now()
	value := SignChallengePassValue("Example.COM", ip, now, 5*time.Minute)
	// 内部会 ToLower，所以验证时 host 统一小写
	if !VerifyChallengePassValue(value, "example.com", ip, now) {
		t.Error("host comparison should be case-insensitive")
	}
}

// --- VerifyChallengePassCookie ---

func TestVerifyChallengePassCookie(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	now := time.Now()
	value := SignChallengePassValue("example.com", ip, now, 5*time.Minute)
	cookieHeader := "__waf_passed=" + value
	if !VerifyChallengePassCookie(cookieHeader, "example.com", ip, now) {
		t.Error("valid cookie should verify")
	}
}

func TestVerifyChallengePassCookieEmpty(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	if VerifyChallengePassCookie("", "example.com", ip, time.Now()) {
		t.Error("empty cookie header should not verify")
	}
}

func TestVerifyChallengePassCookieWrongName(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	now := time.Now()
	value := SignChallengePassValue("example.com", ip, now, 5*time.Minute)
	cookieHeader := "other_cookie=" + value
	if VerifyChallengePassCookie(cookieHeader, "example.com", ip, now) {
		t.Error("wrong cookie name should not verify")
	}
}

func TestVerifyChallengePassCookieMultiple(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	now := time.Now()
	value := SignChallengePassValue("example.com", ip, now, 5*time.Minute)
	cookieHeader := "other=xyz; __waf_passed=" + value
	if !VerifyChallengePassCookie(cookieHeader, "example.com", ip, now) {
		t.Error("valid cookie among multiple should verify")
	}
}

// --- SignChallengePassValueWithClaims round-trip ---

func TestSignAndVerifyChallengePassValueWithClaims(t *testing.T) {
	claims := ChallengePassClaims{
		Host:      "api.example.com",
		ClientIP:  net.ParseIP("192.168.1.1"),
		UserAgent: "Mozilla/5.0 Chrome/125",
		SiteID:    42,
		Bind:      ":443",
	}
	now := time.Now()
	value := SignChallengePassValueWithClaims(claims, now, 10*time.Minute)
	if value == "" {
		t.Fatal("signed claims value should not be empty")
	}
	if !VerifyChallengePassValueWithClaims(value, claims, now) {
		t.Error("freshly signed claims should verify")
	}
}

func TestVerifyChallengePassValueWithClaimsWrongSiteID(t *testing.T) {
	claims := ChallengePassClaims{Host: "example.com", ClientIP: net.ParseIP("1.2.3.4"), SiteID: 1}
	now := time.Now()
	value := SignChallengePassValueWithClaims(claims, now, 10*time.Minute)
	wrongClaims := claims
	wrongClaims.SiteID = 2
	if VerifyChallengePassValueWithClaims(value, wrongClaims, now) {
		t.Error("wrong SiteID should not verify")
	}
}

func TestVerifyChallengePassValueWithClaimsWrongBind(t *testing.T) {
	claims := ChallengePassClaims{Host: "example.com", ClientIP: net.ParseIP("1.2.3.4"), Bind: ":443"}
	now := time.Now()
	value := SignChallengePassValueWithClaims(claims, now, 10*time.Minute)
	wrongClaims := claims
	wrongClaims.Bind = ":80"
	if VerifyChallengePassValueWithClaims(value, wrongClaims, now) {
		t.Error("wrong Bind should not verify")
	}
}

// --- challengeEncrypt / challengeDecrypt round-trip ---

func TestChallengeEncryptDecrypt(t *testing.T) {
	plaintext := []byte("hello challenge world")
	ciphertext, err := challengeEncrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	got, err := challengeDecrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("decrypt got %q, want %q", got, plaintext)
	}
}

func TestChallengeEncryptFailsWhenNonceGenerationFails(t *testing.T) {
	previousReader := challengeNonceReader
	challengeNonceReader = strings.NewReader("")
	t.Cleanup(func() {
		challengeNonceReader = previousReader
	})

	ciphertext, err := challengeEncrypt([]byte("must not be encrypted with a zero nonce"))
	if err == nil {
		t.Fatal("nonce generation failure should return an error")
	}
	if ciphertext != nil {
		t.Fatalf("nonce generation failure should not return ciphertext, got %x", ciphertext)
	}
}

func TestSignChallengePassValueFailsClosedWhenNonceGenerationFails(t *testing.T) {
	previousReader := challengeNonceReader
	challengeNonceReader = strings.NewReader("")
	t.Cleanup(func() {
		challengeNonceReader = previousReader
	})

	value := SignChallengePassValue("example.com", net.ParseIP("192.0.2.1"), time.Now(), time.Minute)
	if value != "" {
		t.Fatalf("nonce generation failure should not issue a challenge pass value, got %q", value)
	}
}

func TestChallengeDecryptTooShort(t *testing.T) {
	_, err := challengeDecrypt([]byte("short"))
	if err == nil {
		t.Error("too-short ciphertext should return error")
	}
}

// --- BuildChallengePassCookie smoke test ---

func TestBuildChallengePassCookie(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	cookie := BuildChallengePassCookie("example.com", ip, false, time.Now(), 5*time.Minute)
	if !strings.Contains(cookie, "__waf_passed=") {
		t.Errorf("cookie should contain name __waf_passed, got %q", cookie)
	}
}

func TestVerifyDynamicProtectionKeyTicketConsumesOnlyAfterClaimsMatch(t *testing.T) {
	dynamicProtectionKeyReplayGuard = newReplayGuard()
	now := time.Now()
	claims := DynamicProtectionKeyClaims{
		DynamicProtectionClaims: DynamicProtectionClaims{
			Host:      "dynamic.example.com",
			ClientIP:  net.ParseIP("192.0.2.10"),
			UserAgent: "dynamic-test-agent",
			SiteID:    7,
			Bind:      ":443",
		},
		Key: "dynamic-key",
	}
	const kek = "dynamic-kek"
	ticket := SignDynamicProtectionKeyTicket(claims, now, time.Minute, kek)
	if ticket == "" {
		t.Fatal("dynamic protection key ticket should not be empty")
	}

	wrongClaims := claims
	wrongClaims.Key = "wrong-key"
	if _, ok := VerifyDynamicProtectionKeyTicket(ticket, wrongClaims, now); ok {
		t.Fatal("ticket should reject mismatched claims")
	}
	if got, ok := VerifyDynamicProtectionKeyTicket(ticket, claims, now); !ok || got != kek {
		t.Fatalf("first matching verification = (%q, %v), want (%q, true)", got, ok, kek)
	}
	if _, ok := VerifyDynamicProtectionKeyTicket(ticket, claims, now); ok {
		t.Fatal("ticket should be rejected after its first successful verification")
	}
}

func TestVerifyDynamicProtectionKeyTicketConcurrentSingleUse(t *testing.T) {
	dynamicProtectionKeyReplayGuard = newReplayGuard()
	now := time.Now()
	claims := DynamicProtectionKeyClaims{
		DynamicProtectionClaims: DynamicProtectionClaims{
			Host:      "dynamic.example.com",
			ClientIP:  net.ParseIP("192.0.2.20"),
			UserAgent: "concurrent-test-agent",
			SiteID:    8,
			Bind:      ":443",
		},
		Key: "concurrent-key",
	}
	ticket := SignDynamicProtectionKeyTicket(claims, now, time.Minute, "concurrent-kek")
	if ticket == "" {
		t.Fatal("dynamic protection key ticket should not be empty")
	}

	const attempts = 32
	results := make(chan bool, attempts)
	var wg sync.WaitGroup
	wg.Add(attempts)
	for range attempts {
		go func() {
			defer wg.Done()
			_, ok := VerifyDynamicProtectionKeyTicket(ticket, claims, now)
			results <- ok
		}()
	}
	wg.Wait()
	close(results)

	successes := 0
	for ok := range results {
		if ok {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent verifications = %d, want 1", successes)
	}
}

func TestVerifyDynamicProtectionKeyTicketRejectsExpirationBoundary(t *testing.T) {
	dynamicProtectionKeyReplayGuard = newReplayGuard()
	now := time.Now()
	claims := DynamicProtectionKeyClaims{
		DynamicProtectionClaims: DynamicProtectionClaims{
			Host:      "dynamic.example.com",
			ClientIP:  net.ParseIP("192.0.2.30"),
			UserAgent: "expiry-test-agent",
			SiteID:    9,
			Bind:      ":443",
		},
		Key: "expiry-key",
	}
	ticket := SignDynamicProtectionKeyTicket(claims, now, time.Second, "expiry-kek")
	if ticket == "" {
		t.Fatal("dynamic protection key ticket should not be empty")
	}
	if _, ok := VerifyDynamicProtectionKeyTicket(ticket, claims, now.Add(time.Second)); ok {
		t.Fatal("ticket should be rejected at its expiration boundary")
	}
}
