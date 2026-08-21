package system

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	acmepkg "My-OpenWaf/internal/acme"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

const acmeTestEmail = "admin@example.test"

type fakeACMEManager struct {
	result      *acmepkg.CertificateResult
	registerErr error
	obtainErr   error
}

func (m *fakeACMEManager) Register(context.Context) error {
	return m.registerErr
}

func (m *fakeACMEManager) ObtainCertificate(context.Context, string) (*acmepkg.CertificateResult, error) {
	if m.obtainErr != nil {
		return nil, m.obtainErr
	}
	return m.result, nil
}

func (m *fakeACMEManager) GetChallengeResponse(string) (string, bool) {
	return "", false
}

func newACMETestRepos(t *testing.T) *repository.Repos {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Certificate{}, &store.Site{}, &store.SiteListener{}, &store.SystemSettings{}); err != nil {
		t.Fatalf("migrate ACME test tables: %v", err)
	}
	return repository.New(db)
}

func newACMEStoreForTest(t *testing.T, repos *repository.Repos, manager acmeManager) *ACMEManagerStore {
	t.Helper()
	cfg := defaultACMEConfig()
	cfg.Enabled = true
	cfg.Email = acmeTestEmail
	if err := saveACMEConfig(repos.SystemSettings, cfg); err != nil {
		t.Fatalf("save ACME test config: %v", err)
	}
	return &ACMEManagerStore{
		settings:     repos.SystemSettings,
		certificates: repos.Certificate,
		manager:      manager,
		cacheKey:     acmeManagerCacheKey(cfg),
	}
}

func TestACMEApplyReloadFailureStripsPrivateKey(t *testing.T) {
	repos := newACMETestRepos(t)
	certPEM, keyPEM := "certificate pem", "private key pem"
	expiresAt := time.Now().Add(time.Hour)
	manager := &fakeACMEManager{result: &acmepkg.CertificateResult{
		Domain:  "apply.example.test",
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		Expiry:  expiresAt,
	}}
	acmeStore := newACMEStoreForTest(t, repos, manager)
	if err := repos.Site.Create(&store.Site{
		Host:         "apply.example.test",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":80",
		Network:      "tcp",
		Enabled:      true,
	}); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeCertificateHandlerForTest(t, ACMEApply(repos, func() error {
		return errors.New("reload boom")
	}, acmeStore), "POST", "/api/v1/certificates/acme/apply", nil, []byte(`{"domain":"apply.example.test","email":"admin@example.test"}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("status = %d, want 500: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if bytes.Contains(ctx.Response.Body(), []byte(keyPEM)) {
		t.Fatal("reload failure response leaked private key")
	}

	var response struct {
		Item store.Certificate `json:"item"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Item.KeyPEM != "" {
		t.Fatalf("response key_pem = %q, want blank", response.Item.KeyPEM)
	}
	stored, err := repos.Certificate.GetByDomain("apply.example.test")
	if err != nil {
		t.Fatalf("load persisted certificate: %v", err)
	}
	if stored.KeyPEM != keyPEM {
		t.Fatalf("persisted key_pem = %q, want original private key", stored.KeyPEM)
	}
}

func TestACMEApplySuccessStripsPrivateKey(t *testing.T) {
	repos := newACMETestRepos(t)
	certPEM, keyPEM := "certificate pem", "private key pem"
	expiresAt := time.Now().Add(time.Hour)
	manager := &fakeACMEManager{result: &acmepkg.CertificateResult{
		Domain:  "apply-success.example.test",
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		Expiry:  expiresAt,
	}}
	acmeStore := newACMEStoreForTest(t, repos, manager)
	if err := repos.Site.Create(&store.Site{
		Host:         "apply-success.example.test",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":80",
		Network:      "tcp",
		Enabled:      true,
	}); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeCertificateHandlerForTest(t, ACMEApply(repos, func() error {
		return nil
	}, acmeStore), "POST", "/api/v1/certificates/acme/apply", nil, []byte(`{"domain":"apply-success.example.test","email":"admin@example.test"}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status = %d, want 200: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if bytes.Contains(ctx.Response.Body(), []byte(keyPEM)) {
		t.Fatal("success response leaked private key")
	}

	var response acmeApplyResponse
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.KeyPEM != "" {
		t.Fatalf("response key_pem = %q, want blank", response.KeyPEM)
	}
	stored, err := repos.Certificate.GetByDomain("apply-success.example.test")
	if err != nil {
		t.Fatalf("load persisted certificate: %v", err)
	}
	if stored.KeyPEM != keyPEM {
		t.Fatalf("persisted key_pem = %q, want original private key", stored.KeyPEM)
	}
}

func TestACMERenewReloadFailureStripsPrivateKey(t *testing.T) {
	repos := newACMETestRepos(t)
	oldKeyPEM, newKeyPEM := "old private key pem", "renewed private key pem"
	cert := &store.Certificate{
		Name:      "renew.example.test",
		CertPEM:   "old certificate pem",
		KeyPEM:    oldKeyPEM,
		Source:    store.CertSourceACME,
		Domain:    "renew.example.test",
		AutoRenew: true,
	}
	if err := repos.Certificate.Create(cert); err != nil {
		t.Fatalf("seed ACME certificate: %v", err)
	}
	expiresAt := time.Now().Add(time.Hour)
	manager := &fakeACMEManager{result: &acmepkg.CertificateResult{
		Domain:  cert.Domain,
		CertPEM: "renewed certificate pem",
		KeyPEM:  newKeyPEM,
		Expiry:  expiresAt,
	}}
	acmeStore := newACMEStoreForTest(t, repos, manager)

	idStr := strconv.FormatUint(uint64(cert.ID), 10)
	ctx := invokeCertificateHandlerForTest(t, ACMERenew(repos, func() error {
		return errors.New("reload boom")
	}, acmeStore), "POST", "/api/v1/certificates/acme/"+idStr+"/renew", param.Params{{Key: "id", Value: idStr}}, nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("status = %d, want 500: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if bytes.Contains(ctx.Response.Body(), []byte(oldKeyPEM)) || bytes.Contains(ctx.Response.Body(), []byte(newKeyPEM)) {
		t.Fatal("reload failure response leaked private key")
	}

	var response struct {
		Item store.Certificate `json:"item"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Item.KeyPEM != "" {
		t.Fatalf("response key_pem = %q, want blank", response.Item.KeyPEM)
	}
	stored, err := repos.Certificate.Get(cert.ID)
	if err != nil {
		t.Fatalf("load renewed certificate: %v", err)
	}
	if stored.KeyPEM != newKeyPEM {
		t.Fatalf("persisted key_pem = %q, want renewed private key", stored.KeyPEM)
	}
}

// acmeLeakedPrivateKeyPEM 模拟 ACME 上游错误回带的私钥 PEM 块。
const acmeLeakedPrivateKeyPEM = "-----BEGIN EC PRIVATE KEY-----\n" +
	"MHcCAQEEIB0RtGkoJ0aVwLLo7hV0uPfNwsKcaOaVsAAAAAAAAAAAoAoGCCqGSM49\n" +
	"AwEHoUQDQgAEsuperSecretPublicPointBytesGoHereAndMorePaddingToBeLong\n" +
	"-----END EC PRIVATE KEY-----"

// seedACMERenewCertificate 建一条可续期的 ACME 证书，供续期错误脱敏用例复用。
func seedACMERenewCertificate(t *testing.T, repos *repository.Repos, domain string) *store.Certificate {
	t.Helper()
	cert := &store.Certificate{
		Name:      domain,
		CertPEM:   "old certificate pem",
		KeyPEM:    "old private key pem",
		Source:    store.CertSourceACME,
		Domain:    domain,
		AutoRenew: true,
	}
	if err := repos.Certificate.Create(cert); err != nil {
		t.Fatalf("seed ACME certificate: %v", err)
	}
	return cert
}

// invokeACMERenewForTest 以给定 obtain 错误触发一次手动续期，返回响应上下文与证书 ID。
func invokeACMERenewForTest(t *testing.T, repos *repository.Repos, domain string, obtainErr error) (*app.RequestContext, uint) {
	t.Helper()
	cert := seedACMERenewCertificate(t, repos, domain)
	acmeStore := newACMEStoreForTest(t, repos, &fakeACMEManager{obtainErr: obtainErr})
	idStr := strconv.FormatUint(uint64(cert.ID), 10)
	ctx := invokeCertificateHandlerForTest(t, ACMERenew(repos, func() error {
		return nil
	}, acmeStore), "POST", "/api/v1/certificates/acme/"+idStr+"/renew", param.Params{{Key: "id", Value: idStr}}, nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("status = %d, want 500: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	return ctx, cert.ID
}

func TestACMERenewTruncatesUpstreamErrorText(t *testing.T) {
	repos := newACMETestRepos(t)
	longErr := errors.New("acme: upstream rejected order " + strings.Repeat("A", 4096))

	ctx, certID := invokeACMERenewForTest(t, repos, "renew-truncate.example.test", longErr)

	var response struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.HasSuffix(response.Error, acmeErrorTruncatedSuffix) {
		t.Fatalf("response error missing truncation marker: %q", response.Error)
	}
	// 响应体前缀是固定文案，脱敏后的错误正文本身才受 acmeErrorTextLimit 约束。
	const prefix = "renew failed: "
	body, ok := strings.CutPrefix(response.Error, prefix)
	if !ok {
		t.Fatalf("response error = %q, want prefix %q", response.Error, prefix)
	}
	if len(body) > acmeErrorTextLimit {
		t.Fatalf("sanitized error len = %d, want <= %d", len(body), acmeErrorTextLimit)
	}

	stored, err := repos.Certificate.Get(certID)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	if len(stored.RenewError) > acmeErrorTextLimit {
		t.Fatalf("persisted renew_error len = %d, want <= %d", len(stored.RenewError), acmeErrorTextLimit)
	}
	if !strings.HasSuffix(stored.RenewError, acmeErrorTruncatedSuffix) {
		t.Fatalf("persisted renew_error missing truncation marker: %q", stored.RenewError)
	}
	if stored.RenewError != body {
		t.Fatalf("persisted renew_error = %q, want same sanitized text as response %q", stored.RenewError, body)
	}
}

func TestACMERenewRedactsPEMFromErrorText(t *testing.T) {
	repos := newACMETestRepos(t)
	obtainErr := fmt.Errorf("acme: order failed, account key was %s and retry is pending", acmeLeakedPrivateKeyPEM)

	ctx, certID := invokeACMERenewForTest(t, repos, "renew-redact.example.test", obtainErr)

	// PEM 块的头尾标记与正文 base64 行都不得出现在响应体里。
	leakedMarkers := []string{
		"-----BEGIN EC PRIVATE KEY-----",
		"-----END EC PRIVATE KEY-----",
		"MHcCAQEEIB0RtGkoJ0aVwLLo7hV0uPfNwsKcaOaVsAAAAAAAAAAAoAoGCCqGSM49",
		"AwEHoUQDQgAEsuperSecretPublicPointBytesGoHereAndMorePaddingToBeLong",
	}
	for _, marker := range leakedMarkers {
		if bytes.Contains(ctx.Response.Body(), []byte(marker)) {
			t.Fatalf("response body leaked PEM fragment %q: %s", marker, ctx.Response.Body())
		}
	}

	stored, err := repos.Certificate.Get(certID)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	for _, marker := range leakedMarkers {
		if strings.Contains(stored.RenewError, marker) {
			t.Fatalf("persisted renew_error leaked PEM fragment %q: %s", marker, stored.RenewError)
		}
	}
	if !strings.Contains(stored.RenewError, "[redacted]") {
		t.Fatalf("persisted renew_error = %q, want redaction marker", stored.RenewError)
	}
	// 脱敏不能把诊断信息全吃掉，前后的正常文本要留下来。
	if !strings.Contains(stored.RenewError, "acme: order failed") || !strings.Contains(stored.RenewError, "retry is pending") {
		t.Fatalf("persisted renew_error lost diagnostic context: %q", stored.RenewError)
	}
}

func TestSanitizeACMEErrorTextKeepsValidUTF8(t *testing.T) {
	// 「续」是 3 字节字符，重复到远超上限后，任意 limit 的切点都可能落在字符中间。
	raw := "acme 续期失败：" + strings.Repeat("续", 4096)
	for limit := 1; limit <= 64; limit++ {
		got := truncateACMEErrorText(raw, limit)
		if len(got) > limit {
			t.Fatalf("limit=%d: len = %d, want <= %d", limit, len(got), limit)
		}
		if !utf8.ValidString(got) {
			t.Fatalf("limit=%d: result is not valid UTF-8: %q", limit, got)
		}
	}
	sanitized := sanitizeACMEErrorText(raw)
	if len(sanitized) > acmeErrorTextLimit {
		t.Fatalf("sanitized len = %d, want <= %d", len(sanitized), acmeErrorTextLimit)
	}
	if !utf8.ValidString(sanitized) {
		t.Fatalf("sanitized text is not valid UTF-8: %q", sanitized)
	}
	if !strings.HasSuffix(sanitized, acmeErrorTruncatedSuffix) {
		t.Fatalf("sanitized text missing truncation marker: %q", sanitized)
	}
}

func TestSanitizeACMEErrorTextRedactsSensitiveFragments(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		absent  []string
		present []string
	}{
		{
			name:    "complete PEM block",
			raw:     "before " + acmeLeakedPrivateKeyPEM + " after",
			absent:  []string{"BEGIN EC PRIVATE KEY", "END EC PRIVATE KEY", "MHcCAQEEIB0RtGkoJ0aVwLLo7hV0uPfNwsKcaOaVsAAAAAAAAAAAoAoGCCqGSM49"},
			present: []string{"before", "after", "[redacted]"},
		},
		{
			// 上游自己截断时只剩 PEM 头，尾部 base64 仍是私钥内容。
			name:    "truncated PEM header without END marker",
			raw:     "obtain failed: -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecretmaterial",
			absent:  []string{"BEGIN RSA PRIVATE KEY", "MIIEowIBAAKCAQEAsecretmaterial"},
			present: []string{"obtain failed:", "[redacted]"},
		},
		{
			name:    "JWK private exponent",
			raw:     `acme: bad signature {"kty":"EC","d":"aVerySecretPrivateScalar","x":"pub"}`,
			absent:  []string{"aVerySecretPrivateScalar"},
			present: []string{"acme: bad signature", "[redacted]", `"x":"pub"`},
		},
		{
			name:    "private key style key value pair",
			raw:     "register failed: private_key=MHcCAQEEIsecret account_key: TOPSECRETVALUE",
			absent:  []string{"MHcCAQEEIsecret", "TOPSECRETVALUE"},
			present: []string{"register failed:", "[redacted]"},
		},
		{
			name:    "plain upstream error stays intact",
			raw:     "acme: urn:ietf:params:acme:error:dns lookup failed for example.test",
			absent:  []string{"[redacted]"},
			present: []string{"urn:ietf:params:acme:error:dns", "example.test"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeACMEErrorText(tc.raw)
			for _, fragment := range tc.absent {
				if strings.Contains(got, fragment) {
					t.Fatalf("sanitized text still contains %q: %q", fragment, got)
				}
			}
			for _, fragment := range tc.present {
				if !strings.Contains(got, fragment) {
					t.Fatalf("sanitized text lost %q: %q", fragment, got)
				}
			}
			if !utf8.ValidString(got) {
				t.Fatalf("sanitized text is not valid UTF-8: %q", got)
			}
		})
	}
	if got := sanitizeACMEErrorText(""); got != "" {
		t.Fatalf("empty input produced %q, want empty string", got)
	}
}
