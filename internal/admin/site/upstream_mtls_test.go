package site

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"My-OpenWaf/internal/store"
)

/**
 * testUpstreamMTLSCertPEM 生成一次性自签客户端证书。
 */
func testUpstreamMTLSCertPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "site-mtls-client.test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

/**
 * siteMTLSBody 组装站点创建请求体。
 */
func siteMTLSBody(host string, certPEM, keyPEM string) []byte {
	body := fmt.Sprintf(`{
		"host":%q,
		"upstream_urls":"https://127.0.0.1:8443",
		"bind":":8081",
		"network":"tcp",
		"enabled":true
	`, host)
	if certPEM != "" {
		certJSON, _ := json.Marshal(certPEM)
		body += fmt.Sprintf(`,"upstream_tls_client_cert_pem":%s`, certJSON)
	}
	if keyPEM != "" {
		keyJSON, _ := json.Marshal(keyPEM)
		body += fmt.Sprintf(`,"upstream_tls_client_key_pem":%s`, keyJSON)
	}
	return []byte(body + "}")
}

/**
 * TestCreateSiteUpstreamMTLSValidation 覆盖创建路径上的成对校验与解析校验。
 */
func TestCreateSiteUpstreamMTLSValidation(t *testing.T) {
	certPEM, keyPEM := testUpstreamMTLSCertPEM(t)
	malformedPair := siteMTLSBody("mtls-malformed.example", certPEM, "-----BEGIN PRIVATE KEY-----\nMALFORMED\n-----END PRIVATE KEY-----")

	repo := newSiteRepoForTest(t)
	ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), siteMTLSBody("mtls-cert-only.example", certPEM, ""))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("cert-only status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	ctx = invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), siteMTLSBody("mtls-key-only.example", "", keyPEM))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("key-only status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	ctx = invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), malformedPair)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("malformed pair status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
}

/**
 * TestCreateSiteUpstreamMTLSStoresRedactsAndEchoes 验证成对证书落库、私钥脱敏。
 */
func TestCreateSiteUpstreamMTLSStoresRedactsAndEchoes(t *testing.T) {
	repo := newSiteRepoForTest(t)
	certPEM, keyPEM := testUpstreamMTLSCertPEM(t)
	ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), siteMTLSBody("mtls-ok.example", certPEM, keyPEM))
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("create status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var created store.Site
	if err := json.Unmarshal(ctx.Response.Body(), &created); err != nil {
		t.Fatal(err)
	}
	if created.UpstreamTLSClientKeyPEM != nil {
		t.Fatalf("create response must redact client key, got %q", *created.UpstreamTLSClientKeyPEM)
	}
	if created.UpstreamTLSClientCertPEM == nil || *created.UpstreamTLSClientCertPEM != certPEM {
		t.Fatalf("create response cert = %#v, want stored cert pem", created.UpstreamTLSClientCertPEM)
	}

	persisted, err := repo.Get(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.UpstreamTLSClientKeyPEM == nil || *persisted.UpstreamTLSClientKeyPEM != keyPEM {
		t.Fatal("persisted client key must keep the original PEM for mTLS dials")
	}
	if persisted.UpstreamTLSClientCertPEM == nil || *persisted.UpstreamTLSClientCertPEM != certPEM {
		t.Fatal("persisted client cert must keep the original PEM")
	}

	ctx = invokeSiteRouteHandler(t, GetSite(repo), "GET", "/api/v1/sites/1", idParams("1"), nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("get status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var fetched store.Site
	if err := json.Unmarshal(ctx.Response.Body(), &fetched); err != nil {
		t.Fatal(err)
	}
	if fetched.UpstreamTLSClientKeyPEM != nil {
		t.Fatalf("get response must redact client key, got %q", *fetched.UpstreamTLSClientKeyPEM)
	}
	if bytes.Contains(ctx.Response.Body(), []byte("PRIVATE KEY")) {
		t.Fatal("get response must not contain private key material")
	}
}

/**
 * TestUpdateSiteUpstreamMTLSClearsByNull 覆盖更新路径划置证书与成对校验。
 */
func TestUpdateSiteUpstreamMTLSClearsByNull(t *testing.T) {
	repo := newSiteRepoForTest(t)
	certPEM, keyPEM := testUpstreamMTLSCertPEM(t)
	created := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), siteMTLSBody("mtls-clear.example", certPEM, keyPEM))
	if created.Response.StatusCode() != 201 {
		t.Fatalf("seed create status %d: %s", created.Response.StatusCode(), created.Response.Body())
	}
	var item store.Site
	if err := json.Unmarshal(created.Response.Body(), &item); err != nil {
		t.Fatal(err)
	}

	// 只更新证书 PEM 会让绑定的旧密钥留存，成对校验必须拒绝。
	updated := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID, []byte(`{"upstream_tls_client_cert_pem":"-----BEGIN CERTIFICATE-----\nXX\n-----END CERTIFICATE-----"}`))
	if updated.Response.StatusCode() != 400 {
		t.Fatalf("half update status %d: %s", updated.Response.StatusCode(), updated.Response.Body())
	}

	// 两个字段同时置空等价于不使用客户端证书。
	cleared := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID, []byte(`{"upstream_tls_client_cert_pem":"","upstream_tls_client_key_pem":""}`))
	if cleared.Response.StatusCode() != 200 {
		t.Fatalf("clear status %d: %s", cleared.Response.StatusCode(), cleared.Response.Body())
	}
	persisted, err := repo.Get(item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.UpstreamTLSClientCertPEM != nil && *persisted.UpstreamTLSClientCertPEM != "" {
		t.Fatalf("cert was not cleared: %q", *persisted.UpstreamTLSClientCertPEM)
	}
	if persisted.UpstreamTLSClientKeyPEM != nil && *persisted.UpstreamTLSClientKeyPEM != "" {
		t.Fatalf("key was not cleared: %q", *persisted.UpstreamTLSClientKeyPEM)
	}
}
