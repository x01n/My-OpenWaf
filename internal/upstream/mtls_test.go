package upstream

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

/**
 * testUpstreamClientCertPEM 生成一次性自签客户端证书，返回 PEM 文本。
 */
func testUpstreamClientCertPEM(tb testing.TB) (string, string) {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate client key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "upstream-mtls-client.test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("create client certificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		tb.Fatalf("marshal client key: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func TestHTTPSClientTLSConfigWithClientCertNoCertMatchesLegacy(t *testing.T) {
	plain := HTTPSClientTLSConfig("origin.example.test", true)
	withEmpty := HTTPSClientTLSConfigWithClientCert("origin.example.test", true, tls.Certificate{}, false)
	if withEmpty.Certificates != nil {
		t.Fatalf("no-cert config Certificates = %#v, want nil", withEmpty.Certificates)
	}
	if plain.MinVersion != withEmpty.MinVersion || plain.ServerName != withEmpty.ServerName || plain.InsecureSkipVerify != withEmpty.InsecureSkipVerify {
		t.Fatalf("no-cert config diverges from legacy: plain=%#v withEmpty=%#v", plain, withEmpty)
	}
	if len(plain.CipherSuites) != len(withEmpty.CipherSuites) {
		t.Fatal("no-cert config cipher suites diverge from legacy")
	}
}

func TestHTTPSClientTLSConfigWithClientCertAttachesCertificates(t *testing.T) {
	certPEM, keyPEM := testUpstreamClientCertPEM(t)
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("parse test pair: %v", err)
	}
	cfg := HTTPSClientTLSConfigWithClientCert("origin.example.test", false, pair, true)
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates = %#v, want exactly one", cfg.Certificates)
	}
	if cfg.Certificates[0].PrivateKey == nil {
		t.Fatal("client certificate private key is nil")
	}
	if len(cfg.Certificates[0].Certificate) == 0 {
		t.Fatal("client certificate chain is empty")
	}
}

func TestUpstreamClientCertificateLoadsPairFromSiteRuntime(t *testing.T) {
	certPEM, keyPEM := testUpstreamClientCertPEM(t)
	blank := "   \n\t"
	bad := "-----BEGIN PRIVATE KEY-----\nMALFORMED\n-----END PRIVATE KEY-----"

	cases := []struct {
		name    string
		rt      snapshot.SiteRuntime
		wantErr bool
		hasCert bool
	}{
		{name: "none", rt: snapshot.SiteRuntime{}},
		{name: "paired", rt: snapshot.SiteRuntime{Site: store.Site{
			UpstreamTLSClientCertPEM: &certPEM,
			UpstreamTLSClientKeyPEM:  &keyPEM,
		}}, hasCert: true},
		{name: "cert-only", rt: snapshot.SiteRuntime{Site: store.Site{
			UpstreamTLSClientCertPEM: &certPEM,
			UpstreamTLSClientCertBad: true,
		}}, wantErr: true},
		{name: "key-only", rt: snapshot.SiteRuntime{Site: store.Site{
			UpstreamTLSClientKeyPEM:  &keyPEM,
			UpstreamTLSClientCertBad: true,
		}}, wantErr: true},
		{name: "malformed", rt: snapshot.SiteRuntime{Site: store.Site{
			UpstreamTLSClientCertPEM: &certPEM,
			UpstreamTLSClientKeyPEM:  &bad,
			UpstreamTLSClientCertBad: true,
		}}, wantErr: true},
		{name: "blank-pair", rt: snapshot.SiteRuntime{Site: store.Site{
			UpstreamTLSClientCertPEM: &blank,
			UpstreamTLSClientKeyPEM:  &blank,
			UpstreamTLSClientCertBad: false,
		}}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cert, hasCert, err := UpstreamClientCertificate(tt.rt)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got hasCert=%v", hasCert)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if hasCert != tt.hasCert {
				t.Fatalf("hasCert = %v, want %v", hasCert, tt.hasCert)
			}
			if !hasCert && cert.PrivateKey != nil {
				t.Fatalf("unconfigured site must not carry a private key: %#v", cert)
			}
		})
	}
}

func TestUpstreamClientCertificateRejectsWrongKey(t *testing.T) {
	certPEM, _ := testUpstreamClientCertPEM(t)
	_, otherKeyPEM := testUpstreamClientCertPEM(t)
	rt := snapshot.SiteRuntime{Site: store.Site{
		UpstreamTLSClientCertPEM: &certPEM,
		UpstreamTLSClientKeyPEM:  &otherKeyPEM,
	}}
	if _, hasCert, err := UpstreamClientCertificate(rt); err == nil || hasCert {
		t.Fatalf("mismatched key pair should error: hasCert=%v err=%v", hasCert, err)
	}
}

/**
 * TestUpstreamClientCertificatePreparedRuntime 覆盖快照预计算主路径：
 * Prepare 后回放 DER/Key 不触碰 PEM，且 Bad 站点按配置错误返回。
 */
func TestUpstreamClientCertificatePreparedRuntime(t *testing.T) {
	certPEM, keyPEM := testUpstreamClientCertPEM(t)

	site := store.Site{
		UpstreamTLSClientCertPEM: &certPEM,
		UpstreamTLSClientKeyPEM:  &keyPEM,
	}
	site.PrepareUpstreamMTLSRuntime()
	if !site.UpstreamTLSClientCertSet || site.UpstreamTLSClientCertBad || site.UpstreamTLSClientCertKey == nil || len(site.UpstreamTLSClientCertDER) == 0 {
		t.Fatalf("prepare failed: set=%v bad=%v der=%d", site.UpstreamTLSClientCertSet, site.UpstreamTLSClientCertBad, len(site.UpstreamTLSClientCertDER))
	}

	rt := snapshot.SiteRuntime{Site: site}
	cert, hasCert, err := UpstreamClientCertificate(rt)
	if err != nil || !hasCert {
		t.Fatalf("prepared pair replay failed: hasCert=%v err=%v", hasCert, err)
	}
	if cert.PrivateKey == nil || len(cert.Certificate) != 1 {
		t.Fatalf("prepared pair certificate = %#v", cert)
	}
	if fp := UpstreamClientCertFingerprint(rt); fp == "" || len(fp) != 32 {
		t.Fatalf("prepared fingerprint = %q, want 32 hex chars", fp)
	}

	bad := store.Site{
		UpstreamTLSClientCertPEM: &certPEM,
		UpstreamTLSClientKeyPEM:  strPtrTest("-----BEGIN PRIVATE KEY-----\nMALFORMED\n-----END PRIVATE KEY-----"),
	}
	bad.PrepareUpstreamMTLSRuntime()
	badRT := snapshot.SiteRuntime{Site: bad}
	if _, _, err := UpstreamClientCertificate(badRT); err == nil {
		t.Fatal("bad prepared pair should error")
	}
	if fp := UpstreamClientCertFingerprint(badRT); fp != "badpair" {
		t.Fatalf("bad prepared fingerprint = %q, want badpair", fp)
	}
}

/**
 * strPtrTest 返回字符串指针，便于内联构造站点字段。
 */
func strPtrTest(s string) *string { return &s }

/**
 * BenchmarkUpstreamClientFingerprintPrepared 度量指纹读取（每请求一次）的纯热路径开销。
 */
func BenchmarkUpstreamClientFingerprintPrepared(b *testing.B) {
	certPEM, keyPEM := benchUpstreamClientCertPEM()
	site := store.Site{
		UpstreamTLSClientCertPEM: &certPEM,
		UpstreamTLSClientKeyPEM:  &keyPEM,
	}
	site.PrepareUpstreamMTLSRuntime()
	if !site.UpstreamTLSClientCertSet || site.UpstreamTLSClientCertBad || len(site.UpstreamTLSClientCertDER) == 0 || site.UpstreamTLSClientCertFP == "" {
		panic("prepare failed")
	}
	rt := snapshot.SiteRuntime{Site: site}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if UpstreamClientCertFingerprint(rt) == "" {
			panic("empty fingerprint")
		}
	}
}

/**
 * benchUpstreamClientCertPEM 生成基准专用证书对；基准首轮 b.N==0 时
 * b.Fatal 会因 runN 未初始化而 panic，因此热路径断言一律用 panic 而非 b.Fatal。
 */
func benchUpstreamClientCertPEM() (string, string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(8),
		Subject:      pkix.Name{CommonName: "upstream-mtls-bench.test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}
