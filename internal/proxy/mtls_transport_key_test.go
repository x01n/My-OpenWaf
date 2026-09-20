package proxy

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
 * proxyTestUpstreamClientCertPEM 生成一次性自签客户端证书，返回 PEM 文本。
 */
func proxyTestUpstreamClientCertPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "proxy-mtls-client.test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

/**
 * TestTransportKeyForUpstreamCertDimension 验证证书指纹参与传输池键：
 * 同一站点仅更换客户端证书时不应复用旧传输连接。
 */
func TestTransportKeyForUpstreamCertDimension(t *testing.T) {
	certPEM, keyPEM := proxyTestUpstreamClientCertPEM(t)

	base := "https://127.0.0.1:8443"
	plainKey := transportKeyForUpstream(base, snapshot.SiteRuntime{})
	if plainKey.clientCertFingerprint != "" {
		t.Fatalf("no-cert key fingerprint = %q, want empty", plainKey.clientCertFingerprint)
	}

	rt := snapshot.SiteRuntime{Site: store.Site{
		UpstreamTLSClientCertPEM: &certPEM,
		UpstreamTLSClientKeyPEM:  &keyPEM,
	}}
	// 快照构建期契约：PEM 解析只在构建/写路径执行一次，热路径只读 DER。
	rt.Site.PrepareUpstreamMTLSRuntime()
	if !rt.Site.UpstreamTLSClientCertSet || rt.Site.UpstreamTLSClientCertBad || len(rt.Site.UpstreamTLSClientCertDER) == 0 {
		t.Fatalf("prepared runtime fields = set:%v bad:%v der:%d", rt.Site.UpstreamTLSClientCertSet, rt.Site.UpstreamTLSClientCertBad, len(rt.Site.UpstreamTLSClientCertDER))
	}
	certKey := transportKeyForUpstream(base, rt)
	if certKey.clientCertFingerprint == "" {
		t.Fatal("configured client cert did not produce a fingerprint")
	}
	if len(certKey.clientCertFingerprint) != 32 {
		t.Fatalf("fingerprint length = %d, want 32 hex chars (first 16 bytes of sha256)", len(certKey.clientCertFingerprint))
	}
	if certKey == plainKey {
		t.Fatal("client cert must differentiate the transport key")
	}
	if certKey.tlsServerName != plainKey.tlsServerName || certKey.isHTTPS != plainKey.isHTTPS || certKey.h2cPrior != plainKey.h2cPrior {
		t.Fatalf("cert key unexpectedly diverges in non-cert dimensions: %#v vs %#v", certKey, plainKey)
	}

	trA := SharedTransportForUpstream(snapshot.SiteRuntime{}, base)
	trB := SharedTransportForUpstream(rt, base)
	if trA == trB {
		t.Fatal("transports with/without client cert must not be shared")
	}
	if trB.TLSClientConfig == nil || len(trB.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("cert transport TLS config = %#v, want one client certificate", trB.TLSClientConfig)
	}
	if trA.TLSClientConfig == nil || len(trA.TLSClientConfig.Certificates) != 0 {
		t.Fatalf("plain transport TLS config = %#v, want no client certificate", trA.TLSClientConfig)
	}
}

/**
 * TestTransportKeyForUpstreamPlainHTTPIgnoresCert 校验明文 HTTP 传输不因证书字段分池。
 */
func TestTransportKeyForUpstreamPlainHTTPIgnoresCert(t *testing.T) {
	certPEM, keyPEM := proxyTestUpstreamClientCertPEM(t)
	rt := snapshot.SiteRuntime{Site: store.Site{
		UpstreamTLSClientCertPEM: &certPEM,
		UpstreamTLSClientKeyPEM:  &keyPEM,
	}}
	trA := SharedTransportForUpstream(snapshot.SiteRuntime{}, "http://127.0.0.1:8080")
	trB := SharedTransportForUpstream(rt, "http://127.0.0.1:8080")
	if trA != trB {
		t.Fatal("plain HTTP upstream should ignore client cert fields in the pool key")
	}
}

/**
 * TestTransportKeyForUpstreamMalformedPairIsolatesPool 校验不可解析成对证书不混用无证书池：
 * 快照 Prepare 后 Bad=true，指纹为 "badpair" 占位维，与无证书站点的键严格不同。
 */
func TestTransportKeyForUpstreamMalformedPairIsolatesPool(t *testing.T) {
	malformedCert := "-----BEGIN CERTIFICATE-----\nMALFORMED\n-----END CERTIFICATE-----"
	malformedKey := "-----BEGIN PRIVATE KEY-----\nMALFORMED\n-----END PRIVATE KEY-----"
	if _, err := tls.X509KeyPair([]byte(malformedCert), []byte(malformedKey)); err == nil {
		t.Fatal("malformed fixture should be invalid")
	}
	rt := snapshot.SiteRuntime{Site: store.Site{
		UpstreamTLSClientCertPEM: strPtr(malformedCert),
		UpstreamTLSClientKeyPEM:  strPtr(malformedKey),
	}}
	rt.Site.PrepareUpstreamMTLSRuntime()
	if !rt.Site.UpstreamTLSClientCertBad {
		t.Fatal("Prepare must mark unparseable pair as bad")
	}
	key := transportKeyForUpstream("https://127.0.0.1:8443", rt)
	if key.clientCertFingerprint != "badpair" {
		t.Fatalf("malformed pair fingerprint = %q, want badpair placeholder", key.clientCertFingerprint)
	}
	if base := transportKeyForUpstream("https://127.0.0.1:8443", snapshot.SiteRuntime{}); key == base {
		t.Fatal("bad-pair key must not collapse into the no-cert pool dimension")
	}
}

/**
 * strPtr 返回字符串指针，便于内联构造站点字段。
 */
func strPtr(s string) *string { return &s }
