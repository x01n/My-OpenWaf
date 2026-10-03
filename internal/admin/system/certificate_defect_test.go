package system

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/route/param"

	"My-OpenWaf/internal/acme"
	"My-OpenWaf/internal/store"
)

func TestDefectParseCertificateMatchedSitesAlwaysEmpty(t *testing.T) {
	repos := newCertificateTestRepos(t)
	certPEM, _, err := acme.GenerateSelfSignedPEM("defect-parse.example.test", []string{"*.example.test", "example.test"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	for _, host := range []string{"api.example.test", "other.test"} {
		if err := repos.site.Create(&store.Site{Host: host, Bind: ":80", UpstreamURLs: "http://127.0.0.1:8080", Enabled: true}); err != nil {
			t.Fatalf("seed site %s: %v", host, err)
		}
	}

	payload, err := json.Marshal(certificateParseRequest{CertPEM: certPEM})
	if err != nil {
		t.Fatalf("encode parse request: %v", err)
	}
	ctx := invokeCertificateHandlerForTest(t, ParseCertificate(repos.site), "POST", "/api/v1/certificates/parse", nil, payload)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("parse status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp certificateParseResponse
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode parse response: %v", err)
	}
	if len(resp.MatchedSites) != 1 || resp.MatchedSites[0].Host != "api.example.test" {
		t.Fatalf("matched_sites = %#v, want api.example.test matched via *.example.test "+
			"(SiteRepo.List(0,0) issues LIMIT 0 and returns no rows)", resp.MatchedSites)
	}
}

func TestDefectApplyCertificateToSitesNeverApplies(t *testing.T) {
	repos := newCertificateTestRepos(t)
	cert, _, _ := seedTestCertificate(t, repos.cert, "defect-apply.example.test", []string{"defect-apply.example.test"})

	matching := &store.Site{Host: "defect-apply.example.test", Bind: ":443", UpstreamURLs: "http://127.0.0.1:8080", Enabled: true, TLSEnabled: true}
	if err := repos.site.Create(matching); err != nil {
		t.Fatalf("seed matching site: %v", err)
	}
	tlsListener := &store.SiteListener{SiteID: matching.ID, Bind: ":8443", TLSEnabled: true, Enabled: true}
	if err := repos.listener.Create(tlsListener); err != nil {
		t.Fatalf("seed tls listener: %v", err)
	}
	plainListener := &store.SiteListener{SiteID: matching.ID, Bind: ":8080", TLSEnabled: false, Enabled: true}
	if err := repos.listener.Create(plainListener); err != nil {
		t.Fatalf("seed plain listener: %v", err)
	}

	reloadCount := 0
	idStr := strconv.FormatUint(uint64(cert.ID), 10)
	ctx := invokeCertificateHandlerForTest(t, ApplyCertificateToSites(repos.cert, repos.site, repos.listener, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/certificates/"+idStr+"/apply", param.Params{{Key: "id", Value: idStr}}, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("apply status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp certificateApplyResponse
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode apply response: %v", err)
	}
	if len(resp.AppliedSites) != 1 || resp.SiteCount != 1 || resp.ListenerCount != 1 {
		t.Fatalf("apply response = %#v, want 1 applied site and 1 TLS listener "+
			"(SiteRepo.List(0,0) issues LIMIT 0 so nothing ever matches)", resp)
	}
	if reloadCount != 1 {
		t.Fatalf("reload count = %d, want 1 after a successful apply", reloadCount)
	}

	updatedListener, err := repos.listener.Get(tlsListener.ID)
	if err != nil {
		t.Fatalf("load tls listener: %v", err)
	}
	if updatedListener.CertID == nil || *updatedListener.CertID != cert.ID {
		t.Fatalf("tls listener cert_id = %v, want %d", updatedListener.CertID, cert.ID)
	}
	untouched, err := repos.listener.Get(plainListener.ID)
	if err != nil {
		t.Fatalf("load plain listener: %v", err)
	}
	if untouched.CertID != nil {
		t.Fatalf("non-TLS listener must not receive a certificate, got %v", *untouched.CertID)
	}
}

func TestDefectUpdateCertificateEchoesStoredPrivateKey(t *testing.T) {
	repos := newCertificateTestRepos(t)
	cert, _, keyPEM := seedTestCertificate(t, repos.cert, "defect-key.example.test", []string{"defect-key.example.test"})
	idStr := strconv.FormatUint(uint64(cert.ID), 10)

	// 请求体只改名字，完全不携带 key_pem。
	ctx := invokeCertificateHandlerForTest(t, UpdateCertificate(repos.cert, func() error { return nil }),
		"POST", "/api/v1/certificates/"+idStr+"/update", param.Params{{Key: "id", Value: idStr}}, []byte(`{"name":"renamed"}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("update status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var got store.Certificate
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if got.KeyPEM != "" {
		t.Fatalf("update response returned the stored private key; key_pem must be blank like in List/Get responses")
	}
	if bytes.Contains(ctx.Response.Body(), []byte("PRIVATE KEY")) {
		t.Fatalf("update response body contains PEM private key material")
	}
	if strings.TrimSpace(got.KeyPEM) == strings.TrimSpace(keyPEM) {
		t.Fatalf("update response echoed the exact stored private key")
	}

	// 库中的私钥必须保持完好，脱敏只应作用于响应。
	stored, err := repos.cert.Get(cert.ID)
	if err != nil {
		t.Fatalf("load stored certificate: %v", err)
	}
	if strings.TrimSpace(stored.KeyPEM) != strings.TrimSpace(keyPEM) {
		t.Fatalf("stored private key must remain intact after an update")
	}
}

/**
 * 显式提交空私钥时必须拒绝更新，并保留数据库中的原私钥。
 */
func TestDefectUpdateWithExplicitEmptyPrivateKeyPreservesStoredKey(t *testing.T) {
	repos := newCertificateTestRepos(t)
	cert, _, keyPEM := seedTestCertificate(t, repos.cert, "defect-empty-key.example.test", []string{"defect-empty-key.example.test"})
	idStr := strconv.FormatUint(uint64(cert.ID), 10)

	ctx := invokeCertificateHandlerForTest(t, UpdateCertificate(repos.cert, func() error { return nil }),
		"POST", "/api/v1/certificates/"+idStr+"/update", param.Params{{Key: "id", Value: idStr}}, []byte(`{"name":"must-not-apply","key_pem":""}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("explicit empty private key status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if bytes.Contains(ctx.Response.Body(), []byte("PRIVATE KEY")) {
		t.Fatalf("explicit empty private key error leaked PEM material")
	}

	stored, err := repos.cert.Get(cert.ID)
	if err != nil {
		t.Fatalf("load stored certificate: %v", err)
	}
	if stored.Name != cert.Name {
		t.Fatalf("rejected update changed name to %q", stored.Name)
	}
	if strings.TrimSpace(stored.KeyPEM) != strings.TrimSpace(keyPEM) {
		t.Fatalf("rejected update changed the stored private key")
	}
}
