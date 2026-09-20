package system

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/acme"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// certificateTestRepos 聚合证书相关 handler 需要的三个仓库。
type certificateTestRepos struct {
	cert     *repository.CertificateRepo
	site     *repository.SiteRepo
	listener *repository.SiteListenerRepo
}

/**
 * newCertificateTestRepos 建立含证书、站点与监听器表的内存库。
 */
func newCertificateTestRepos(t *testing.T) certificateTestRepos {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Certificate{}, &store.Site{}, &store.SiteListener{}); err != nil {
		t.Fatalf("migrate certificate tables: %v", err)
	}
	return certificateTestRepos{
		cert:     repository.NewCertificateRepo(db),
		site:     repository.NewSiteRepo(db),
		listener: repository.NewSiteListenerRepo(db),
	}
}

/**
 * seedTestCertificate 生成自签证书并落库，返回记录与原始 PEM。
 */
func seedTestCertificate(t *testing.T, repo *repository.CertificateRepo, commonName string, dnsNames []string) (*store.Certificate, string, string) {
	t.Helper()
	certPEM, keyPEM, err := acme.GenerateSelfSignedPEM(commonName, dnsNames, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate certificate for %s: %v", commonName, err)
	}
	item := &store.Certificate{Name: commonName, CertPEM: certPEM, KeyPEM: keyPEM, Source: store.CertSourceManual, Domain: commonName}
	if err := repo.Create(item); err != nil {
		t.Fatalf("seed certificate %s: %v", commonName, err)
	}
	return item, certPEM, keyPEM
}

func TestListCertificatesStripsPrivateKey(t *testing.T) {
	repos := newCertificateTestRepos(t)
	_, _, keyPEM := seedTestCertificate(t, repos.cert, "list-a.example.test", []string{"list-a.example.test"})
	seedTestCertificate(t, repos.cert, "list-b.example.test", []string{"list-b.example.test"})

	ctx := invokeCertificateHandlerForTest(t, ListCertificates(repos.cert), "GET", "/api/v1/certificates?page=1&page_size=20", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("list status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	body := ctx.Response.Body()
	if bytes.Contains(body, []byte("PRIVATE KEY")) {
		t.Fatalf("certificate list leaked a private key: %s", bytes.TrimSpace(body))
	}
	if bytes.Contains(body, []byte(firstPEMLine(keyPEM))) {
		t.Fatalf("certificate list leaked private key material")
	}

	var resp struct {
		Items []store.Certificate `json:"items"`
		Total int64               `json:"total"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode certificate list: %v", err)
	}
	if resp.Total != 2 || len(resp.Items) != 2 {
		t.Fatalf("certificate list = total %d len %d, want 2", resp.Total, len(resp.Items))
	}
	for _, item := range resp.Items {
		if item.KeyPEM != "" {
			t.Fatalf("certificate %d key_pem must be blank in list responses", item.ID)
		}
		if item.CertPEM == "" {
			t.Fatalf("certificate %d cert_pem should still be returned", item.ID)
		}
	}
}

func TestGetCertificateStripsPrivateKeyAndValidatesID(t *testing.T) {
	repos := newCertificateTestRepos(t)
	cert, _, keyPEM := seedTestCertificate(t, repos.cert, "detail.example.test", []string{"detail.example.test"})
	idStr := strconv.FormatUint(uint64(cert.ID), 10)

	ok := invokeCertificateHandlerForTest(t, GetCertificate(repos.cert), "GET", "/api/v1/certificates/"+idStr, param.Params{{Key: "id", Value: idStr}}, nil)
	if ok.Response.StatusCode() != 200 {
		t.Fatalf("get status %d: %s", ok.Response.StatusCode(), bytes.TrimSpace(ok.Response.Body()))
	}
	if bytes.Contains(ok.Response.Body(), []byte("PRIVATE KEY")) || bytes.Contains(ok.Response.Body(), []byte(firstPEMLine(keyPEM))) {
		t.Fatalf("certificate detail leaked a private key: %s", bytes.TrimSpace(ok.Response.Body()))
	}
	var got store.Certificate
	if err := json.Unmarshal(ok.Response.Body(), &got); err != nil {
		t.Fatalf("decode certificate detail: %v", err)
	}
	if got.KeyPEM != "" {
		t.Fatalf("certificate detail key_pem must be blank")
	}
	if got.ID != cert.ID {
		t.Fatalf("certificate detail id = %d, want %d", got.ID, cert.ID)
	}

	// 私钥在库中保持完好，只是不返回给客户端。
	stored, err := repos.cert.Get(cert.ID)
	if err != nil {
		t.Fatalf("load stored certificate: %v", err)
	}
	if stored.KeyPEM == "" {
		t.Fatalf("stripping the response must not wipe the stored private key")
	}

	badID := invokeCertificateHandlerForTest(t, GetCertificate(repos.cert), "GET", "/api/v1/certificates/abc", param.Params{{Key: "id", Value: "abc"}}, nil)
	if badID.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d, want 400", badID.Response.StatusCode())
	}

	missing := invokeCertificateHandlerForTest(t, GetCertificate(repos.cert), "GET", "/api/v1/certificates/9999", param.Params{{Key: "id", Value: "9999"}}, nil)
	if missing.Response.StatusCode() != 404 {
		t.Fatalf("missing certificate status = %d, want 404", missing.Response.StatusCode())
	}
}

func TestParseCertificateReturnsCertificateMetadata(t *testing.T) {
	repos := newCertificateTestRepos(t)
	certPEM, _, err := acme.GenerateSelfSignedPEM("wildcard.example.test", []string{"*.example.test", "example.test"}, []net.IP{net.IPv4(203, 0, 113, 5)}, time.Hour)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
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
	if resp.CommonName != "wildcard.example.test" {
		t.Fatalf("common_name = %q, want wildcard.example.test", resp.CommonName)
	}
	if len(resp.DNSNames) != 2 || resp.DNSNames[0] != "*.example.test" {
		t.Fatalf("dns_names = %v, want [*.example.test example.test]", resp.DNSNames)
	}
	if len(resp.IPAddresses) != 1 || resp.IPAddresses[0] != "203.0.113.5" {
		t.Fatalf("ip_addresses = %v, want [203.0.113.5]", resp.IPAddresses)
	}
	if resp.ExpiresAt.IsZero() {
		t.Fatalf("expires_at must be populated")
	}
}

func TestParseCertificateRejectsInvalidInput(t *testing.T) {
	repos := newCertificateTestRepos(t)

	badBody := invokeCertificateHandlerForTest(t, ParseCertificate(repos.site), "POST", "/api/v1/certificates/parse", nil, []byte(`{"cert_pem":`))
	if badBody.Response.StatusCode() != 400 {
		t.Fatalf("malformed body status = %d, want 400", badBody.Response.StatusCode())
	}

	badPEM := invokeCertificateHandlerForTest(t, ParseCertificate(repos.site), "POST", "/api/v1/certificates/parse", nil, []byte(`{"cert_pem":"not a pem"}`))
	if badPEM.Response.StatusCode() != 400 {
		t.Fatalf("invalid pem status = %d, want 400", badPEM.Response.StatusCode())
	}
	if !bytes.Contains(badPEM.Response.Body(), []byte("invalid certificate pem")) {
		t.Fatalf("invalid pem body = %s, want an explanatory error", bytes.TrimSpace(badPEM.Response.Body()))
	}
}

func TestApplyCertificateToSitesErrorPaths(t *testing.T) {
	repos := newCertificateTestRepos(t)
	cert, _, _ := seedTestCertificate(t, repos.cert, "noamatch.example.test", []string{"noamatch.example.test"})
	idStr := strconv.FormatUint(uint64(cert.ID), 10)

	badID := invokeCertificateHandlerForTest(t, ApplyCertificateToSites(repos.cert, repos.site, repos.listener, func() error { return nil }),
		"POST", "/api/v1/certificates/xx/apply", param.Params{{Key: "id", Value: "xx"}}, nil)
	if badID.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d, want 400", badID.Response.StatusCode())
	}

	missing := invokeCertificateHandlerForTest(t, ApplyCertificateToSites(repos.cert, repos.site, repos.listener, func() error { return nil }),
		"POST", "/api/v1/certificates/8888/apply", param.Params{{Key: "id", Value: "8888"}}, nil)
	if missing.Response.StatusCode() != 404 {
		t.Fatalf("missing certificate status = %d, want 404", missing.Response.StatusCode())
	}

	// 没有站点匹配时返回 200 且不触发 reload。
	reloadCount := 0
	noMatch := invokeCertificateHandlerForTest(t, ApplyCertificateToSites(repos.cert, repos.site, repos.listener, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/certificates/"+idStr+"/apply", param.Params{{Key: "id", Value: idStr}}, nil)
	if noMatch.Response.StatusCode() != 200 {
		t.Fatalf("no-match status = %d, want 200", noMatch.Response.StatusCode())
	}
	if reloadCount != 0 {
		t.Fatalf("reload count without matches = %d, want 0", reloadCount)
	}
	var noMatchResp certificateApplyResponse
	if err := json.Unmarshal(noMatch.Response.Body(), &noMatchResp); err != nil {
		t.Fatalf("decode no-match response: %v", err)
	}
	if len(noMatchResp.AppliedSites) != 0 || noMatchResp.SiteCount != 0 {
		t.Fatalf("no-match response = %#v, want empty applied sites", noMatchResp)
	}
}

func TestDeleteCertificateBlocksWhileReferenced(t *testing.T) {
	repos := newCertificateTestRepos(t)
	cert, _, _ := seedTestCertificate(t, repos.cert, "referenced.example.test", []string{"referenced.example.test"})
	certID := cert.ID
	if err := repos.site.Create(&store.Site{Host: "referenced.example.test", Bind: ":443", UpstreamURLs: "http://127.0.0.1:8080", Enabled: true, TLSEnabled: true, CertID: &certID}); err != nil {
		t.Fatalf("seed referencing site: %v", err)
	}
	idStr := strconv.FormatUint(uint64(certID), 10)

	reloadCount := 0
	ctx := invokeCertificateHandlerForTest(t, DeleteCertificate(repos.cert, repos.site, repos.listener, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/certificates/"+idStr+"/delete", param.Params{{Key: "id", Value: idStr}}, nil)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("referenced delete status = %d, want 400", ctx.Response.StatusCode())
	}
	if reloadCount != 0 {
		t.Fatalf("blocked delete must not reload, got %d calls", reloadCount)
	}

	var resp struct {
		Error         string `json:"error"`
		SiteRefs      int64  `json:"site_refs"`
		ListenerRefs  int64  `json:"listener_refs"`
		UnusedPadding string `json:"-"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode blocked delete response: %v", err)
	}
	if resp.SiteRefs != 1 || resp.ListenerRefs != 0 {
		t.Fatalf("reference counts = site %d listener %d, want 1/0", resp.SiteRefs, resp.ListenerRefs)
	}
	if !strings.Contains(resp.Error, "still referenced") {
		t.Fatalf("error = %q, want a still-referenced message", resp.Error)
	}
	if _, err := repos.cert.Get(certID); err != nil {
		t.Fatalf("blocked delete must keep the certificate: %v", err)
	}
}

func TestDeleteCertificateSucceedsWhenUnreferenced(t *testing.T) {
	repos := newCertificateTestRepos(t)
	cert, _, _ := seedTestCertificate(t, repos.cert, "free.example.test", []string{"free.example.test"})
	idStr := strconv.FormatUint(uint64(cert.ID), 10)

	reloadCount := 0
	ctx := invokeCertificateHandlerForTest(t, DeleteCertificate(repos.cert, repos.site, repos.listener, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/certificates/"+idStr+"/delete", param.Params{{Key: "id", Value: idStr}}, nil)
	if ctx.Response.StatusCode() != 204 {
		t.Fatalf("delete status = %d, want 204: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload count = %d, want 1", reloadCount)
	}
	if _, err := repos.cert.Get(cert.ID); err == nil {
		t.Fatalf("certificate should be gone after delete")
	}
}

func TestDeleteCertificateInvalidIDAndReloadFailure(t *testing.T) {
	repos := newCertificateTestRepos(t)

	badID := invokeCertificateHandlerForTest(t, DeleteCertificate(repos.cert, repos.site, repos.listener, func() error { return nil }),
		"POST", "/api/v1/certificates/zz/delete", param.Params{{Key: "id", Value: "zz"}}, nil)
	if badID.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d, want 400", badID.Response.StatusCode())
	}

	cert, _, _ := seedTestCertificate(t, repos.cert, "reloadfail.example.test", []string{"reloadfail.example.test"})
	idStr := strconv.FormatUint(uint64(cert.ID), 10)
	ctx := invokeCertificateHandlerForTest(t, DeleteCertificate(repos.cert, repos.site, repos.listener, func() error { return errors.New("reload boom") }),
		"POST", "/api/v1/certificates/"+idStr+"/delete", param.Params{{Key: "id", Value: idStr}}, nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("reload failure status = %d, want 500", ctx.Response.StatusCode())
	}
	if !bytes.Contains(ctx.Response.Body(), []byte("reload failed")) {
		t.Fatalf("reload failure body = %s, want it to mention the failure", bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestCreateCertificateRejectsInvalidInput(t *testing.T) {
	repos := newCertificateTestRepos(t)
	certPEM, keyPEM, err := acme.GenerateSelfSignedPEM("create-bad.example.test", []string{"create-bad.example.test"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	otherCertPEM, _, err := acme.GenerateSelfSignedPEM("mismatch.example.test", []string{"mismatch.example.test"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate mismatch certificate: %v", err)
	}

	mismatched, err := json.Marshal(map[string]string{"name": "mismatch", "cert_pem": otherCertPEM, "key_pem": keyPEM})
	if err != nil {
		t.Fatalf("encode mismatch payload: %v", err)
	}

	tests := []struct {
		name    string
		payload []byte
		wantMsg string
	}{
		{name: "malformed json", payload: []byte(`{"name":`), wantMsg: ""},
		{name: "mismatched key pair", payload: mismatched, wantMsg: "invalid certificate/key pair"},
		{name: "empty pems", payload: []byte(`{"name":"empty","cert_pem":"","key_pem":""}`), wantMsg: "invalid certificate/key pair"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := invokeCertificateHandlerForTest(t, CreateCertificate(repos.cert, func() error { return nil }), "POST", "/api/v1/certificates", nil, tt.payload)
			if ctx.Response.StatusCode() != 400 {
				t.Fatalf("status = %d, want 400: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
			if tt.wantMsg != "" && !bytes.Contains(ctx.Response.Body(), []byte(tt.wantMsg)) {
				t.Fatalf("body = %s, want it to contain %q", bytes.TrimSpace(ctx.Response.Body()), tt.wantMsg)
			}
		})
	}

	// 合法证书应回填 source/domain/expires_at 默认值。
	valid, err := json.Marshal(map[string]string{"name": "defaults", "cert_pem": certPEM, "key_pem": keyPEM})
	if err != nil {
		t.Fatalf("encode valid payload: %v", err)
	}
	ok := invokeCertificateHandlerForTest(t, CreateCertificate(repos.cert, func() error { return nil }), "POST", "/api/v1/certificates", nil, valid)
	if ok.Response.StatusCode() != 201 {
		t.Fatalf("valid create status %d: %s", ok.Response.StatusCode(), bytes.TrimSpace(ok.Response.Body()))
	}
	var created store.Certificate
	if err := json.Unmarshal(ok.Response.Body(), &created); err != nil {
		t.Fatalf("decode created certificate: %v", err)
	}
	if created.Source != store.CertSourceManual {
		t.Fatalf("source = %q, want %q", created.Source, store.CertSourceManual)
	}
	if created.Domain != "create-bad.example.test" {
		t.Fatalf("domain = %q, want the first SAN", created.Domain)
	}
	if created.ExpiresAt == nil {
		t.Fatalf("expires_at should default to the certificate NotAfter")
	}
	if created.KeyPEM != "" {
		t.Fatal("created certificate key_pem must be blank")
	}
	if bytes.Contains(ok.Response.Body(), []byte("PRIVATE KEY")) || bytes.Contains(ok.Response.Body(), []byte(firstPEMLine(keyPEM))) {
		t.Fatalf("create response leaked private key material")
	}
	stored, err := repos.cert.Get(created.ID)
	if err != nil {
		t.Fatalf("load created certificate: %v", err)
	}
	if stored.KeyPEM == "" {
		t.Fatal("created certificate private key must remain persisted")
	}
}

func TestCreateCertificateReportsReloadFailure(t *testing.T) {
	repos := newCertificateTestRepos(t)
	certPEM, keyPEM, err := acme.GenerateSelfSignedPEM("createreload.example.test", []string{"createreload.example.test"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	payload, err := json.Marshal(map[string]string{"name": "reload", "cert_pem": certPEM, "key_pem": keyPEM})
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}

	ctx := invokeCertificateHandlerForTest(t, CreateCertificate(repos.cert, func() error { return errors.New("reload boom") }), "POST", "/api/v1/certificates", nil, payload)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("reload failure status = %d, want 500", ctx.Response.StatusCode())
	}
	if bytes.Contains(ctx.Response.Body(), []byte("PRIVATE KEY")) || bytes.Contains(ctx.Response.Body(), []byte(firstPEMLine(keyPEM))) {
		t.Fatal("reload failure response leaked private key material")
	}
	var response struct {
		Item store.Certificate `json:"item"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("decode reload failure response: %v", err)
	}
	if response.Item.KeyPEM != "" {
		t.Fatal("reload failure response item key_pem must be blank")
	}
	// 记录已落库，仅 reload 失败。
	items, total, err := repos.cert.List(0, 0)
	if err != nil {
		t.Fatalf("list certificates: %v", err)
	}
	if total != 1 {
		t.Fatalf("certificate total = %d, want 1 even when reload fails", total)
	}
	if len(items) != 1 || items[0].KeyPEM == "" {
		t.Fatal("reload failure must keep the persisted private key")
	}
}

func TestUpdateCertificateErrorPaths(t *testing.T) {
	repos := newCertificateTestRepos(t)
	cert, certPEM, _ := seedTestCertificate(t, repos.cert, "update-err.example.test", []string{"update-err.example.test"})
	idStr := strconv.FormatUint(uint64(cert.ID), 10)
	idParams := param.Params{{Key: "id", Value: idStr}}

	badID := invokeCertificateHandlerForTest(t, UpdateCertificate(repos.cert, func() error { return nil }),
		"POST", "/api/v1/certificates/qq/update", param.Params{{Key: "id", Value: "qq"}}, []byte(`{"name":"x"}`))
	if badID.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d, want 400", badID.Response.StatusCode())
	}

	missing := invokeCertificateHandlerForTest(t, UpdateCertificate(repos.cert, func() error { return nil }),
		"POST", "/api/v1/certificates/7777/update", param.Params{{Key: "id", Value: "7777"}}, []byte(`{"name":"x"}`))
	if missing.Response.StatusCode() != 404 {
		t.Fatalf("missing certificate status = %d, want 404", missing.Response.StatusCode())
	}

	badBody := invokeCertificateHandlerForTest(t, UpdateCertificate(repos.cert, func() error { return nil }),
		"POST", "/api/v1/certificates/"+idStr+"/update", idParams, []byte(`{"name":`))
	if badBody.Response.StatusCode() != 400 {
		t.Fatalf("malformed body status = %d, want 400", badBody.Response.StatusCode())
	}

	// 替换成与私钥不匹配的证书应被拒绝，且不写库。
	otherCertPEM, _, err := acme.GenerateSelfSignedPEM("other-update.example.test", []string{"other-update.example.test"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate mismatch certificate: %v", err)
	}
	mismatch, err := json.Marshal(map[string]string{"cert_pem": otherCertPEM})
	if err != nil {
		t.Fatalf("encode mismatch payload: %v", err)
	}
	rejected := invokeCertificateHandlerForTest(t, UpdateCertificate(repos.cert, func() error { return nil }),
		"POST", "/api/v1/certificates/"+idStr+"/update", idParams, mismatch)
	if rejected.Response.StatusCode() != 400 {
		t.Fatalf("mismatched pair status = %d, want 400", rejected.Response.StatusCode())
	}
	stored, err := repos.cert.Get(cert.ID)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	if strings.TrimSpace(stored.CertPEM) != strings.TrimSpace(certPEM) {
		t.Fatalf("rejected update must not replace the stored certificate")
	}
}

func TestUpdateCertificateReportsReloadFailure(t *testing.T) {
	repos := newCertificateTestRepos(t)
	cert, _, _ := seedTestCertificate(t, repos.cert, "updatereload.example.test", []string{"updatereload.example.test"})
	idStr := strconv.FormatUint(uint64(cert.ID), 10)

	ctx := invokeCertificateHandlerForTest(t, UpdateCertificate(repos.cert, func() error { return errors.New("reload boom") }),
		"POST", "/api/v1/certificates/"+idStr+"/update", param.Params{{Key: "id", Value: idStr}}, []byte(`{"name":"renamed"}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("reload failure status = %d, want 500", ctx.Response.StatusCode())
	}
	stored, err := repos.cert.Get(cert.ID)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	if stored.Name != "renamed" {
		t.Fatalf("name = %q, want the update to persist before the reload failure", stored.Name)
	}
}

func TestCertificateIPStrings(t *testing.T) {
	if got := certificateIPStrings(nil); got != nil {
		t.Fatalf("certificateIPStrings(nil) = %v, want nil", got)
	}
	if got := certificateIPStrings(&x509.Certificate{}); got != nil {
		t.Fatalf("certificateIPStrings(no ips) = %v, want nil", got)
	}
	cert := &x509.Certificate{IPAddresses: []net.IP{net.IPv4(198, 51, 100, 3), net.ParseIP("2001:db8::1")}}
	got := certificateIPStrings(cert)
	if len(got) != 2 || got[0] != "198.51.100.3" || got[1] != "2001:db8::1" {
		t.Fatalf("certificateIPStrings = %v, want [198.51.100.3 2001:db8::1]", got)
	}
}

func TestCertificateMatchNamesDeduplicatesAndLowercases(t *testing.T) {
	if got := certificateMatchNames(nil); got != nil {
		t.Fatalf("certificateMatchNames(nil) = %v, want nil", got)
	}

	cert := &x509.Certificate{
		DNSNames: []string{"  API.Example.Test  ", "api.example.test", "", "*.Example.Test"},
		Subject:  pkix.Name{CommonName: " API.Example.Test "},
	}
	got := certificateMatchNames(cert)
	want := []string{"api.example.test", "*.example.test"}
	if len(got) != len(want) {
		t.Fatalf("certificateMatchNames = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("certificateMatchNames = %v, want %v", got, want)
		}
	}

	// CN 不在 SAN 中时应被追加。
	cnOnly := &x509.Certificate{Subject: pkix.Name{CommonName: "Legacy.Example.Test"}}
	if got := certificateMatchNames(cnOnly); len(got) != 1 || got[0] != "legacy.example.test" {
		t.Fatalf("certificateMatchNames(cn only) = %v, want [legacy.example.test]", got)
	}
}

func TestMatchCertificateSitesHandlesMultiHostAndDeduplicates(t *testing.T) {
	cert := &x509.Certificate{
		DNSNames: []string{"*.example.test", "example.test"},
		Subject:  pkix.Name{CommonName: "example.test"},
	}
	certID := uint(9)
	sites := []store.Site{
		// 同一站点同时命中通配符和精确名，只能产出一条结果。
		{ID: 1, Host: "api.example.test, example.test", TLSEnabled: true, CertID: &certID},
		{ID: 2, Host: "deep.sub.example.test"},
		{ID: 3, Host: "other.test"},
		{ID: 4, Host: "  WEB.Example.Test  "},
	}

	matches := matchCertificateSites(cert, sites)
	if len(matches) != 2 {
		t.Fatalf("matches = %#v, want 2 (site 1 and site 4)", matches)
	}
	if matches[0].ID != 1 || matches[0].MatchedName != "*.example.test" {
		t.Fatalf("first match = %#v, want site 1 via wildcard", matches[0])
	}
	if !matches[0].TLSEnabled || matches[0].CertID == nil || *matches[0].CertID != certID {
		t.Fatalf("first match should carry site TLS metadata: %#v", matches[0])
	}
	if matches[1].ID != 4 {
		t.Fatalf("second match = %#v, want site 4", matches[1])
	}

	if got := matchCertificateSites(cert, nil); len(got) != 0 {
		t.Fatalf("matchCertificateSites(no sites) = %#v, want empty", got)
	}
}

func TestPreferredCertificateDomain(t *testing.T) {
	if got := preferredCertificateDomain(nil); got != "" {
		t.Fatalf("preferredCertificateDomain(nil) = %q, want empty", got)
	}
	withSAN := &x509.Certificate{DNSNames: []string{"first.example.test", "second.example.test"}, Subject: pkix.Name{CommonName: "cn.example.test"}}
	if got := preferredCertificateDomain(withSAN); got != "first.example.test" {
		t.Fatalf("preferredCertificateDomain(SAN) = %q, want first.example.test", got)
	}
	cnOnly := &x509.Certificate{Subject: pkix.Name{CommonName: "  cn.example.test  "}}
	if got := preferredCertificateDomain(cnOnly); got != "cn.example.test" {
		t.Fatalf("preferredCertificateDomain(CN) = %q, want cn.example.test", got)
	}
}

/**
 * firstPEMLine 返回 PEM 正文首行，用于在响应体中检测私钥泄漏。
 */
func firstPEMLine(pemText string) string {
	lines := strings.Split(strings.TrimSpace(pemText), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "-----") {
			return trimmed
		}
	}
	return strings.TrimSpace(pemText)
}
