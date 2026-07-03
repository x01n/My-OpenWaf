package system

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/acme"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

func newCertificateRepoForOCSPTest(t *testing.T) *repository.CertificateRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Certificate{}); err != nil {
		t.Fatalf("migrate certificates: %v", err)
	}
	return repository.NewCertificateRepo(db)
}

func invokeCertificateHandlerForTest(t *testing.T, handler app.HandlerFunc, method, uri string, params param.Params, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI(uri)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(payload)
	}

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = params
	handler(context.Background(), ctx)
	return ctx
}

func TestCreateCertificatePersistsOCSPStapleAndReloads(t *testing.T) {
	repo := newCertificateRepoForOCSPTest(t)
	certPEM, keyPEM, err := acme.GenerateSelfSignedPEM("ocsp-admin.example.test", []string{"ocsp-admin.example.test"}, []net.IP{net.IPv4(127, 0, 0, 1)}, time.Hour)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	payload, err := json.Marshal(map[string]string{
		"name":            "ocsp-admin",
		"cert_pem":        certPEM,
		"key_pem":         keyPEM,
		"ocsp_staple_pem": "raw-ocsp-response",
	})
	if err != nil {
		t.Fatalf("encode request body: %v", err)
	}
	reloadCount := 0
	ctx := invokeCertificateHandlerForTest(t, CreateCertificate(repo, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/certificates", nil, payload)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("create certificate status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload count = %d, want 1", reloadCount)
	}

	items, total, err := repo.List(0, 0)
	if err != nil {
		t.Fatalf("list certificates: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("stored certificates = total %d items %d", total, len(items))
	}
	if items[0].OCSPStaplePEM != "raw-ocsp-response" {
		t.Fatalf("ocsp_staple_pem = %q, want raw-ocsp-response", items[0].OCSPStaplePEM)
	}
}

func TestUpdateCertificatePersistsOCSPStapleAndReloads(t *testing.T) {
	repo := newCertificateRepoForOCSPTest(t)
	certPEM, keyPEM, err := acme.GenerateSelfSignedPEM("ocsp-update.example.test", []string{"ocsp-update.example.test"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	cert := store.Certificate{Name: "old", CertPEM: certPEM, KeyPEM: keyPEM}
	if err := repo.Create(&cert); err != nil {
		t.Fatalf("seed certificate: %v", err)
	}

	payload, err := json.Marshal(map[string]string{
		"name":            "updated",
		"cert_pem":        certPEM,
		"key_pem":         keyPEM,
		"ocsp_staple_pem": "updated-ocsp-response",
	})
	if err != nil {
		t.Fatalf("encode request body: %v", err)
	}
	reloadCount := 0
	ctx := invokeCertificateHandlerForTest(t, UpdateCertificate(repo, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/certificates/1/update", param.Params{{Key: "id", Value: "1"}}, payload)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("update certificate status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload count = %d, want 1", reloadCount)
	}

	updated, err := repo.Get(cert.ID)
	if err != nil {
		t.Fatalf("load updated certificate: %v", err)
	}
	if updated.Name != "updated" || updated.OCSPStaplePEM != "updated-ocsp-response" {
		t.Fatalf("updated certificate = %#v", updated)
	}
}
