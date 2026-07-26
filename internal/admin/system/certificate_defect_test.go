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

/*
本文件中的测试用于复现生产代码缺陷，当前预期为失败。修复生产代码后即应转绿。

缺陷 A —— 证书站点匹配永远为空：
  internal/admin/system/certificate.go:134 (ParseCertificate) 与 :166 (ApplyCertificateToSites)
  以 siteRepo.List(0, 0) 表达“取全部站点”，但
  internal/store/repository/site.go:19 无条件执行 .Limit(limit)，
  GORM 在 limit==0 时生成 `LIMIT 0` 并返回 0 行（total 仍为真实值）。
  结果：证书解析预览的 matched_sites 恒为空，一键应用证书恒不生效且不触发 reload。
  建议修复：对齐 CertificateRepo.List 的写法，在 site.go:19 加 `if limit > 0` 守卫；
  或将两个调用点改为使用明确的大 limit。

缺陷 B —— 更新证书的响应回显数据库中的私钥：
  internal/admin/system/certificate.go:236 在 200 响应中返回 existing（含 KeyPEM）。
  ListCertificates(:58) 与 GetCertificate(:76) 都会清空 KeyPEM，说明设计意图是私钥不出网。
  UpdateCertificate 的 existing 来自 repo.Get()，当请求体不含 key_pem 时，
  BindJSON 不会覆盖它，于是响应把库中原有私钥明文回传给调用方。
  同一问题也存在于 :233 的 reload 失败分支（"item": existing）与 :115 的创建分支。
  建议修复：写库成功后在响应前置空 KeyPEM，与 List/Get 保持一致。
*/

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
