package system

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"strconv"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

type certificateParseRequest struct {
	CertPEM string `json:"cert_pem"`
}

type certificateMatchedSite struct {
	ID          uint   `json:"id"`
	Host        string `json:"host"`
	TLSEnabled  bool   `json:"tls_enabled"`
	CertID      *uint  `json:"cert_id,omitempty"`
	MatchedName string `json:"matched_name"`
}

type certificateParseResponse struct {
	CommonName   string                   `json:"common_name"`
	DNSNames     []string                 `json:"dns_names"`
	IPAddresses  []string                 `json:"ip_addresses"`
	ExpiresAt    time.Time                `json:"expires_at"`
	MatchedSites []certificateMatchedSite `json:"matched_sites"`
}

type certificateApplyResponse struct {
	CertificateID uint                     `json:"certificate_id"`
	AppliedSites  []certificateMatchedSite `json:"applied_sites"`
	SiteCount     int64                    `json:"site_count"`
	ListenerCount int64                    `json:"listener_count"`
}

func ListCertificates(repo *repository.CertificateRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		size, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
		offset, limit := utils.Paginate(page, size)
		items, total, err := repo.List(offset, limit)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": total})
	}
}

func GetCertificate(repo *repository.CertificateRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		item, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "not found"})
			return
		}
		c.JSON(200, item)
	}
}

func CreateCertificate(repo *repository.CertificateRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var item store.Certificate
		if err := c.BindJSON(&item); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if _, err := tls.X509KeyPair([]byte(item.CertPEM), []byte(item.KeyPEM)); err != nil {
			c.JSON(400, map[string]string{"error": "invalid certificate/key pair: " + err.Error()})
			return
		}
		if !validOptionalOCSPStaple(item.OCSPStaplePEM) {
			c.JSON(400, map[string]string{"error": "invalid ocsp_staple_pem"})
			return
		}
		parsed, err := parseCertificatePEM(item.CertPEM)
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid certificate pem: " + err.Error()})
			return
		}
		if item.Source == "" {
			item.Source = store.CertSourceManual
		}
		if item.Domain == "" {
			item.Domain = preferredCertificateDomain(parsed)
		}
		if item.ExpiresAt == nil {
			item.ExpiresAt = &parsed.NotAfter
		}
		if err := repo.Create(&item); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": item})
			return
		}
		c.JSON(201, item)
	}
}

func ParseCertificate(siteRepo *repository.SiteRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req certificateParseRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		cert, err := parseCertificatePEM(req.CertPEM)
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid certificate pem: " + err.Error()})
			return
		}
		sites, _, err := siteRepo.List(0, 0)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, certificateParseResponse{
			CommonName:   cert.Subject.CommonName,
			DNSNames:     cert.DNSNames,
			IPAddresses:  certificateIPStrings(cert),
			ExpiresAt:    cert.NotAfter,
			MatchedSites: matchCertificateSites(cert, sites),
		})
	}
}

func ApplyCertificateToSites(certRepo *repository.CertificateRepo, siteRepo *repository.SiteRepo, listenerRepo *repository.SiteListenerRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		cert, err := certRepo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "certificate not found"})
			return
		}
		parsed, err := parseCertificatePEM(cert.CertPEM)
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid certificate pem: " + err.Error()})
			return
		}
		sites, _, err := siteRepo.List(0, 0)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		matches := matchCertificateSites(parsed, sites)
		if len(matches) == 0 {
			c.JSON(200, certificateApplyResponse{CertificateID: cert.ID, AppliedSites: nil})
			return
		}
		siteIDs := make([]uint, 0, len(matches))
		for _, match := range matches {
			siteIDs = append(siteIDs, match.ID)
		}
		siteCount, err := siteRepo.ApplyCertificate(siteIDs, cert.ID)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		listenerCount, err := listenerRepo.ApplyCertificateToTLSListeners(siteIDs, cert.ID)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "applied_sites": matches})
			return
		}
		c.JSON(200, certificateApplyResponse{
			CertificateID: cert.ID,
			AppliedSites:  matches,
			SiteCount:     siteCount,
			ListenerCount: listenerCount,
		})
	}
}

func UpdateCertificate(repo *repository.CertificateRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		existing, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "not found"})
			return
		}
		if err := c.BindJSON(existing); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if _, err := tls.X509KeyPair([]byte(existing.CertPEM), []byte(existing.KeyPEM)); err != nil {
			c.JSON(400, map[string]string{"error": "invalid certificate/key pair: " + err.Error()})
			return
		}
		if !validOptionalOCSPStaple(existing.OCSPStaplePEM) {
			c.JSON(400, map[string]string{"error": "invalid ocsp_staple_pem"})
			return
		}
		existing.ID = id
		if err := repo.Update(existing); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": existing})
			return
		}
		c.JSON(200, existing)
	}
}

func validOptionalOCSPStaple(raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return true
	}
	staple, ok := snapshot.ParseOCSPStaple(raw)
	return ok && len(staple) > 0
}

func parseCertificatePEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(certPEM)))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, x509.CertificateInvalidError{}
	}
	return x509.ParseCertificate(block.Bytes)
}

func preferredCertificateDomain(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return strings.TrimSpace(cert.Subject.CommonName)
}

func certificateIPStrings(cert *x509.Certificate) []string {
	if cert == nil || len(cert.IPAddresses) == 0 {
		return nil
	}
	out := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

func matchCertificateSites(cert *x509.Certificate, sites []store.Site) []certificateMatchedSite {
	names := certificateMatchNames(cert)
	matches := make([]certificateMatchedSite, 0)
	seen := make(map[uint]struct{})
	for _, site := range sites {
		for _, host := range splitSiteHosts(site.Host) {
			for _, name := range names {
				if certificateNameMatchesHost(name, host) {
					if _, ok := seen[site.ID]; ok {
						continue
					}
					seen[site.ID] = struct{}{}
					matches = append(matches, certificateMatchedSite{
						ID:          site.ID,
						Host:        site.Host,
						TLSEnabled:  site.TLSEnabled,
						CertID:      site.CertID,
						MatchedName: name,
					})
				}
			}
		}
	}
	return matches
}

func certificateMatchNames(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(cert.DNSNames)+1)
	for _, raw := range cert.DNSNames {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	cn := strings.ToLower(strings.TrimSpace(cert.Subject.CommonName))
	if cn != "" {
		if _, ok := seen[cn]; !ok {
			out = append(out, cn)
		}
	}
	return out
}

func splitSiteHosts(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		host := strings.ToLower(strings.TrimSpace(part))
		if host != "" {
			out = append(out, host)
		}
	}
	return out
}

func certificateNameMatchesHost(name, host string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	host = strings.ToLower(strings.TrimSpace(host))
	if name == "" || host == "" {
		return false
	}
	if name == host {
		return true
	}
	if !strings.HasPrefix(name, "*.") {
		return false
	}
	suffix := strings.TrimPrefix(name, "*")
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	left := strings.TrimSuffix(host, suffix)
	return left != "" && !strings.Contains(left, ".")
}

func DeleteCertificate(repo *repository.CertificateRepo, siteRepo *repository.SiteRepo, listenerRepo *repository.SiteListenerRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		siteRefs, err := siteRepo.CountByCertID(id)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		listenerRefs, err := listenerRepo.CountByCertID(id)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if siteRefs+listenerRefs > 0 {
			c.JSON(400, map[string]any{"error": "certificate is still referenced", "site_refs": siteRefs, "listener_refs": listenerRefs})
			return
		}
		if err := repo.Delete(id); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(204, nil)
	}
}
