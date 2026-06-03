package system

import (
	"context"
	"errors"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"gorm.io/gorm"

	acmepkg "My-OpenWaf/internal/acme"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// acmeRequest ACME 证书申请请求体。
type acmeRequest struct {
	Domain string `json:"domain"`
	Email  string `json:"email"`
	Name   string `json:"name"`
}

// ACMEApply 申请 Let's Encrypt 证书（HTTP-01 质询）。
func ACMEApply(repos *repository.Repos, reload func() error, acmeMgr *acmepkg.Manager) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req acmeRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		if req.Domain == "" {
			c.JSON(400, map[string]string{"error": "domain is required"})
			return
		}
		if req.Name == "" {
			req.Name = req.Domain
		}

		if acmeMgr == nil {
			c.JSON(500, map[string]string{"error": "ACME manager not initialized; set MY_OPENWAF_ACME_EMAIL first"})
			return
		}
		if req.Email != "" && req.Email != acmeMgr.Email() {
			c.JSON(400, map[string]string{"error": "email must match configured MY_OPENWAF_ACME_EMAIL"})
			return
		}

		// 注册帐户（幂等）
		if err := acmeMgr.Register(ctx); err != nil {
			c.JSON(500, map[string]string{"error": "ACME register failed: " + err.Error()})
			return
		}

		// 申请证书
		result, err := acmeMgr.ObtainCertificate(ctx, req.Domain)
		if err != nil {
			c.JSON(500, map[string]string{"error": "certificate obtain failed: " + err.Error()})
			return
		}

		// 存储到数据库
		now := time.Now()
		cert := store.Certificate{
			Name:        req.Name,
			CertPEM:     result.CertPEM,
			KeyPEM:      result.KeyPEM,
			Source:      store.CertSourceACME,
			Domain:      req.Domain,
			ACMEEmail:   acmeMgr.Email(),
			ExpiresAt:   &result.Expiry,
			AutoRenew:   true,
			LastRenewAt: &now,
		}

		existing, err := repos.Certificate.GetByDomain(req.Domain)
		if err == nil {
			cert.ID = existing.ID
			if err := repos.Certificate.Update(&cert); err != nil {
				c.JSON(500, map[string]string{"error": "update certificate failed: " + err.Error()})
				return
			}
		} else if errors.Is(err, gorm.ErrRecordNotFound) {
			if err := repos.Certificate.Create(&cert); err != nil {
				c.JSON(500, map[string]string{"error": "save certificate failed: " + err.Error()})
				return
			}
		} else {
			c.JSON(500, map[string]string{"error": "load existing certificate failed: " + err.Error()})
			return
		}

		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": cert})
			return
		}
		c.JSON(200, cert)
	}
}

// ACMERenew 手动触发证书续期。
func ACMERenew(repos *repository.Repos, reload func() error, acmeMgr *acmepkg.Manager) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		idStr := c.Param("id")
		if idStr == "" {
			c.JSON(400, map[string]string{"error": "id is required"})
			return
		}

		cert, err := repos.Certificate.GetByID(idStr)
		if err != nil {
			c.JSON(404, map[string]string{"error": "certificate not found"})
			return
		}

		if cert.Source != store.CertSourceACME {
			c.JSON(400, map[string]string{"error": "only ACME certificates can be renewed"})
			return
		}

		if cert.Domain == "" {
			c.JSON(400, map[string]string{"error": "certificate has no domain configured"})
			return
		}

		if acmeMgr == nil {
			c.JSON(500, map[string]string{"error": "ACME manager not initialized; set MY_OPENWAF_ACME_EMAIL first"})
			return
		}

		// 注册帐户（幂等）
		if err := acmeMgr.Register(ctx); err != nil {
			c.JSON(500, map[string]string{"error": "ACME register failed: " + err.Error()})
			return
		}

		result, err := acmeMgr.ObtainCertificate(ctx, cert.Domain)
		if err != nil {
			// 记录错误
			now := time.Now()
			if statusErr := repos.Certificate.UpdateRenewStatus(cert.ID, err.Error(), &now); statusErr != nil {
				c.JSON(500, map[string]string{"error": "renew failed: " + err.Error() + "; update renew status failed: " + statusErr.Error()})
				return
			}
			c.JSON(500, map[string]string{"error": "renew failed: " + err.Error()})
			return
		}

		// 更新证书
		now := time.Now()
		if err := repos.Certificate.UpdateCert(cert.ID, result.CertPEM, result.KeyPEM, &result.Expiry, &now); err != nil {
			c.JSON(500, map[string]string{"error": "renewed certificate but save failed: " + err.Error()})
			return
		}

		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": cert})
			return
		}
		c.JSON(200, map[string]interface{}{
			"message":    "certificate renewed successfully",
			"domain":     cert.Domain,
			"expires_at": result.Expiry,
		})
	}
}

// ACMEStatus 查询 ACME 证书状态。
func ACMEStatus(repos *repository.Repos) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certs, err := repos.Certificate.ListBySource(store.CertSourceACME)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}

		type certStatus struct {
			ID        uint       `json:"id"`
			Name      string     `json:"name"`
			Domain    string     `json:"domain"`
			ExpiresAt *time.Time `json:"expires_at"`
			AutoRenew bool       `json:"auto_renew"`
			Error     string     `json:"error,omitempty"`
		}

		var result []certStatus
		for _, cert := range certs {
			result = append(result, certStatus{
				ID:        cert.ID,
				Name:      cert.Name,
				Domain:    cert.Domain,
				ExpiresAt: cert.ExpiresAt,
				AutoRenew: cert.AutoRenew,
				Error:     cert.RenewError,
			})
		}

		c.JSON(200, map[string]interface{}{"items": result})
	}
}
