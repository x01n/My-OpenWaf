package system

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"gorm.io/gorm"

	acmepkg "My-OpenWaf/internal/acme"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// ACMEConfig ACME 证书申请配置。
type ACMEConfig struct {
	Enabled           bool   `json:"enabled"`
	Email             string `json:"email"`
	DirectoryURL      string `json:"directory_url"`
	AutoRenew         bool   `json:"auto_renew"`
	RenewBeforeDays   int    `json:"renew_before_days"`
	CAACheckEnabled   bool   `json:"caa_check_enabled"`
	CAAAllowedIssuers string `json:"caa_allowed_issuers"`
	CAADNSServer      string `json:"caa_dns_server"`
}

// ACMEManagerStore 维护当前进程可重载的 ACME manager。
type ACMEManagerStore struct {
	mu           sync.RWMutex
	settings     *repository.SystemSettingsRepo
	certificates *repository.CertificateRepo
	reload       func() error
	log          *slog.Logger
	manager      *acmepkg.Manager
	cacheKey     string
}

// acmeRequest ACME 证书申请请求体。
type acmeRequest struct {
	Domain string `json:"domain"`
	Email  string `json:"email"`
	Name   string `json:"name"`
}

type acmeMatchedSite struct {
	ID          uint   `json:"id"`
	Host        string `json:"host"`
	TLSEnabled  bool   `json:"tls_enabled"`
	CertID      *uint  `json:"cert_id,omitempty"`
	MatchedName string `json:"matched_name"`
}

type acmeApplyResponse struct {
	store.Certificate
	AppliedSites  []acmeMatchedSite `json:"applied_sites"`
	SiteCount     int64             `json:"site_count"`
	ListenerCount int64             `json:"listener_count"`
}

// NewACMEManagerStore 创建 ACME manager 存储器。
func NewACMEManagerStore(settings *repository.SystemSettingsRepo, certificates *repository.CertificateRepo, reload func() error, log *slog.Logger) *ACMEManagerStore {
	if log == nil {
		log = slog.Default()
	}
	return &ACMEManagerStore{settings: settings, certificates: certificates, reload: reload, log: log}
}

func defaultACMEConfig() ACMEConfig {
	return ACMEConfig{
		DirectoryURL:      acmepkg.DefaultDirectoryURL,
		AutoRenew:         true,
		RenewBeforeDays:   30,
		CAAAllowedIssuers: acmepkg.DefaultCAAAllowedIssuer,
	}
}

func loadACMEConfig(repo *repository.SystemSettingsRepo) ACMEConfig {
	cfg := defaultACMEConfig()
	val, err := repo.Get(store.SettingKeyACMEConfig)
	if err != nil || val == "" {
		return cfg
	}
	_ = json.Unmarshal([]byte(val), &cfg)
	cfg.Email = strings.TrimSpace(cfg.Email)
	cfg.DirectoryURL = strings.TrimSpace(cfg.DirectoryURL)
	cfg.CAAAllowedIssuers = strings.TrimSpace(cfg.CAAAllowedIssuers)
	cfg.CAADNSServer = strings.TrimSpace(cfg.CAADNSServer)
	if cfg.DirectoryURL == "" {
		cfg.DirectoryURL = acmepkg.DefaultDirectoryURL
	}
	if cfg.RenewBeforeDays <= 0 {
		cfg.RenewBeforeDays = 30
	}
	if cfg.CAAAllowedIssuers == "" {
		cfg.CAAAllowedIssuers = acmepkg.DefaultCAAAllowedIssuer
	}
	return cfg
}

func saveACMEConfig(repo *repository.SystemSettingsRepo, cfg ACMEConfig) error {
	cfg.Email = strings.TrimSpace(cfg.Email)
	cfg.DirectoryURL = strings.TrimSpace(cfg.DirectoryURL)
	cfg.CAAAllowedIssuers = strings.TrimSpace(cfg.CAAAllowedIssuers)
	cfg.CAADNSServer = strings.TrimSpace(cfg.CAADNSServer)
	if cfg.DirectoryURL == "" {
		cfg.DirectoryURL = acmepkg.DefaultDirectoryURL
	}
	if cfg.RenewBeforeDays <= 0 {
		cfg.RenewBeforeDays = 30
	}
	if cfg.CAAAllowedIssuers == "" {
		cfg.CAAAllowedIssuers = acmepkg.DefaultCAAAllowedIssuer
	}
	data, _ := json.Marshal(cfg)
	return repo.Set(store.SettingKeyACMEConfig, string(data))
}

func randomACMEEmail(domain string) (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	emailDomain := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "*."), ".")
	if emailDomain == "" {
		emailDomain = "my-openwaf.local"
	}
	return "acme-" + hex.EncodeToString(raw[:]) + "@" + emailDomain, nil
}

func resolveACMEEmail(domain, requestEmail string) (string, error) {
	if email := strings.TrimSpace(requestEmail); email != "" {
		return email, nil
	}
	return randomACMEEmail(domain)
}

func matchACMESites(sites []store.Site, domain string) []acmeMatchedSite {
	domain = strings.ToLower(strings.TrimSpace(domain))
	matches := make([]acmeMatchedSite, 0)
	seen := make(map[uint]struct{})
	for _, site := range sites {
		if !site.Enabled {
			continue
		}
		for _, host := range splitSiteHosts(site.Host) {
			matched := certificateNameMatchesHost(domain, host) || certificateNameMatchesHost(host, domain)
			if !matched {
				continue
			}
			if _, ok := seen[site.ID]; ok {
				continue
			}
			seen[site.ID] = struct{}{}
			matches = append(matches, acmeMatchedSite{
				ID:          site.ID,
				Host:        site.Host,
				TLSEnabled:  site.TLSEnabled,
				CertID:      site.CertID,
				MatchedName: host,
			})
		}
	}
	return matches
}

func (s *ACMEManagerStore) Manager() (*acmepkg.Manager, ACMEConfig, error) {
	if s == nil || s.settings == nil {
		return nil, ACMEConfig{}, errors.New("ACME manager store is not initialized")
	}
	cfg := loadACMEConfig(s.settings)
	if !cfg.Enabled {
		return nil, cfg, errors.New("ACME is disabled")
	}
	if cfg.Email == "" {
		email, err := randomACMEEmail("")
		if err != nil {
			return nil, cfg, fmt.Errorf("generate ACME email: %w", err)
		}
		cfg.Email = email
		if err := saveACMEConfig(s.settings, cfg); err != nil {
			return nil, cfg, fmt.Errorf("save ACME config: %w", err)
		}
	}
	key := strings.Join([]string{
		cfg.Email,
		cfg.DirectoryURL,
		fmt.Sprintf("%t", cfg.CAACheckEnabled),
		cfg.CAAAllowedIssuers,
		cfg.CAADNSServer,
	}, "\n")

	s.mu.RLock()
	mgr := s.manager
	cacheKey := s.cacheKey
	s.mu.RUnlock()
	if mgr != nil && cacheKey == key {
		return mgr, cfg, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.manager != nil && s.cacheKey == key {
		return s.manager, cfg, nil
	}
	next, err := acmepkg.NewManager(acmepkg.Config{
		Email:        cfg.Email,
		DirectoryURL: cfg.DirectoryURL,
		Log:          s.log,
		OnRenew:      s.onRenew,
		CAAPolicy: acmepkg.CAAPolicy{
			Enabled:        cfg.CAACheckEnabled,
			AllowedIssuers: []string{cfg.CAAAllowedIssuers},
			DNSServer:      cfg.CAADNSServer,
		},
	})
	if err != nil {
		return nil, cfg, err
	}
	s.manager = next
	s.cacheKey = key
	return next, cfg, nil
}

func (s *ACMEManagerStore) onRenew(domain, certPEM, keyPEM string, expiry time.Time, renewErr error) error {
	cert, err := s.certificates.GetByDomain(domain)
	if err != nil {
		return fmt.Errorf("load certificate by domain %s: %w", domain, err)
	}
	now := time.Now()
	if renewErr != nil {
		return s.certificates.UpdateRenewStatus(cert.ID, renewErr.Error(), &now)
	}
	if err := s.certificates.UpdateCert(cert.ID, certPEM, keyPEM, &expiry, &now); err != nil {
		return fmt.Errorf("update renewed certificate %s: %w", domain, err)
	}
	if s.reload != nil {
		if err := s.reload(); err != nil {
			return fmt.Errorf("reload after renewing %s: %w", domain, err)
		}
	}
	return nil
}

func (s *ACMEManagerStore) GetChallengeResponse(token string) (string, bool) {
	if s == nil {
		return "", false
	}
	s.mu.RLock()
	mgr := s.manager
	s.mu.RUnlock()
	if mgr == nil {
		if next, _, err := s.Manager(); err == nil {
			mgr = next
		}
	}
	if mgr == nil {
		return "", false
	}
	return mgr.GetChallengeResponse(token)
}

func (s *ACMEManagerStore) RenewLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		s.renewDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *ACMEManagerStore) renewDue(ctx context.Context) {
	mgr, cfg, err := s.Manager()
	if err != nil || !cfg.AutoRenew {
		return
	}
	items, err := s.certificates.ListAutoRenew()
	if err != nil {
		s.log.Warn("加载待续期证书失败", slog.Any("err", err))
		return
	}
	for _, item := range items {
		if item.Domain == "" || item.ExpiresAt == nil {
			continue
		}
		if time.Until(*item.ExpiresAt) > time.Duration(cfg.RenewBeforeDays)*24*time.Hour {
			continue
		}
		if err := mgr.Register(ctx); err != nil {
			s.log.Warn("ACME 帐户注册失败", slog.String("domain", item.Domain), slog.Any("err", err))
			continue
		}
		result, err := mgr.ObtainCertificate(ctx, item.Domain)
		if err != nil {
			now := time.Now()
			_ = s.certificates.UpdateRenewStatus(item.ID, err.Error(), &now)
			continue
		}
		now := time.Now()
		if err := s.certificates.UpdateCert(item.ID, result.CertPEM, result.KeyPEM, &result.Expiry, &now); err != nil {
			s.log.Warn("保存续期证书失败", slog.String("domain", item.Domain), slog.Any("err", err))
			continue
		}
		if s.reload != nil {
			if err := s.reload(); err != nil {
				s.log.Warn("续期后重载失败", slog.String("domain", item.Domain), slog.Any("err", err))
			}
		}
	}
}

// GetACMEConfig 获取 ACME 配置。
func GetACMEConfig(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, loadACMEConfig(repo))
	}
}

// UpdateACMEConfig 更新 ACME 配置。
func UpdateACMEConfig(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			Enabled           *bool   `json:"enabled"`
			Email             *string `json:"email"`
			DirectoryURL      *string `json:"directory_url"`
			AutoRenew         *bool   `json:"auto_renew"`
			RenewBeforeDays   *int    `json:"renew_before_days"`
			CAACheckEnabled   *bool   `json:"caa_check_enabled"`
			CAAAllowedIssuers *string `json:"caa_allowed_issuers"`
			CAADNSServer      *string `json:"caa_dns_server"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		cfg := loadACMEConfig(repo)
		if req.Enabled != nil {
			cfg.Enabled = *req.Enabled
		}
		if req.Email != nil {
			cfg.Email = strings.TrimSpace(*req.Email)
		}
		if req.DirectoryURL != nil {
			cfg.DirectoryURL = strings.TrimSpace(*req.DirectoryURL)
		}
		if req.AutoRenew != nil {
			cfg.AutoRenew = *req.AutoRenew
		}
		if req.RenewBeforeDays != nil {
			cfg.RenewBeforeDays = *req.RenewBeforeDays
		}
		if req.CAACheckEnabled != nil {
			cfg.CAACheckEnabled = *req.CAACheckEnabled
		}
		if req.CAAAllowedIssuers != nil {
			cfg.CAAAllowedIssuers = strings.TrimSpace(*req.CAAAllowedIssuers)
		}
		if req.CAADNSServer != nil {
			cfg.CAADNSServer = strings.TrimSpace(*req.CAADNSServer)
		}
		if cfg.Enabled && cfg.Email == "" {
			email, err := randomACMEEmail("")
			if err != nil {
				c.JSON(500, map[string]string{"error": "generate ACME email failed: " + err.Error()})
				return
			}
			cfg.Email = email
		}
		if cfg.RenewBeforeDays <= 0 {
			c.JSON(400, map[string]string{"error": "renew_before_days must be > 0"})
			return
		}
		if cfg.CAACheckEnabled {
			if strings.TrimSpace(cfg.CAADNSServer) == "" {
				c.JSON(400, map[string]string{"error": "caa_dns_server is required when caa_check_enabled is true"})
				return
			}
			if strings.TrimSpace(cfg.CAAAllowedIssuers) == "" {
				c.JSON(400, map[string]string{"error": "caa_allowed_issuers is required when caa_check_enabled is true"})
				return
			}
		}
		if err := saveACMEConfig(repo, cfg); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, cfg)
	}
}

// ACMEApply 申请 Let's Encrypt 证书（HTTP-01 质询）。
func ACMEApply(repos *repository.Repos, reload func() error, acmeStore *ACMEManagerStore) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req acmeRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}

		domain := strings.ToLower(strings.TrimSpace(req.Domain))
		if domain == "" {
			c.JSON(400, map[string]string{"error": "domain is required"})
			return
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = domain
		}

		sites, err := repos.Site.FindEnabled()
		if err != nil {
			c.JSON(500, map[string]string{"error": "load enabled sites failed: " + err.Error()})
			return
		}
		matches := matchACMESites(sites, domain)
		if len(matches) == 0 {
			c.JSON(400, map[string]string{"error": "domain does not match any enabled site host"})
			return
		}

		cfg := loadACMEConfig(repos.SystemSettings)
		email, err := resolveACMEEmail(domain, req.Email)
		if err != nil {
			c.JSON(500, map[string]string{"error": "generate ACME email failed: " + err.Error()})
			return
		}
		cfg.Email = email
		cfg.Enabled = true
		if err := saveACMEConfig(repos.SystemSettings, cfg); err != nil {
			c.JSON(500, map[string]string{"error": "save ACME config failed: " + err.Error()})
			return
		}
		acmeMgr, cfg, err := acmeStore.Manager()
		if err != nil {
			c.JSON(500, map[string]string{"error": "ACME manager not initialized: " + err.Error()})
			return
		}

		if err := acmeMgr.Register(ctx); err != nil {
			c.JSON(500, map[string]string{"error": "ACME register failed: " + err.Error()})
			return
		}

		result, err := acmeMgr.ObtainCertificate(ctx, domain)
		if err != nil {
			c.JSON(500, map[string]string{"error": "certificate obtain failed: " + err.Error()})
			return
		}

		now := time.Now()
		cert := store.Certificate{
			Name:        name,
			CertPEM:     result.CertPEM,
			KeyPEM:      result.KeyPEM,
			Source:      store.CertSourceACME,
			Domain:      domain,
			ACMEEmail:   cfg.Email,
			ExpiresAt:   &result.Expiry,
			AutoRenew:   true,
			LastRenewAt: &now,
		}

		existing, err := repos.Certificate.GetByDomain(domain)
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

		siteIDs := make([]uint, 0, len(matches))
		for _, match := range matches {
			siteIDs = append(siteIDs, match.ID)
		}
		siteCount, err := repos.Site.ApplyCertificate(siteIDs, cert.ID)
		if err != nil {
			c.JSON(500, map[string]string{"error": "apply certificate to sites failed: " + err.Error()})
			return
		}
		listenerCount, err := repos.SiteListener.ApplyCertificateToTLSListeners(siteIDs, cert.ID)
		if err != nil {
			c.JSON(500, map[string]string{"error": "apply certificate to listeners failed: " + err.Error()})
			return
		}

		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": cert, "applied_sites": matches})
			return
		}
		c.JSON(200, acmeApplyResponse{Certificate: cert, AppliedSites: matches, SiteCount: siteCount, ListenerCount: listenerCount})
	}
}

// ACMERenew 手动触发证书续期。
func ACMERenew(repos *repository.Repos, reload func() error, acmeStore *ACMEManagerStore) app.HandlerFunc {
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

		acmeMgr, _, err := acmeStore.Manager()
		if err != nil {
			c.JSON(500, map[string]string{"error": "ACME manager not initialized: " + err.Error()})
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
