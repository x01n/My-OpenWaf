package system

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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
	manager      acmeManager
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

type acmeManager interface {
	Register(context.Context) error
	ObtainCertificate(context.Context, string) (*acmepkg.CertificateResult, error)
	GetChallengeResponse(string) (string, bool)
}

// NewACMEManagerStore 创建 ACME manager 存储器。
func NewACMEManagerStore(settings *repository.SystemSettingsRepo, certificates *repository.CertificateRepo, reload func() error, log *slog.Logger) *ACMEManagerStore {
	if log == nil {
		log = slog.Default()
	}
	return &ACMEManagerStore{settings: settings, certificates: certificates, reload: reload, log: log}
}

/**
 * acmeErrorTextLimit 是 ACME 错误文本进入响应体或落库前的字节上限（含截断标记）。
 *
 * 取 512 与 store.Certificate.RenewError 的 `gorm:"size:512"` 对齐
 * （internal/store/certificate.go:38）：该列在 MySQL/PostgreSQL 上是定长约束，
 * 超长文本会被驱动静默截断或直接报错，先在这里收口可让响应体与落库值一致，
 * 不会出现「接口返回全文、库里只存前半截」的分歧。
 * internal/upstream/health.go 的 truncateStateError 对上游探测错误用的也是 512。
 */
const acmeErrorTextLimit = 512

// acmeErrorTruncatedSuffix 是截断标记，与 internal/dataplane 日志截断的写法保持一致。
const acmeErrorTruncatedSuffix = "...[truncated]"

/**
 * acmeErrorRedactPatterns 按顺序抹除 ACME/上游错误文本中的敏感片段。
 *
 * ACME 客户端会把上游的请求/响应片段包进 error，可能夹带账户私钥、证书私钥或
 * JWS 材料。三条规则分别覆盖：
 *  1. 完整 PEM 块（跨行，非贪婪，避免一次吞掉多个块之间的正常文本）；
 *  2. 只剩头部的残缺 PEM（上游自己已截断时，尾部 base64 仍是私钥前缀）；
 *  3. JWK 私钥参数与私钥/凭据样式的键值对。
 */
var acmeErrorRedactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?s)-----BEGIN[^-]*-----.*?-----END[^-]*-----`),
	regexp.MustCompile(`-----BEGIN[^-]*-----[\s\S]*`),
	regexp.MustCompile(`(?i)"(d|p|q|dp|dq|qi|k)"\s*:\s*"[^"]*"`),
	regexp.MustCompile(`(?i)(private[_-]?key|key[_-]?pem|account[_-]?key|secret[_-]?key|password|passwd|secret|token|credential)(["'\s:=]+)([^&,"'}\s]+)`),
}

// acmeErrorRedactReplacements 与 acmeErrorRedactPatterns 一一对应，下标必须同步。
var acmeErrorRedactReplacements = []string{
	"[redacted]",
	"[redacted]",
	`"${1}":"[redacted]"`,
	"${1}${2}[redacted]",
}

/**
 * sanitizeACMEErrorText 抹除敏感片段并把错误文本收敛到 acmeErrorTextLimit 内。
 *
 * 顺序是「先脱敏、再折叠空白、最后截断」，三步都不能换位：先截断会把 PEM 块切成
 * 半截，残留的 base64 依然是私钥内容；折叠空白放在脱敏之后，才不会先破坏 PEM 的
 * 行结构导致规则漏匹配，同时让 512 字节容纳更多有效诊断信息。
 *
 * @param raw 上游或本地错误的原始文本。
 * @return 脱敏且长度不超过 acmeErrorTextLimit 的合法 UTF-8 文本。
 */
func sanitizeACMEErrorText(raw string) string {
	if raw == "" {
		return ""
	}
	for i, pattern := range acmeErrorRedactPatterns {
		raw = pattern.ReplaceAllString(raw, acmeErrorRedactReplacements[i])
	}
	raw = strings.Join(strings.Fields(raw), " ")
	return truncateACMEErrorText(raw, acmeErrorTextLimit)
}

/**
 * truncateACMEErrorText 按 rune 边界截断，保证结果长度不超过 limit 且仍是合法 UTF-8。
 *
 * 预算里已扣掉截断标记，因此返回值整体（含标记）不会突破 limit，可以直接落到
 * size:512 的列上。切点落在多字节字符中间时向前回退到最近的 rune 起始字节。
 *
 * @param s     待截断文本。
 * @param limit 输出的字节上限，含截断标记。
 * @return 不超过 limit 字节的文本。
 */
func truncateACMEErrorText(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	if limit <= 0 {
		return ""
	}
	budget := limit - len(acmeErrorTruncatedSuffix)
	if budget <= 0 {
		// 预算装不下标记本身时退化为截断标记的前缀，仍不突破 limit。
		return acmeErrorTruncatedSuffix[:limit]
	}
	cut := budget
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + acmeErrorTruncatedSuffix
}

func defaultACMEConfig() ACMEConfig {
	return ACMEConfig{
		DirectoryURL:      acmepkg.DefaultDirectoryURL,
		AutoRenew:         true,
		RenewBeforeDays:   30,
		CAAAllowedIssuers: acmepkg.DefaultCAAAllowedIssuer,
	}
}

func acmeManagerCacheKey(cfg ACMEConfig) string {
	return strings.Join([]string{
		cfg.Email,
		cfg.DirectoryURL,
		fmt.Sprintf("%t", cfg.CAACheckEnabled),
		cfg.CAAAllowedIssuers,
		cfg.CAADNSServer,
	}, "\n")
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

func (s *ACMEManagerStore) Manager() (acmeManager, ACMEConfig, error) {
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
	key := acmeManagerCacheKey(cfg)

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
		// 与手动续期同一暴露面：renew_error 会被 ACMEStatus 回显，落库前先脱敏截断。
		return s.certificates.UpdateRenewStatus(cert.ID, sanitizeACMEErrorText(renewErr.Error()), &now)
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
			_ = s.certificates.UpdateRenewStatus(item.ID, sanitizeACMEErrorText(err.Error()), &now)
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
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
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
				c.JSON(500, map[string]string{"error": "generate ACME email failed: " + sanitizeACMEErrorText(err.Error())})
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
			c.JSON(500, map[string]string{"error": sanitizeACMEErrorText(err.Error())})
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
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
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
			c.JSON(500, map[string]string{"error": "load enabled sites failed: " + sanitizeACMEErrorText(err.Error())})
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
			c.JSON(500, map[string]string{"error": "generate ACME email failed: " + sanitizeACMEErrorText(err.Error())})
			return
		}
		cfg.Email = email
		cfg.Enabled = true
		if err := saveACMEConfig(repos.SystemSettings, cfg); err != nil {
			c.JSON(500, map[string]string{"error": "save ACME config failed: " + sanitizeACMEErrorText(err.Error())})
			return
		}
		acmeMgr, cfg, err := acmeStore.Manager()
		if err != nil {
			c.JSON(500, map[string]string{"error": "ACME manager not initialized: " + sanitizeACMEErrorText(err.Error())})
			return
		}

		if err := acmeMgr.Register(ctx); err != nil {
			c.JSON(500, map[string]string{"error": "ACME register failed: " + sanitizeACMEErrorText(err.Error())})
			return
		}

		result, err := acmeMgr.ObtainCertificate(ctx, domain)
		if err != nil {
			c.JSON(500, map[string]string{"error": "certificate obtain failed: " + sanitizeACMEErrorText(err.Error())})
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
				c.JSON(500, map[string]string{"error": "update certificate failed: " + sanitizeACMEErrorText(err.Error())})
				return
			}
		} else if errors.Is(err, gorm.ErrRecordNotFound) {
			if err := repos.Certificate.Create(&cert); err != nil {
				c.JSON(500, map[string]string{"error": "save certificate failed: " + sanitizeACMEErrorText(err.Error())})
				return
			}
		} else {
			c.JSON(500, map[string]string{"error": "load existing certificate failed: " + sanitizeACMEErrorText(err.Error())})
			return
		}

		siteIDs := make([]uint, 0, len(matches))
		for _, match := range matches {
			siteIDs = append(siteIDs, match.ID)
		}
		siteCount, err := repos.Site.ApplyCertificate(siteIDs, cert.ID)
		if err != nil {
			c.JSON(500, map[string]string{"error": "apply certificate to sites failed: " + sanitizeACMEErrorText(err.Error())})
			return
		}
		listenerCount, err := repos.SiteListener.ApplyCertificateToTLSListeners(siteIDs, cert.ID)
		if err != nil {
			c.JSON(500, map[string]string{"error": "apply certificate to listeners failed: " + sanitizeACMEErrorText(err.Error())})
			return
		}

		// 必须先脱敏再 reload：下面的 500 分支会回显 cert，顺序颠倒会漏出私钥。
		redactCertificatePrivateKey(&cert)
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + sanitizeACMEErrorText(err.Error()), "item": cert, "applied_sites": matches})
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
			c.JSON(500, map[string]string{"error": "ACME manager not initialized: " + sanitizeACMEErrorText(err.Error())})
			return
		}

		// 注册帐户（幂等）
		if err := acmeMgr.Register(ctx); err != nil {
			c.JSON(500, map[string]string{"error": "ACME register failed: " + sanitizeACMEErrorText(err.Error())})
			return
		}

		result, err := acmeMgr.ObtainCertificate(ctx, cert.Domain)
		if err != nil {
			// 记录错误。renew_error 会由 ACMEStatus 与证书 list/get 回显，
			// 故落库与响应体用同一份脱敏文本，避免库里留下未脱敏的上游片段。
			now := time.Now()
			renewErr := sanitizeACMEErrorText(err.Error())
			if statusErr := repos.Certificate.UpdateRenewStatus(cert.ID, renewErr, &now); statusErr != nil {
				c.JSON(500, map[string]string{"error": "renew failed: " + renewErr + "; update renew status failed: " + sanitizeACMEErrorText(statusErr.Error())})
				return
			}
			c.JSON(500, map[string]string{"error": "renew failed: " + renewErr})
			return
		}

		// 更新证书
		now := time.Now()
		if err := repos.Certificate.UpdateCert(cert.ID, result.CertPEM, result.KeyPEM, &result.Expiry, &now); err != nil {
			c.JSON(500, map[string]string{"error": "renewed certificate but save failed: " + sanitizeACMEErrorText(err.Error())})
			return
		}

		// 必须先脱敏再 reload：下面的 500 分支会回显 cert，顺序颠倒会漏出私钥。
		redactCertificatePrivateKey(cert)
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + sanitizeACMEErrorText(err.Error()), "item": cert})
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
			c.JSON(500, map[string]string{"error": sanitizeACMEErrorText(err.Error())})
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
				// 落库前已脱敏；这里再过一次是为了兜住本次改动之前写入的历史 renew_error。
				Error: sanitizeACMEErrorText(cert.RenewError),
			})
		}

		c.JSON(200, map[string]interface{}{"items": result})
	}
}
