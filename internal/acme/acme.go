package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// CertificateResult 表示成功申请的证书。
type CertificateResult struct {
	Domain  string
	CertPEM string
	KeyPEM  string
	Expiry  time.Time
}

// Manager 管理 ACME 证书的申请和续期。
type Manager struct {
	mu           sync.Mutex
	client       *acme.Client
	accountKey   crypto.Signer
	email        string
	directoryURL string
	log          *slog.Logger

	// HTTP-01 质询令牌存储
	challenges  map[string]string
	challengeMu sync.RWMutex

	// 证书续期回调
	onRenew func(domain, certPEM, keyPEM string, expiry time.Time, renewErr error) error
}

// Config ACME 管理器配置。
type Config struct {
	Email        string
	DirectoryURL string // 默认 Let's Encrypt 生产环境
	Log          *slog.Logger
	OnRenew      func(domain, certPEM, keyPEM string, expiry time.Time, renewErr error) error
}

// DefaultDirectoryURL Let's Encrypt 生产环境 URL。
const DefaultDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"

// StagingDirectoryURL Let's Encrypt 测试环境 URL。
const StagingDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

// NewManager 创建新的 ACME 管理器。
func NewManager(cfg Config) (*Manager, error) {
	if cfg.DirectoryURL == "" {
		cfg.DirectoryURL = DefaultDirectoryURL
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}

	// 生成 ACME 帐户密钥
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate account key: %w", err)
	}

	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: cfg.DirectoryURL,
	}

	m := &Manager{
		client:       client,
		accountKey:   accountKey,
		email:        cfg.Email,
		directoryURL: cfg.DirectoryURL,
		log:          cfg.Log,
		challenges:   make(map[string]string),
		onRenew:      cfg.OnRenew,
	}

	return m, nil
}

func (m *Manager) Email() string {
	return m.email
}

// Register 注册 ACME 帐户。
func (m *Manager) Register(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	account := &acme.Account{
		Contact: []string{"mailto:" + m.email},
	}
	_, err := m.client.Register(ctx, account, acme.AcceptTOS)
	if err != nil && !isAlreadyRegistered(err) {
		return fmt.Errorf("acme register: %w", err)
	}
	m.log.Info("ACME 帐户注册成功", slog.String("email", m.email))
	return nil
}

// ObtainCertificate 为指定域名申请证书（HTTP-01 质询）。
func (m *Manager) ObtainCertificate(ctx context.Context, domain string) (*CertificateResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.log.Info("开始申请证书", slog.String("domain", domain))

	// 创建订单
	order, err := m.client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return nil, fmt.Errorf("authorize order: %w", err)
	}

	// 处理每个授权
	for _, authURL := range order.AuthzURLs {
		auth, err := m.client.GetAuthorization(ctx, authURL)
		if err != nil {
			return nil, fmt.Errorf("get authorization: %w", err)
		}

		if auth.Status == acme.StatusValid {
			continue
		}

		// 查找 HTTP-01 质询
		var chal *acme.Challenge
		for _, c := range auth.Challenges {
			if c.Type == "http-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return nil, errors.New("no http-01 challenge found")
		}

		// 准备质询响应
		response, err := m.client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return nil, fmt.Errorf("challenge response: %w", err)
		}

		// 存储质询令牌
		m.challengeMu.Lock()
		m.challenges[chal.Token] = response
		m.challengeMu.Unlock()

		defer func(token string) {
			m.challengeMu.Lock()
			delete(m.challenges, token)
			m.challengeMu.Unlock()
		}(chal.Token)

		// 通知 ACME 服务器我们已准备好
		if _, err := m.client.Accept(ctx, chal); err != nil {
			return nil, fmt.Errorf("accept challenge: %w", err)
		}

		// 等待授权完成
		if _, err := m.client.WaitAuthorization(ctx, authURL); err != nil {
			return nil, fmt.Errorf("wait authorization: %w", err)
		}
	}

	// 生成证书私钥
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate cert key: %w", err)
	}

	// 创建 CSR
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{domain},
	}, certKey)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	// 完成订单并获取证书
	derChain, _, err := m.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("create order cert: %w", err)
	}

	// 编码证书 PEM
	var certBuf strings.Builder
	for _, der := range derChain {
		pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}

	// 编码私钥 PEM
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// 解析过期时间
	cert, err := x509.ParseCertificate(derChain[0])
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	result := &CertificateResult{
		Domain:  domain,
		CertPEM: certBuf.String(),
		KeyPEM:  string(keyPEM),
		Expiry:  cert.NotAfter,
	}

	m.log.Info("证书申请成功",
		slog.String("domain", domain),
		slog.Time("expiry", result.Expiry),
	)

	return result, nil
}

// HandleHTTP01Challenge 处理 HTTP-01 质询请求。
// 应当挂载到 /.well-known/acme-challenge/ 路径。
func (m *Manager) HandleHTTP01Challenge(w http.ResponseWriter, r *http.Request) bool {
	token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
	if token == "" || token == r.URL.Path {
		return false
	}

	m.challengeMu.RLock()
	response, ok := m.challenges[token]
	m.challengeMu.RUnlock()

	if !ok {
		return false
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))
	return true
}

// GetChallengeResponse 返回指定令牌的质询响应（用于与 Hertz 集成）。
func (m *Manager) GetChallengeResponse(token string) (string, bool) {
	m.challengeMu.RLock()
	defer m.challengeMu.RUnlock()
	response, ok := m.challenges[token]
	return response, ok
}

// RenewLoop 启动证书续期循环。
func (m *Manager) RenewLoop(ctx context.Context, domains []string, checkInterval time.Duration) {
	m.RenewLoopFunc(ctx, checkInterval, func(context.Context) ([]string, error) {
		return domains, nil
	})
}

// RenewLoopFunc 启动证书续期循环，并在每次 tick 时动态获取域名列表。
func (m *Manager) RenewLoopFunc(ctx context.Context, checkInterval time.Duration, domains func(context.Context) ([]string, error)) {
	if checkInterval <= 0 {
		checkInterval = 12 * time.Hour
	}

	if err := m.Register(ctx); err != nil {
		m.log.Warn("ACME 帐户注册失败，续期循环将继续重试", slog.Any("err", err))
	}
	m.runRenewTick(ctx, domains)

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.runRenewTick(ctx, domains)
		}
	}
}

func (m *Manager) runRenewTick(ctx context.Context, domains func(context.Context) ([]string, error)) {
	items, err := domains(ctx)
	if err != nil {
		m.log.Error("加载待续期证书失败", slog.Any("err", err))
		return
	}
	for _, domain := range items {
		if domain == "" {
			continue
		}
		m.tryRenew(ctx, domain)
	}
}

func (m *Manager) tryRenew(ctx context.Context, domain string) {
	if err := m.Register(ctx); err != nil {
		m.log.Warn("ACME 帐户注册失败", slog.String("domain", domain), slog.Any("err", err))
		return
	}

	result, err := m.ObtainCertificate(ctx, domain)
	if err != nil {
		m.log.Warn("证书续期失败", slog.String("domain", domain), slog.Any("err", err))
		if m.onRenew != nil {
			if hookErr := m.onRenew(domain, "", "", time.Time{}, err); hookErr != nil {
				m.log.Error("证书续期失败回调失败", slog.String("domain", domain), slog.Any("err", hookErr))
			}
		}
		return
	}

	if m.onRenew != nil {
		if err := m.onRenew(domain, result.CertPEM, result.KeyPEM, result.Expiry, nil); err != nil {
			m.log.Error("证书续期回调失败", slog.String("domain", domain), slog.Any("err", err))
		}
	}
}

func isAlreadyRegistered(err error) bool {
	if err == nil {
		return false
	}
	var ae *acme.Error
	if errors.As(err, &ae) {
		return ae.StatusCode == 409
	}
	return false
}
