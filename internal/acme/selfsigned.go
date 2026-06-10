package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"time"
)

// SelfSignedCache 缓存自签证书以避免重复生成。
type SelfSignedCache struct {
	mu    sync.RWMutex
	certs map[string]*selfSignedEntry
}

type selfSignedEntry struct {
	cert   tls.Certificate
	expiry time.Time
}

// NewSelfSignedCache 创建自签证书缓存。
func NewSelfSignedCache() *SelfSignedCache {
	return &SelfSignedCache{
		certs: make(map[string]*selfSignedEntry),
	}
}

// GetOrCreate 获取或创建指定地址的自签证书。
// 当通过 IP:端口 直接访问 HTTPS 时使用此证书。
func (c *SelfSignedCache) GetOrCreate(addr string) (tls.Certificate, error) {
	cert, err := c.GetOrCreatePtr(addr)
	if err != nil {
		return tls.Certificate{}, err
	}
	return *cert, nil
}

// GetOrCreatePtr 获取或创建指定地址的自签证书，并返回缓存中的稳定指针。
func (c *SelfSignedCache) GetOrCreatePtr(addr string) (*tls.Certificate, error) {
	now := time.Now()
	c.mu.RLock()
	if entry, ok := c.certs[addr]; ok && now.Before(entry.expiry) {
		c.mu.RUnlock()
		return &entry.cert, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	if entry, ok := c.certs[addr]; ok && now.Before(entry.expiry) {
		c.mu.Unlock()
		return &entry.cert, nil
	}
	for key, entry := range c.certs {
		if !now.Before(entry.expiry) {
			delete(c.certs, key)
		}
	}
	cert, err := GenerateSelfSigned(addr)
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	entry := &selfSignedEntry{
		cert:   cert,
		expiry: now.Add(24 * time.Hour),
	}
	c.certs[addr] = entry
	c.mu.Unlock()

	return &entry.cert, nil
}

// GenerateSelfSigned 生成一个自签名 TLS 证书。
// 支持 IP 地址和域名。
func GenerateSelfSigned(addr string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"My-OpenWAF Self-Signed"},
			CommonName:   "My-OpenWAF",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 解析地址，提取 host 部分
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}

	// 判断是 IP 还是域名
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	// 始终添加 localhost 和 127.0.0.1
	template.IPAddresses = append(template.IPAddresses, net.IPv4(127, 0, 0, 1), net.IPv6loopback)
	template.DNSNames = append(template.DNSNames, "localhost")

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// GenerateSelfSignedPEM 生成自签名证书并返回 PEM 编码的证书和密钥。
func GenerateSelfSignedPEM(commonName string, dnsNames []string, ips []net.IP, validity time.Duration) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	if validity <= 0 {
		validity = 365 * 24 * time.Hour
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"My-OpenWAF"},
			CommonName:   commonName,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}

	certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return string(certPEMBytes), string(keyPEMBytes), nil
}
