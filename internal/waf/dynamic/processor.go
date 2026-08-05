// Package dynamic 实现 WAF 动态防护功能，包括 HTML/JS AES-256-GCM 加密和图片水印。
package dynamic

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
)

// KeyTicketSigner 为每个动态保护信封签发密钥兑换票据。
type KeyTicketSigner func(key string, ttl int, kekB64 string) string

// ProtectionConfig 是动态防护的运行时配置。
type ProtectionConfig struct {
	HTMLObfuscationEnabled bool   `json:"html_obfuscation_enabled"`
	JSObfuscationEnabled   bool   `json:"js_obfuscation_enabled"`
	ImageWatermarkEnabled  bool   `json:"image_watermark_enabled"`
	JSProtectionMode       string `json:"js_protection_mode,omitempty"` // "all" 或 "paths"
	// JSObfuscationPaths 是需要进行 JS 加密的资源路径模式
	JSObfuscationPaths []string `json:"js_obfuscation_paths,omitempty"`
	// ImageWatermarkPaths 是需要添加水印的图片路径模式
	ImageWatermarkPaths []string `json:"image_watermark_paths,omitempty"`
	// WatermarkText 是水印文字内容
	WatermarkText string `json:"watermark_text,omitempty"`
	// EncryptionKeyBase 基础密钥材料（32 字节，由 snapshot 管理）
	EncryptionKeyBase []byte `json:"-"`
	// DecryptCacheTTLSeconds 客户端解密缓存时间（秒）
	DecryptCacheTTLSeconds int `json:"decrypt_cache_ttl_seconds,omitempty"`
	// SiteID 站点标识（用于密钥派生隔离）
	SiteID uint `json:"site_id,omitempty"`
}

// Processor 是动态防护处理器。
type Processor struct {
	cfg        ProtectionConfig
	cek        []byte // Content Encryption Key (AES-256)
	kek        []byte // Key Encryption Key（用于包装 CEK 交付给客户端）
	signTicket KeyTicketSigner
}

// derivedKeys 是一组站点密钥。缓存后按值共享，故内容不可修改。
type derivedKeys struct {
	cek []byte
	kek []byte
}

// keyCacheKey 标识一组站点密钥。
//
// EncryptionKeyBase 以 string 承载（Go 中 string 可比较且 []byte→string 只是一次
// 小额复制，比再算一次摘要便宜）。
type keyCacheKey struct {
	base   string
	siteID uint
}

// keyCacheMaxEntries 是密钥缓存的条目上限。
//
// 键的数量约等于「站点数 × 配置变体数」，本身有界；设上限只为防御异常场景
// （例如快照反复重建导致 base 不断变化）下的无界增长。超限即整体清空重建，
// 代价仅是下一批请求重新派生一次。
const keyCacheMaxEntries = 1024

var (
	keyCacheMu sync.RWMutex
	keyCache   = make(map[keyCacheKey]derivedKeys, 16)
)

/**
 * lookupDerivedKeys 返回站点密钥，命中缓存时跳过 HKDF 派生。
 *
 * 密钥派生要跑两次 HKDF-SHA256，而响应转换器对每个响应都会构造一次
 * Processor，该开销在 pprof 中是最大的单点分配来源。配置在快照周期内不变，故可缓存。
 *
 * @param cfg 动态防护配置，调用方必须先验证 EncryptionKeyBase 为 32 字节。
 * @return 该配置对应的 CEK/KEK。
 */
func lookupDerivedKeys(cfg ProtectionConfig) derivedKeys {
	k := keyCacheKey{
		base:   string(cfg.EncryptionKeyBase),
		siteID: cfg.SiteID,
	}

	keyCacheMu.RLock()
	keys, ok := keyCache[k]
	keyCacheMu.RUnlock()
	if ok {
		return keys
	}

	keys = derivedKeys{
		cek: deriveKey(cfg.EncryptionKeyBase, fmt.Sprintf("owaf-brp/1:cek:site:%d", cfg.SiteID), 32),
		kek: deriveKey(cfg.EncryptionKeyBase, fmt.Sprintf("owaf-brp/1:kek:site:%d", cfg.SiteID), 32),
	}

	keyCacheMu.Lock()
	if len(keyCache) >= keyCacheMaxEntries {
		keyCache = make(map[keyCacheKey]derivedKeys, 16)
	}
	keyCache[k] = keys
	keyCacheMu.Unlock()
	return keys
}

// NewProcessor 创建一个新的动态防护处理器。
// 密钥经进程内缓存复用，避免每个响应都重跑 HKDF 派生。
func NewProcessor(cfg ProtectionConfig) *Processor {
	return NewProcessorWithKeyTicketSigner(cfg, nil)
}

func NewProcessorWithKeyTicketSigner(cfg ProtectionConfig, signer KeyTicketSigner) *Processor {
	keys := lookupDerivedKeys(cfg)
	return &Processor{cfg: cfg, cek: keys.cek, kek: keys.kek, signTicket: signer}
}

// ProcessHTML 对 HTML 响应进行 AES-256-GCM 加密保护。
func (p *Processor) ProcessHTML(html []byte) ([]byte, error) {
	if !p.cfg.HTMLObfuscationEnabled {
		return html, nil
	}
	return p.encryptHTML(html)
}

// ProcessHTMLWithScriptNonce encrypts HTML and returns the nonce used by the bootstrap script.
func (p *Processor) ProcessHTMLWithScriptNonce(html []byte) ([]byte, string, error) {
	if !p.cfg.HTMLObfuscationEnabled {
		return html, "", nil
	}
	env, err := p.makeEnvelope(html)
	if err != nil {
		return html, "", err
	}
	nonce := randomNonceB64()
	result, err := renderHTMLBootstrap(env, nonce)
	if err != nil {
		return html, "", err
	}
	return result, nonce, nil
}

// ProcessJS 对 JS 响应进行 AES-256-GCM 加密保护。
func (p *Processor) ProcessJS(path string, js []byte) ([]byte, error) {
	if !p.cfg.JSObfuscationEnabled {
		return js, nil
	}
	mode := p.cfg.JSProtectionMode
	if mode == "" {
		mode = "all"
	}
	if mode == "paths" && !matchPathPatterns(path, p.cfg.JSObfuscationPaths) {
		return js, nil
	}
	return p.encryptJS(js)
}

// ProcessImage 对图片响应进行处理（添加水印）。
func (p *Processor) ProcessImage(path string, img []byte) ([]byte, error) {
	if !p.cfg.ImageWatermarkEnabled {
		return img, nil
	}
	if !matchPathPatterns(path, p.cfg.ImageWatermarkPaths) {
		return img, nil
	}
	text := p.cfg.WatermarkText
	if text == "" {
		text = "Protected"
	}
	return addWatermark(img, text)
}

// Process 根据 Content-Type 自动选择合适的处理方式。
func (p *Processor) Process(path string, contentType string, body []byte) ([]byte, error) {
	kind := ShouldProcessContentType(contentType)
	switch kind {
	case "html":
		return p.ProcessHTML(body)
	case "js":
		return p.ProcessJS(path, body)
	case "image":
		return p.ProcessImage(path, body)
	default:
		return body, nil
	}
}

// defaultKeyBase 当未配置 EncryptionKeyBase 时生成确定性密钥种子。
func defaultKeyBase(cfg ProtectionConfig) []byte {
	seed := fmt.Sprintf("owaf-dp-default-key-site-%d-html-%v-js-%v",
		cfg.SiteID, cfg.HTMLObfuscationEnabled, cfg.JSObfuscationEnabled)
	return deriveKey([]byte(seed), "owaf-brp/1:default-base", 32)
}

// makeEnvelope 构建加密信封。
func (p *Processor) makeEnvelope(plaintext []byte) (envelope, error) {
	iv, ct, err := aesGCMEncrypt(p.cek, plaintext)
	if err != nil {
		return envelope{}, err
	}
	wrapped, err := aesKeyWrap(p.kek, p.cek)
	if err != nil {
		return envelope{}, err
	}
	ttl := p.cfg.DecryptCacheTTLSeconds
	if ttl <= 0 {
		ttl = 300
	}
	keyHash := sha256.New()
	keyHash.Write(p.kek)
	keyHash.Write(wrapped)
	key := base64.StdEncoding.EncodeToString(keyHash.Sum(nil))
	kek := base64.StdEncoding.EncodeToString(p.kek)
	ticket := ""
	if p.signTicket != nil {
		ticket = p.signTicket(key, ttl, kek)
		kek = ""
	}
	return envelope{
		data:   base64.StdEncoding.EncodeToString(ct),
		iv:     base64.StdEncoding.EncodeToString(iv),
		wrap:   base64.StdEncoding.EncodeToString(wrapped),
		kek:    kek,
		ticket: ticket,
		key:    key,
		ttl:    ttl,
	}, nil
}

// encryptHTML 加密 HTML body 内容并注入 Web Crypto 解密引导。
func (p *Processor) encryptHTML(html []byte) ([]byte, error) {
	return p.wrapFullHTML(html)
}

// wrapFullHTML 对无 body 标签的 HTML 进行完整加密包装。
func (p *Processor) wrapFullHTML(html []byte) ([]byte, error) {
	env, err := p.makeEnvelope(html)
	if err != nil {
		return html, err
	}
	return renderHTMLBootstrap(env, randomNonceB64())
}

// encryptJS 加密 JS 内容，返回自解密包装脚本。
func (p *Processor) encryptJS(js []byte) ([]byte, error) {
	env, err := p.makeEnvelope(js)
	if err != nil {
		return js, err
	}
	return renderJSSelfDecrypt(env), nil
}

// matchPathPatterns 检查路径是否匹配任一模式。
func matchPathPatterns(path string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if matchWildcard(path, pattern) {
			return true
		}
	}
	return false
}

// matchWildcard 执行简单的通配符匹配。
func matchWildcard(s, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		return strings.Contains(s, pattern[1:len(pattern)-1])
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(s, pattern[1:])
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	}
	return s == pattern
}

// ShouldProcessContentType 根据 Content-Type 判断是否需要处理响应。
func ShouldProcessContentType(ct string) string {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if strings.Contains(ct, "text/html") {
		return "html"
	}
	if strings.Contains(ct, "application/javascript") || strings.Contains(ct, "text/javascript") || strings.Contains(ct, "application/x-javascript") {
		return "js"
	}
	if strings.Contains(ct, "image/png") || strings.Contains(ct, "image/jpeg") || strings.Contains(ct, "image/jpg") || strings.Contains(ct, "image/gif") {
		return "image"
	}
	return ""
}
