// Package dynamic 实现 WAF 动态防护功能，包括 HTML/JS AES-256-GCM 加密和图片水印。
package dynamic

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

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
	EncryptionKeyBase []byte `json:"encryption_key_base,omitempty"`
	// DecryptCacheTTLSeconds 客户端解密缓存时间（秒）
	DecryptCacheTTLSeconds int `json:"decrypt_cache_ttl_seconds,omitempty"`
	// SiteID 站点标识（用于密钥派生隔离）
	SiteID uint `json:"site_id,omitempty"`
}

// Processor 是动态防护处理器。
type Processor struct {
	cfg ProtectionConfig
	cek []byte // Content Encryption Key (AES-256)
	kek []byte // Key Encryption Key（用于包装 CEK 交付给客户端）
}

// NewProcessor 创建一个新的动态防护处理器。
func NewProcessor(cfg ProtectionConfig) *Processor {
	base := cfg.EncryptionKeyBase
	if len(base) == 0 {
		base = defaultKeyBase(cfg)
	}
	cek := deriveKey(base, fmt.Sprintf("owaf-brp/1:cek:site:%d", cfg.SiteID), 32)
	kek := deriveKey(base, fmt.Sprintf("owaf-brp/1:kek:site:%d", cfg.SiteID), 32)
	return &Processor{cfg: cfg, cek: cek, kek: kek}
}

// ProcessHTML 对 HTML 响应进行 AES-256-GCM 加密保护。
func (p *Processor) ProcessHTML(html []byte) ([]byte, error) {
	if !p.cfg.HTMLObfuscationEnabled {
		return html, nil
	}
	return p.encryptHTML(html)
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
	return envelope{
		data: base64.StdEncoding.EncodeToString(ct),
		iv:   base64.StdEncoding.EncodeToString(iv),
		wrap: base64.StdEncoding.EncodeToString(wrapped),
		kek:  base64.StdEncoding.EncodeToString(p.kek),
		ttl:  ttl,
	}, nil
}

// encryptHTML 加密 HTML body 内容并注入 Web Crypto 解密引导。
func (p *Processor) encryptHTML(html []byte) ([]byte, error) {
	bodyStart := bytes.Index(html, []byte("<body"))
	if bodyStart < 0 {
		bodyStart = bytes.Index(html, []byte("<BODY"))
	}
	if bodyStart < 0 {
		return p.wrapFullHTML(html)
	}

	bodyTagEnd := bytes.IndexByte(html[bodyStart:], '>')
	if bodyTagEnd < 0 {
		return html, nil
	}
	bodyTagEnd += bodyStart + 1

	bodyEnd := bytes.Index(html[bodyTagEnd:], []byte("</body>"))
	if bodyEnd < 0 {
		bodyEnd = bytes.Index(html[bodyTagEnd:], []byte("</BODY>"))
	}

	var bodyContent, afterBody []byte
	if bodyEnd < 0 {
		bodyContent = html[bodyTagEnd:]
	} else {
		bodyEnd += bodyTagEnd
		bodyContent = html[bodyTagEnd:bodyEnd]
		afterBody = html[bodyEnd:]
	}

	env, err := p.makeEnvelope(bodyContent)
	if err != nil {
		return html, err
	}

	nonce := randomNonceB64()
	tag := buildHTMLScriptTag(env, nonce)

	result := make([]byte, 0, len(html)+len(tag)+64)
	result = append(result, html[:bodyTagEnd]...)
	result = append(result, tag...)
	if afterBody != nil {
		result = append(result, afterBody...)
	}
	return result, nil
}

// wrapFullHTML 对无 body 标签的 HTML 进行完整加密包装。
func (p *Processor) wrapFullHTML(html []byte) ([]byte, error) {
	env, err := p.makeEnvelope(html)
	if err != nil {
		return html, err
	}
	nonce := randomNonceB64()
	tag := buildHTMLScriptTag(env, nonce)

	var buf bytes.Buffer
	buf.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>`)
	buf.Write(tag)
	buf.WriteString(`</body></html>`)
	return buf.Bytes(), nil
}

// buildHTMLScriptTag 构建包含解密引导的 script 标签。
func buildHTMLScriptTag(env envelope, cspNonce string) []byte {
	var buf bytes.Buffer
	buf.WriteString(`<script nonce="`)
	buf.WriteString(cspNonce)
	buf.WriteString(`" data-owaf-dp="2" data-owaf-data="`)
	buf.WriteString(env.data)
	buf.WriteString(`" data-owaf-iv="`)
	buf.WriteString(env.iv)
	buf.WriteString(`" data-owaf-wrap="`)
	buf.WriteString(env.wrap)
	buf.WriteString(`" data-owaf-kek="`)
	buf.WriteString(env.kek)
	buf.WriteString(`" data-owaf-ttl="`)
	buf.WriteString(fmt.Sprintf("%d", env.ttl))
	buf.WriteString(`">`)
	buf.WriteString(htmlBootstrapScript)
	buf.WriteString(`</script>`)
	return buf.Bytes()
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
