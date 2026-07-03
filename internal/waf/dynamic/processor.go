// Package dynamic 实现 WAF 动态防护功能，包括 HTML 加密、JS 混淆和图片水印。
package dynamic

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// ProtectionConfig 是动态防护的运行时配置。
type ProtectionConfig struct {
	HTMLObfuscationEnabled bool `json:"html_obfuscation_enabled"`
	JSObfuscationEnabled   bool `json:"js_obfuscation_enabled"`
	ImageWatermarkEnabled  bool `json:"image_watermark_enabled"`
	// JSObfuscationPaths 是需要进行 JS 混淆的资源路径模式（支持通配符）
	JSObfuscationPaths []string `json:"js_obfuscation_paths,omitempty"`
	// ImageWatermarkPaths 是需要添加水印的图片路径模式（支持通配符）
	ImageWatermarkPaths []string `json:"image_watermark_paths,omitempty"`
	// WatermarkText 是水印文字内容
	WatermarkText string `json:"watermark_text,omitempty"`
}

// Processor 是动态防护处理器，根据配置对响应内容进行转换。
type Processor struct {
	cfg ProtectionConfig
	key []byte // 加密密钥（每个 snapshot 周期重新生成）
}

// NewProcessor 创建一个新的动态防护处理器。
func NewProcessor(cfg ProtectionConfig) *Processor {
	// 生成一个稳定的密钥（基于配置哈希）
	key := deriveKey(cfg)
	return &Processor{cfg: cfg, key: key}
}

// ProcessHTML 对 HTML 响应进行处理（HTML 动态加密）。
// 如果未启用 HTML 加密，返回原始内容。
func (p *Processor) ProcessHTML(html []byte) ([]byte, error) {
	if !p.cfg.HTMLObfuscationEnabled {
		return html, nil
	}
	return encryptHTML(html, p.key)
}

// ProcessJS 对 JS 响应进行处理（JS 动态混淆）。
// 如果未启用 JS 混淆，返回原始内容。
func (p *Processor) ProcessJS(path string, js []byte) ([]byte, error) {
	if !p.cfg.JSObfuscationEnabled {
		return js, nil
	}
	if !matchPathPatterns(path, p.cfg.JSObfuscationPaths) {
		return js, nil
	}
	return obfuscateJS(js)
}

// ProcessImage 对图片响应进行处理（添加水印）。
// 如果未启用水印，返回原始内容。
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

// deriveKey 从配置派生一个稳定的加密密钥。
func deriveKey(cfg ProtectionConfig) []byte {
	// 使用配置的简单哈希作为密钥种子
	seed := fmt.Sprintf("%v|%v|%v", cfg.HTMLObfuscationEnabled, cfg.JSObfuscationEnabled, cfg.ImageWatermarkEnabled)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(seed[i%len(seed)] + byte(i))
	}
	return key
}

// xorEncrypt 使用 XOR 加密/解密数据。
func xorEncrypt(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// matchPathPatterns 检查路径是否匹配任一模式（简单通配符支持）。
func matchPathPatterns(path string, patterns []string) bool {
	if len(patterns) == 0 {
		return true // 未指定模式时默认匹配所有
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

// matchWildcard 执行简单的通配符匹配（* 匹配任意字符序列，? 匹配单个字符）。
func matchWildcard(s, pattern string) bool {
	// 简单实现：如果模式包含 *，则按前缀/后缀匹配
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

// encryptHTML 加密 HTML 内容：提取 body，加密后注入解密脚本。
func encryptHTML(html, key []byte) ([]byte, error) {
	bodyStart := bytes.Index(html, []byte("<body"))
	if bodyStart < 0 {
		bodyStart = bytes.Index(html, []byte("<BODY"))
	}
	if bodyStart < 0 {
		// 没有 body 标签，加密整个 HTML
		return wrapEncryptedHTML(html, key), nil
	}

	// 找到 body 标签的结束位置
	bodyTagEnd := bytes.IndexByte(html[bodyStart:], '>')
	if bodyTagEnd < 0 {
		return html, nil
	}
	bodyTagEnd += bodyStart + 1

	// 找到 </body> 结束标签
	bodyEnd := bytes.Index(html[bodyTagEnd:], []byte("</body>"))
	if bodyEnd < 0 {
		bodyEnd = bytes.Index(html[bodyTagEnd:], []byte("</BODY>"))
	}
	if bodyEnd < 0 {
		// 没有结束标签，加密从 body 开始到文档末尾
		encrypted := xorEncrypt(html[bodyTagEnd:], key)
		encoded := base64.StdEncoding.EncodeToString(encrypted)
		return buildEncryptedHTML(html[:bodyTagEnd], []byte(encoded), key, []byte{}), nil
	}
	bodyEnd += bodyTagEnd

	// 提取并加密 body 内容
	bodyContent := html[bodyTagEnd:bodyEnd]
	encrypted := xorEncrypt(bodyContent, key)
	encoded := base64.StdEncoding.EncodeToString(encrypted)

	// 构建新的 HTML：保留 head 和 body 标签，注入解密脚本
	result := make([]byte, 0, len(html)+1024)
	result = append(result, html[:bodyTagEnd]...)
	result = append(result, []byte(`<script data-owaf-dp="1">`)...)
	result = append(result, buildDecryptScript(encoded, key)...)
	result = append(result, []byte(`</script>`)...)
	result = append(result, html[bodyEnd:]...)
	return result, nil
}

// wrapEncryptedHTML 对整个 HTML 进行加密包装。
func wrapEncryptedHTML(html, key []byte) []byte {
	encrypted := xorEncrypt(html, key)
	encoded := base64.StdEncoding.EncodeToString(encrypted)

	return []byte(`<!DOCTYPE html><html><head><meta charset="utf-8"><script data-owaf-dp="1">` +
		string(buildDecryptScript(encoded, key)) +
		`</script></head><body></body></html>`)
}

// buildEncryptedHTML 构建加密后的 HTML 结构。
func buildEncryptedHTML(beforeBody, encodedBody []byte, key []byte, afterBody []byte) []byte {
	result := make([]byte, 0, len(beforeBody)+len(encodedBody)+len(afterBody)+2048)
	result = append(result, beforeBody...)
	result = append(result, []byte(`<script data-owaf-dp="1">`)...)
	result = append(result, buildDecryptScript(string(encodedBody), key)...)
	result = append(result, []byte(`</script>`)...)
	result = append(result, afterBody...)
	return result
}

// buildDecryptScript 生成客户端解密脚本。
func buildDecryptScript(encodedBody string, key []byte) []byte {
	// 将密钥转换为 JS 数组
	var keyJS strings.Builder
	keyJS.WriteByte('[')
	for i, b := range key {
		if i > 0 {
			keyJS.WriteByte(',')
		}
		keyJS.WriteString(strconv.Itoa(int(b)))
	}
	keyJS.WriteByte(']')

	// 内联的解密脚本，不依赖外部资源
	script := `(function(){
var e="` + encodedBody + `";
var k=` + keyJS.String() + `;
function d(s){
var b=atob(s);
var r="";
for(var i=0;i<b.length;i++){
r+=String.fromCharCode(b.charCodeAt(i)^k[i%k.length]);
}
return r;
}
var t=document.currentScript;
if(t&&t.dataset.owafDp){
var p=t.parentNode;
if(p){
var tmp=document.createElement("div");
tmp.innerHTML=d(e);
while(tmp.firstChild){
p.insertBefore(tmp.firstChild,t);
}
p.removeChild(t);
}
}
})();`
	return []byte(script)
}
