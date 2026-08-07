package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// 浏览器签名请求头（由站点挂载 JS 写入，WAF 侧校验）。
const (
	BrowserSignHeaderNonce   = "X-OWAF-BS-N"
	BrowserSignHeaderExp     = "X-OWAF-BS-E"
	BrowserSignHeaderMAC     = "X-OWAF-BS-M"
	BrowserSignHeaderTS      = "X-OWAF-BS-TS"
	BrowserSignHeaderSig     = "X-OWAF-BS-S"
	BrowserSignHeaderEnv     = "X-OWAF-BS-Env"
	browserSignTicketVersion = "bs1"
	defaultBrowserSignTTL    = 300
	browserSignSkewSecs      = 60
)

// BrowserSignTicket 是下发给页面 JS 的短时效签名票据材料。
type BrowserSignTicket struct {
	Nonce     string
	ExpiresAt int64
	TicketMAC string
	SignKey   string // hex，客户端用于请求 HMAC；由 challengeSecret 派生，短时效
	EnvKeyHex string // 可选环境指纹加密密钥
	TTL       int
	CSPNonce  string // 注入脚本的 CSP nonce
}

// IssueBrowserSignTicket 签发短时效 nonce+HMAC 票据。
// siteID 参与 ticket MAC，避免跨站复用（不绑定 Host，兼容站点多域名）。
// envCheck 仅标记页面是否采集环境指纹；站点签名链路为无状态，环境指纹使用明文 JSON。
func IssueBrowserSignTicket(siteID uint, host string, ttlSecs int, envCheck bool) BrowserSignTicket {
	if ttlSecs <= 0 {
		ttlSecs = defaultBrowserSignTTL
	}
	nonceBytes := make([]byte, 16)
	_, _ = rand.Read(nonceBytes)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	cspNonceBytes := make([]byte, 16)
	_, _ = rand.Read(cspNonceBytes)
	cspNonce := base64.RawURLEncoding.EncodeToString(cspNonceBytes)
	exp := time.Now().Add(time.Duration(ttlSecs) * time.Second).Unix()
	// host 参数保留以兼容调用方；ticket 仅绑定 siteID，避免多 Host 站点注入/校验不一致。
	_ = host
	ticketMAC := browserSignTicketMAC(nonce, exp, siteID)
	signKey := browserSignRequestKey(nonce)
	envKeyHex := ""
	if envCheck {
		// 占位标记：Inject 侧看到非空则启用环境采集（明文）。
		envKeyHex = "1"
	}
	return BrowserSignTicket{
		Nonce:     nonce,
		ExpiresAt: exp,
		TicketMAC: ticketMAC,
		SignKey:   hex.EncodeToString(signKey),
		EnvKeyHex: envKeyHex,
		TTL:       ttlSecs,
		CSPNonce:  cspNonce,
	}
}

// VerifyBrowserSignHeaders 校验请求头中的浏览器签名。
// 返回 ok 与原因（失败时）。host 保留兼容调用方，不参与 ticket 校验。
// query 参与请求 MAC，防止在固定 path 上篡改查询参数绕过。
func VerifyBrowserSignHeaders(headers map[string]string, method, path, query, host string, siteID uint, now time.Time, envHardFail bool) (bool, string) {
	_ = host
	nonce, _ := lookupBrowserSignHeader(headers, BrowserSignHeaderNonce)
	expRaw, _ := lookupBrowserSignHeader(headers, BrowserSignHeaderExp)
	ticketMAC, _ := lookupBrowserSignHeader(headers, BrowserSignHeaderMAC)
	tsRaw, _ := lookupBrowserSignHeader(headers, BrowserSignHeaderTS)
	reqSig, _ := lookupBrowserSignHeader(headers, BrowserSignHeaderSig)
	envFP, _ := lookupBrowserSignHeader(headers, BrowserSignHeaderEnv)

	if nonce == "" || expRaw == "" || ticketMAC == "" || tsRaw == "" || reqSig == "" {
		return false, "missing browser sign headers"
	}
	exp, err := strconv.ParseInt(expRaw, 10, 64)
	if err != nil || exp <= 0 {
		return false, "invalid browser sign exp"
	}
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil || ts <= 0 {
		return false, "invalid browser sign ts"
	}
	nowUnix := now.Unix()
	if nowUnix > exp {
		return false, "browser sign ticket expired"
	}
	if abs64(nowUnix-ts) > browserSignSkewSecs {
		return false, "browser sign timestamp skew"
	}
	expectedTicket := browserSignTicketMAC(nonce, exp, siteID)
	if !hmac.Equal([]byte(ticketMAC), []byte(expectedTicket)) {
		return false, "browser sign ticket mac mismatch"
	}
	expectedReq := browserSignRequestMAC(nonce, method, path, query, ts)
	if !hmac.Equal([]byte(reqSig), []byte(expectedReq)) {
		return false, "browser sign request mac mismatch"
	}
	if envHardFail {
		if envFP == "" {
			return false, "missing browser env fingerprint"
		}
		// 站点签名链路无会话密钥，环境指纹使用明文 JSON。
		fp := ParseEnvFingerprint(envFP)
		if fp == nil {
			return false, "invalid browser env fingerprint"
		}
		if ValidateEnvFingerprint(fp).Score >= 100 {
			return false, "browser env hard-fail"
		}
	}
	return true, ""
}

// BrowserSignInjectScript 生成注入到 HTML 的混淆签名/环境采集脚本。
func BrowserSignInjectScript(ticket BrowserSignTicket) string {
	// 站点签名链路不签发服务端会话，环境数据仅作不可信风险信号，不参与授权。
	envJS := ""
	if ticket.EnvKeyHex != "" {
		envJS = EnvCheckJSPlain()
	}
	raw := fmt.Sprintf(browserSignJSTemplate,
		ticket.Nonce,
		ticket.ExpiresAt,
		ticket.TicketMAC,
		ticket.SignKey,
		BrowserSignHeaderNonce,
		BrowserSignHeaderExp,
		BrowserSignHeaderMAC,
		BrowserSignHeaderTS,
		BrowserSignHeaderSig,
		BrowserSignHeaderEnv,
	)
	combined := envJS + "\n" + raw
	attr := ""
	if ticket.CSPNonce != "" {
		attr = ` nonce="` + ticket.CSPNonce + `" data-owaf-bs="1"`
	}
	return "<script" + attr + ">" + obfuscateBrowserSignJS(combined) + "</script>"
}

// InjectBrowserSignIntoHTML 将签名脚本注入 HTML 响应体。
// 优先插入 </body> 前；否则追加到末尾。
func InjectBrowserSignIntoHTML(html []byte, ticket BrowserSignTicket) []byte {
	if len(html) == 0 {
		return html
	}
	script := BrowserSignInjectScript(ticket)
	lower := strings.ToLower(string(html))
	if idx := strings.LastIndex(lower, "</body>"); idx >= 0 {
		var b strings.Builder
		b.Grow(len(html) + len(script) + 1)
		b.Write(html[:idx])
		b.WriteString(script)
		b.Write(html[idx:])
		return []byte(b.String())
	}
	out := make([]byte, 0, len(html)+len(script))
	out = append(out, html...)
	out = append(out, script...)
	return out
}

// IsLikelyAPIRequest 按请求特征自动识别是否应按浏览器签名校验的 API 请求。
func IsLikelyAPIRequest(method, path string, headers map[string]string) bool {
	lp := strings.ToLower(path)
	if lp == "" {
		return false
	}
	if strings.HasPrefix(lp, "/__owaf/") {
		return false
	}
	if isBrowserSignStaticPath(lp) {
		return false
	}
	// 文档导航通常带 text/html，不作为 API。
	if mode, ok := lookupBrowserSignHeader(headers, "sec-fetch-mode"); ok {
		if strings.EqualFold(strings.TrimSpace(mode), "navigate") {
			return false
		}
	}
	if dest, ok := lookupBrowserSignHeader(headers, "sec-fetch-dest"); ok {
		d := strings.ToLower(strings.TrimSpace(dest))
		if d == "document" || d == "iframe" || d == "frame" {
			return false
		}
	}

	if ct, ok := lookupBrowserSignHeader(headers, "content-type"); ok {
		ct = strings.ToLower(ct)
		if strings.Contains(ct, "application/json") ||
			strings.Contains(ct, "application/xml") ||
			strings.Contains(ct, "application/grpc") ||
			strings.Contains(ct, "application/x-www-form-urlencoded") ||
			strings.Contains(ct, "multipart/form-data") {
			return true
		}
	}
	if accept, ok := lookupBrowserSignHeader(headers, "accept"); ok {
		al := strings.ToLower(accept)
		if strings.Contains(al, "application/json") && !strings.Contains(al, "text/html") {
			return true
		}
	}
	if xrw, ok := lookupBrowserSignHeader(headers, "x-requested-with"); ok {
		if strings.EqualFold(strings.TrimSpace(xrw), "XMLHttpRequest") {
			return true
		}
	}
	if mode, ok := lookupBrowserSignHeader(headers, "sec-fetch-mode"); ok {
		if strings.EqualFold(strings.TrimSpace(mode), "cors") {
			return true
		}
	}
	if strings.Contains(lp, "/api/") ||
		strings.HasSuffix(lp, "/api") ||
		strings.HasSuffix(lp, ".json") ||
		strings.Contains(lp, "/graphql") {
		return true
	}
	// 非 GET/HEAD 且 Accept 不含 html，倾向 API。
	m := strings.ToUpper(method)
	if m != "GET" && m != "HEAD" && m != "OPTIONS" {
		if accept, ok := lookupBrowserSignHeader(headers, "accept"); ok {
			al := strings.ToLower(accept)
			if al != "" && !strings.Contains(al, "text/html") {
				return true
			}
		} else {
			return true
		}
	}
	return false
}

func browserSignTicketMAC(nonce string, exp int64, siteID uint) string {
	payload := fmt.Sprintf("%s|%s|%d|%d", browserSignTicketVersion, nonce, exp, siteID)
	mac := hmac.New(sha256.New, loadChallengeSecret())
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func browserSignRequestKey(nonce string) []byte {
	mac := hmac.New(sha256.New, loadChallengeSecret())
	mac.Write([]byte(browserSignTicketVersion + "|reqkey|" + nonce))
	sum := mac.Sum(nil)
	return sum[:16]
}

func browserSignRequestMAC(nonce, method, path, query string, ts int64) string {
	key := browserSignRequestKey(nonce)
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	// path 与 query 分开签名：若 path 自带 query 且显式 query 为空，则从 path 拆出 query，
	// 保证与客户端 URL 解析（pathname + search）一致。
	if i := strings.IndexByte(path, '?'); i >= 0 {
		if query == "" {
			query = path[i+1:]
		}
		path = path[:i]
	}
	query = strings.TrimPrefix(query, "?")
	// query 参与签名，防止在固定 path 上篡改查询参数绕过；使用原始串直接比对，两端保持一致。
	payload := method + "|" + path + "|" + query + "|" + strconv.FormatInt(ts, 10) + "|" + nonce
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func lookupBrowserSignHeader(headers map[string]string, name string) (string, bool) {
	if headers == nil {
		return "", false
	}
	if v, ok := headers[name]; ok {
		return v, true
	}
	lower := strings.ToLower(name)
	if v, ok := headers[lower]; ok {
		return v, true
	}
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

func isBrowserSignStaticPath(lowerPath string) bool {
	staticExt := []string{
		".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".mp3", ".wav", ".pdf",
		".txt", ".xml", ".rss", ".atom", ".zip", ".gz", ".br", ".wasm",
	}
	for _, ext := range staticExt {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	staticPrefixes := []string{"/static/", "/assets/", "/favicon", "/robots.txt", "/sitemap"}
	for _, p := range staticPrefixes {
		if strings.HasPrefix(lowerPath, p) {
			return true
		}
	}
	return false
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func obfuscateBrowserSignJS(js string) string {
	v := randomVarNames(10)
	r := strings.NewReplacer(
		"__owaf_bs_nonce", v[0],
		"__owaf_bs_exp", v[1],
		"__owaf_bs_mac", v[2],
		"__owaf_bs_key", v[3],
		"__owaf_bs_hn", v[4],
		"__owaf_bs_he", v[5],
		"__owaf_bs_hm", v[6],
		"__owaf_bs_hts", v[7],
		"__owaf_bs_hs", v[8],
		"__owaf_bs_henv", v[9],
	)
	return r.Replace(js)
}

// browserSignJSTemplate：挂载后 hook fetch/XHR，为请求附加短时效签名头与环境指纹。
// 使用 Web Crypto 对 method|path|query|ts|nonce 做 HMAC-SHA256。
const browserSignJSTemplate = `
(function(){
var __owaf_bs_nonce="%s";
var __owaf_bs_exp=%d;
var __owaf_bs_mac="%s";
var __owaf_bs_key="%s";
var __owaf_bs_hn="%s";
var __owaf_bs_he="%s";
var __owaf_bs_hm="%s";
var __owaf_bs_hts="%s";
var __owaf_bs_hs="%s";
var __owaf_bs_henv="%s";
function loadWasm(){
if(typeof wasm_bindgen!=="undefined")return wasm_bindgen("/__owaf/pow.wasm?v=f54bf002");
return new Promise(function(ok,err){var sc=document.createElement("script");sc.src="/__owaf/pow_glue.js?v=7ad1dbac";sc.onload=function(){wasm_bindgen("/__owaf/pow.wasm?v=f54bf002").then(ok).catch(err)};sc.onerror=function(){err(new Error("browser sign wasm glue load failed"))};document.head.appendChild(sc)})
}
var __owaf_bs_wasm=loadWasm();
function pathOnly(u){try{var x=new URL(u,location.href);return x.pathname||"/"}catch(e){var p=String(u||"");var i=p.indexOf("?");return i>=0?p.slice(0,i):p}}
function queryOnly(u){try{var x=new URL(u,location.href);var s=x.search||"";return s.charAt(0)==="?"?s.slice(1):s}catch(e){var p=String(u||"");var i=p.indexOf("?");return i>=0?p.slice(i+1):""}}
function shouldSign(u,method){
try{
var x=new URL(u,location.href);
if(x.origin!==location.origin)return false;
var p=(x.pathname||"/").toLowerCase();
if(p.indexOf("/__owaf/")===0)return false;
if(/\.(css|js|mjs|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|otf|mp4|webm|mp3|wav|pdf|wasm)(\?|$)/i.test(p))return false;
return true;
}catch(e){return false}
}
async function signHeaders(method,url){
var ts=Math.floor(Date.now()/1000);
var path=pathOnly(url);
var query=queryOnly(url);
var m=(method||"GET").toUpperCase();
var payload=m+"|"+path+"|"+query+"|"+String(ts)+"|"+__owaf_bs_nonce;
await __owaf_bs_wasm;
var sig=wasm_bindgen.hmac_sha256(__owaf_bs_key,payload);
var h={};
h[__owaf_bs_hn]=__owaf_bs_nonce;
h[__owaf_bs_he]=String(__owaf_bs_exp);
h[__owaf_bs_hm]=__owaf_bs_mac;
h[__owaf_bs_hts]=String(ts);
h[__owaf_bs_hs]=sig;
try{if(window.__owaf_env_encrypted)h[__owaf_bs_henv]=window.__owaf_env_encrypted}catch(e){}
return h;
}
function mergeHeaders(base,extra){
if(!extra)return base;
if(!base){var o={};for(var k in extra)o[k]=extra[k];return o}
if(typeof Headers!=="undefined"&&base instanceof Headers){for(var k in extra)base.set(k,extra[k]);return base}
if(Array.isArray(base)){for(var k in extra)base.push([k,extra[k]]);return base}
var out={};for(var k in base)out[k]=base[k];for(var k2 in extra)out[k2]=extra[k2];return out;
}
if(window.fetch){
var ofetch=window.fetch;
window.fetch=function(input,init){
var fetchThis=this,fetchArgs=arguments;
try{
var url=(typeof input==="string")?input:(input&&input.url)||location.href;
var method=(init&&init.method)||(input&&input.method)||"GET";
if(!shouldSign(url,method))return ofetch.apply(fetchThis,fetchArgs);
return signHeaders(method,url).then(function(h){
init=init?Object.assign({},init):{};
init.headers=mergeHeaders(init.headers||(input&&input.headers),h);
return ofetch.call(fetchThis,input,init);
}).catch(function(){return ofetch.apply(fetchThis,fetchArgs)});
}catch(e){return ofetch.apply(fetchThis,fetchArgs)}
};
}
if(window.XMLHttpRequest){
var XO=window.XMLHttpRequest;
function P(){
var xhr=new XO(),open=xhr.open,send=xhr.send,_m="GET",_u=location.href;
xhr.open=function(method,url){_m=method||"GET";_u=url||location.href;return open.apply(xhr,arguments)};
xhr.send=function(body){
if(!shouldSign(_u,_m))return send.apply(xhr,arguments);
var args=arguments;
signHeaders(_m,_u).then(function(h){
try{for(var k in h)xhr.setRequestHeader(k,h[k])}catch(e){}
send.apply(xhr,args);
}).catch(function(){send.apply(xhr,args)});
};
return xhr;
}
P.prototype=XO.prototype;
window.XMLHttpRequest=P;
}
})();
`
