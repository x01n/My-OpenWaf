package pages

import (
	"bytes"
	"html/template"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/snapshot"
	challengepow "My-OpenWaf/internal/waf/challenge/pow"
	"My-OpenWaf/internal/waf/pageconfig"
)

// CookieRenewSeed 是服务端签发的 C2 种子，随续期页下发给浏览器。
// Envelope 为单片分片信封文本（base64url），KeyHex 为信封密钥（64 字符 hex）；
// 二者皆空表示签发失败，页面回退到「重载并重新签发」路径。
type CookieRenewSeed struct {
	Envelope string
	KeyHex   string
}

type cookieRenewPageData struct {
	PageTitle      string
	BrandName      string
	BrandLogoURL   template.URL
	PrimaryColor   template.CSS
	Background     template.CSS
	CheckingText   string
	CheckingTextZh string
	WaitText       string
	WaitTextZh     string
	RequestID      string
	FooterText     string
	SeedEnvelope   string
	SeedKeyHex     string
	HasSeed        bool
	// WasmURL / GlueURL 带内容派生版本串（见 challenge/powdata 包）。
	WasmURL string
	GlueURL string
}

// cookieRenewPageTemplate 是续期页的最小 HTML 模板，卡片样式复用
// challenge.html 的 sensory 卡片形态。
var cookieRenewPageTemplate = template.Must(template.New("cookie-renew").Parse(cookieRenewPageHTML))

// cookieRenewPageHTML 定义续期页正文。内联 script 仅做两件事：
// 读取 C1（__waf_nonce）末 8 位派生 C2，尝试 5 次写 __waf_nonce2 后重载。
const cookieRenewPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.PageTitle}}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:{{.Background}};color:#1e293b}
.card{background:#fff;border-radius:16px;box-shadow:0 4px 32px rgba(0,0,0,.08),0 1px 4px rgba(0,0,0,.04);max-width:460px;width:92%;padding:48px 40px;text-align:center}
@keyframes spin{to{transform:rotate(360deg)}}
.spinner{width:40px;height:40px;border:3px solid #e2e8f0;border-top-color:{{.PrimaryColor}};border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 20px}
h2{font-size:1.15rem;font-weight:600;color:#334155;margin-bottom:6px}
.sub{font-size:.875rem;color:#64748b;margin-bottom:4px}
.rid{font-size:.7rem;color:#94a3b8;margin-top:20px}
.footer{margin-top:20px;padding-top:14px;border-top:1px solid #f1f5f9;font-size:.7rem;color:#94a3b8}
.brand-logo{display:block;max-width:64px;max-height:64px;object-fit:contain;margin:0 auto 16px}
.brand{font-size:.75rem;color:#94a3b8;margin-bottom:10px}
.icon{font-size:48px;margin-bottom:16px;line-height:1.2}
</style>
</head>
<body><div class="card">
{{if .BrandLogoURL}}<img class="brand-logo" src="{{.BrandLogoURL}}" alt="">{{else}}<div class="icon">&#128737;</div>{{end}}
<div class="brand">{{.BrandName}}</div>
<div class="spinner"></div>
<h2>{{.CheckingText}} / {{.CheckingTextZh}}</h2>
<p class="sub">{{.WaitText}}</p>
<p class="sub">{{.WaitTextZh}}</p>
<p class="rid">Request ID: {{.RequestID}}</p>
<div class="footer">{{.FooterText}}</div>
</div>
<input type="hidden" id="__owaf_c2_env" value="{{.SeedEnvelope}}">
<input type="hidden" id="__owaf_c2_key" value="{{.SeedKeyHex}}">
<script>
(function(){
var envEl=document.getElementById("__owaf_c2_env");
var keyEl=document.getElementById("__owaf_c2_key");
var ENV=envEl?envEl.value:"";
var KEY=keyEl?keyEl.value:"";
var SETTLED=false;
function setC2(value){
 // Max-Age=86400 与校验窗口（种子的 exp，默认 900s）是两件事：cookie 留存
// 让「关浏览器次日再来」不必从零开始，校验窗口只由 exp 决定。
 try{document.cookie="__waf_nonce2="+encodeURIComponent(value)+"; Path=/; Max-Age=86400; SameSite=Strict"+(location.protocol==="https:"?"; Secure":"");}catch(e){}
}
function finish(){if(SETTLED)return;SETTLED=true;location.reload()}
function loadWasm(){
 if(window.__owaf_wasm_ready)return window.__owaf_wasm_ready;
 window.__owaf_wasm_ready=new Promise(function(resolve,reject){
  if(typeof WebAssembly==="undefined"){reject(new Error("WebAssembly is unavailable"));return}
  function initialize(){
   if(typeof wasm_bindgen==="undefined"){reject(new Error("WASM glue is unavailable"));return}
   wasm_bindgen({module_or_path:"{{.WasmURL}}"}).then(resolve).catch(reject)
  }
  if(typeof wasm_bindgen!=="undefined"){initialize();return}
  var s=document.createElement("script");
  s.src="{{.GlueURL}}";
  s.async=true;
  s.onload=initialize;
  s.onerror=function(){reject(new Error("WASM glue load failed"))};
  (document.head||document.documentElement).appendChild(s);
 });
 return window.__owaf_wasm_ready;
}
// 设计意图（反直觉，勿改）：C2 的 MAC **不绑定 C1**。C1 每次请求都被
// ValidateAndRotate 轮换成新值，若把 MAC 绑到 C1，则「用下一枚 C1 校验绑定
// 上一枚 C1 的 MAC」永远不匹配，dual 站点会陷入无限 412。因此绑定面收敛为
// (clientIP, exp)：不可伪造靠 k_mac 不下发，不可跨客户端靠 clientIP，
// 时限靠 exp。C1 轮换后 C2 仍然有效是**刻意设计**。
//
// 种子缺失（服务端签发失败）时直接重载：由服务端再次尝试签发，
// 既不放行、也不构造弱值。
if(!ENV||!KEY){finish();return}
loadWasm().then(function(){
 var plain=wasm_bindgen.vm_assemble_shards(ENV,KEY);
 if(typeof plain!=="string"||!plain.length)throw new Error("C2 seed assembly failed");
 var seed=JSON.parse(plain);
 // cookie 是服务端算好的完整值，客户端**原样落位**：不拼接、不计算。
 // 拼接是可被省略或篡改的一步，而值本身已不可伪造，拼接只会引入
 // 「拼错格式 -> 解析失败 -> 反复续期」的失败面。
 if(!seed||typeof seed.cookie!=="string"||!seed.cookie.length)throw new Error("C2 seed malformed");
 setC2(seed.cookie);
}).catch(function(e){
 // 解密失败不落位任何值，重载后由服务端重新签发。
 try{if(window.console&&console.warn)console.warn("owaf c2 seed:",(e&&e.message)||String(e))}catch(x){}
}).then(function(){
 var tries=0;
 function settle(){
  if(document.cookie.indexOf("__waf_nonce2=")>=0||tries>=5){finish();return}
  tries++;setTimeout(settle,150);
 }
 setTimeout(settle,30);
});
})();
</script></body>
</html>`

/**
 * WriteCookieRenewPage 渲染 C2 续期页并写入响应（诊断头为 X-OWAF-Probe: renew）。
 *
 * @param c Hertz 请求上下文
 * @param reqID 请求 ID
 * @param rt 站点运行时；nil 时仍可渲染默认品牌
 * @param sn 当前快照；nil 或缺少页面配置时用默认品牌
 * @param statusCode 状态码（调用方传 412 = StatusPreconditionFailed）
 * @param seed 服务端签发的 C2 种子；出参为空串时页面走「重载重签」回退路径
 */
func WriteCookieRenewPage(c *app.RequestContext, reqID string, rt *snapshot.SiteRuntime, sn *snapshot.Snapshot, statusCode int, seed CookieRenewSeed) {
	c.Response.Header.Set("X-Request-ID", reqID)
	c.Response.Header.Del("Server")
	c.Response.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	c.Response.Header.Set("X-OWAF-Probe", "renew")

	cfg := pageconfig.DefaultChallengePageConfig()
	if sn != nil && sn.ChallengePage.BrandName != "" {
		cfg = sn.ChallengePage
	}
	data := cookieRenewPageData{
		PageTitle:      cfg.Title,
		BrandName:      cfg.BrandName,
		BrandLogoURL:   pageconfig.SafeLogoURL(cfg.LogoURL),
		PrimaryColor:   template.CSS(pageconfig.SafePrimaryColor(cfg.PrimaryColor, pageconfig.DefaultChallengePageConfig().PrimaryColor)),
		Background:     template.CSS(pageconfig.SafeBackground(cfg.BgGradient, pageconfig.DefaultChallengePageConfig().BgGradient)),
		CheckingText:   "Establishing secure session",
		CheckingTextZh: "正在建立安全会话",
		WaitText:       "Please keep this page open, it will refresh automatically.",
		WaitTextZh:     "请保持页面开启，稍后将自动刷新。",
		RequestID:      reqID,
		FooterText:     cfg.FooterText,
		SeedEnvelope:   seed.Envelope,
		SeedKeyHex:     seed.KeyHex,
		HasSeed:        seed.Envelope != "" && seed.KeyHex != "",
		WasmURL:        challengepow.PowWasmURL(),
		GlueURL:        challengepow.PowGlueURL(),
	}
	var buf bytes.Buffer
	if err := cookieRenewPageTemplate.Execute(&buf, data); err != nil {
		c.Data(statusCode, "text/html", []byte("<!DOCTYPE html><html><head><title>Security Check</title></head><body><h1>Please wait...</h1></body></html>"))
		return
	}
	c.Data(statusCode, "text/html", buf.Bytes())
}
