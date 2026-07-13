package dynamic

import "strings"

// envelope 承载交付给浏览器的一次性加密信封数据（均为 base64 编码）。
type envelope struct {
	data string // AES-256-GCM 密文（含认证标签）
	iv   string // 本次加密的 12 字节 nonce
	wrap string // AES-KW 封装后的 CEK
	kek  string // HKDF 派生的包装密钥（原始字节）
	ttl  int    // 客户端 CEK 缓存时间（秒）
}

// htmlBootstrapScript 是注入到 HTML 中的解密引导脚本模板。
// 通过 Web Crypto API 完成：importKey(KEK) -> unwrapKey(CEK) -> AES-GCM 解密 body。
// 解密后的 CEK 原始字节缓存在 window.__owafDP 与 sessionStorage 中，
// 供同站点 JS 资源在 TTL 窗口内复用，避免重复解包（每页 body 密文仍各自解密）。
const htmlBootstrapScript = `(function(){
var s=document.currentScript,x=s.dataset;
function u(v){var b=atob(v),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a}
function fail(){var m=document.createElement("div");m.setAttribute("style","padding:16px;font-family:system-ui,sans-serif;color:#b00020");m.textContent="内容解密失败，请刷新页面或联系站点管理员。";var p=s.parentNode;if(p){p.insertBefore(m,s);p.removeChild(s)}}
async function cek(){
var g=window.__owafDP=window.__owafDP||{};
var ttl=parseInt(x.owafTtl||"0",10);
try{var c=sessionStorage.getItem("__owafDPCek");if(c){var o=JSON.parse(c);if(o.exp>Date.now()){g.cek=u(o.raw).buffer;return crypto.subtle.importKey("raw",g.cek,{name:"AES-GCM"},false,["decrypt"])}}}catch(e){}
var kek=await crypto.subtle.importKey("raw",u(x.owafKek),{name:"AES-KW"},false,["unwrapKey"]);
var k=await crypto.subtle.unwrapKey("raw",u(x.owafWrap),kek,{name:"AES-KW"},{name:"AES-GCM"},true,["decrypt"]);
var raw=await crypto.subtle.exportKey("raw",k);g.cek=raw;
try{if(ttl>0){var b=new Uint8Array(raw),str="";for(var i=0;i<b.length;i++)str+=String.fromCharCode(b[i]);sessionStorage.setItem("__owafDPCek",JSON.stringify({raw:btoa(str),exp:Date.now()+ttl*1000}))}}catch(e){}
return k}
(async function(){
try{
var k=await cek();
var pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:u(x.owafIv)},k,u(x.owafData));
var html=new TextDecoder().decode(pt);
var t=document.createElement("template");t.innerHTML=html;
var p=s.parentNode;p.insertBefore(t.content,s);p.removeChild(s);
}catch(e){fail()}
})();
})();`

// jsSelfDecryptTemplate 是加密 JS 响应体的自解密外层包装模板。
// 优先复用 HTML 引导建立的全局 CEK（window.__owafDP.cek），否则回退到内联信封自行解包，
// 解密得到原始 JS 后通过间接 eval 在全局作用域执行。
const jsSelfDecryptTemplate = `(function(){
var D="__DATA__",V="__IV__",W="__WRAP__",K="__KEK__";
function u(v){var b=atob(v),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a}
async function cek(){
var g=window.__owafDP;
if(g&&g.cek){return crypto.subtle.importKey("raw",g.cek,{name:"AES-GCM"},false,["decrypt"])}
var kek=await crypto.subtle.importKey("raw",u(K),{name:"AES-KW"},false,["unwrapKey"]);
return crypto.subtle.unwrapKey("raw",u(W),kek,{name:"AES-KW"},{name:"AES-GCM"},false,["decrypt"])}
(async function(){
try{
var k=await cek();
var pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:u(V)},k,u(D));
var code=new TextDecoder().decode(pt);
(0,eval)(code);
}catch(e){if(window.console)console.error("owaf-dp: JS 解密失败",e)}
})();
})();`

// renderJSSelfDecrypt 用信封数据填充 JS 自解密模板。
func renderJSSelfDecrypt(env envelope) []byte {
	r := strings.NewReplacer(
		"__DATA__", env.data,
		"__IV__", env.iv,
		"__WRAP__", env.wrap,
		"__KEK__", env.kek,
	)
	return []byte(r.Replace(jsSelfDecryptTemplate))
}
