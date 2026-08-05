package dynamic

import "strings"

// envelope 承载交付给浏览器的一次性加密信封数据（均为 base64 编码）。
type envelope struct {
	data   string // AES-256-GCM 密文（含认证标签）
	iv     string // 本次加密的 12 字节 nonce
	wrap   string // AES-KW 封装后的 CEK
	kek    string // HKDF 派生的包装密钥（原始字节，仅本地/测试模式使用）
	ticket string // 服务端密钥兑换票据
	key    string // 当前信封的缓存绑定标识
	ttl    int    // 客户端 CEK 缓存时间（秒）
}

// htmlBootstrapScript 是注入到 HTML 中的解密引导脚本模板。
// 通过 Rust WASM 完成 AES-KW 解包与 AES-256-GCM 解密，避免依赖 crypto.subtle。
// 解密后的 CEK 原始字节缓存在 window.__owafDP 与 sessionStorage 中，
// 供同站点 JS 资源在 TTL 窗口内复用，避免重复解包（每页 body 密文仍各自解密）。
const dynamicEnvironmentCheck = `function owafCheckEnvironment(){
var g=window.__owafDP=window.__owafDP||{};
if(g.envResult){return g.envResult}
var reasons=[],softReasons=[],softScore=0,hardBlocked=false;
function mark(reason){hardBlocked=true;reasons.push(reason)}
function markSoft(reason,score){softReasons.push(reason);softScore+=score}
try{if(navigator.webdriver===true){mark("webdriver")}}catch(e){}
try{if(/HeadlessChrome|HeadlessFirefox|PhantomJS|SlimerJS/i.test(navigator.userAgent||"")){mark("headless user agent")}}catch(e){}
try{if(window.callPhantom||window._phantom||window.__nightmare||window.__selenium_unwrapped||document.__selenium_unwrapped||window.__webdriver_evaluate||window.__fxdriver_unwrapped){mark("automation framework")}}catch(e){}
try{if(window.__playwright||window.__pw_manual||window._playwrightInstance||document.__playwright_target__||window.__puppeteer_evaluation_script__||window.__pptr_tmp_binding){mark("browser automation runtime")}}catch(e){}
try{if(window.Cypress||window.__cypress){mark("cypress runtime")}}catch(e){}
try{var keys=["__webdriver_evaluate","__selenium_evaluate","__fxdriver_evaluate","__driver_unwrapped","__webdriver_unwrapped","__driver_evaluate","__selenium_unwrapped","__fxdriver_unwrapped","_Selenium_IDE_Recorder","_selenium","calledSelenium","_WEBDRIVER_ELEM_CACHE","ChromeDriverw","driver-hierarchical-name"];for(var i=0;i<keys.length;i++){if(window[keys[i]]!==undefined){mark("webdriver marker");break}}}catch(e){}
try{var cdc=false;for(var k in document){if(/^cdc_|^\\$cdc_/.test(k)){cdc=true;break}}if(cdc){mark("chrome driver marker")}}catch(e){}
try{var d=Object.getOwnPropertyDescriptor(Navigator.prototype,"webdriver");if(d&&d.get&&d.get.toString().indexOf("native code")===-1){mark("webdriver getter")}}catch(e){}
try{if(window.Runtime&&typeof window.Runtime.evaluate==="function"){mark("cdp runtime")}}catch(e){}
try{if(window.process&&window.process.versions&&window.process.versions.electron){markSoft("electron runtime",35)}}catch(e){}
try{var ow=window.outerWidth||0,iw=window.innerWidth||0,oh=window.outerHeight||0,ih=window.innerHeight||0;if((ow>0&&iw>0&&ow-iw>160)||(oh>0&&ih>0&&oh-ih>160)){markSoft("devtools window gap",35)}}catch(e){}
try{var getter=0,probe=new Image();Object.defineProperty(probe,"id",{get:function(){getter++}});if(window.console&&typeof window.console.log==="function"){window.console.log(probe);if(typeof window.console.clear==="function"){window.console.clear()}}if(getter>0){markSoft("devtools console",35)}}catch(e){}
try{var before=performance.now();debugger;if(performance.now()-before>150){markSoft("debugger pause",50)}}catch(e){}
var signals={webdriver:!!navigator.webdriver,plugins:navigator.plugins?navigator.plugins.length:0,languages:navigator.languages?navigator.languages.length:0,language:navigator.language||"",userAgent:navigator.userAgent||"",vendor:navigator.vendor||"",platform:navigator.platform||"",userAgentData:!!navigator.userAgentData,webgl:typeof WebGLRenderingContext!=="undefined",webgl2:typeof WebGL2RenderingContext!=="undefined",svg:typeof SVGElement!=="undefined",canvasToBlob:false,webglRenderer:"",canvasHash:"",audioContext:typeof AudioContext!=="undefined"||typeof webkitAudioContext!=="undefined",fonts:0,storage:!!window.sessionStorage,indexedDB:!!window.indexedDB,localStorage:!!window.localStorage,crypto:!!(window.crypto&&window.crypto.subtle),fetch:typeof fetch==="function",webSocket:typeof WebSocket!=="undefined",rtc:typeof RTCPeerConnection!=="undefined",notifications:typeof Notification!=="undefined",permissions:!!navigator.permissions,credentials:!!navigator.credentials,serviceWorker:!!navigator.serviceWorker,cacheAPI:!!window.caches,webAssembly:typeof WebAssembly!=="undefined",sharedWorker:typeof SharedWorker!=="undefined",broadcastChannel:typeof BroadcastChannel!=="undefined",performanceObserver:typeof PerformanceObserver!=="undefined",mutationObserver:typeof MutationObserver!=="undefined",resizeObserver:typeof ResizeObserver!=="undefined",intersectionObserver:typeof IntersectionObserver!=="undefined",visualViewport:!!window.visualViewport,screenWidth:screen.width||0,screenHeight:screen.height||0,viewportWidth:window.innerWidth||0,viewportHeight:window.innerHeight||0,outerWidth:window.outerWidth||0,outerHeight:window.outerHeight||0,screenX:window.screenX||window.screenLeft||0,screenY:window.screenY||window.screenTop||0};
try{var canvas=document.createElement("canvas");signals.canvasToBlob=typeof canvas.toBlob==="function";canvas.width=160;canvas.height=40;var ctx=canvas.getContext("2d");if(ctx){ctx.font="14px Arial";ctx.fillText("OWAF",2,2);var data=canvas.toDataURL(),hash=0;for(var ci=0;ci<data.length;ci++){hash=((hash<<5)-hash)+data.charCodeAt(ci);hash|=0}signals.canvasHash=String(hash)}}catch(e){}
try{var gl=document.createElement("canvas").getContext("webgl");if(gl){signals.webglRenderer=String(gl.getParameter(gl.RENDERER)||"")}}catch(e){}
try{var fonts=["Arial","Courier New","Georgia","Times New Roman","Verdana","monospace","serif","sans-serif"],probe=document.createElement("span");probe.textContent="mmmmmmmmmmlli";probe.style.cssText="position:absolute;left:-9999px;font-size:72px";document.body.appendChild(probe);var base=probe.offsetWidth;for(var fi=0;fi<fonts.length;fi++){probe.style.fontFamily=fonts[fi];if(probe.offsetWidth!==base){signals.fonts++}}probe.parentNode.removeChild(probe)}catch(e){}
try{var lang=(navigator.language||"").split("-")[0].toLowerCase(),intl=(Intl.DateTimeFormat().resolvedOptions().locale||"").split("-")[0].toLowerCase();signals.languageConsistent=!lang||!intl||lang===intl}catch(e){signals.languageConsistent=true}
try{var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;signals.timezone=tz||"";signals.timezoneConsistent=!!tz}catch(e){signals.timezone="";signals.timezoneConsistent=true}
try{var m1=Math.tan(-1e300),m2=Math.tan(-1e300);signals.mathConsistent=m1===m2}catch(e){signals.mathConsistent=true}
try{if(navigator.userAgentData){var brands=navigator.userAgentData.brands||[];signals.uaBrands=brands.map(function(b){return b.brand+"/"+b.version}).join(",");signals.uaMobile=!!navigator.userAgentData.mobile}}catch(e){signals.uaBrands="";signals.uaMobile=false}
var blocked=hardBlocked||softScore>=100;
var result={blocked:blocked,reasons:reasons.concat(blocked?softReasons:[]),softReasons:softReasons,softScore:softScore,signals:signals};g.envResult=result;return result}
function owafDebugJSON(v){try{var s=JSON.stringify(v,null,2);return s.length>12000?s.slice(0,12000)+"\n... truncated":s}catch(e){return String(v)}}
function owafErrorInfo(e){if(!e){return null}return{name:e.name||"Error",message:e.message||String(e),stack:e.stack||""}}
function owafEnvelopeInfo(x){return{present:!!x,hasData:!!(x&&x.owafData),dataLength:x&&x.owafData?x.owafData.length:0,hasIv:!!(x&&x.owafIv),ivLength:x&&x.owafIv?x.owafIv.length:0,hasWrap:!!(x&&x.owafWrap),wrapLength:x&&x.owafWrap?x.owafWrap.length:0,hasTicket:!!(x&&x.owafTicket),ticketLength:x&&x.owafTicket?x.owafTicket.length:0,hasKek:!!(x&&x.owafKek),kekLength:x&&x.owafKek?x.owafKek.length:0,hasKey:!!(x&&x.owafKey),keyLength:x&&x.owafKey?x.owafKey.length:0,ttl:x&&x.owafTtl?x.owafTtl:""}}
function owafExchangeDynamicKey(ticket,key,env){return fetch("/__owaf/dynamic/key",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({ticket:ticket||"",key:key||"",env:env||null})}).then(function(r){return r.text().then(function(t){var j={};try{j=t?JSON.parse(t):{}}catch(e){throw new Error("dynamic key response parse failed: "+t.slice(0,512))}if(!r.ok){throw new Error(j.error||("dynamic key exchange failed: "+r.status))}if(!j.kek){throw new Error("dynamic key response missing kek")}return j})})}
function owafDebugPayload(stage,err,extra){var g=window.__owafDP=window.__owafDP||{},payload={stage:stage||"unknown",error:owafErrorInfo(err),extra:extra||{},environment:g.envResult||null,cache:{cekCached:!!g.cekCached,hasCek:!!g.cek,hasCekKey:!!g.cekKey,sessionStorage:!!window.sessionStorage},browser:{href:location.href,secureContext:!!window.isSecureContext,crypto:!!(window.crypto&&window.crypto.subtle),language:navigator.language||"",userAgent:navigator.userAgent||"",time:(new Date()).toISOString()}};return payload}
function owafHasRecentSuccess(){try{var now=Date.now(),s=parseInt(sessionStorage.getItem("__owafDPFastUntil")||"0",10),l=parseInt(localStorage.getItem("__owafDPFastUntil")||"0",10);if(s>now||l>now){return true}}catch(e){}try{return document.cookie.indexOf("__owaf_dp_recent=1")>=0}catch(e){return false}}
function owafMarkRecentSuccess(ttl){var n=parseInt(ttl||"0",10);if(n<=0){n=300}n=Math.min(n,1800);var exp=Date.now()+n*1000;try{sessionStorage.setItem("__owafDPFastUntil",String(exp));localStorage.setItem("__owafDPFastUntil",String(exp))}catch(e){}try{document.cookie="__owaf_dp_recent=1; Max-Age="+n+"; Path=/; SameSite=Lax"}catch(e){}}
function owafStatus(text,blocked,debug){
var g=window.__owafDP=window.__owafDP||{};
var old=document.getElementById("__owaf_dp_loading")||document.getElementById("__owaf_dp_blocked");if(old&&old.parentNode){old.parentNode.removeChild(old)}
var el=document.createElement("div");el.id=blocked?"__owaf_dp_blocked":"__owaf_dp_loading";el.setAttribute("role",blocked?"alert":"status");el.setAttribute("aria-live","polite");el.setAttribute("style","position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;justify-content:center;padding:24px;box-sizing:border-box;background:linear-gradient(135deg,#020817 0%,#0f172a 48%,#111827 100%);color:#e5e7eb;font:14px/1.6 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;text-align:left");
var card=document.createElement("div");card.setAttribute("style","width:min(720px,100%);max-height:min(720px,calc(100vh - 48px));overflow:auto;padding:24px;border:1px solid "+(blocked?"rgba(248,113,113,.46)":"rgba(59,130,246,.34)")+";border-radius:18px;background:rgba(15,23,42,.94);box-shadow:0 24px 80px rgba(2,6,23,.55);backdrop-filter:blur(18px)");
var top=document.createElement("div");top.setAttribute("style","display:flex;align-items:center;gap:12px;margin-bottom:16px");var icon=document.createElement("div");icon.setAttribute("style","display:flex;height:38px;width:38px;align-items:center;justify-content:center;border-radius:12px;background:"+(blocked?"rgba(239,68,68,.14);color:#fecaca;border:1px solid rgba(248,113,113,.35)":"rgba(37,99,235,.16);color:#bfdbfe;border:1px solid rgba(96,165,250,.35)")+";font-weight:800;letter-spacing:-.04em");icon.textContent="W";var head=document.createElement("div");var badge=document.createElement("div");badge.setAttribute("style","font-size:12px;font-weight:650;color:"+(blocked?"#fecaca":"#bfdbfe")+";letter-spacing:.02em");badge.textContent=blocked?"OpenWAF 内容保护调试":"OpenWAF 安全网关";var title=document.createElement("div");title.setAttribute("style","font-size:22px;font-weight:720;letter-spacing:-.025em;color:#f8fafc");title.textContent=blocked?"当前浏览器环境无法显示此内容":"正在解密页面内容…";head.appendChild(badge);head.appendChild(title);top.appendChild(icon);top.appendChild(head);
var body=document.createElement("div");body.setAttribute("style","color:#cbd5e1;margin-bottom:"+(debug?"18px":"0"));body.textContent=text;card.appendChild(top);card.appendChild(body);
if(!blocked&&!debug){var bar=document.createElement("div");bar.setAttribute("style","position:relative;overflow:hidden;height:4px;margin-top:18px;border-radius:999px;background:rgba(30,41,59,.95)");var fill=document.createElement("div");fill.setAttribute("style","position:absolute;inset:0;width:42%;border-radius:999px;background:linear-gradient(90deg,#2563eb,#38bdf8);animation:owafBar 1.1s ease-in-out infinite alternate");bar.appendChild(fill);card.appendChild(bar);if(!document.getElementById("__owaf_dp_style")){var st=document.createElement("style");st.id="__owaf_dp_style";st.textContent="@keyframes owafBar{from{transform:translateX(-35%)}to{transform:translateX(165%)}}";document.head.appendChild(st)}}
if(debug){var grid=document.createElement("div");grid.setAttribute("style","display:grid;gap:12px;margin-top:18px");var label=document.createElement("div");label.setAttribute("style","font-size:13px;font-weight:700;color:#e2e8f0");label.textContent="调试输出";var hint=document.createElement("div");hint.setAttribute("style","font-size:12px;color:#94a3b8");hint.textContent="已隐藏密钥、密文和 CEK 原文，仅显示阶段、错误、环境信号和字段长度。";var pre=document.createElement("pre");pre.setAttribute("style","margin:0;max-height:420px;overflow:auto;white-space:pre-wrap;word-break:break-word;padding:14px;border-radius:14px;border:1px solid rgba(148,163,184,.24);background:rgba(2,6,23,.72);color:#dbeafe;font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace");pre.textContent=owafDebugJSON(debug);grid.appendChild(label);grid.appendChild(hint);grid.appendChild(pre);card.appendChild(grid)}
el.appendChild(card);var host=document.body||document.documentElement;if(host){host.appendChild(el);g.status=el}return el}
function owafMaybeStatus(text,blocked,debug){var g=window.__owafDP=window.__owafDP||{};if(blocked||debug){return owafStatus(text,blocked,debug)}if(owafHasRecentSuccess()){return null}try{clearTimeout(g.statusTimer)}catch(e){}g.statusTimer=setTimeout(function(){owafStatus(text,false,null)},180);return g.statusTimer}
function owafRemoveStatus(){var g=window.__owafDP;if(g){try{clearTimeout(g.statusTimer)}catch(e){}g.statusTimer=null}if(g&&g.status&&g.status.parentNode){g.status.parentNode.removeChild(g.status)}var old=document.getElementById("__owaf_dp_loading")||document.getElementById("__owaf_dp_blocked");if(old&&old.parentNode){old.parentNode.removeChild(old)}if(g){g.status=null}}
`

const htmlBootstrapScript = dynamicEnvironmentCheck + `(function(){
function current(){var cs=document.currentScript;if(cs&&cs.dataset&&cs.dataset.owafDp==="2"){return cs}var list=document.querySelectorAll?document.querySelectorAll("script[data-owaf-dp='2']"):[];return list.length?list[list.length-1]:null}
var s=current(),x=s&&s.dataset;
var g=window.__owafDP=window.__owafDP||{};
owafMaybeStatus("请稍候，正在准备安全页面。",false);
function u(v){var b=atob(v),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a}
function b64(a){var s="",b=new Uint8Array(a);for(var i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);return btoa(s)}
function forget(){try{sessionStorage.removeItem("__owafDPCek")}catch(e){}g.cek=null;g.cekKey=null;g.cekCached=false}
function fail(text,stage,err,extra){owafRemoveStatus();var p=s&&s.parentNode,debug=owafDebugPayload(stage,err,Object.assign({envelope:owafEnvelopeInfo(x)},extra||{})),m=owafStatus(text||"内容解密失败，请刷新页面或联系站点管理员。",true,debug);if(p){if(m.parentNode!==p){p.insertBefore(m,s)}if(s.parentNode===p){p.removeChild(s)}}}
function deny(env){fail("检测到自动化或调试浏览器，页面内容已被保护。请使用正常浏览器重新打开。","environment-blocked",null,{environment:env})}
function activateScripts(root){var list=[];if(root&&root.tagName&&root.tagName.toLowerCase()==="script"){list=[root]}else{list=root&&root.querySelectorAll?root.querySelectorAll("script"):[]}for(var i=0;i<list.length;i++){var old=list[i],fresh=document.createElement("script");for(var j=0;j<old.attributes.length;j++){var attr=old.attributes[j];fresh.setAttribute(attr.name,attr.value)}fresh.text=old.text||old.textContent||"";old.parentNode.replaceChild(fresh,old)}}
async function wasm(){if(g.wasm)return g.wasm;if(typeof wasm_bindgen!=="undefined"){g.wasm=await wasm_bindgen("/__owaf/pow.wasm");return g.wasm}await new Promise(function(ok,err){var sc=document.createElement("script");sc.src="/__owaf/pow_glue.js";sc.onload=ok;sc.onerror=function(){err(new Error("dynamic wasm glue load failed"))};document.head.appendChild(sc)});g.wasm=await wasm_bindgen("/__owaf/pow.wasm");return g.wasm}
async function cek(force){
if(!x){throw new Error("missing dynamic envelope")}
await wasm();var ttl=parseInt(x.owafTtl||"0",10),key=x.owafKey||x.owafWrap;
if(ttl<=0){forget()}
if(!force&&g.cek&&g.cekKey===key){g.cekCached=true;return g.cek}
if(!force&&ttl>0){try{var c=sessionStorage.getItem("__owafDPCek");if(c){var o=JSON.parse(c);if(o.exp>Date.now()&&o.key===key){g.cek=u(o.raw);g.cekKey=key;g.cekCached=true;return g.cek}}}catch(e){}}
g.cekCached=false;var kek=x.owafKek||"";if(!kek&&x.owafTicket){var env=owafCheckEnvironment();var rsp=await owafExchangeDynamicKey(x.owafTicket,key,env);kek=rsp.kek;ttl=parseInt(rsp.ttl||ttl||"0",10)||ttl}
var raw=wasm_bindgen.unwrap_dynamic_cek(x.owafWrap,kek);g.cek=raw;g.cekKey=key;
try{if(ttl>0){sessionStorage.setItem("__owafDPCek",JSON.stringify({key:key,raw:b64(raw),exp:Date.now()+ttl*1000}))}}catch(e){}
return raw}
async function decryptWithRetry(){var k;try{k=await cek(false);return wasm_bindgen.decrypt_dynamic_with_cek(x.owafData,x.owafIv,k)}catch(e){if(g.cekCached){forget();k=await cek(true);return wasm_bindgen.decrypt_dynamic_with_cek(x.owafData,x.owafIv,k)}throw e}}
(async function(){
try{
if(!s||!x){fail("动态保护信封缺失，无法读取页面加密字段。","missing-envelope",null,{scriptFound:!!s});return}
var env=owafCheckEnvironment();if(env.blocked){deny(env);return}
var pt=await decryptWithRetry();
var html=new TextDecoder().decode(pt);
var t=document.createElement("template");t.innerHTML=html;
owafMarkRecentSuccess(x.owafTtl);document.open();document.write(html);document.close();
}catch(e){fail("内容解密失败，请刷新页面或联系站点管理员。","html-decrypt",e)}
})();
})();`

const jsSelfDecryptTemplate = dynamicEnvironmentCheck + `(function(){
var D="__DATA__",V="__IV__",W="__WRAP__",K="__KEK__",T="__TICKET__",Q="__KEY__";
owafMaybeStatus("请稍候，正在准备安全脚本。",false);
function u(v){var b=atob(v),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a}
function b64(a){var s="",b=new Uint8Array(a);for(var i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);return btoa(s)}
function forget(){var g=window.__owafDP=window.__owafDP||{};try{sessionStorage.removeItem("__owafDPCek")}catch(e){}g.cek=null;g.cekKey=null;g.cekCached=false}
async function wasm(){var g=window.__owafDP=window.__owafDP||{};if(g.wasm)return g.wasm;if(typeof wasm_bindgen!=="undefined"){g.wasm=await wasm_bindgen("/__owaf/pow.wasm");return g.wasm}await new Promise(function(ok,err){var sc=document.createElement("script");sc.src="/__owaf/pow_glue.js";sc.onload=ok;sc.onerror=function(){err(new Error("dynamic wasm glue load failed"))};document.head.appendChild(sc)});g.wasm=await wasm_bindgen("/__owaf/pow.wasm");return g.wasm}
async function cek(force){
var g=window.__owafDP=window.__owafDP||{},key=Q||W,ttl=parseInt(g.owafTtl||"0",10);
await wasm();
if(ttl<=0){forget()}
if(!force&&g.cek&&g.cekKey===key){g.cekCached=true;return g.cek}
if(!force&&ttl>0){try{var c=sessionStorage.getItem("__owafDPCek");if(c){var o=JSON.parse(c);if(o.exp>Date.now()&&o.key===key){g.cek=u(o.raw);g.cekKey=key;g.cekCached=true;return g.cek}}}catch(e){}}
g.cekCached=false;var kek=K;if(!kek&&T){var env=owafCheckEnvironment();var rsp=await owafExchangeDynamicKey(T,key,env);kek=rsp.kek;if(rsp.ttl){ttl=parseInt(rsp.ttl,10)||ttl;g.owafTtl=String(ttl)}}
var raw=wasm_bindgen.unwrap_dynamic_cek(W,kek);g.cek=raw;g.cekKey=key;if(ttl>0){try{sessionStorage.setItem("__owafDPCek",JSON.stringify({key:key,raw:b64(raw),exp:Date.now()+ttl*1000}))}catch(e){}}return raw}
async function decryptWithRetry(){var g=window.__owafDP||{},k;try{k=await cek(false);return wasm_bindgen.decrypt_dynamic_with_cek(D,V,k)}catch(e){if(g.cekCached){forget();k=await cek(true);return wasm_bindgen.decrypt_dynamic_with_cek(D,V,k)}throw e}}
(async function(){
try{
var env=owafCheckEnvironment();if(env.blocked){owafRemoveStatus();owafStatus("检测到自动化或调试浏览器，脚本内容已被保护。请使用正常浏览器重新打开。",true,owafDebugPayload("js-environment-blocked",null,{environment:env,envelope:{dataLength:D.length,ivLength:V.length,wrapLength:W.length,ticketLength:T.length,kekLength:K.length,keyLength:Q.length}}));return}
var pt=await decryptWithRetry();
var code=new TextDecoder().decode(pt);
(0,eval)(code);owafMarkRecentSuccess(300);owafRemoveStatus();
}catch(e){owafRemoveStatus();owafStatus("脚本解密失败，请刷新页面或联系站点管理员。",true,owafDebugPayload("js-decrypt",e,{envelope:{dataLength:D.length,ivLength:V.length,wrapLength:W.length,ticketLength:T.length,kekLength:K.length,keyLength:Q.length}}))}
})();
})();`

// renderJSSelfDecrypt 用信封数据填充 JS 自解密模板。
func renderJSSelfDecrypt(env envelope) []byte {
	r := strings.NewReplacer(
		"__DATA__", env.data,
		"__IV__", env.iv,
		"__WRAP__", env.wrap,
		"__KEK__", env.kek,
		"__TICKET__", env.ticket,
		"__KEY__", env.key,
	)
	return []byte(r.Replace(jsSelfDecryptTemplate))
}
