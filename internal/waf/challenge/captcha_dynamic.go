package challenge

import (
	"strings"

	"My-OpenWaf/internal/waf/challenge/pow"
)

// 本文件实现验证码「执行逻辑动态下发」：服务端每次签发新题目时，为信封生成一段
// 行为等价但文本多态的交互脚本（exec_script），随题目一起进入 SM4-GCM 信封；
// 客户端模板解密 envelope 后经 (0,eval) 执行；执行失败或旧信封（无 exec_script）
// 一律回退模板内保留的 legacy 静态逻辑，因此不存在断链。
//
// 多态来源（严格限定，不得引入行为差异）：
//   - 变量名字段随机（randomVarNames，占位槽 @c0@..@c18@）；
//   - 题型交互段分为变体 A（贴近 captcha.html 模板原语义）与变体 B（等价重排 +
//     polymorphicEncode 字符串常量，占位槽 @e0@..@e7@），由 crypto/rand 二选一；
//   - 四类题型（click/slide/rotate/math）的 DOM 构建、事件绑定顺序、
//     currentPlain 读取优先级均与 templates/captcha.html 111-223 行逐条等价。

// captchaScriptSkeleton 是四类题型共用的动态脚本骨架。
// 入口形态为 (function(KEYHEX,DATA,payload){...})，由模板薄壳 runInject 以
// (script+'('+JSON.stringify(KEYHEX)+','+JSON.stringify(DATA)+','+JSON.stringify(parsed)+')')
// 的形式补齐实参后 (0,eval) 执行——KEYHEX/DATA/题面一律经参数注入，脚本本身不再
// 重复读取 DOM 上的 cap-key/cap-data，capture 语义由薄壳统一保证。
// 脚本通过薄壳注入的 window.__owaf_inject_captcha 句柄获取表单/按钮/根节点等
// 元素 id 与 loadWasm 就绪 Promise，不自行写死 'cap-form' 等 id 字面量。
const captchaScriptSkeleton = `(function(@c0@,@c1@,@c2@){
var @c3@=window.__owaf_inject_captcha;
if(!@c3@)throw new Error('CAPTCHA exec handle missing');
var @c4@=document.getElementById(@c3@.form);
var @c5@=@c4@?document.getElementById(@c3@.submit):null;
var @c6@=false;
function @c7@(msg){var @c8@=document.getElementById(@c3@.status);if(!@c8@)return;@c8@.style.display='block';@c8@.textContent=msg;}
function @c9@(){
 var el=document.getElementById('cap-answer-plain');
 if(el)return el.value.trim();
 var c=document.getElementById('cap-click-state');
 if(c&&c.value)return c.value;
 var s=document.getElementById('cap-slide-state');
 if(s&&s.value)return s.value;
 var r=document.getElementById('cap-rotate-state');
 if(r&&r.value)return r.value;
 return '';
}
function @c10@(id){
 var i=document.createElement('input');
 i.type='hidden';
 i.id=id;
 var @c11@=document.getElementById(@c3@.answer);
 @c11@.parentNode.insertBefore(i,@c11@);
 return i;
}
function @c12@(node){
 var root=document.getElementById(@c3@.root);
 if(!root)return;
 root.appendChild(node);
}
@seg@
@c3@.plain=@c9@;
if(@c4@){
 @c4@.addEventListener('submit',function(@c13@){
  if(@c6@)return;
  @c13@.preventDefault();
  var @c14@=@c9@();
  if(!@c14@){@c7@('请先完成验证。');return;}
  @c3@.loadWasm().then(function(){
   if(typeof wasm_bindgen.gm_encrypt_challenge_answer!=="function")throw new Error('WebAssembly verification is unavailable. / 当前环境不支持 WebAssembly 安全验证');
   var @c15@=wasm_bindgen.gm_encrypt_challenge_answer(@c14@,@c0@);
   if(!@c15@)throw new Error('Answer encryption failed. / 答案加密失败');
   return @c15@;
  }).then(function(@c15@){
   @c6@=true;
   @c5@.disabled=true;
   document.getElementById(@c3@.answer).value=@c15@;
   if(window.__owaf_env_ready&&typeof window.__owaf_env_ready.then==='function'){
    return window.__owaf_env_ready.then(function(@c16@){
     if(@c16@)document.getElementById('cap-env').value=@c16@;
     HTMLFormElement.prototype.submit.call(@c4@);
    });
   }
   var @c17@=window.__owaf_env_encrypted;
   if(@c17@)document.getElementById('cap-env').value=@c17@;
   HTMLFormElement.prototype.submit.call(@c4@);
  }).catch(function(@c18@){@c7@((@c18@&&@c18@.message)||'验证失败，请刷新重试。');});
 });
}
})`

// 变体 A：贴近 templates/captcha.html build(parsed) 对应分支的原语义。

const captchaClickVarA = `
var st=document.createElement('div');st.className='captcha-stack';
var wr=document.createElement('div');wr.className='img-wrap';
var im=document.createElement('img');im.id='cap-img';im.src=@c2@.master_img;im.alt='CAPTCHA';
wr.appendChild(im);st.appendChild(wr);
if(@c2@.thumb_img){var th=document.createElement('img');th.className='thumb';th.src=@c2@.thumb_img;th.alt='target';st.appendChild(th);}
var cl=document.createElement('button');cl.type='button';cl.className='mini';cl.textContent='Clear clicks / 清空点击';st.appendChild(cl);
@c12@(st);
var pts=[];
var cs=@c10@('cap-click-state');
im.addEventListener('click',function(e){
 var r=im.getBoundingClientRect();
 var x=Math.round(((e.clientX-r.left)/r.width)*(im.naturalWidth||r.width));
 var y=Math.round(((e.clientY-r.top)/r.height)*(im.naturalHeight||r.height));
 pts.push({x:x,y:y});
 cs.value=JSON.stringify(pts);
 var d=document.createElement('span');
 d.className='dot';d.textContent=String(pts.length);
 d.style.left=((x/(im.naturalWidth||r.width))*100)+'%';
 d.style.top=((y/(im.naturalHeight||r.height))*100)+'%';
 wr.appendChild(d);
});
cl.addEventListener('click',function(){
 pts=[];cs.value='';
 document.querySelectorAll('.dot').forEach(function(n){n.remove();});
});`

const captchaClickVarB = `
var st=document.createElement('div');st.className=@e2@;
var wr=document.createElement('div');wr.className=@e3@;
var im=document.createElement('img');im.id='cap-img';im.src=@c2@.master_img;im.alt=@e1@;
wr.appendChild(im);st.appendChild(wr);
if(@c2@.thumb_img){var th=document.createElement('img');th.className=@e4@;th.src=@c2@.thumb_img;th.alt='target';st.appendChild(th);}
var cl=document.createElement('button');cl.type='button';cl.className=@e5@;cl.textContent=@e0@;st.appendChild(cl);
var cs=@c10@('cap-click-state');
var pts=[];
(function(acc){
 im.addEventListener('click',function(e){
  var r=im.getBoundingClientRect();
  var x=Math.round(((e.clientX-r.left)/r.width)*(im.naturalWidth||r.width));
  var y=Math.round(((e.clientY-r.top)/r.height)*(im.naturalHeight||r.height));
  acc.push({x:x,y:y});
  cs.value=JSON.stringify(acc);
  var d=document.createElement('span');
  d.className='dot';d.textContent=String(acc.length);
  d.style.left=((x/(im.naturalWidth||r.width))*100)+'%';
  d.style.top=((y/(im.naturalHeight||r.height))*100)+'%';
  wr.appendChild(d);
 });
 cl.addEventListener('click',function(){
  acc.length=0;cs.value='';
  document.querySelectorAll('.dot').forEach(function(n){n.remove();});
 });
})(pts);
@c12@(st);`

const captchaSlideVarA = `
var st=document.createElement('div');st.className='captcha-stack';
var mi=document.createElement('img');mi.id='cap-img';mi.src=@c2@.master_img;mi.alt='CAPTCHA';
st.appendChild(mi);
var th=null;
if(@c2@.thumb_img){th=document.createElement('img');th.id='slide-thumb';th.className='thumb slide-thumb';th.src=@c2@.thumb_img;th.alt='slider';st.appendChild(th);}
var rw=Math.max(200,(@c2@.width||300));
var rn=document.createElement('input');rn.type='range';rn.min='0';rn.max=String(rw);rn.value='0';rn.id='slide-range';
st.appendChild(rn);@c12@(st);
var ss=@c10@('cap-slide-state');
rn.addEventListener('input',function(){
 ss.value=JSON.stringify({x:Number(rn.value)});
 if(th)th.style.transform='translateX('+rn.value+'px)';
});`

const captchaSlideVarB = `
var st=document.createElement('div');st.className=@e2@;
var ss=@c10@('cap-slide-state');
var mi=document.createElement('img');mi.id='cap-img';mi.src=@c2@.master_img;mi.alt=@e1@;
st.appendChild(mi);
var th=null;
if(@c2@.thumb_img){th=document.createElement('img');th.id='slide-thumb';th.className=@e4@+' slide-thumb';th.src=@c2@.thumb_img;th.alt='slider';st.appendChild(th);}
var rn=document.createElement('input');rn.type='range';rn.min='0';rn.max=String(Math.max(200,(@c2@.width||300)));rn.value='0';rn.id='slide-range';
st.appendChild(rn);@c12@(st);
function upd(){ss.value=JSON.stringify({x:Number(rn.value)});if(th)th.style.transform='translateX('+rn.value+'px)';}
rn.addEventListener('input',upd);`

const captchaRotateVarA = `
var st=document.createElement('div');st.className='captcha-stack rotate-captcha';
var mi=document.createElement('img');mi.id='cap-img';mi.src=@c2@.master_img;mi.alt='CAPTCHA';
st.appendChild(mi);
var th=null;
if(@c2@.thumb_img){th=document.createElement('img');th.id='rotate-thumb';th.className='thumb';th.src=@c2@.thumb_img;th.alt='target';st.appendChild(th);}
var rn=document.createElement('input');rn.type='range';rn.min='0';rn.max='360';rn.value='0';rn.id='rotate-range';
st.appendChild(rn);@c12@(st);
var rs=@c10@('cap-rotate-state');
rn.addEventListener('input',function(){
 rs.value=JSON.stringify({angle:Number(rn.value)});
 if(th)th.style.transform='rotate('+rn.value+'deg)';
});`

const captchaRotateVarB = `
var st=document.createElement('div');st.className=@e2@+' rotate-captcha';
var rs=@c10@('cap-rotate-state');
var mi=document.createElement('img');mi.id='cap-img';mi.src=@c2@.master_img;mi.alt=@e1@;
st.appendChild(mi);
var th=null;
if(@c2@.thumb_img){th=document.createElement('img');th.id='rotate-thumb';th.className=@e4@;th.src=@c2@.thumb_img;th.alt='target';st.appendChild(th);}
var rn=document.createElement('input');rn.type='range';rn.min='0';rn.max=@e6@;rn.value='0';rn.id='rotate-range';
st.appendChild(rn);@c12@(st);
function upd(){rs.value=JSON.stringify({angle:Number(rn.value)});if(th)th.style.transform='rotate('+rn.value+'deg)';}
rn.addEventListener('input',upd);`

const captchaMathVarA = `
if(@c2@.master_img){
 var mi2=document.createElement('img');mi2.id='cap-img';mi2.src=@c2@.master_img;mi2.alt='CAPTCHA';
 @c12@(mi2);
}
var box=document.createElement('div');box.style.width='100%';
var input=document.createElement('input');input.type='text';input.id='cap-answer-plain';
input.placeholder=(@c2@.prompt||'输入计算结果');
input.setAttribute('aria-label',(@c2@.input_mode||'输入计算结果'));
input.autocomplete='off';input.autofocus=true;
box.appendChild(input);@c12@(box);`

const captchaMathVarB = `
var box=document.createElement('div');box.style.width='100%';
var input=document.createElement('input');input.type='text';input.id='cap-answer-plain';
input.placeholder=(@c2@.prompt||@e7@);
input.setAttribute('aria-label',(@c2@.input_mode||@e7@));
input.autocomplete='off';input.autofocus=true;
box.appendChild(input);
if(@c2@.master_img){
 var mi2=document.createElement('img');mi2.id='cap-img';mi2.src=@c2@.master_img;mi2.alt=@e1@;
 @c12@(mi2);
}
@c12@(box);`

// captchaScriptSkeleton 里的变量名槽位数量（@c0@..@c18@，共 19 个）。
const captchaScriptNameSlots = 19

// captchaScriptEncodeLiterals 是变体 B 内 @e0@..@e7@ 占位符对应的字符串常量，
// 顺序必须与 captchaScriptEncoders 的返回下标一一对应。
var captchaScriptEncodeLiterals = []string{
	"Clear clicks / 清空点击",
	"CAPTCHA",
	"captcha-stack",
	"img-wrap",
	"thumb",
	"mini",
	"360",
	"输入计算结果",
}

// captchaScriptEncoders 为单次签发准备 8 个字符串常量各自的多态编码 JS 文本。
func captchaScriptEncoders() []string {
	out := make([]string, len(captchaScriptEncodeLiterals))
	for i, literal := range captchaScriptEncodeLiterals {
		out[i] = pow.PolymorphicEncode(literal)
	}
	return out
}

// captchaExecScriptVariants 生成题型 t 的两个行为等价变体文本（当下随机态），
// 供 BuildCaptchaExecScript 随机选用，也供测试枚举对照。
// 返回 nil 表示题型不受支持（不发动态脚本，客户端自然走 legacy 路径）。
func captchaExecScriptVariants(t CaptchaType) []string {
	var segA, segB string
	switch t {
	case CaptchaTypeClick:
		segA, segB = captchaClickVarA, captchaClickVarB
	case CaptchaTypeSlide:
		segA, segB = captchaSlideVarA, captchaSlideVarB
	case CaptchaTypeRotate:
		segA, segB = captchaRotateVarA, captchaRotateVarB
	case CaptchaTypeMath:
		segA, segB = captchaMathVarA, captchaMathVarB
	default:
		return nil
	}
	names := pow.RandomVarNames(captchaScriptNameSlots)
	enc := captchaScriptEncoders()
	return []string{
		renderCaptchaScriptVariant(segA, names, enc),
		renderCaptchaScriptVariant(segB, names, enc),
	}
}

// renderCaptchaScriptVariant 把题型交互段装配进公共骨架，并把随机变量名槽
// （@c0@..）与多态编码槽（@e0@..）替换为本次签发的具名文本。
// 注意槽位替换顺序从高到低无关紧要：槽位标签自带数字边界（@c10@ 文本不会命中
// @c1@ 替换，因为 "@c1@" 不是 "@c10@" 的子串）。
func renderCaptchaScriptVariant(seg string, names []string, enc []string) string {
	s := strings.Replace(captchaScriptSkeleton, "@seg@", seg, 1)
	for i := 0; i < captchaScriptNameSlots && i < len(names); i++ {
		s = strings.ReplaceAll(s, "@c"+itoaSmall(i)+"@", names[i])
	}
	for i := 0; i < len(captchaScriptEncodeLiterals) && i < len(enc); i++ {
		s = strings.ReplaceAll(s, "@e"+itoaSmall(i)+"@", enc[i])
	}
	return s
}

// itoaSmall 是 itoa 的零依赖替代：槽位下标只取 0..18，避免引入 strconv 仅为一个调用。
func itoaSmall(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// BuildCaptchaExecScript 为题型 t 随机选择一个行为等价变体作为动态执行脚本。
// 未知题型返回空串；空串落入信封后客户端按 legacy 路径运行旧静态逻辑。
func BuildCaptchaExecScript(t CaptchaType) string {
	if !IsValidCaptchaType(t) {
		return ""
	}
	variants := captchaExecScriptVariants(t)
	if len(variants) == 0 {
		return ""
	}
	return variants[pow.RandIntN(len(variants))]
}
