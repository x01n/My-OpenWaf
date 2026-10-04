package challenge

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/pkg/vmpasm"
	"My-OpenWaf/internal/waf/challenge/powdata"
)

var (
	gzipWASMOnce sync.Once
	gzipWASM     []byte
	gzipGlueOnce sync.Once
	gzipGlueJS   []byte
)

func gzipBytes(data []byte) []byte {
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

/**
 * PowGlueURL 返回 Gecko 侧引用的 glue 脚本 URL，带内容派生版本串。
 *
 * 版本串必须与资产内容绑定：这两个 URL 的响应带 `immutable`，浏览器在缓存
 * 窗口内不回源校验；URL 不随内容变时换资产会让老访客继续用旧文件。
 * 分开导出的原因见 ServePoWWASM 的注释。
 */
func PowGlueURL() string {
	return "/__owaf/pow_glue.js?v=" + powdata.GlueVersion()
}

// PowWasmURL 返回 Gecko 侧引用的 WASM 二进制 URL，带内容派生版本串。
func PowWasmURL() string {
	return "/__owaf/pow.wasm?v=" + powdata.WasmVersion()
}

/**
 * ServePoWWASM 下发预编译的 WASM 二进制（gzip 压缩）。
 *
 * Cache-Control 用 `immutable` + 30 天：客户端引用的 URL 带内容派生版本串
 * （见 PowWasmURL），换资产即换 URL，因此长窗口不会造成旧资产滞留。
 * 反向约束：**改这个 max-age 必须与版本串机制同批**——只调大 max-age 而
 * URL 不随内容变，会把「旧 wasm 滞留 1 小时」恶化成「滞留 30 天」。
 */
func ServePoWWASM(c *app.RequestContext) {
	gzipWASMOnce.Do(func() { gzipWASM = gzipBytes(powdata.WASMBinary) })
	c.Response.SetStatusCode(200)
	c.Response.Header.Set("Content-Type", "application/wasm")
	c.Response.Header.Set("Content-Encoding", "gzip")
	c.Response.Header.Set("Cache-Control", "public,max-age=2592000,immutable")
	c.Response.SetBody(gzipWASM)
}

// ServePowGlueJS 下发 Rust wasm-bindgen 生成的 glue JS（gzip 压缩）。
// max-age 与版本串的配对关系同 ServePoWWASM。
func ServePowGlueJS(c *app.RequestContext) {
	gzipGlueOnce.Do(func() { gzipGlueJS = gzipBytes(powdata.PowGlueJS) })
	c.Response.SetStatusCode(200)
	c.Response.Header.Set("Content-Type", "application/javascript")
	c.Response.Header.Set("Content-Encoding", "gzip")
	c.Response.Header.Set("Cache-Control", "public,max-age=2592000,immutable")
	c.Response.SetBody(gzipGlueJS)
}

// GeneratePoWNonce 为 PoW 挑战生成一个密码学随机的 nonce。
func GeneratePoWNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

const (
	// sha256HexLen 是 SHA-256 十六进制摘要的固定长度。
	sha256HexLen = 64

	// minPoWDifficulty 是允许的最小 PoW 难度（前导零个数）。
	// 难度 0 等价于“零工作量”，必须拒绝。
	minPoWDifficulty = 1

	// maxPoWDifficulty 是允许的最大 PoW 难度。
	// 每增加 1 位前导零，期望哈希次数 ×16；难度 7 的期望工作量约 2.7e8 次
	// SHA-256，在多 Worker WASM 求解器上已是数秒级，再高会导致真实用户超时。
	// 生成与校验两侧都必须钳制到同一上限，否则会出现“永远无法通过”的挑战。
	maxPoWDifficulty = 7
)

// ClampPoWDifficulty 将配置的 PoW 难度钳制到 [minPoWDifficulty, maxPoWDifficulty]。
// 生成挑战与校验解答必须使用同一钳制结果，避免二者难度不一致导致挑战永不通过。
func ClampPoWDifficulty(difficulty int) int {
	if difficulty < minPoWDifficulty {
		return minPoWDifficulty
	}
	if difficulty > maxPoWDifficulty {
		return maxPoWDifficulty
	}
	return difficulty
}

// isLowerHexSHA256 判断字符串是否为 64 位小写十六进制摘要。
// 客户端提交的 hash 必须与 hex.EncodeToString 的输出编码完全一致，
// 否则大小写变体会绕过前导零前缀检查。
func isLowerHexSHA256(s string) bool {
	if len(s) != sha256HexLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

/**
 * VerifyPoW 校验一份工作量证明解答。
 * 检查 SHA-256(nonce + counter) 是否具备要求的前导零个数。
 *
 * 校验顺序：先拒绝非法难度与畸形摘要，再检查前导零，最后重算摘要做常量时间比较。
 * difficulty 超出 [minPoWDifficulty, maxPoWDifficulty] 一律拒绝——难度 0 会接受
 * 零工作量解答，负难度会让 strings.Repeat panic。
 */
func VerifyPoW(nonce string, counter int64, hash string, difficulty int) bool {
	if difficulty < minPoWDifficulty || difficulty > maxPoWDifficulty {
		return false
	}
	if counter < 0 {
		return false
	}
	if !isLowerHexSHA256(hash) {
		return false
	}
	for i := 0; i < difficulty; i++ {
		if hash[i] != '0' {
			return false
		}
	}
	msg := nonce + strconv.FormatInt(counter, 10)
	computed := sha256Hex(msg)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) == 1
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

/**
 * GenerateVMProgram 生成 PoW 程序字节码（程序容器格式，十六进制）。
 *
 * 程序内容是 `SHA-256(nonce ‖ decimal(counter))` 的完整实现 + 前导零判定，
 * 由 vmpasm 汇编成 ISA 字节码。**没有任何 PoW 专用指令**：前导零检查是
 * 「循环 + 无符号比较 + 条件跳转」（见 temp/_vmp-track/ISA.md §4.3.6）。
 *
 * # 为什么不再做多态填充
 *
 * 旧实现（固定 5 步状态机 + 随机 NOP 填充）已被删除：ISA 现在是通用指令集，
 * 程序是真实计算，多态性由**程序本身的结构**（分支、循环、变量布局）承担，
 * 而不是靠插入无操作字节。ISA 里也没有 NOP 填充这一说 —— `NOP` 是可执行
 * 指令，插进控制流会改变可达性分析，不是"无害填充"。
 *
 * 程序是**确定性**的：同一版本下所有客户端拿到相同字节码，其版本串通过
 * WASM 资产的内容派生版本机制传播（PowWasmURL / PowGlueURL）。
 */
func GenerateVMProgram() string {
	prog, err := vmpasm.Assemble(vmpasm.PoWProgramLayout(), vmpasm.BuildPoWProgram())
	if err != nil {
		// 程序是编译期常量，汇编失败只可能是代码缺陷；返回空串会让
		// solve_pow_batched 以 vm_bad_magic 失败（可见的错误，不是静默降级）。
		return ""
	}
	return vmpasm.Hex(prog)
}

func GeneratePoWWASMScript(difficulty int, nonce string) string {
	return generatePoWScriptBody(difficulty, nonce)
}

func generatePoWScriptBody(difficulty int, nonce string) string {
	difficulty = ClampPoWDifficulty(difficulty)
	program := GenerateVMProgram()
	v := randomVarNames(2)
	encodedNonce := polymorphicEncode(nonce)

	return fmt.Sprintf(`(function(){
var %s=%s,%s=%d;
if(window.__owaf_pow_cancel){try{window.__owaf_pow_cancel()}catch(e){}}
var nc=navigator.hardwareConcurrency||4;
var bs=50000;
var ws=[];
var done=false;
function cleanup(){for(var j=0;j<ws.length;j++)ws[j].terminate();ws=[]}
function fail(msg){if(done)return;done=true;cleanup();window.__owaf_pow_last_error=msg;if(window.__owaf_pow_error){window.__owaf_pow_error(msg)}}
window.__owaf_pow_cancel=function(){done=true;cleanup()};
function begin(){
var wc='importScripts("'+location.origin+'%s");wasm_bindgen({module_or_path:location.origin+"%s"}).then(function(){var off=BigInt(self.__off);function batch(){if(self.__stop)return;try{var r=wasm_bindgen.solve_pow_batched(self.__n,self.__d,self.__p,self.__bs,off);var o=JSON.parse(r);if(o.found){self.postMessage(JSON.stringify({found:true,pow:r}))}else{off+=BigInt(self.__bs*self.__nc);self.postMessage(JSON.stringify({found:false}));setTimeout(batch,0)}}catch(e){self.postMessage(JSON.stringify({error:e.message||String(e)||"pow solve failed"}))}}batch()}).catch(function(e){self.postMessage(JSON.stringify({error:e.message||"wasm init failed"}))});';
for(var i=0;i<nc;i++){
var code='self.__n='+JSON.stringify(%s)+';self.__d='+%s+';self.__p=%q;self.__off='+i+'*'+bs+';self.__bs='+bs+';self.__nc='+nc+';self.__stop=false;'+wc;
try{var b=new Blob([code],{type:'application/javascript'});var w=new Worker(URL.createObjectURL(b))}catch(e){fail("[OWAF] WASM Worker creation failed: "+(e.message||String(e)));return}
w.onmessage=function(e){
if(done)return;
try{var msg=JSON.parse(e.data);
if(msg.error){fail("[OWAF] WASM PoW failed: "+msg.error);return}
if(msg.found){done=true;
cleanup();
var p=JSON.parse(msg.pow);
window.__powResult={nonce:%s,counter:p.counter,hash:p.hash,difficulty:%s};
if(window.__owaf_pow_callback)window.__owaf_pow_callback(p.counter,p.hash,window.__powResult);
if(window.__onPoWComplete)window.__onPoWComplete(window.__powResult);
}}catch(ex){fail(ex.message||String(ex)||"[OWAF] WASM PoW failed")}};
w.onerror=function(e){fail("[OWAF] WASM Worker error: "+(e.message||"unknown"))};
ws.push(w);
}
}
function start(){if(window.__owaf_env_required){if(!window.__owaf_env_ready||typeof window.__owaf_env_ready.then!=="function"){fail("[OWAF] environment WASM is unavailable");return}window.__owaf_env_ready.then(function(env){if(!env){fail("[OWAF] environment WASM fingerprint failed");return}begin()}).catch(function(e){fail(e&&e.message||String(e))})}else{begin()}}
setTimeout(start,0);
})();`,
		v[0], encodedNonce,
		v[1], difficulty,
		PowGlueURL(), PowWasmURL(),
		v[0], v[1], program,
		v[0], v[1],
	)
}

func randomVarNames(n int) []string {
	names := make([]string, n)
	for i := range names {
		b := make([]byte, 3)
		_, _ = rand.Read(b)
		names[i] = "_" + hex.EncodeToString(b)
	}
	return names
}

func polymorphicEncode(s string) string {
	switch randIntN(5) {
	case 0:
		var parts []string
		for _, c := range s {
			parts = append(parts, fmt.Sprintf("%d", c))
		}
		return fmt.Sprintf("String.fromCharCode(%s)", strings.Join(parts, ","))
	case 1:
		var parts []string
		for _, c := range s {
			parts = append(parts, fmt.Sprintf("'%c'", c))
		}
		return fmt.Sprintf("[%s].join('')", strings.Join(parts, ","))
	case 2:
		return fmt.Sprintf(`(function(){for(var h="%s",r="",i=0;i<h.length;i+=2)r+=String.fromCharCode(parseInt(h.substr(i,2),16));return r})()`, hex.EncodeToString([]byte(s)))
	case 3:
		reversed := reverseString(s)
		return fmt.Sprintf(`"%s".split('').reverse().join('')`, reversed)
	default:
		key := byte(randIntN(200) + 33)
		var encoded []string
		for _, c := range []byte(s) {
			encoded = append(encoded, fmt.Sprintf("%d", c^key))
		}
		return fmt.Sprintf(`(function(){for(var a=[%s],k=%d,r="",i=0;i<a.length;i++)r+=String.fromCharCode(a[i]^k);return r})()`,
			strings.Join(encoded, ","), key)
	}
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func randIntN(max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

const ChallengeProofDifficulty = 4

/**
 * VerifyChallengeProof 校验 JS 挑战页提交的工作量证明。
 * @param token   挑战页下发的 nonce。
 * @param counter 客户端求得的计数器（十进制字符串）。
 * @param hash    客户端算出的十六进制小写摘要。
 * @return 解答有效则为 true；参数缺失或不匹配均为 false。
 */
func VerifyChallengeProof(token, counter, hash string) bool {
	if token == "" || counter == "" || hash == "" {
		return false
	}
	n, err := strconv.ParseInt(counter, 10, 64)
	if err != nil {
		return false
	}
	return VerifyPoW(token, n, hash, ChallengeProofDifficulty)
}
