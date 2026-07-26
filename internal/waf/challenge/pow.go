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

// ServePoWWASM serves the pre-compiled WASM binary (gzipped).
func ServePoWWASM(c *app.RequestContext) {
	gzipWASMOnce.Do(func() { gzipWASM = gzipBytes(powdata.WASMBinary) })
	c.Response.SetStatusCode(200)
	c.Response.Header.Set("Content-Type", "application/wasm")
	c.Response.Header.Set("Content-Encoding", "gzip")
	c.Response.Header.Set("Cache-Control", "public,max-age=3600,immutable")
	c.Response.SetBody(gzipWASM)
}

// ServePowGlueJS serves the Rust wasm-bindgen glue JS (gzipped).
func ServePowGlueJS(c *app.RequestContext) {
	gzipGlueOnce.Do(func() { gzipGlueJS = gzipBytes(powdata.PowGlueJS) })
	c.Response.SetStatusCode(200)
	c.Response.Header.Set("Content-Type", "application/javascript")
	c.Response.Header.Set("Content-Encoding", "gzip")
	c.Response.Header.Set("Cache-Control", "public,max-age=3600,immutable")
	c.Response.SetBody(gzipGlueJS)
}

// GeneratePoWNonce creates a cryptographically random nonce for PoW challenges.
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

// VerifyPoW verifies a proof-of-work solution.
// It checks that SHA-256(nonce + counter) has the required leading zeros.
//
// 校验顺序：先拒绝非法难度与畸形摘要，再检查前导零，最后重算摘要做常量时间比较。
// difficulty 超出 [minPoWDifficulty, maxPoWDifficulty] 一律拒绝——难度 0 会接受
// 零工作量解答，负难度会让 strings.Repeat panic。
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

// VM opcodes for polymorphic bytecode generation.
const (
	vmOpNop         byte = 0x00
	vmOpLoadNonce   byte = 0x10
	vmOpLoadCounter byte = 0x11
	vmOpConcat      byte = 0x12
	vmOpSHA256      byte = 0x13
	vmOpCheckPrefix byte = 0x14
)

// GenerateVMProgram creates a polymorphic bytecode program for the WASM VM.
// Each call shuffles NOP padding to produce unique bytecode.
func GenerateVMProgram() string {
	base := []byte{vmOpLoadNonce, vmOpLoadCounter, vmOpConcat, vmOpSHA256, vmOpCheckPrefix}
	nopCount := 2 + randIntN(4)
	prog := make([]byte, 0, len(base)+nopCount)
	inserted := 0
	for _, op := range base {
		for inserted < nopCount && randIntN(3) == 0 {
			prog = append(prog, vmOpNop)
			inserted++
		}
		prog = append(prog, op)
	}
	for inserted < nopCount {
		prog = append(prog, vmOpNop)
		inserted++
	}
	return hex.EncodeToString(prog)
}

// GeneratePoWWASMScript returns a JS loader that spawns multiple Web Workers
// (one per CPU core) to solve PoW in parallel using the Rust WASM module.
// Each worker processes a different counter range via solve_pow_batched.
// If the WASM module fails to load, an error is thrown — there is no JS fallback.
func GeneratePoWWASMScript(difficulty int, nonce string, envKeyHex string) string {
	v := randomVarNames(6)
	encodedNonce := polymorphicEncode(nonce)
	program := GenerateVMProgram()
	cacheBust := make([]byte, 4)
	_, _ = rand.Read(cacheBust)
	cb := hex.EncodeToString(cacheBust)

	return fmt.Sprintf(`(function(){
var %s=%s,%s=%d,%s="%s";
var envD=window.__owaf_env?JSON.stringify(window.__owaf_env):"";
var ek="%s";
var nc=navigator.hardwareConcurrency||4;
var bs=50000;
var ws=[];
var done=false;
var wc='importScripts("'+location.origin+'/__owaf/pow_glue.js?_=%s");wasm_bindgen("'+location.origin+'/__owaf/pow.wasm?_=%s").then(function(){var off=self.__off;function batch(){if(self.__stop)return;var r=wasm_bindgen.solve_pow_batched(self.__n,self.__d,self.__p,self.__bs,off);var o=JSON.parse(r);if(o.found){var enc="";if(self.__e&&self.__k){try{enc=wasm_bindgen.encrypt_env_data(self.__e,self.__k)}catch(x){}}self.postMessage(JSON.stringify({found:true,pow:r,enc:enc}))}else{off+=self.__bs*self.__nc;self.postMessage(JSON.stringify({found:false}));setTimeout(batch,0)}}batch()}).catch(function(e){self.postMessage(JSON.stringify({error:e.message||"wasm init failed"}))});';
for(var i=0;i<nc;i++){
var code='self.__n='+JSON.stringify(%s)+';self.__d='+%s+';self.__p='+JSON.stringify(%s)+';self.__e='+JSON.stringify(envD)+';self.__k='+JSON.stringify(ek)+';self.__off='+i+'*'+bs+';self.__bs='+bs+';self.__nc='+nc+';self.__stop=false;'+wc;
var b=new Blob([code],{type:'application/javascript'});
var w=new Worker(URL.createObjectURL(b));
w.onmessage=function(e){
if(done)return;
try{var msg=JSON.parse(e.data);
if(msg.error){done=true;for(var j=0;j<ws.length;j++)ws[j].terminate();throw new Error("[OWAF] WASM PoW failed: "+msg.error)}
if(msg.found){done=true;
for(var j=0;j<ws.length;j++)ws[j].terminate();
var p=JSON.parse(msg.pow);
if(msg.enc&&!window.__owaf_env_encrypted)window.__owaf_env_encrypted=msg.enc;
window.__powResult={nonce:%s,counter:p.counter,hash:p.hash,difficulty:%s,env_score:p.env_score,markers:p.markers,sig:p.sig};
if(window.__owaf_pow_callback)window.__owaf_pow_callback(p.counter,p.hash,window.__powResult);
if(window.__onPoWComplete)window.__onPoWComplete(window.__powResult);
}}catch(ex){if(!done){done=true;for(var j=0;j<ws.length;j++)ws[j].terminate();}throw ex}};
w.onerror=function(e){if(!done){done=true;for(var j=0;j<ws.length;j++)ws[j].terminate();throw new Error("[OWAF] WASM Worker error: "+(e.message||"unknown"))}};
ws.push(w);
}
})();`,
		v[0], encodedNonce,
		v[1], difficulty,
		v[2], program,
		envKeyHex,
		cb, cb,
		v[0], v[1], v[2],
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

// ChallengeProofDifficulty 是 JS 挑战页 PoW 的前导零位数。
// 挑战页脚本与本包校验必须使用同一取值，否则合法解答会被判失败。
const ChallengeProofDifficulty = 4

// powResultSalt 与 wasm-pow-solver/src/integrity.rs 的 COMPILE_SALT 一致。
//
// 该盐嵌在下发给客户端的 WASM 内，攻击者可从中提取，因此 sig 只能证明
// env_score/markers 未被 WASM 之外的脚本改写（防篡改），不能证明它们出自
// 未被修改的 WASM（防伪造）。据此，env_score 只用作附加信号，
// 真正的准入判定仍由服务端侧的 PoW 与 token 校验承担。
var powResultSalt = []byte("owaf_pow_v2_2026")

/**
 * VerifyPoWResultSig 校验 WASM 回传的结果签名。
 *
 * 与 Rust 侧 compute_result_sig 保持一致：
 * sha256("nonce:counter:hash:score:markers" || COMPILE_SALT) 取前 8 字节的十六进制。
 *
 * @param nonce   PoW 的 nonce（JS 挑战页用挑战 token）。
 * @param counter 客户端求得的计数器。
 * @param hash    PoW 摘要。
 * @param score   WASM 计算的环境分。
 * @param markers WASM 输出的标记位（十六进制字符串）。
 * @param sig     客户端回传的签名。
 * @return 签名匹配则为 true。
 */
func VerifyPoWResultSig(nonce, counter, hash string, score, markers, sig string) bool {
	if sig == "" {
		return false
	}
	payload := nonce + ":" + counter + ":" + hash + ":" + score + ":" + markers
	h := sha256.New()
	h.Write([]byte(payload))
	h.Write(powResultSalt)
	want := hex.EncodeToString(h.Sum(nil)[:8])
	return subtle.ConstantTimeCompare([]byte(want), []byte(sig)) == 1
}

/**
 * VerifyChallengeProof 校验 JS 挑战页提交的工作量证明。
 *
 * 挑战页以签名 token 作为 nonce 求解 SHA-256(token+counter) 的前导零，
 * 因此工作量与该次挑战一一绑定：token 每次签发都不同，攻击者无法预先算好或
 * 硬编码结果复用。历史实现提交的是一个与 token 无关的常量（定值 996500000），
 * 校验它没有任何意义，故一并改为真实 PoW。
 *
 * @param token   挑战页下发的签名 token，充当 PoW 的 nonce。
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
