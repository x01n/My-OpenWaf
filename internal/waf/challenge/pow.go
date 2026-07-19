package challenge

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
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


// VerifyPoW verifies a proof-of-work solution.
// It checks that SHA-256(nonce + counter) has the required leading zeros.
func VerifyPoW(nonce string, counter int64, hash string, difficulty int) bool {
	if len(hash) < difficulty {
		return false
	}
	prefix := ""
	for i := 0; i < difficulty; i++ {
		prefix += "0"
	}
	if hash[:difficulty] != prefix {
		return false
	}
	// Re-compute to verify (prevent hash spoofing)
	msg := fmt.Sprintf("%s%d", nonce, counter)
	computed := sha256Hex(msg)
	return computed == hash
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
