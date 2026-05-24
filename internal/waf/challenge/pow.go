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
	gzipExecOnce sync.Once
	gzipExecJS   []byte
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
	c.Response.Header.Set("Cache-Control", "no-store")
	c.Response.SetBody(gzipWASM)
}

// ServeWasmExecJS serves the Go wasm_exec.js glue (gzipped).
func ServeWasmExecJS(c *app.RequestContext) {
	gzipExecOnce.Do(func() { gzipExecJS = gzipBytes(powdata.WasmExecJS) })
	c.Response.SetStatusCode(200)
	c.Response.Header.Set("Content-Type", "application/javascript")
	c.Response.Header.Set("Content-Encoding", "gzip")
	c.Response.Header.Set("Cache-Control", "no-store")
	c.Response.SetBody(gzipExecJS)
}

// GeneratePoWNonce creates a cryptographically random nonce for PoW challenges.
func GeneratePoWNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// GeneratePoWScript returns inline JavaScript that performs SHA-256 proof-of-work
// in a Web Worker (inline blob). The script finds a counter such that
// SHA-256(nonce + counter) has `difficulty` leading zero hex characters.
//
// Phase 1: Pure JS Web Worker implementation.
// Phase 2 (future): WASM module for faster computation.
func GeneratePoWScript(difficulty int, nonce string) string {
	return fmt.Sprintf(`
(function(){
var nonce="%s",difficulty=%d;
var workerCode='self.onmessage=function(e){var nonce=e.data.nonce,diff=e.data.difficulty,prefix="";for(var i=0;i<diff;i++)prefix+="0";var counter=0;function toHex(buf){var h="";var u=new Uint8Array(buf);for(var i=0;i<u.length;i++){var s=u[i].toString(16);h+=s.length===1?"0"+s:s}return h}function check(){var batch=5000;for(var i=0;i<batch;i++){var msg=nonce+counter;crypto.subtle.digest("SHA-256",new TextEncoder().encode(msg)).then(function(c,hash){var hex=toHex(hash);if(hex.substring(0,diff)===prefix){self.postMessage({found:true,counter:c,hash:hex})}}.bind(null,counter));counter++}setTimeout(check,0)}check()}';
var blob=new Blob([workerCode],{type:'application/javascript'});
var w=new Worker(URL.createObjectURL(blob));
w.postMessage({nonce:nonce,difficulty:difficulty});
w.onmessage=function(e){
if(e.data.found){
w.terminate();
window.__powResult={nonce:nonce,counter:e.data.counter,hash:e.data.hash,difficulty:difficulty};
if(window.__owaf_pow_callback)window.__owaf_pow_callback(e.data.counter,e.data.hash,window.__powResult);
if(window.__onPoWComplete)window.__onPoWComplete(window.__powResult);
}};
window.__powWorker=w;
})();`, nonce, difficulty)
}

// GeneratePoWScriptSync returns a synchronous (main-thread) PoW script fallback
// for environments where Web Workers may not be available.
func GeneratePoWScriptSync(difficulty int, nonce string) string {
	return fmt.Sprintf(`
(function(){
var nonce="%s",difficulty=%d;
var prefix="";for(var i=0;i<difficulty;i++)prefix+="0";
async function solve(){
var counter=0;
while(true){
var msg=nonce+counter;
var buf=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(msg));
var u=new Uint8Array(buf);var h="";
for(var i=0;i<u.length;i++){var s=u[i].toString(16);h+=s.length===1?"0"+s:s;}
if(h.substring(0,difficulty)===prefix){
window.__powResult={nonce:nonce,counter:counter,hash:h,difficulty:difficulty};
if(window.__owaf_pow_callback)window.__owaf_pow_callback(counter,h,window.__powResult);
if(window.__onPoWComplete)window.__onPoWComplete(window.__powResult);
return;}
counter++;
if(counter%%1000===0)await new Promise(r=>setTimeout(r,0));
}}
solve();
})();`, nonce, difficulty)
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

// GeneratePoWWASMScript returns a minimal JS loader that loads the WASM module
// and invokes the PoW solver. All computation happens inside WASM; JS only
// passes nonce, difficulty, and the VM bytecode program.
func GeneratePoWWASMScript(difficulty int, nonce string) string {
	v := randomVarNames(6)
	encodedNonce := polymorphicEncode(nonce)
	program := GenerateVMProgram()
	// Cache-busting: add random query parameter to prevent browser/proxy caching of assets.
	cacheBust := make([]byte, 4)
	_, _ = rand.Read(cacheBust)
	cb := hex.EncodeToString(cacheBust)

	return fmt.Sprintf(`(function(){
var %s=%s,%s=%d,%s="%s";
var %s=document.createElement("script");
%s.src="/__owaf/wasm_exec.js?_=%s";
%s.onerror=function(){if(window.__owaf_pow_error)window.__owaf_pow_error("wasm_exec.js load failed")};
%s.onload=function(){
var go=new Go();
fetch("/__owaf/pow.wasm?_=%s").then(function(r){if(!r.ok)throw new Error("pow.wasm "+r.status);return r.arrayBuffer()}).then(function(b){
return WebAssembly.instantiate(b,go.importObject)
}).then(function(r){
go.run(r.instance);
__wasm_pow_solve(%s,%s,%s);
}).catch(function(e){if(window.__owaf_pow_error)window.__owaf_pow_error(e.message||"wasm load failed")});
};
document.head.appendChild(%s);
})();`,
		v[0], encodedNonce,
		v[1], difficulty,
		v[2], program,
		v[3],
		v[3], cb,
		v[3],
		v[3], cb,
		v[0], v[1], v[2],
		v[3],
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
	switch randIntN(3) {
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
	default:
		return fmt.Sprintf(`(function(){for(var h="%s",r="",i=0;i<h.length;i+=2)r+=String.fromCharCode(parseInt(h.substr(i,2),16));return r})()`, hex.EncodeToString([]byte(s)))
	}
}

func randIntN(max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}
