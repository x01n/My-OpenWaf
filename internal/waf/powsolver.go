package waf

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/waf/powdata"
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
