package waf

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

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
