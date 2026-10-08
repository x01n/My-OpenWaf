package challenge

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"My-OpenWaf/internal/waf/challenge/gm"

	"My-OpenWaf/internal/waf/challenge/pow"
)

// powShardJSVarCount 是装配器脚本中随机变量名的数量：
// D/K/hx/fv/out/code 共 6 个。
const powShardJSVarCount = 6

// powShardTemplate 是拆片装配器的固定 JS 模板，占位符顺序为：
// 6 个随机变量名（D/K/hx/fv/out/code）、hex 片数组、XOR 密钥数组、
// 以及 Go 侧预计算的 FNV-1a 32 位校验和（十进制 uint32 字面量）。
const powShardTemplate = `(function(){
var %s=["%s"];
var %s=[%s];
function %s(s){var o="";for(var i=0;i<s.length;i+=2)o+=String.fromCharCode(parseInt(s.substr(i,2),16));return o}
function %s(s){var h=2166136261;for(var i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619)>>>0}return h>>>0}
var %s=[];
for(var i=0;i<%s.length;i++){var b=%s(%s[i]);var s="";for(var j=0;j<b.length;j++)s+=String.fromCharCode(b.charCodeAt(j)^%s[i]);%s.push(s)}
var %s=%s.join("");
if(%s(%s)!==(%d>>>0)){throw new Error("shard checksum mismatch")}
(0,eval).call(window,%s);
})();`

// powShardMinParts 与 powShardMaxParts 分别是拆片数量的下界与上界。
const (
	powShardMinParts = 3
	powShardMaxParts = 5
)

// fnv1a32OffsetBasis 与 fnv1a32Prime 是标准 FNV-1a 32 位常量。
const (
	fnv1a32OffsetBasis uint32 = 2166136261
	fnv1a32Prime       uint32 = 16777619
)

// PowShardScript 是拆片后的 PoW 挑战下发产物。
type PowShardScript struct {
	// PageScript 是页面内联 <script> 内容：随机变量名的装配器，
	// 解码并拼接各片后经 (0,eval).call(window, code) 执行完整 worker 代码。
	PageScript string
	// BodyHexParts 是每片 XOR 后的 hex 编码，仅用于测试解码对照。
	BodyHexParts []string
	// Keys 是每片对应的单字节 XOR 密钥，仅用于测试解码对照。
	Keys []byte
	// Checksum 是 FNV-1a 32 位校验和，作用于完整正文（装配器 eval 前校验）。
	Checksum uint32
}

// GeneratePoWShardedScript 把 PoW worker 代码正文切成随机片数（3..5 片），
// 每片以随机单字节密钥 XOR 并 hex 编码，交给随机变量名的装配器脚本在
// 客户端拼回、校验后 eval。拼装产物与 GeneratePoWWASMScript 的输出逐字节等价。
func GeneratePoWShardedScript(difficulty int, nonce string) PowShardScript {
	body := pow.GeneratePoWScriptBody(difficulty, nonce)
	pieces := SplitPowShardBody(body)

	encoded := make([]string, 0, len(pieces))
	keys := make([]byte, 0, len(pieces))
	for _, piece := range pieces {
		key := byte(1 + pow.RandIntN(255))
		buf := []byte(piece)
		for i := range buf {
			buf[i] ^= key
		}
		encoded = append(encoded, hex.EncodeToString(buf))
		keys = append(keys, key)
	}

	names := pow.RandomVarNames(powShardJSVarCount)
	checksum := fnv1a32(body)

	return PowShardScript{
		PageScript:   buildPowShardAssembler(encoded, keys, checksum, names),
		BodyHexParts: encoded,
		Keys:         keys,
		Checksum:     checksum,
	}
}

// SplitPowShardBody 把 body 切成 powShardMinParts..powShardMaxParts 片。
// 切点取随机字节位置并校正到 rune 边界（body 为 ASCII 时校正为空操作）；
// 分片经 XOR+hex 编码后以 JS 字符串字面量下发，装配器拿到的只是纯数据，
// 因此任意切点均安全，不存在引号或转义问题。拼接结果与输入严格恒等。
func SplitPowShardBody(body string) []string {
	length := len(body)
	k := powShardMinParts + pow.RandIntN(powShardMaxParts-powShardMinParts+1)
	if k > length {
		k = length
	}
	if k < 1 {
		k = 1
	}

	cuts := make([]int, 0, k-1)
	cutSet := make(map[int]struct{}, k-1)
	for len(cutSet) < k-1 {
		pos := 1 + pow.RandIntN(length-1)
		// 校正到 rune 边界：多字节 rune 的延续字节位特征为 10xxxxxx，
		// 向前回退直到 rune 首字节；ASCII 正文内此步不改变 pos。
		for pos > 0 && pos < length && body[pos]&0xC0 == 0x80 {
			pos--
		}
		cutSet[pos] = struct{}{}
	}
	for pos := range cutSet {
		cuts = append(cuts, pos)
	}
	sort.Ints(cuts)

	pieces := make([]string, 0, k)
	start := 0
	for _, cut := range cuts {
		pieces = append(pieces, body[start:cut])
		start = cut
	}
	pieces = append(pieces, body[start:])
	return pieces
}

// fnv1a32 计算 body 的 32 位 FNV-1a 校验和，与装配器脚本中的 JS 实现一致。
func fnv1a32(body string) uint32 {
	hash := fnv1a32OffsetBasis
	for i := 0; i < len(body); i++ {
		hash ^= uint32(body[i])
		hash *= fnv1a32Prime
	}
	return hash
}

// buildPowShardAssembler 按固定模板组装装配器脚本；随机变量名与片内容
// 仅以纯数据（hex / 十进制）形式嵌入，不引入任何转义路径。
func buildPowShardAssembler(parts []string, keys []byte, checksum uint32, names []string) string {
	hexLiteral := strings.Join(parts, `","`)
	keyLiteral := ""
	for i, key := range keys {
		if i > 0 {
			keyLiteral += ","
		}
		keyLiteral += fmt.Sprintf("%d", key)
	}
	return fmt.Sprintf(
		powShardTemplate,
		names[0], hexLiteral,
		names[1], keyLiteral,
		names[2],
		names[3],
		names[4],
		names[0], names[2], names[0], names[1], names[4],
		names[5], names[4],
		names[3], names[5], checksum,
		names[5],
	)
}

/**
 * VerifyShardEnvelopeSignature 核对 0x06 域信封的 SM2 签名并返回其明文
 * （分片内层 JSON）；任一环节失败返回空串。
 *
 * ⚠️ **本函数不校验调用方传入的 pubHex**：`gm.Open(..., verifySig=true)` 用的是
 * 进程内已装载的 SM2 身份（`gm/sealed.go` 的 Open 签名根本没有 pubHex 参数，
 * 内部走 `VerifySignature` → `signIdent`）。pubHex 参数在此仅作**身份存在性
 * 守卫**：为空时拒绝，避免调用方在没有身份的情况下误以为已验签。要真正用
 * 外部公钥核对，须走 `gm.VerifyExternalSignature`（本函数不涉及该路径）。
 *
 * 用途：**服务端签发后自检**。客户端侧的同名核对由浏览器 WASM 的
 * `wasm_bindgen.gm_open_verify_sig` 用页面注入的公钥完成——那是唯一真正
 * 「用外部公钥」的验签路径，两边必须逐字节同构，否则会出现「服务端自检
 * 通过、客户端全体验签失败」的静默断链（跨语言对拍锁住这一点）。
 *
 * domain 必须传 gm.DomainPowShards（0x06）**具体值，不能传 0**：
 * Go 的 gm.Open 把 0 当通配（gm/sealed.go 的 `if domain != 0 && ...`），
 * 而 Rust 的 open_raw_signed 无此豁免（gm.rs 的 `raw[5] != domain`），
 * 两端不对称，传 0 会在客户端直接失败。
 *
 * ⚠️ **不缓存公钥**是这条链成立的前提：SM2 身份在进程内固定，但**跨重启会
 * 变化**（见 SetChallengeSecret 的注释）。公钥必须随每次信封下发新鲜注入
 * 页面，任何跨请求/跨进程的公钥缓存都会在重启后造成全体验签失败。
 */
func VerifyShardEnvelopeSignature(envelope, keyHex, pubHex string) string {
	if pubHex == "" {
		return ""
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != envSessionKeySize {
		return ""
	}
	raw, err := gm.Decode(envelope)
	if err != nil {
		return ""
	}
	plaintext, err := gm.Open(key[:16], raw, nil, gm.DomainPowShards, true)
	if err != nil {
		return ""
	}
	if len(plaintext) == 0 || len(plaintext) > maxPowShardPlaintextBytes {
		return ""
	}
	return string(plaintext)
}

// maxPowShardPlaintextBytes 是分片内层 JSON 的长度上限，防止畸形信封触发
// 超大分配。与 captchaItemDataMaxPlaintext 同级取 512 KiB。
const maxPowShardPlaintextBytes = 512 * 1024

/**
 * powShardsAAD 是 PoW 代码分片信封的 AAD（标签生成器产物，禁止散落字面量）。
 *
 * ⚠️ 域 0x06（gm.DomainPowShards）被 PoW 分片、动态保护分片（internal/waf/dynamic）
 * 与本包的 C2 种子信封三方共用，而 gm.Seal/gm.Open 的 aad 参数**不参与认证**
 * （GCM 的 AAD 实为信封前 8 字节头部，见 gm/sealed.go 的注释）：本变量的标签
 * 只影响派生文本，不提供任何隔离。**域内多用途隔离完全依赖「三条链的密钥互不
 * 相同」**——改动任一条链时，不得让它与另两条共用密钥，否则其信封可被另一条
 * 链的解封路径接受。
 */
var powShardsAAD = gm.EnvelopeAAD(gm.EnvelopeLabel("pow-shards", gm.GMEnvelopeVersion), gm.PurposeChallengeData)

// PowShardEnvelope 是加密分片的内层 JSON（v2）：分片已 XOR 单字节密钥并
// base64url 编码，CRC 为完整正文的 FNV-1a 32（十进制字符串），只由 WASM
// 在内存内组装，JS 侧不接触任何片明文。
type PowShardEnvelope struct {
	Shards []powShardEnvelopeItem `json:"shards"`
	CRC    string                 `json:"crc"`
	V      int                    `json:"v"`
}

// powShardEnvelopeItem 是单片的 JSON 编码形态：Key 为单字节 XOR 密钥
// （十进制），Data 为 XOR 后的 base64url（RawURLEncoding）编码。
type powShardEnvelopeItem struct {
	Key  byte   `json:"k"`
	Data string `json:"d"`
}

/**
 * powShardVMBootstrapTemplate 是 VM 内拼装引导薄壳的固定模板，占位符为
 * 2 个随机变量名（env/key）与 1 个用于信封/密钥 hidden input 的常量名。
 * 壳内不嵌任何分片数据，全部经 wasm_bindgen.vm_assemble_shards 在 WASM
 * 内存中完成，拼装产物交给 (0,eval).call(window, code)。
 */
var powShardVMBootstrapTemplate = `(function(){
function %s(id){var e=document.getElementById(id);return e?e.value:""}
var %s=%s("__owaf_pow_env");
var %s=%s("__owaf_pow_key");` +
	`
function %s(){if(typeof wasm_bindgen!=="undefined"&&typeof wasm_bindgen.vm_assemble_shards==="function"){return Promise.resolve()}return new Promise(function(resolve,reject){var s=document.createElement("script");s.src="%s";s.onload=function(){wasm_bindgen({module_or_path:"%s"}).then(resolve).catch(reject)};s.onerror=function(e){reject(e||new Error("WASM glue load failed"))};(document.head||document.documentElement).appendChild(s)})}` +
	`
function %s(msg){if(typeof window.__owaf_pow_error==="function")window.__owaf_pow_error(msg)}
function fail(err){%s((err&&err.message)||String(err||"Power of work assembly failed"));return}
if(!%s||!%s){fail(new Error("power of work shard envelope missing"));return}
%s().then(function(){
if(typeof wasm_bindgen==="undefined"||typeof wasm_bindgen.vm_assemble_shards!=="function"){fail(new Error("power of work VM assembler unavailable"));return}
var code;
try{code=wasm_bindgen.vm_assemble_shards(%s,%s)}catch(err){fail(err);return}
if(typeof code!=="string"||!code.length){fail(new Error("power of work shard assembly failed"));return}
try{(0,eval).call(window,code)}catch(err){fail(err)}
}).catch(function(err){fail(err)});
})();`

// powShardVMBootstrapVarCount 是 VM 拼装引导壳中随机变量名的数量：
// env/key 读取器、错误上报器、初始化器、加载器共 6 个。
const powShardVMBootstrapVarCount = 6

// GeneratePoWShardedEnvelope 把 PoW worker 代码正文切成 3..5 片、每片
// XOR 单字节密钥，内层 JSON 经 GM 信封（域 0x06）加密下发；页面侧只有
// 极薄引导壳：从 hidden input 读信封与 keyHex，调 WASM
// vm_assemble_shards 在 VM 内存内拼出完整代码后交给 (0,eval) 执行。
// 失败一律走既有回调 window.__owaf_pow_error。
//
// key 必须为 32 字节会话密钥（SM4 取前 16 字节），envelope 为 base64url
// 信封文本，pageBootstrap 为可注入 challenge.html 的 <script> 内容。
func GeneratePoWShardedEnvelope(difficulty int, nonce string, key []byte) (envelope string, pageBootstrap string, err error) {
	if len(key) != envSessionKeySize {
		return "", "", fmt.Errorf("owaf: invalid session key length %d", len(key))
	}
	body := pow.GeneratePoWScriptBody(difficulty, nonce)
	pieces := SplitPowShardBody(body)

	checksum := fnv1a32(body)
	items := make([]powShardEnvelopeItem, 0, len(pieces))
	for _, piece := range pieces {
		xorKey := byte(1 + pow.RandIntN(255))
		buf := []byte(piece)
		for i := range buf {
			buf[i] ^= xorKey
		}
		items = append(items, powShardEnvelopeItem{
			Key:  xorKey,
			Data: base64.RawURLEncoding.EncodeToString(buf),
		})
	}

	inner, err := json.Marshal(PowShardEnvelope{
		V:      int(gm.GMEnvelopeVersion),
		Shards: items,
		CRC:    strconv.FormatUint(uint64(checksum), 10),
	})
	if err != nil {
		return "", "", fmt.Errorf("owaf: marshal pow shard envelope: %w", err)
	}
	raw, err := gm.Seal(key[:16], gm.DomainPowShards, inner, []byte(powShardsAAD))
	if err != nil {
		return "", "", fmt.Errorf("owaf: seal pow shard envelope: %w", err)
	}

	names := pow.RandomVarNames(powShardVMBootstrapVarCount)
	bootstrap := fmt.Sprintf(
		powShardVMBootstrapTemplate,
		names[0], names[1], names[0], names[2], names[0], names[3],
		// 槽位 7/8 是引导壳里的两个资产 URL：先 glue、后 wasm，
		// 顺序与模板出现顺序一致。用内容派生版本串（powdata），
		// 与 /__owaf/* 的 immutable 缓存配对（见 pow.go 的 ServePoWWASM）。
		pow.PowGlueURL(), pow.PowWasmURL(),
		names[4], names[4],
		names[1], names[2], names[3], names[1], names[2],
	)
	return gm.Encode(raw), bootstrap, nil
}
