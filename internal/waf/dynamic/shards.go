package dynamic

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"My-OpenWaf/internal/waf/challenge/gm"
)

const (
	dynamicShardMinParts = 3
	dynamicShardMaxParts = 5
)

const dynamicShardJSVarCount = 5

var dynamicShardsAAD = gm.EnvelopeAAD(gm.EnvelopeLabel("dyn-shards", gm.GMEnvelopeVersion), gm.PurposeChallengeData)

type dynamicShardEnvelopeItem struct {
	Key  byte   `json:"k"`
	Data string `json:"d"`
}

type dynamicShardEnvelope struct {
	Shards []dynamicShardEnvelopeItem `json:"shards"`
	CRC    string                     `json:"crc"`
	V      int                        `json:"v"`
}

const dynamicShardShellTemplate = `(function(){
var %[1]s="%[2]s";
var %[3]s="%[4]s";
function %[5]s(err){try{console.error("owaf dynamic shard assembly:",(err&&err.message)||String(err||"VM assembly failed"))}catch(e){}throw err}
if(typeof wasm_bindgen==="undefined"||typeof wasm_bindgen.vm_assemble_shards!=="function"){%[5]s(new Error("dynamic VM assembler unavailable"))}
var %[6]s;
try{%[6]s=wasm_bindgen.vm_assemble_shards(%[1]s,%[3]s)}catch(%[7]s){%[5]s(%[7]s)}
if(typeof %[6]s!=="string"||!%[6]s.length){%[5]s(new Error("dynamic shard assembly failed"))}
try{(0,eval).call(window,%[6]s)}catch(%[7]s){%[5]s(%[7]s)}
})();`

const (
	dynamicFnv1a32OffsetBasis uint32 = 2166136261
	dynamicFnv1a32Prime       uint32 = 16777619
)

func dynamicFnv1a32(body string) uint32 {
	hash := dynamicFnv1a32OffsetBasis
	for i := 0; i < len(body); i++ {
		hash ^= uint32(body[i])
		hash *= dynamicFnv1a32Prime
	}
	return hash
}

// dynamicRandIntN 返回 [0, max) 的均匀随机整数（与 challenge 包
// randIntN 同构，本包不复用其未导出实现）。
func dynamicRandIntN(max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

/**
 * dynamicSplitShardBody 把 body 切成 dynamicShardMinParts..MaxParts 片，
 * 切点取随机字节位置并校正回退非 ASCII 延续字节（UTF-8 正文安全）；
 * 分片只以数据形态进入信封，任意切点均无引号/转义风险。
 * 拼接结果与输入严格恒等。
 */
func dynamicSplitShardBody(body string) []string {
	length := len(body)
	k := dynamicShardMinParts + dynamicRandIntN(dynamicShardMaxParts-dynamicShardMinParts+1)
	if k > length {
		k = length
	}
	if k < 1 {
		k = 1
	}

	cuts := make([]int, 0, k-1)
	cutSet := make(map[int]struct{}, k-1)
	for len(cutSet) < k-1 {
		pos := 1 + dynamicRandIntN(length-1)
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

// dynamicRandomVarNames 生成 n 个随机 JS 变量名（"_"+6 hex 字符）。
func dynamicRandomVarNames(n int) []string {
	names := make([]string, n)
	for i := range names {
		b := make([]byte, 3)
		_, _ = rand.Read(b)
		names[i] = "_" + hex.EncodeToString(b)
	}
	return names
}

/**
 * buildDynamicShardShell 用随机变量名组装 VM 引导薄壳。
 * 信封文本（base64url）与 CEK hex 只以纯数据字符串字面量嵌入，
 * 不存在任何转义路径。
 */
func buildDynamicShardShell(envelopeText, keyHex string) string {
	names := dynamicRandomVarNames(dynamicShardJSVarCount)
	return fmt.Sprintf(
		dynamicShardShellTemplate,
		names[0], envelopeText,
		names[1], keyHex,
		names[2],
		names[3],
		names[4],
	)
}

/**
 * GenerateEncryptedShardedCode 把动态 JS 明文 code 切成 3..5 片、每片
 * XOR 单字节密钥，内层 JSON 经 GM 信封（域 0x06 DomainPowShards）加密
 * 下发。CEK 取 32 字节内容加密密钥的前 16 字节（SM4-GCM 密钥），
 * 客户端壳以同一 CEK 的 hex 通过 wasm_bindgen.vm_assemble_shards 在
 * WASM 内存内拼回 code 后 (0,eval).call(window, code)。
 *
 * @param code 解密后的 JS 明文（上一级 decrypt_dynamic_with_cek 的输出）。
 * @param cek  32 字节内容加密密钥（CEK，与 decrypt_dynamic_with_cek 同一把）。
 * @param aad  分片信封合同 AAD 字节（dynamicShardsAAD 的字节形态）。
 * @return 信封文本（base64url）与引导薄壳脚本。
 */
func GenerateEncryptedShardedCode(code string, cek []byte, aad []byte) (envelope string, shell string, err error) {
	if len(cek) != 32 {
		return "", "", fmt.Errorf("owaf-dynamic: invalid CEK length %d, want 32", len(cek))
	}
	if code == "" {
		return "", "", fmt.Errorf("owaf-dynamic: empty code")
	}

	pieces := dynamicSplitShardBody(code)
	checksum := dynamicFnv1a32(code)
	items := make([]dynamicShardEnvelopeItem, 0, len(pieces))
	for _, piece := range pieces {
		xorKey := byte(1 + dynamicRandIntN(255))
		buf := []byte(piece)
		for i := range buf {
			buf[i] ^= xorKey
		}
		items = append(items, dynamicShardEnvelopeItem{
			Key:  xorKey,
			Data: base64.RawURLEncoding.EncodeToString(buf),
		})
	}

	inner, err := json.Marshal(dynamicShardEnvelope{
		V:      int(gm.GMEnvelopeVersion),
		Shards: items,
		CRC:    fmt.Sprintf("%d", checksum),
	})
	if err != nil {
		return "", "", fmt.Errorf("owaf-dynamic: marshal shard envelope: %w", err)
	}
	raw, err := gm.Seal(cek[:16], gm.DomainPowShards, inner, aad)
	if err != nil {
		return "", "", fmt.Errorf("owaf-dynamic: seal shard envelope: %w", err)
	}
	return gm.Encode(raw), buildDynamicShardShell(gm.Encode(raw), hex.EncodeToString(cek)), nil
}

// dynamicShardAssembleForTest 还原信封内的所有分片并拼接（仅测试使用），
// 校验 CRC 后返回与 raw 正文逐字节相等的内容。
func dynamicShardAssembleForTest(envelopeText string, cek []byte) (string, error) {
	raw, err := gm.Decode(envelopeText)
	if err != nil {
		return "", err
	}
	plain, err := gm.Open(cek[:16], raw, []byte(dynamicShardsAAD), gm.DomainPowShards, false)
	if err != nil {
		return "", err
	}
	var env dynamicShardEnvelope
	if err := json.Unmarshal(plain, &env); err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, item := range env.Shards {
		data, err := base64.RawURLEncoding.DecodeString(item.Data)
		if err != nil {
			return "", err
		}
		for i := range data {
			data[i] ^= item.Key
		}
		sb.Write(data)
	}
	body := sb.String()
	if dynamicFnv1a32(body) != checksumFromString(env.CRC) {
		return "", fmt.Errorf("owaf-dynamic: crc mismatch")
	}
	return body, nil
}

// checksumFromString 把信封内 crc 十进制字符串还原为 uint32（测试辅助）。
func checksumFromString(s string) uint32 {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

/**
 * cekJSDynamicShardChain 是 encryptJS 的装配核心：用解密侧同一把 CEK 把
 * 合成占位符替换为「分片信封 + VM 拼装同步调用 + eval 执行位」。
 * vm_assemble_shards 失败（undefined/异常/空串）时抛出 Error，交由模板
 * 既有 catch 路径显示「脚本解密失败」页面；错误先 console.error 记录，
 * 与旧失败回调同构。返回的 shellGenerated 为完整 JS 字符串（变量名
 * 随机）用于回归锁测试；assembly 中的信封文本用 JSON 转义嵌入（纯
 * 数据，无任何可解释路径）。
 */
func cekJSDynamicShardChain(cek []byte) (shellGenerated string, assembly string, err error) {
	envText, shellGenerated, err := GenerateEncryptedShardedCode(codeEvalHoldGuard(), cek, []byte(dynamicShardsAAD))
	if err != nil {
		return "", "", err
	}
	keyHex := hex.EncodeToString(cek)
	assembly = "var __owaf_code_env=" + strconv.Quote(envText) + ",__owaf_code_key=" + strconv.Quote(keyHex) + ";"
	assembly += "(function(){"
	assembly += "var e=__owaf_code_env,k=__owaf_code_key;"
	assembly += "if(typeof wasm_bindgen===\"undefined\"||typeof wasm_bindgen.vm_assemble_shards!==\"function\"){throw new Error(\"dynamic vm assembler unavailable\")}"
	assembly += "var c=wasm_bindgen.vm_assemble_shards(e,k);"
	assembly += "if(typeof c!==\"string\"||!c.length){throw new Error(\"dynamic shard assembly failed\")}"
	assembly += "(0,eval).call(window,c)"
	assembly += "})();"
	return shellGenerated, assembly, nil
}

/**
 * codeEvalHoldGuard 是分片装箱用的最小合法代码占位：本占位只存在于
 * 合成构建的既时拆装验证（PVS），实际响应流程中的 code 来自客户端
 * decrypt_dynamic_with_cek 的解密结果，同一个合成占位符被 JS 侧跨
 * 会话复制没有意义。此占位确保信封在 Go 侧锁测试里可解回并与占位
 * 逐字节相等。
 */
func codeEvalHoldGuard() string {
	return "owaf_dynamic_void_statement;"
}
