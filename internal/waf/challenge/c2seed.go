package challenge

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"My-OpenWaf/internal/waf/challenge/gm"
)

/**
 * C2 种子（dual 模式的第二枚 Cookie）签发与校验。
 *
 * 语义变更：旧实现让续期页自行派生 C2（`__waf_nonce` 末 8 位 + 时间戳），
 * 任何脚本都能构造出同样的值，因此 C2 实际不构成第二个因子。新实现把 C2
 * 改为「服务端算出的 MAC」，客户端只能原样落位、无法伪造：
 *
 *	C2 = "w2." + hex( MAC ) + "." + exp
 *	MAC    = SM3( k_mac ‖ clientIP ‖ "|" ‖ exp )
 *	cookie = "w2." + hex(MAC) + "." + exp
 *
 * **为什么 MAC 不绑定 C1**：C1 每次请求都被 ValidateAndRotate 轮换成新值
 * （antireplay.go 的 newNonce 恒为新生成），而 C2 是客户端在上一轮响应里
 * 落位的。若 MAC 绑定 C1，则每个携带 C2 的请求都会拿「下一枚 C1」去比对
 * 「绑定上一枚 C1」的 MAC，**永远不匹配**，dual 站点会陷入无限 412。因此
 * 绑定面收敛为 (clientIP, exp)：不可伪造靠 k_mac 不下发，不可跨客户端靠
 * clientIP，时限靠 exp。
 *
 * 密钥分离（关键）：信封密钥与 MAC 密钥由不同标签派生，页面只拿到信封密钥，
 * 因此能解开种子却算不出 MAC。
 *
 *	k_seal = SM3KDF(challengeSecret, "c2-seal")  // 随页面下发，仅用于解信封
 *	k_mac  = SM3KDF(challengeSecret, "c2-mac")   // 永不下发，仅服务端持有
 *
 * 与相邻用途的隔离：0x06 域（DomainPowShards）被 PoW 分片、动态保护分片与
 * 本种子信封三方共用，且 gm.Seal/gm.Open 的 aad 参数**不参与认证**（见下方
 * c2SeedEnvelopeAAD 注释），因此**域内多用途隔离仅靠密钥互不相同**。k_c2 由
 * challengeSecret 经 "c2-seal"/"c2-mac" 标签派生，与 pow_shard 会话密钥、动态
 * 保护 CEK 均无派生关系；改动任一侧时不得让三者共用密钥。
 *
 * 信封复用既有分片通道：种子被包成「单片分片信封」（k=0 表示不做 XOR），
 * 客户端直接调用现成的 wasm_bindgen.vm_assemble_shards 在 WASM 内存内解出，
 * 无需新增 Rust 导出、无需新增域名、无需新增 HTTP 路由。客户端只做一件事：
 * 把载荷里的 cookie 字段原样写进 document.cookie，**不拼接、不计算**。
 */

const (
	// C2SeedPrefix 是 C2 cookie 值的版本前缀。服务端据此前缀区分新旧格式，
	// 无此前缀的值一律判为无效（旧派生值自然失效）。
	C2SeedPrefix = "w2."

	// c2SeedTTL 是单枚 C2 种子的有效期，也就是「一次续期能用多久」。
	//
	// 取值权衡：exp 在 cookie 值里是**明文**（w2.<mac>.<exp>），而 MAC 是唯一
	// 防伪造凭据，因此该窗口同时是「同一 IP 的 C2 可被重放多久」。60s 会让
	// 用户每 60 秒被挑战一次；24h 会把重放窗口拉到一整天。900s（15 分钟）
	// 是两者之间的取舍点：用户可见打扰从「频繁」降到「每刻钟一次」，
	// 重放窗口仍受控。
	//
	// 注意：本值**不等于** cookie 的 Max-Age。cookie 留存（86400）与校验
	// 窗口（本值）是两件事——关浏览器次日再来时 cookie 还在，只是重签一次。
	c2SeedTTL = 900 * time.Second

	// c2SealCategory 与 c2MACCategory 是两条密钥的域分离标签（禁止合并）。
	c2SealCategory = "c2-seal"
	c2MACCategory  = "c2-mac"

	// c2FieldSeparator 是 MAC 消息拼接的分隔符，防止字段边界歧义
	// （例如 clientIP="1.2" + exp="34" 与 clientIP="1.23" + exp="4" 互异）。
	c2FieldSeparator = "|"
)

// c2SeedEnvelopeAAD 是种子信封的 AAD 标签（标签生成器产物，禁止散落字面量）。
//
// 注意：该值当前**不参与信封认证**——`gm.Seal`/`gm.Open` 传给 SM4-GCM 的
// AAD 是信封前 8 字节头部，调用方传入的 aad 参数未被使用。派生的 k_seal 只
// 下发给页面（用于解信封），k_mac 永不下发，因此种子不可伪造。
var c2SeedEnvelopeAAD = gm.EnvelopeAAD(gm.EnvelopeLabel("c2-seed", gm.GMEnvelopeVersion), gm.PurposeChallengeData)

// C2SeedPayload 是种子信封内的 JSON 载荷。
//
// Cookie 字段是**服务端算好的完整 cookie 值**，客户端只做一件事：原样写进
// document.cookie。原样下发而非让客户端拼接，是因为拼接是可被省略或篡改的
// 一步，而值本身已不可伪造——拼接没有安全价值，只会引入「拼错格式 → 解析
// 失败 → 反复续期」的失败面。
type C2SeedPayload struct {
	Version int    `json:"v"`
	MAC     string `json:"mac"`
	Exp     int64  `json:"exp"`
	Cookie  string `json:"cookie"`
}

// c2SealKey 派生信封密钥（32 字节，SM4 取前 16 字节）；密钥材料不足时返回 nil。
func c2SealKey() []byte {
	secret := loadChallengeSecret()
	if len(secret) != 32 {
		return nil
	}
	return gm.SM3KDF(secret, c2SealCategory)
}

// c2MACKey 派生 MAC 密钥；只在本包内使用，任何调用面都不下发。
func c2MACKey() []byte {
	secret := loadChallengeSecret()
	if len(secret) != 32 {
		return nil
	}
	return gm.SM3KDF(secret, c2MACCategory)
}

// c2SeedMAC 计算绑定 (clientIP, exp) 的 MAC，输出 32 字节。
func c2SeedMAC(key []byte, clientIP string, exp int64) []byte {
	msg := clientIP + c2FieldSeparator + strconv.FormatInt(exp, 10)
	return sm3HMAC(key, msg)
}

// IssueC2Seed 为 clientIP 签发一枚 C2 种子，返回页面可下发的信封文本与
// 信封密钥的 hex（64 字符）。
//
// 任一前置缺失（密钥未装载）时返回 not-ok，调用方据此跳过续期页注入。
func IssueC2Seed(clientIP string) (envelope string, keyHex string, ok bool) {
	sealKey := c2SealKey()
	macKey := c2MACKey()
	if len(sealKey) != envSessionKeySize || len(macKey) == 0 {
		return "", "", false
	}
	exp := time.Now().Add(c2SeedTTL).Unix()
	mac := hex.EncodeToString(c2SeedMAC(macKey, clientIP, exp))
	payload, err := json.Marshal(C2SeedPayload{
		Version: int(gm.GMEnvelopeVersion),
		MAC:     mac,
		Exp:     exp,
		Cookie:  C2SeedCookieValue(mac, exp),
	})
	if err != nil {
		return "", "", false
	}
	envelope, err = sealC2SeedEnvelope(payload, sealKey)
	if err != nil {
		return "", "", false
	}
	return envelope, hex.EncodeToString(sealKey), true
}

/**
 * sealC2SeedEnvelope 把载荷包成「单片分片信封」并经 GM 信封（域 0x06）加密。
 *
 * 选用单片分片形态是为了复用客户端既有的 wasm_bindgen.vm_assemble_shards：
 * 该导出已在 WASM 内存内完成解码、XOR、FNV-1a 校验与拼装。单片的 XOR 密钥
 * 固定为 0（等价于不加密），分片层在此只承担「与 WASM 拼装通道同构」的角色，
 * 机密性完全由外层 SM4-GCM 信封提供。
 */
func sealC2SeedEnvelope(payload []byte, sealKey []byte) (string, error) {
	body := string(payload)
	inner, err := json.Marshal(PowShardEnvelope{
		V: int(gm.GMEnvelopeVersion),
		Shards: []powShardEnvelopeItem{{
			Key:  0,
			Data: base64.RawURLEncoding.EncodeToString(payload),
		}},
		CRC: strconv.FormatUint(uint64(fnv1a32(body)), 10),
	})
	if err != nil {
		return "", err
	}
	raw, err := gm.Seal(sealKey[:16], gm.DomainPowShards, inner, []byte(c2SeedEnvelopeAAD))
	if err != nil {
		return "", err
	}
	return gm.Encode(raw), nil
}

/**
 * VerifyC2Cookie 校验浏览器落位的 C2 值。
 *
 * 校验链：前缀 -> 结构 -> exp 未过期 -> 重算 MAC 恒定时间比对。
 * clientIP 必须与签发时一致；调用方在 C1 轮换后调用本函数是安全的
 * （MAC 不绑定 C1，见文件头注释）。
 * 任一环节不符返回 false，调用方据此重新签发 412 续期页。
 */
func VerifyC2Cookie(value, clientIP string) bool {
	macKey := c2MACKey()
	if len(macKey) == 0 || !strings.HasPrefix(value, C2SeedPrefix) {
		return false
	}
	rest := strings.TrimPrefix(value, C2SeedPrefix)
	macHex, expStr, found := strings.Cut(rest, ".")
	if !found || len(macHex) != 64 {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || exp <= 0 {
		return false
	}
	if time.Now().Unix() > exp {
		return false
	}
	presented, err := hex.DecodeString(macHex)
	if err != nil {
		return false
	}
	expected := c2SeedMAC(macKey, clientIP, exp)
	return gm.ConstTimeEqual(presented, expected)
}

/**
 * C2SeedCookieValue 构造 C2 cookie 值。服务端签发时把结果放进种子的 cookie
 * 字段原样下发，浏览器不做本计算；函数保留给测试与工具路径，并与页面写入
 * 的值保持逐字一致。
 */
func C2SeedCookieValue(mac string, exp int64) string {
	return C2SeedPrefix + mac + "." + strconv.FormatInt(exp, 10)
}
