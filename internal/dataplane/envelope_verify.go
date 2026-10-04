/**
 * B3 签名接线：密码学层。
 *
 * 本文件只承载**与传输形态无关**的部分：把「用签名验封信封」收敛成一个
 * 类型与一个方法。它不关心信封是内联在页面 hidden input 里、还是走独立
 * 路由（L4 A′ 路线），因此 A′ 结论落地后只需替换调用点，不必改这里。
 */
package dataplane

import (
	"log/slog"

	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/challenge/gm"
)

/**
 * EnvelopeVerifier 是信封验签的唯一收口。
 *
 * 语义：**失败关闭**。任何一步不成立都不放行信封，调用方据此拒绝下发或
 * 拒绝消费该信封。
 *
 * 关于「公钥未装载」这一分支：`gm.PubKeyHex()` 在真实启动路径上**恒非空**
 * —— challenge 包的 init() 无条件装载 32 字节随机身份，而唯一调用点
 * `SetChallengeSecret` 的内门条件（len == 32）恒假，因此不会被覆盖。
 * 所以本类型不区分「公钥未装载」与「验签失败」两类错误：前者是内部不变量
 * 被破坏（只可能是 bug），按失败关闭处理并以 error 级记录；后者是安全事件，
 * 以 warn 级记录。这不是两套策略，而是同一策略下的两种可观测性。
 *
 * 调用点形态（有意保留的临时状态）：**当前尚无生产调用点**，仅测试与
 * 「服务端签发后自检」使用。信封的实际来源（内联 hidden input vs 独立路由）
 * 取决于 L4 的 A′ 结论，届时收口点可能上移到路由处理器或下移到两处调用点。
 * 本类型刻意不知道信封从哪来，因此那次移动不需要改这里。
 */
type EnvelopeVerifier struct {
	log *slog.Logger
}

// NewEnvelopeVerifier 构造验签器；log 为 nil 时静默（仅用于测试与预览路径）。
func NewEnvelopeVerifier(log *slog.Logger) EnvelopeVerifier {
	return EnvelopeVerifier{log: log}
}

/**
 * Verify 对域 0x06（DomainPowShards）的信封做验签并返回明文。
 * 返回 ok=false 表示必须拒绝，plaintext 恒为空串。
 *
 * 为什么域固定为 0x06：PoW 分片信封、动态保护分片信封、C2 种子信封三者
 * 同域，且域字段参与签名覆盖范围（`gm.Seal` 的 toSign 含整个头部），因此
 * 域不匹配会先被 Rust 侧 `raw[5] != domain` 拒掉，落到失败分支。
 *
 * 为什么必须传具体域而不能传 0：Go 的 `gm.Open` 把 `domain == 0` 当通配
 * （`gm/sealed.go` 的 `if domain != 0 && ...`），而 Rust 的 `open_raw_signed`
 * 无此豁免（`gm.rs` 的 `raw[5] != domain`）。两端不对称，传 0 会在客户端
 * 直接失败。
 */
func (v EnvelopeVerifier) Verify(envelope, keyHex string) (plaintext string, ok bool) {
	pub := gm.PubKeyHex()
	if pub == "" {
		// 内部不变量被破坏：challenge 包 init() 已装载身份，此处为空说明
		// 进程未执行该 init 或身份被显式清空。只可能是 bug，不是配置错误。
		if v.log != nil {
			v.log.Error("envelope verification aborted: signing identity is not loaded (internal invariant violation)",
				"reason", "signing_identity_missing")
		}
		return "", false
	}
	if envelope == "" || keyHex == "" {
		return "", false
	}
	plaintext = challenge.VerifyShardEnvelopeSignature(envelope, keyHex, pub)
	if plaintext == "" {
		if v.log != nil {
			v.log.Warn("envelope signature verification failed; the envelope may have been tampered with",
				"reason", "signature_mismatch")
		}
		return "", false
	}
	return plaintext, true
}
