package gm

import (
	"encoding/base64"
	"errors"
)

/**
 * 挑战 GM 信封（Envelope v2）常量与字节布局。
 *
 * 线格式（版本头 + 域 + nonce + SM4-GCM 密文 + SM2 签名 + SM3 tag）：
 *
 *	偏移 0   4 字节 magic：0x4F57 0x5645（ASCII "OWVE"，拒绝旧 v1/v3 密文）
 *	偏移 4   1 字节 version：0x02（信封 v2，与 magic 联合鉴伪）
 *	偏移 5   1 字节 domain：用途域，见下
 *	偏移 6   1 字节 reserved：保留，固定 0x00
 *	偏移 7   1 字节 sig_len：SM2 签名长度字节数（取模 256，定值 64）
 *	偏移 8   12 字节 nonce：SM4-GCM 唯一随机数
 *	偏移 20  N  字节 ciphertext：SM4-GCM 密文（N >= 0，可为空）
 *	偏移 20+N  16 字节 gcm_tag：SM4-GCM 认证标签
 *	偏移 36+N  (sig_len) 字节 sig：SM2 签名（纯哈希模式）
 *	偏移 36+N+sig_len  32 字节 tag：SM3 对前部内容的整体校验
 *
 * 参与 SM2 签名的 e = SM3(signed)[:32]，signed 覆盖 headerid
 * （本轮统一为 4 字节，全部填充 0x00）到 gcm_tag 末尾之间的全部字节。
 * 参与 SM3 整体 tag 的数据为信封前部 magic 到 sig 末尾之间的全部字节。
 *
 * 静态部分（magic+version+domain+reserved+sig_len 共 8 字节）+ nonce 12 字节
 * + tag 16 字节 + sig 64 字节 + sm3_tag 32 字节构成最小 132 字节信封。
 */
const (
	// Magic 是信封魔数，ASCII "OWVE"。
	// 与旧 AES-GCM 信封（v1. base64(nonce|ciphertext|tag)）天然冲突，
	// Open 时二者都无从命中，实现零回退拒绝。
	Magic = "OWVE"

	// EnvelopeVersion 是信封线格式版本，当前为 v2。
	EnvelopeVersion byte = 0x02

	// headerLen 是魔数+版本+域+保留+签名长度头部的固定字节数。
	headerLen = 8

	// NonceSize 是 SM4-GCM 的随机数长度（12 字节）。
	NonceSize = 12

	// TagSize 是 SM4-GCM 认证标签长度（16 字节）。
	TagSize = 16

	// SigSize 是 SM2 签名的定长字节数（64 字节，r||s，各 32 字节大端）。
	SigSize = 64

	// Sm3TagSize 是信封整体 SM3 校验值长度（32 字节）。
	Sm3TagSize = 32

	// MinEnvelopeLen 是空明文信封的最小字节长度。
	MinEnvelopeLen = headerLen + NonceSize + TagSize + SigSize + Sm3TagSize

	// MaxEnvelopeTextLen 是信封文本（base64url）的长度上限。
	// 上限需覆盖 captchaItemDataMaxPlaintext（512 KiB）的编码膨胀：
	// 4/3*(132+512KiB) ≈ 699 KiB，取 1 MiB 留余量。
	MaxEnvelopeTextLen = 1 << 20
)

/**
 * ErrOpenFailed 表示 Open 阶段以不可区分错误拒绝。
 * 具体失败原因不得向调用方暴露（防 oracle），该值只用于内部短路。
 */
var ErrOpenFailed = errors.New("owaf: sealed envelope verification failed")

/**
 * ErrDomainMismatch 表示信封用途域与期望不符（防跨用途密文重用），
 * 仅由 Open 的 domain 参数强制校验时返回。
 */
var ErrDomainMismatch = errors.New("owaf: envelope domain mismatch")

// 信封用途域代号（与 b2 契约 0x01-0x04 对齐，0x05 为服务端单向通行信封扩展域）。
const (
	DomainEnv           byte = 0x01 // 环境指纹（浏览器 -> 服务端）
	DomainCaptchaItem   byte = 0x02 // captcha 题目（服务端 -> 浏览器）
	DomainCaptchaAnswer byte = 0x03 // captcha 答案（浏览器 -> 服务端）
	DomainBrowserSign   byte = 0x04 // browser-sign 票据（服务端签署）
	DomainToken         byte = 0x05 // 通行 cookie / 动态保护令牌（服务端单向）
)

/**
 * Encode 将原始信封字节编码为 base64.RawURLEncoding（无内联换行符），
 * 可直接作为 HTTP cookie、表单字段与 URL 参数值。
 */
func Encode(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

/**
 * Decode 还原 Encode 产生的 envelope 文本表示。
 * 语法错误与超长输入（> MaxEnvelopeTextLen）都返回空切片。
 */
func Decode(s string) ([]byte, error) {
	if len(s) > MaxEnvelopeTextLen {
		return nil, ErrOpenFailed
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrOpenFailed
	}
	return raw, nil
}
