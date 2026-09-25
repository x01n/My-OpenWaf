package gm

import (
	"fmt"
	"strconv"

	"github.com/emmansun/gmsm/sm3"
)

// GMEnvelopeVersion 是国密信封的唯一协议版本（强制化后不存在旧版本分支）。
const GMEnvelopeVersion uint = 2

func ProtocolVersionString() string {
	return strconv.FormatUint(uint64(GMEnvelopeVersion), 10)
}
func EnvelopeLabel(category string, version uint) string {
	return fmt.Sprintf("owaf-%s:v%d", category, version)
}

// EnvelopePrefix 生成单版本 ASCII 前缀（label-spec 定稿形态）：
//
//	EnvelopePrefix(version, label) = "v" + version + "." + label
func EnvelopePrefix(version uint, label string) string {
	return "v" + strconv.FormatUint(uint64(version), 10) + "." + label
}
func EnvelopeAAD(label, purpose string) string {
	return label + "|" + purpose
}

const (
	PurposeChallengeData = "challenge-data"
	PurposeShield        = "shield"
	PurposeCaptcha       = "captcha"
	PurposeBrowserSign   = "browsersign"
	PurposePass          = "pass"
	PurposeDynProtect    = "dyn-protect"
)
const (
	CategoryServerSign      = "server-sign"      // SM2 服务端签名身份私钥派生
	CategoryBrowserSign     = "browsersign"      // browsersign 票据/请求/环境密钥派生
	CategoryBrowserSignSign = "browsersign-sign" // browsersign 票据 SM2 签名身份私钥派生（主裁裁决）
	CategoryPassToken       = "pass"             // 通行 cookie / 动态保护令牌的 SM4 密钥派生
	CategoryDynProtect      = "dyn-protect"      // 动态保护会话密钥派生（预留）
)

func SM3KDF(key []byte, category string) []byte {
	info := EnvelopeLabel(category, GMEnvelopeVersion)
	in := make([]byte, 0, len(key)+len(info))
	in = append(in, key...)
	in = append(in, info...)
	sum := sm3.Sum(in)
	return append([]byte(nil), sum[:]...)
}
