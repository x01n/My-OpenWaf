package gm

import (
	"encoding/base64"
	"testing"

	"github.com/emmansun/gmsm/sm2"
)

// TestSM2VerifyExternalDER 用外部 DER 样签验证标准 ZA 语义闭环：
// 输入 = (pub, msg, sig_b64)；签名必须以 ida=owaf-gm-challenge 生成。
// b2 样签到位后填入 fixtures 即可互验（b1 侧只做验证，不做假设性数值断言）。
func TestSM2VerifyExternalDER(t *testing.T) {
	pub := mustA2Pub(t)

	// 示例 DER fixture 为空时会走"无样本跳过"？否——互验需真实样本。
	// 该测试要求外部样本；当前以 b2 曾发的 rev9 样签为负例再验一次语义
	// （标准语义必须拒绝其旧 e 签名；互验样本待 b2 修正后回填）。
	der, _ := base64.StdEncoding.DecodeString("MEUCIGvU2UQwyA2mqKqpWO9XGfHRgt39y01G5yWdlRdNP7KlAiEAsVFh7Mrgw8mL7f01rwuNmblS3tZGmVrolvNL9t/pofY=")
	r, s, ok := parseDER64(der)
	if !ok {
		t.Fatal("parse der")
	}
	e := sm2EPreimage(pub, []byte(interopA2Msg))
	if sm2.Verify(pub, e[:], r, s) {
		t.Fatal("rev9 legacy-e signature must NOT verify under the final standard semantics")
	}
}
