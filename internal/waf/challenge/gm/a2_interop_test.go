package gm

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/emmansun/gmsm/sm2"
)

const (
	interopA2Pub = "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020" +
		"ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13"
	interopA2Msg = "message digest"
)

// TestSM2StandardVectorE 断言标准 ZA 语义（GM/T 0003-2012）：
// ZA = SM3(ENTL‖IDa‖a‖b‖xG‖yG‖xA‖yA)、e = SM3(ZA‖msg)。
// gmsm 的 CalculateZA 与 sm2EPreimage 即标准实现，均为确定性值。
func TestSM2StandardVectorE(t *testing.T) {
	pub := mustA2Pub(t)

	za, err := sm2.CalculateZA(pub, []byte(DefaultSM2UserID))
	if err != nil {
		t.Fatalf("CalculateZA: %v", err)
	}
	wantZA := "125ecf2961352a4220ec1d562987ee9f1570b7ffb62b70b7f34e6a98d99f4d62"
	if got := hex.EncodeToString(za); got != wantZA {
		t.Fatalf("ZA mismatch:\ngot  %s\nwant %s", got, wantZA)
	}

	e := sm2EPreimage(pub, []byte(interopA2Msg))
	wantE := "6cd941ebc58389079c29abd48c9d1601810870593f469ec64a808a2934cd8f50"
	if got := hex.EncodeToString(e[:]); got != wantE {
		t.Fatalf("e mismatch:\ngot  %s\nwant %s", got, wantE)
	}
}

// TestSM2StandardVectorRejectsNonStandardSig 证明 b2 样本 sig 的 e 路径
// （preimage‖00000000‖msg）与 GM/T 0003-2012 标准语义不一致：标准语义必须拒签。
func TestSM2StandardVectorRejectsNonStandardSig(t *testing.T) {
	pub := mustA2Pub(t)
	der, err := base64.StdEncoding.DecodeString("MEUCIGvU2UQwyA2mqKqpWO9XGfHRgt39y01G5yWdlRdNP7KlAiEAsVFh7Mrgw8mL7f01rwuNmblS3tZGmVrolvNL9t/pofY=")
	if err != nil {
		t.Fatalf("decode b2 sig: %v", err)
	}
	r, s, ok := parseDER64(der)
	if !ok {
		t.Fatalf("parse DER sig failed: %x", der)
	}
	e := sm2EPreimage(pub, []byte(interopA2Msg))
	if sm2.Verify(pub, e[:], r, s) {
		t.Fatal("non-standard-e signature must NOT verify under standard ZA semantics")
	}
}

func mustA2Pub(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	raw, err := hex.DecodeString(interopA2Pub)
	if err != nil || len(raw) != 64 {
		t.Fatalf("bad pub hex: %v", err)
	}
	pub, err := pubFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// parseDER64 解析 SM2 DER 签名（SEQUENCE{INTEGER r, INTEGER s}）。
func parseDER64(der []byte) (r *big.Int, s *big.Int, ok bool) {
	if len(der) < 8 || der[0] != 0x30 || int(der[1]) != len(der)-2 || der[2] != 0x02 {
		return nil, nil, false
	}
	rLen := int(der[3])
	rBytes := der[4 : 4+rLen]
	idx := 4 + rLen
	if der[idx] != 0x02 {
		return nil, nil, false
	}
	sLen := int(der[idx+1])
	sBytes := der[idx+2 : idx+2+sLen]
	if idx+2+sLen != len(der) {
		return nil, nil, false
	}
	return new(big.Int).SetBytes(rBytes), new(big.Int).SetBytes(sBytes), true
}
