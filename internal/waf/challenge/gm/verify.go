package gm

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
)

const DefaultSM2UserID = "owaf-gm-challenge"

func sm2EPreimage(pub *ecdsa.PublicKey, msg []byte) [32]byte {
	za, err := sm2.CalculateZA(pub, []byte(DefaultSM2UserID))
	if err != nil {
		return [32]byte{}
	}
	buf := make([]byte, 0, len(za)+len(msg))
	buf = append(buf, za...)
	buf = append(buf, msg...)
	return sm3.Sum(buf)
}

func VerifySignature(msg []byte, sig []byte) bool {
	cached := signIdent.Load()
	if cached == nil || cached.signer == nil || len(sig) != SigSize {
		return false
	}
	pub := &cached.signer.PublicKey
	e := sm2EPreimage(pub, msg)
	return sm2.Verify(pub, e[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

/**
 * VerifyExternalSignature 验证外部任意公钥（hex 128，无 0x04 前缀）的
 * r||s 签名（标准 ZA 语义）。公钥非法或签名不符返回 false。
 */
func VerifyExternalSignature(pubHex string, msg []byte, sig []byte) bool {
	if len(sig) != SigSize || len(pubHex) != 128 {
		return false
	}
	raw := decodeHexNoLookup(pubHex)
	if len(raw) != 64 {
		return false
	}
	pub := &ecdsa.PublicKey{
		Curve: sm2.P256(),
		X:     new(big.Int).SetBytes(raw[:32]),
		Y:     new(big.Int).SetBytes(raw[32:]),
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return false
	}
	e := sm2EPreimage(pub, msg)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return sm2.Verify(pub, e[:], r, s)
}
