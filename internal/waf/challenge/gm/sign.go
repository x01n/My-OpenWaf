package gm

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"sync/atomic"

	"github.com/emmansun/gmsm/sm2"
)

// signCtx 缓存当前 secret 的派生私钥与公钥，避免每个请求重复做椭圆曲线标量乘法。
type signCtx struct {
	secret32 []byte
	pub      string // hex，无 0x04 前缀（64 字节 => 128 hex）
	signer   *sm2.PrivateKey
}

var signIdent atomic.Pointer[signCtx]

/**
 * LoadIdentity 基于 32 字节服务器密钥材料装载 SM2 签名身份。
 * 返回公钥的 hex 编码（无 0x04 前缀，128 字符）。同一 secret 重复调用幂等无副作用。
 */
func LoadIdentity(secret []byte) string {
	if len(secret) != 32 {
		return ""
	}
	if cached := signIdent.Load(); cached != nil && ConstTimeEqual(cached.secret32, secret) {
		return cached.pub
	}
	d := KDF(secret, []byte(EnvelopeLabel(CategoryServerSign, GMEnvelopeVersion)))[:32]
	priv, err := sm2.NewPrivateKey(d)
	if err != nil {
		return ""
	}
	x := priv.X.Bytes()
	y := priv.Y.Bytes()
	pub := make([]byte, 64)
	copy(pub[32-len(x):], x)
	copy(pub[64-len(y):], y)
	signIdent.Store(&signCtx{secret32: append([]byte(nil), secret...), pub: hex.EncodeToString(pub), signer: priv})
	return hex.EncodeToString(pub)
}

/**
 * SignMessage 返回传入消息的标准 SM2 签名
 *
 * 输出为定长 64 字节 r||s（各 32 字节大端）。
 * e = SM3(ZA‖msg) 由 sm2EPreimage 计算后喂入低层公式签名，
 * 与 b2 的标准语义同构；不存在无 ZA 变体，也不存在 0x00000000 拼接。
 */
func SignMessage(msg []byte) ([]byte, error) {
	cached := signIdent.Load()
	if cached == nil || cached.signer == nil {
		return nil, errMissingIdentity
	}
	e := sm2EPreimage(&cached.signer.PublicKey, msg)
	r, s, err := sm2.Sign(rand.Reader, &cached.signer.PrivateKey, e[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, SigSize)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(sig[32-len(rb):], rb)
	copy(sig[64-len(sb):], sb)
	return sig, nil
}

var errMissingIdentity = errNoIdentity{}

type errNoIdentity struct{}

func (errNoIdentity) Error() string { return "owaf: no SM2 identity loaded" }

/**
 * PubKeyHex 返回当前装载身份的 SM2 公钥（hex 128 字符，无 0x04 前缀）。
 * 无身份时返回空串。挑战页渲染前必须调用 LoadIdentity。
 */
func PubKeyHex() string {
	cached := signIdent.Load()
	if cached == nil {
		return ""
	}
	return cached.pub
}

// catIdentity 缓存按 (secret32, category) 派生的签名身份，供 stateless 校验方
// （browsersign 票据签名）在无会话存储的路径上重算同一身份。
type catIdentity struct {
	secret32 []byte
	category string
	pub      string
	signer   *sm2.PrivateKey
}

var catIdentities sync.Map

func catKey(secret []byte, category string) string {
	return string(secret) + "|" + category
}

/**
 * DeriveIdentityPub 按主裁类别派生一次性 SM2 身份：
 * priv = SM3KDF(challengeSecret, category)[:32]，返回 pub 128 hex（无 0x04 前缀）。
 * 派生确定性且幂等缓存，票据校验路径可无状态重算同一公钥。
 * category 示例："browsersign-sign"。
 */
func DeriveIdentityPub(secret []byte, category string) string {
	if len(secret) != 32 || category == "" {
		return ""
	}
	key := catKey(secret, category)
	if v, ok := catIdentities.Load(key); ok {
		if id, ok := v.(*catIdentity); ok {
			return id.pub
		}
	}
	d := SM3KDF(secret, category)[:32]
	priv, err := sm2.NewPrivateKey(d)
	if err != nil {
		return ""
	}
	x := priv.X.Bytes()
	y := priv.Y.Bytes()
	pub := make([]byte, 64)
	copy(pub[32-len(x):], x)
	copy(pub[64-len(y):], y)
	id := &catIdentity{
		secret32: append([]byte(nil), secret...),
		category: category,
		pub:      hex.EncodeToString(pub),
		signer:   priv,
	}
	catIdentities.Store(key, id)
	return id.pub
}

/**
 * DerivedSignMessage 用派生（类别）身份对 msg 做标准 ZA 签名，输出 r||s 64B。
 * 派生身份缺失时返回 no-SM2-identity 错误。
 */
func DerivedSignMessage(secret []byte, category string, msg []byte) ([]byte, error) {
	if DeriveIdentityPub(secret, category) == "" {
		return nil, errMissingIdentity
	}
	v, _ := catIdentities.Load(catKey(secret, category))
	id := v.(*catIdentity)
	e := sm2EPreimage(&id.signer.PublicKey, msg)
	r, s, err := sm2.Sign(rand.Reader, &id.signer.PrivateKey, e[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, SigSize)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(sig[32-len(rb):], rb)
	copy(sig[64-len(sb):], sb)
	return sig, nil
}
