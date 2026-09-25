package gm

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
)

/**
 * 服务端信封 Seal/Open 核心。
 *
 * 生成方向（Seal）：
 *   1. nonce = 12 字节随机数；
 *   2. ct||tag = SM4-GCM（AAD 为信封前 8 字节头部，域字段参与 AAD，域绑定在密文内）；
 *   3. sig = SM2 签名（覆盖 header 至 ct||tag 末尾，headerid 4 字节全零保留）；
 *   4. sm3_tag = SM3(前部全部字节)，打开侧校验。
 */
const (
	// headerIDLen 是签名字段保留的 headerid 长度（当前合约保留全零）。
	headerIDLen = 4
)

var NonceReader io.Reader = rand.Reader

func Seal(key []byte, domain byte, plaintext []byte, aad []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.New("owaf: sealed envelope requires 16-byte SM4 key")
	}
	if len(aad) > 2046 {
		return nil, errors.New("owaf: sealed envelope aad too large")
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(block)
	if err != nil {
		return nil, err
	}
	full := make([]byte, headerLen+NonceSize+len(plaintext)+TagSize)
	full[0], full[1], full[2], full[3] = Magic[0], Magic[1], Magic[2], Magic[3]
	full[4] = EnvelopeVersion
	full[5] = domain
	full[7] = SigSize
	nonce := make([]byte, NonceSize)
	if _, err := NonceReader.Read(nonce); err != nil {
		return nil, err
	}
	copy(full[headerLen:], nonce)
	// GCM AAD = 信封前 8 字节头部（magic|version|domain|reserved|sig_len），
	// 域字段参与认证，跨域密文重用被拒。
	head := full[:headerLen]
	sealed := gcm.Seal(nonce, plaintext, head)
	copy(full[headerLen+NonceSize:], sealed[NonceSize:])
	// SM2 签名覆盖 headerid||头部||nonce||ct||tag。
	toSign := make([]byte, 0, headerIDLen+len(full))
	toSign = append(toSign, 0, 0, 0, 0)
	toSign = append(toSign, full...)
	sig, err := SignMessage(toSign)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(full)+SigSize+Sm3TagSize)
	out = append(out, full...)
	out = append(out, sig...)
	sm3Tag := sm3.Sum(out)
	out = append(out, sm3Tag[:]...)
	return out, nil
}

/**
 * Open 验证并解密 v2 信封。verifySig=false 时跳过 SM2 验签（客户端上行
 * 信封的 sig 字段为零填充）；false 供对外强校验。任何失败都以
 * ErrOpenFailed 拒绝（不可区分）。
 */
func Open(key []byte, raw []byte, aad []byte, domain byte, verifySig bool) ([]byte, error) {
	if len(key) != 16 || len(raw) < MinEnvelopeLen {
		return nil, ErrOpenFailed
	}
	// SM3 整体校验先行（廉价拒绝篡改密文，避免下游重计算）。
	sm3Tag := raw[len(raw)-Sm3TagSize:]
	computed := sm3.Sum(raw[:len(raw)-Sm3TagSize])
	if !ConstTimeEqual(computed[:], sm3Tag) {
		return nil, ErrOpenFailed
	}
	header := raw[:headerLen]
	if string(header[:4]) != Magic || header[4] != EnvelopeVersion || header[6] != 0 || header[7] != SigSize {
		return nil, ErrOpenFailed
	}
	if domain != 0 && header[5] != domain {
		return nil, ErrOpenFailed
	}
	if verifySig {
		sig := raw[len(raw)-Sm3TagSize-SigSize : len(raw)-Sm3TagSize]
		toSign := make([]byte, 0, headerIDLen+len(raw)-Sm3TagSize-SigSize)
		toSign = append(toSign, 0, 0, 0, 0)
		toSign = append(toSign, raw[:len(raw)-Sm3TagSize-SigSize]...)
		if !VerifySignature(toSign, sig) {
			return nil, ErrOpenFailed
		}
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, ErrOpenFailed
	}
	gcm, err := newGCM(block)
	if err != nil {
		return nil, ErrOpenFailed
	}
	nonce := raw[headerLen : headerLen+NonceSize]
	ct := raw[headerLen+NonceSize : len(raw)-Sm3TagSize-SigSize]
	plaintext, err := gcm.Open(nonce, ct, header)
	if err != nil {
		return nil, ErrOpenFailed
	}
	return plaintext, nil
}
