package gm

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
)

// pubFromBytes 还原 64 字节无 04 前缀公钥；sm3Sum 输出 [32]byte 的切片视图。

func pubFromBytes(raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) != 64 {
		return nil, fmt.Errorf("bad pub length")
	}
	return &ecdsa.PublicKey{
		Curve: sm2.P256(),
		X:     new(big.Int).SetBytes(raw[:32]),
		Y:     new(big.Int).SetBytes(raw[32:]),
	}, nil
}

func sm3Sum(in []byte) []byte {
	sum := sm3.Sum(in)
	return sum[:]
}
