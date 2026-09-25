// Package gm 提供 My-OpenWaf 挑战链路所需的国密算法信封原语：
// SM4-GCM 保密、SM2（纯哈希模式）签名、SM3 哈希/HMAC/KDF。
//
// 该包是挑战信封（v2 线格式）的唯一权威实现：Go 服务端用于签发/验证，
// Rust WASM 侧按同一字节布局实现对偶原语。信封里的任何字段偏移改动
// 都必须同步两个实现，因此所有常量集中定义在 envelope.go。
package gm
