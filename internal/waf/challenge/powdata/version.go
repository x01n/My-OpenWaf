package powdata

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

var (
	powAssetVerOnce sync.Once
	wasmVersion     string
	glueVersion     string
)

// versionOf 返回资产字节的内容派生版本串（sha256 前 8 位 hex）。
func versionOf(asset []byte) string {
	sum := sha256.Sum256(asset)
	return hex.EncodeToString(sum[:4])
}

// WasmVersion 返回 pow.wasm 的版本串（进程内只计算一次）。
func WasmVersion() string {
	powAssetVerOnce.Do(computeAssetVersions)
	return wasmVersion
}

// GlueVersion 返回 pow_glue.js 的版本串（进程内只计算一次）。
func GlueVersion() string {
	powAssetVerOnce.Do(computeAssetVersions)
	return glueVersion
}

func computeAssetVersions() {
	wasmVersion = versionOf(WASMBinary)
	glueVersion = versionOf(PowGlueJS)
}
