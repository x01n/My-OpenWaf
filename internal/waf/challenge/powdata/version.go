package powdata

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

/**
 * 资产版本串：**内容派生**，不是固定常量。
 *
 * 为什么内容派生：客户端的 `?v=` 是缓存键的一部分，而 `/__owaf/pow.wasm`
 * 与 `/__owaf/pow_glue.js` 用 `Cache-Control: public,max-age=...,immutable`
 * 下发（`immutable` 承诺窗口内**不回源校验**）。若版本串是写死的常量，
 * 换资产后老访客会在窗口内继续用旧资产 —— `challenge/browsersign.go` 历史
 * 上的 `?v=f54bf002` / `?v=7ad1dbac` 就是这种失配（资产换过多次、串从未更新）。
 *
 * 为什么不用 -ldflags -X 注入：那会让「资产换了但注入没跟上」成为新的静默
 * 失配源。内容派生把版本串与资产本身绑死，资产变则串必变。
 *
 * 为什么不去掉查询串：`immutable` 的安全前提正是「URL 随内容变」；去掉查询
 * 串会让换版本后的老访客拿旧资产，方向反了。
 *
 * 取值：sha256(资产字节) 的前 8 位十六进制（32 bit）。碰撞概率对本用途足够低
 * （每次发布只比一次），且短到不增加 URL 体积。
 */
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
