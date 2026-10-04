package dataplane

import (
	"encoding/base64"
	"encoding/binary"
	"math/rand/v2"
	"sync/atomic"
	"time"
)

/**
 * reqIDPrefix 是 8 字节的进程内随机前缀，编码为类 base32hex 的 hex 字符串。
 * 启动时计算一次，避免每请求都消耗系统调用。
 */
var reqIDPrefix string

/**
 * reqIDCounter 是原子递增的 64 位计数器，与前缀组合成快速且抗碰撞的请求 ID，
 * 既不消耗 crypto/rand 系统调用，也没有 UUID 解析开销。
 */
var reqIDCounter atomic.Uint64

func init() {
	var seed [8]byte
	// math/rand/v2 自动播种；取 8 字节作为进程前缀。
	binary.BigEndian.PutUint64(seed[:], rand.Uint64())
	reqIDPrefix = base64.RawURLEncoding.EncodeToString(seed[:]) // ~11 chars
	// 把启动时间混入计数器，使其在进程重启后不可预测。
	reqIDCounter.Store(uint64(time.Now().UnixNano()))
}

/**
 * fastRequestID 返回一个不消耗 crypto/rand 系统调用的短唯一请求 ID。
 * 格式：<prefix>-<counter-base64url>，11+1+11 个字符。计数器是原子的，
 * 并发调用不会碰撞。
 *
 * 与旧实现逐字节一致：后缀仍是同一 RawURLEncoding 的输出（8 字节 → 11 位，
 * 无填充），仅把目标换成栈上 11 字节缓冲；终串在 23 字节栈缓冲合成后一次
 * 搬入堆，把每请求的 3 次小分配（两个 EncodeToString + 拼接）收敛为 1 次。
 */
func fastRequestID() string {
	n := reqIDCounter.Add(1)
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], n)
	var enc [11]byte
	base64.RawURLEncoding.Encode(enc[:], v[:])
	plen := len(reqIDPrefix) // 恒为 11：8 字节 seed 的 RawURL 编码，无边 padding
	var buf [23]byte
	copy(buf[:plen], reqIDPrefix)
	buf[plen] = '-'
	copy(buf[plen+1:], enc[:])
	return string(buf[:])
}
