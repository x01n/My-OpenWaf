package dataplane

import (
	"encoding/base64"
	"encoding/binary"
	"math/rand/v2"
	"sync/atomic"
	"time"
)

// reqIDPrefix is an 8-byte process-local random prefix encoded as base32hex-ish
// hex string. Computed once at startup so we don't burn syscalls per request.
var reqIDPrefix string

// reqIDCounter is an atomically incremented 64-bit counter combined with the
// prefix to form a fast, collision-resistant request ID without crypto/rand
// syscalls or UUID parsing overhead.
var reqIDCounter atomic.Uint64

func init() {
	var seed [8]byte
	// math/rand/v2 is seeded automatically; pull 8 bytes for a process prefix.
	binary.BigEndian.PutUint64(seed[:], rand.Uint64())
	reqIDPrefix = base64.RawURLEncoding.EncodeToString(seed[:]) // ~11 chars
	// Mix the start time into the counter so it isn't predictable across restarts.
	reqIDCounter.Store(uint64(time.Now().UnixNano()))
}

// fastRequestID returns a short unique request ID without crypto/rand syscalls.
// Format: <prefix>-<counter-base64url>, 11+1+11 chars. Counter is atomic so
// concurrent calls never collide.
//
// 与旧实现逐字节一致：后缀仍是同一 RawURLEncoding 的输出（8 字节 → 11 位，
// 无填充），仅把目标换成栈上 11 字节缓冲；终串在 23 字节栈缓冲合成后一次
// 搬入堆，把每请求的 3 次小分配（两个 EncodeToString + 拼接）收敛为 1 次。
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
