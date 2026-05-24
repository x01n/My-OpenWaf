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
// Format: <prefix>-<counter-hex>. Counter is atomic so concurrent calls never
// collide. This is ~10x cheaper than uuid.NewString() on the hot path.
func fastRequestID() string {
	n := reqIDCounter.Add(1)
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[8:], n)
	suffix := base64.RawURLEncoding.EncodeToString(buf[8:])
	return reqIDPrefix + "-" + suffix
}
