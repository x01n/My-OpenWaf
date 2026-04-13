// Package cache provides process-local caching for immutable config snapshots.
//
// Design:
//   - Snapshot cache: purely in-process (ristretto). The Snapshot struct is an in-memory
//     object held via atomic.Pointer — serializing it to Redis would be wasteful.
//   - Distributed KV cache: see RedisKV for cross-node shared state (rate limit counters,
//     API response caching, etc.).
package cache

import (
	"fmt"
	"sync/atomic"

	"github.com/dgraph-io/ristretto"

	"My-OpenWaf/internal/snapshot"
)

// Layer is the process-local snapshot cache backed by ristretto.
// Each WAF node holds its own copy; cross-node sync is handled by Redis pub/sub
// (config_sync) which triggers a DB reload, not by sharing cached snapshots.
type Layer struct {
	rev   atomic.Uint64
	inner *ristretto.Cache
}

// NewLayer creates a local snapshot cache.
func NewLayer() (*Layer, error) {
	c, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e4,
		MaxCost:     1 << 20,
		BufferItems: 64,
	})
	if err != nil {
		return nil, err
	}
	return &Layer{inner: c}, nil
}

const snapKey = "snapshot"

// SetSnapshot caches the immutable snapshot under the given revision.
func (l *Layer) SetSnapshot(rev uint64, sn *snapshot.Snapshot) {
	l.rev.Store(rev)
	k := fmt.Sprintf("%s:%d", snapKey, rev)
	l.inner.Set(k, sn, 1)
	l.inner.Wait()
}

// GetSnapshot retrieves a cached snapshot by revision. Returns nil on miss.
func (l *Layer) GetSnapshot(rev uint64) (*snapshot.Snapshot, bool) {
	k := fmt.Sprintf("%s:%d", snapKey, rev)
	v, ok := l.inner.Get(k)
	if !ok {
		return nil, false
	}
	sn, _ := v.(*snapshot.Snapshot)
	return sn, sn != nil
}

// InvalidateAll clears the entire local cache.
func (l *Layer) InvalidateAll() {
	l.inner.Clear()
}
