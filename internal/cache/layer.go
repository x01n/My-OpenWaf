// Package cache provides in-process (L1) caching via ristretto.
// Optional Redis is constructed in internal/core/redis for distributed cache later.
package cache

import (
	"fmt"
	"sync/atomic"

	"github.com/dgraph-io/ristretto"

	"My-OpenWaf/internal/snapshot"
)

// Layer is a small process-local cache keyed by config revision (invalidates wholesale).
type Layer struct {
	rev   atomic.Uint64
	inner *ristretto.Cache
}

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

// SetSnapshot caches the immutable snapshot under current revision marker.
func (l *Layer) SetSnapshot(rev uint64, sn *snapshot.Snapshot) {
	l.rev.Store(rev)
	// Cost 1 — we store one blob per process; revision bump clears logically by key including rev.
	k := fmt.Sprintf("%s:%d", snapKey, rev)
	l.inner.Set(k, sn, 1)
	l.inner.Wait()
}

func (l *Layer) GetSnapshot(rev uint64) (*snapshot.Snapshot, bool) {
	k := fmt.Sprintf("%s:%d", snapKey, rev)
	v, ok := l.inner.Get(k)
	if !ok {
		return nil, false
	}
	sn, _ := v.(*snapshot.Snapshot)
	return sn, sn != nil
}

func (l *Layer) InvalidateAll() {
	l.inner.Clear()
}
