// Package cache 提供进程内的配置快照缓存。
//
// 设计：
//   - 快照缓存：纯进程内实现（ristretto）。Snapshot 结构体是通过
//     atomic.Pointer 持有的内存对象，把它序列化到 Redis 纯属浪费。
//   - 分布式 KV 缓存：跨节点共享状态（限流计数器、API 响应缓存等）
//     见 RedisKV。
package cache

import (
	"fmt"

	"github.com/dgraph-io/ristretto"

	"My-OpenWaf/internal/snapshot"
)

/**
 * Layer 是以 ristretto 为底层的进程内快照缓存。
 *
 * 每个 WAF 节点各持一份副本；跨节点同步走 Redis pub/sub（config_sync）
 * 触发数据库重载，而不是共享缓存中的快照。
 */
type Layer struct {
	inner *ristretto.Cache
}

// NewLayer 创建本地快照缓存。
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

// SetSnapshot 按给定版本号缓存不可变快照。
func (l *Layer) SetSnapshot(rev uint64, sn *snapshot.Snapshot) {
	if sn == nil || sn.Revision != rev {
		return
	}
	k := fmt.Sprintf("%s:%d", snapKey, rev)
	l.inner.Set(k, sn, 1)
	l.inner.Wait()
}

// GetSnapshot 按版本号取出缓存的快照；未命中返回 nil。
func (l *Layer) GetSnapshot(rev uint64) (*snapshot.Snapshot, bool) {
	k := fmt.Sprintf("%s:%d", snapKey, rev)
	v, ok := l.inner.Get(k)
	if !ok {
		return nil, false
	}
	sn, _ := v.(*snapshot.Snapshot)
	return sn, sn != nil
}

// InvalidateAll 清空整个本地缓存。
func (l *Layer) InvalidateAll() {
	if l == nil || l.inner == nil {
		return
	}
	l.inner.Clear()
}
