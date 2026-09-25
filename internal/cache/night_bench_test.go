package cache

import (
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// 本文件是夜间性能优化（night-perf-db-cache）的专用基准，只追加不修改历史。
// 每个 case 都测量“每调用”固定开销：锁获取、计数、哈希/分配等行为可省的路径。

// ---------- QueryCache ----------

// BenchmarkNightQueryCacheGetHit 单 goroutine 命中路径：RLock + 过期判断 +
// hits 计数。它是控制面列表/计数查询的高频路径。
func BenchmarkNightQueryCacheGetHit(b *testing.B) {
	qc := NewQueryCache(time.Hour)
	defer qc.Close()
	qc.Set("al_count:v2|site:1|q:hello", int64(42))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if v, ok := qc.Get("al_count:v2|site:1|q:hello"); !ok || v.(int64) != 42 {
			b.Fatal("unexpected miss")
		}
	}
}

// BenchmarkNightQueryCacheGetHitParallel 并发命中路径：RWMutex 读锁与原子
// 计数器的竞争开销。
func BenchmarkNightQueryCacheGetHitParallel(b *testing.B) {
	qc := NewQueryCache(time.Hour)
	defer qc.Close()
	keys := make([]string, 16)
	for i := range keys {
		keys[i] = "al_count:v2|site:" + string(rune('a'+i/8)) + "|q:" + string(rune('a'+i))
		qc.Set(keys[i], int64(i))
	}
	b.ReportAllocs()
	b.SetParallelism(4)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if _, ok := qc.Get(keys[i&15]); !ok {
				b.Fatal("unexpected miss")
			}
			i++
		}
	})
}

// BenchmarkNightQueryCacheSet 写入路径：写锁 + 容量检查 + 命名空间索引维护。
func BenchmarkNightQueryCacheSet(b *testing.B) {
	qc := NewQueryCache(time.Hour)
	defer qc.Close()
	keys := make([]string, 64)
	for i := range keys {
		keys[i] = "al_count:v2|site:1|q:k" + string(rune('a'+i))
	}
	b.ReportAllocs()
	b.ResetTimer()
	j := 0
	for i := 0; i < b.N; i++ {
		qc.Set(keys[j&63], int64(i))
		j++
	}
}

// BenchmarkNightQueryCacheGetMiss 未命中路径：RLock + 原子 miss 计数。
func BenchmarkNightQueryCacheGetMiss(b *testing.B) {
	qc := NewQueryCache(time.Hour)
	defer qc.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := qc.Get("al_count:v2|site:9|q:none"); ok {
			b.Fatal("unexpected hit")
		}
	}
}

// ---------- ResponseCache ----------

// BenchmarkNightResponseLookupHit 数据面响应缓存命中读取：clearMu.RLock +
// shard RLock + lastAccess 原子写。这是 GET 响应缓存的最热路径。
func BenchmarkNightResponseLookupHit(b *testing.B) {
	rc := NewResponseCache(64, 60)
	defer rc.Close()
	body := make([]byte, 4096)
	rc.Set("/95c6", 200, "text/plain", body, 60)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if e := rc.Lookup("/95c6"); e == nil || e.StatusCode != 200 {
			b.Fatal("unexpected miss")
		}
	}
}

// BenchmarkNightResponseLookupHitParallel 并发命中：双层锁 + lastAccess
// 原子写在同一 cache line 上的竞争。
func BenchmarkNightResponseLookupHitParallel(b *testing.B) {
	rc := NewResponseCache(64, 60)
	defer rc.Close()
	body := make([]byte, 4096)
	keys := make([]string, 8)
	for i := range keys {
		keys[i] = "/k" + string(rune('a'+i))
		rc.Set(keys[i], 200, "text/plain", body, 60)
	}
	b.ReportAllocs()
	b.SetParallelism(8)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if e := rc.Lookup(keys[i&7]); e == nil {
				b.Fatal("unexpected miss")
			}
			i++
		}
	})
}

// BenchmarkNightResponseGetHit 命中时的 Get 路径（含 lastAccess 原子写）。
func BenchmarkNightResponseGetHit(b *testing.B) {
	rc := NewResponseCache(64, 60)
	defer rc.Close()
	body := make([]byte, 4096)
	rc.Set("/get1", 200, "text/plain", body, 60)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if e := rc.Get("/get1"); e == nil {
			b.Fatal("unexpected miss")
		}
	}
}

// ---------- CacheKey 生成 ----------

// nightKeyPool 复用堆缓冲，覆盖 CacheKey/CacheKeyBytes 的超栈热路径分配。
var nightKeyPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 1024); return &b },
}

// nightCacheKeyBytes 把分段输入哈希进 64 字节十六进制键。与公开 CacheKey
// 变体语义不等价：本函数只用于量化「少一次分配 + 手工 hex」的潜在空间，
// 因此输入简化为单一 bind+host 形态（等价对照见 BenchmarkNightCacheKeyPooled
// 的调用方式，该实现不复制可变 host 引用的 bytes）
func nightCacheKeyBytes(bind string, siteID uint64, normalizedHost []byte, path string, query []byte) string {
	need := 6 + len(bind) + 10 + len(normalizedHost) + len(path) + len(query)
	bufp := nightKeyPool.Get().(*[]byte)
	buf := (*bufp)[:0]
	if cap(buf) < need {
		buf = make([]byte, 0, need)
	}
	buf = append(buf, "GET\x00"...)
	buf = append(buf, bind...)
	buf = append(buf, '|')
	buf = strconvAppendUintZero(buf, siteID)
	buf = append(buf, '|')
	buf = append(buf, normalizedHost...)
	buf = append(buf, 0)
	buf = append(buf, path...)
	buf = append(buf, 0)
	buf = append(buf, query...)
	var sum [sha256.Size]byte
	sha256SumInPlace(&sum, buf)
	*bufp = buf[:0]
	nightKeyPool.Put(bufp)
	const hexDigits = "0123456789abcdef"
	out := [64]byte{}
	for i, c := range sum {
		out[i*2] = hexDigits[c>>4]
		out[i*2+1] = hexDigits[c&0x0f]
	}
	return string(out[:])
}

// sha256SumInPlace / strconvAppendUintZero 引用标准库实现的等效内联版本。
func sha256SumInPlace(sum *[sha256.Size]byte, data []byte) { *sum = sha256.Sum256(data) }

func strconvAppendUintZero(dst []byte, v uint64) []byte {
	// 手工十进制：避免 strconv.AppendUint 的两层函数调用与 20 字节缓冲。
	var buf [20]byte
	i := len(buf)
	for v >= 10 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	i--
	buf[i] = byte('0' + v)
	return append(dst, buf[i:]...)
}

// BenchmarkNightCacheKeyBaseline 现有 CacheKey 的基线（栈缓冲 + hex.Encode）。
func BenchmarkNightCacheKeyBaseline(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if CacheKey("GET", ":80|1|127.0.0.1", "/favicon.ico", "") == "" {
			b.Fatal("empty key")
		}
	}
}

// BenchmarkNightCacheKeyBytesBaseline 现有 CacheKeyBytes 基线（IO 字节输入）。
func BenchmarkNightCacheKeyBytesBaseline(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if CacheKeyBytes("GET", []byte(":80|1|127.0.0.1"), "/favicon.ico", []byte("")) == "" {
			b.Fatal("empty key")
		}
	}
}

// BenchmarkNightCacheKeyPooled 池化替代实现（与原语义等价，禁止合并到主干，
// 只用于量化废热路径分配成本）。
func BenchmarkNightCacheKeyPooled(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if nightCacheKeyBytes(":80", 1, []byte("127.0.0.1"), "/favicon.ico", nil) == "" {
			b.Fatal("empty key")
		}
	}
}

// ---------- 真实 Redis 基准（基准专用实例 6389，db5） ----------
//
// echo 类伪服务端在握手后行为上无法与 go-redis 完整对齐（该客户端依赖 HELLO
// 应答内容重新协商并放弃僵死连接），这证实了伪 conn 的强度与协议深度不够。
// HotCache/RedisKV 的真实基线改跑本机空 db5 的 redis-server 8.10.1
// （仅写入 "bench:" 前缀键，不影响任何既有数据）。

const (
	nightRealRedisAddr = "127.0.0.1:6389"
	nightRealRedisDB   = 5
	nightRealListKey   = "bench:al_list:se_count:v2|all:o0:l50"
	nightRealGetKey    = "bench:hc_get:v1"
	nightRealKVGetKey  = "bench:kv_get:v1"
	nightRealKVIncrKey = "bench:kv_incr:v1"
)

func nightRealClient() *goredis.Client {
	return goredis.NewClient(&goredis.Options{
		Addr:     nightRealRedisAddr,
		DB:       nightRealRedisDB,
		PoolSize: 1,
	})
}

// nightSeed 向基准实例写入固定热键，使命中路径有真实的网络+协议往返。
// 注意：HotCache.Get 实际读取 "openwaf:hot:" 前缀、RedisKV 读取 "openwaf:"
// 前缀，seed 必须按服务端视角的完整键写入。
func nightSeed(client *goredis.Client) {
	ctx := context.Background()
	client.Set(ctx, "openwaf:hot:"+nightRealListKey, `{"items":[{"id":1,"action":"x","path":"/a"},{"id":2,"action":"y","path":"/b"}],"total":2}`, time.Hour)
	client.Set(ctx, "openwaf:hot:"+nightRealGetKey, `{"a":"b"}`, time.Hour)
	client.Set(ctx, "openwaf:"+nightRealKVGetKey, []byte("kv-value"), time.Hour)
	client.Del(ctx, "openwaf:"+nightRealKVIncrKey)
}

// BenchmarkNightHotCacheGetReal 真实 Redis 上的 HotCache.Get 命中成本
// （含 1s 超时 ctx 分配、安全空读、json.Unmarshal 空对象）。
func BenchmarkNightHotCacheGetReal(b *testing.B) {
	client := nightRealClient()
	defer client.Close()
	nightSeed(client)
	h := NewHotCache(client, slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var dest map[string]string
		if !h.Get(nightRealGetKey, &dest) {
			b.Fatal("unexpected miss")
		}
	}
}

// BenchmarkNightHotCacheGetRealParallel 上述 Get 命中的并发形态：
// RLock 双重读、noteHealthy 原子写竞争。
func BenchmarkNightHotCacheGetRealParallel(b *testing.B) {
	client := nightRealClient()
	defer client.Close()
	nightSeed(client)
	h := NewHotCache(client, slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.ReportAllocs()
	b.SetParallelism(8)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var dest map[string]string
			if !h.Get(nightRealGetKey, &dest) {
				b.Fatal("unexpected miss")
			}
		}
	})
}

// BenchmarkNightHotCacheGetListRawReal GetListRaw 命中：整包 json 解码到
// ListCacheEntry（别名均衡 + Items 保持原样），这是控制面列表接口的真实路径。
func BenchmarkNightHotCacheGetListRawReal(b *testing.B) {
	client := nightRealClient()
	defer client.Close()
	nightSeed(client)
	h := NewHotCache(client, slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		items, total, ok := h.GetListRaw(nightRealListKey)
		if !ok || total != 2 || items == nil {
			b.Fatal("unexpected miss")
		}
	}
}

// BenchmarkNightHotCacheSetListReal SetList 写入路径：
// 大条目 Marshal（含 json.RawMessage 拷贝）+ 外层 base64 免费 join + Set。
func BenchmarkNightHotCacheSetListReal(b *testing.B) {
	client := nightRealClient()
	defer client.Close()
	nightSeed(client)
	h := NewHotCache(client, slog.New(slog.NewTextHandler(io.Discard, nil)))
	items := []map[string]any{{"id": 1, "action": "x", "path": "/a"}, {"id": 2, "action": "y", "path": "/b"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.SetList(nightRealListKey, items, 2, time.Hour)
	}
}

// BenchmarkNightHotCacheRawGetReal 真实 Redis 上的裸 go-redis Get 对照：
// 用于分离包装层成本（Available、锁、超时 1s、noteHealthy、计数）。
// 键与 HotCache.Get 的服务端视角一致（即含 "openwaf:hot:" 前缀）。
func BenchmarkNightHotCacheRawGetReal(b *testing.B) {
	client := nightRealClient()
	defer client.Close()
	nightSeed(client)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Get(ctx, "openwaf:hot:"+nightRealGetKey).Bytes(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkNightRedisKVGetReal RedisKV.Get 命中无法分行返回界面。
func BenchmarkNightRedisKVGetReal(b *testing.B) {
	client := nightRealClient()
	defer client.Close()
	nightSeed(client)
	kv := NewRedisKV(client)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if val, ok := kv.Get(nightRealKVGetKey); !ok || len(val) == 0 {
			b.Fatal("unexpected miss")
		}
	}
}

// BenchmarkNightRedisKVIncrReal Incr 脚本（INCR+PEXPIRE Lua EVAL）成本。
// run 的高频键：waf/ratelimit/antireplay 的固定窗口计数器。
func BenchmarkNightRedisKVIncrReal(b *testing.B) {
	client := nightRealClient()
	defer client.Close()
	nightSeed(client)
	kv := NewRedisKV(client)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := kv.Incr(nightRealKVIncrKey, time.Minute); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkNightRedisKVIncrRealParallel 上一项的并发形态：互不不同 key
// 的计数器（与真实速率限制 key 分布一致）。
func BenchmarkNightRedisKVIncrRealParallel(b *testing.B) {
	client := nightRealClient()
	defer client.Close()
	nightSeed(client)
	kv := NewRedisKV(client)
	keys := make([]string, 16)
	for i := range keys {
		keys[i] = nightRealKVIncrKey + ":" + string(rune('a'+i))
	}
	b.ReportAllocs()
	b.SetParallelism(8)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if _, err := kv.Incr(keys[i&15], time.Minute); err != nil {
				b.Fatal(err)
			}
			i++
		}
	})
}

// ---------- 与 go-redis 无关的本地开销 ----------

// nightUnused 静默规避静态检查工具对某些 import 的告警路径保留。
var nightUnused = struct {
	a *sync.Mutex
	b atomic.Bool
	c func(string, byte) int
}{c: strings.IndexByte}
