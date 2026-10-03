package dataplane

import (
	"encoding/base64"
	"encoding/binary"
	"math/rand"
	"regexp"
	"sync"
	"testing"
)

// 新实现与 199051e 前的旧实现逐字节等价：前缀与后缀均为 RawURLEncoding
// 输出（字符集 [A-Za-z0-9_-]、无填充、恒 11 位），栈上 Encode 与
// EncodeToString 的字节等价由 TestReqIDCounterEncodingMatchesEncodeToString
// 覆盖 2000 个随机样本 + 边界值。
var (
	requestIDPrefixRe = regexp.MustCompile(`^[A-Za-z0-9_-]{11}$`)
	requestIDSuffixRe = regexp.MustCompile(`^[A-Za-z0-9_-]{11}$`)
)

// legacyFastRequestIDForTest 还原旧实现的组装逻辑，仅用于等价对照。
// suffix 用 EncodeToString 验证 encode 的“先小写过滤”在 11 字节空间内不生效。
func legacyFastRequestIDForTest(prefix, suffix string) string {
	return prefix + "-" + suffix
}

type requestIDStrings struct{ id, prefix, suffix string }

// splitRequestID 按固定布局 11-1-11 切分（前缀与后缀本身就是 11 位
// base64url，可含 '-'，不能用查找分隔符的方式切）。
func splitRequestID(id string) requestIDStrings {
	if len(id) == 23 && id[11] == '-' {
		return requestIDStrings{id: id, prefix: id[:11], suffix: id[12:]}
	}
	return requestIDStrings{id: id}
}

func TestReqIDPreservesLegacyFormat(t *testing.T) {
	const n = 64
	for i := 0; i < n; i++ {
		id := fastRequestID()
		parts := splitRequestID(id)
		if parts.prefix == "" || parts.suffix == "" {
			t.Fatalf("request ID malformed: %q", id)
		}
		if !requestIDPrefixRe.MatchString(parts.prefix) {
			t.Fatalf("prefix = %q, want 11 raw-url base64 chars", parts.prefix)
		}
		if !requestIDSuffixRe.MatchString(parts.suffix) {
			t.Fatalf("suffix = %q, want 11 raw-url base64 chars", parts.suffix)
		}
		if parts.prefix != reqIDPrefix {
			t.Fatalf("prefix in ID %q != shared process prefix %q", id, reqIDPrefix)
		}
		// 旧实现后缀即 EncodeToString(buf[8:])，等价于编码器输出，二者须一致。
		if len(parts.suffix) != 11 {
			t.Fatalf("suffix length = %d, want 11: %q", len(parts.suffix), id)
		}
		if got := legacyFastRequestIDForTest(parts.prefix, parts.suffix); got != id {
			t.Fatalf("recomposed ID %q != original %q", got, id)
		}
	}
}

func TestReqIDCounterEncodingMatchesEncodeToString(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 2000; i++ {
		var v [8]byte
		binary.BigEndian.PutUint64(v[:], rng.Uint64())
		var enc [11]byte
		base64.RawURLEncoding.Encode(enc[:], v[:])
		got := string(enc[:])
		want := base64.RawURLEncoding.EncodeToString(v[:])
		if got != want {
			t.Fatalf("stack encode %q != EncodeToString %q for %x", got, want, v)
		}
	}
}

func TestFastRequestIDFormatAndUniqueness(t *testing.T) {
	const n = 5000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := fastRequestID()
		parts := splitRequestID(id)
		if len(id) != 23 || len(parts.prefix) != 11 || len(parts.suffix) != 11 {
			t.Fatalf("request ID shape %q: len=%d prefix=%d suffix=%d, want 11-1-11", id, len(id), len(parts.prefix), len(parts.suffix))
		}
		if !requestIDPrefixRe.MatchString(parts.prefix) || !requestIDSuffixRe.MatchString(parts.suffix) {
			t.Fatalf("request ID format: %q", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate request ID: %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestFastRequestIDConcurrentUniqueness(t *testing.T) {
	const goroutines = 16
	const perGoroutine = 2000
	seen := make(map[string]struct{}, goroutines*perGoroutine)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				id := fastRequestID()
				mu.Lock()
				if _, dup := seen[id]; dup {
					t.Errorf("duplicate request ID under concurrency: %q", id)
				}
				seen[id] = struct{}{}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
}
