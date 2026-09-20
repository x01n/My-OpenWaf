package dynamic

import (
	"bytes"
	"sync"
	"testing"
)

// resetKeyCache 清空缓存，避免用例间相互影响。
func resetKeyCache() {
	keyCacheMu.Lock()
	keyCache = make(map[keyCacheKey]derivedKeys, 16)
	keyCacheMu.Unlock()
}

func keyCacheLen() int {
	keyCacheMu.RLock()
	defer keyCacheMu.RUnlock()
	return len(keyCache)
}

// TestNewProcessorReusesDerivedKeys 验证相同配置复用同一组密钥。
func TestNewProcessorReusesDerivedKeys(t *testing.T) {
	resetKeyCache()
	cfg := ProtectionConfig{SiteID: 7, HTMLObfuscationEnabled: true}

	p1 := NewProcessor(cfg)
	p2 := NewProcessor(cfg)

	if !bytes.Equal(p1.cek, p2.cek) || !bytes.Equal(p1.kek, p2.kek) {
		t.Fatal("相同配置必须派生出相同密钥")
	}
	if keyCacheLen() != 1 {
		t.Fatalf("缓存条目数 = %d, want 1", keyCacheLen())
	}
}

// TestDerivedKeysIsolatedPerSite 是核心正确性回归：
// 缓存不得让不同站点共用密钥，否则站点间的加密隔离被打破。
func TestDerivedKeysIsolatedPerSite(t *testing.T) {
	resetKeyCache()
	a := NewProcessor(ProtectionConfig{SiteID: 1, HTMLObfuscationEnabled: true})
	b := NewProcessor(ProtectionConfig{SiteID: 2, HTMLObfuscationEnabled: true})

	if bytes.Equal(a.cek, b.cek) {
		t.Fatal("不同站点的 CEK 不得相同")
	}
	if bytes.Equal(a.kek, b.kek) {
		t.Fatal("不同站点的 KEK 不得相同")
	}
	if keyCacheLen() != 2 {
		t.Fatalf("缓存条目数 = %d, want 2", keyCacheLen())
	}
}

// TestDerivedKeysCEKAndKEKDiffer 验证同一站点的 CEK 与 KEK 相互独立。
func TestDerivedKeysCEKAndKEKDiffer(t *testing.T) {
	resetKeyCache()
	p := NewProcessor(ProtectionConfig{SiteID: 3, HTMLObfuscationEnabled: true})
	if bytes.Equal(p.cek, p.kek) {
		t.Fatal("CEK 与 KEK 不得相同")
	}
	if len(p.cek) != 32 || len(p.kek) != 32 {
		t.Fatalf("密钥长度 = %d/%d, want 32/32", len(p.cek), len(p.kek))
	}
}

// TestDerivedKeysVaryWithKeyBase 验证不同的 EncryptionKeyBase 产出不同密钥，
// 且缓存按 base 区分而非误判为同一条目。
func TestDerivedKeysVaryWithKeyBase(t *testing.T) {
	resetKeyCache()
	base1 := bytes.Repeat([]byte{0xA1}, 32)
	base2 := bytes.Repeat([]byte{0xB2}, 32)

	p1 := NewProcessor(ProtectionConfig{SiteID: 9, EncryptionKeyBase: base1})
	p2 := NewProcessor(ProtectionConfig{SiteID: 9, EncryptionKeyBase: base2})

	if bytes.Equal(p1.cek, p2.cek) {
		t.Fatal("不同 EncryptionKeyBase 必须派生出不同密钥")
	}
	if keyCacheLen() != 2 {
		t.Fatalf("缓存条目数 = %d, want 2", keyCacheLen())
	}
}

// TestDerivedKeysIgnoreFeatureToggles 验证密钥只由基础密钥和站点隔离，
// 开关变化不会造成无意义的密钥轮换。
func TestDerivedKeysIgnoreFeatureToggles(t *testing.T) {
	resetKeyCache()
	base := bytes.Repeat([]byte{0x5C}, 32)
	htmlOnly := NewProcessor(ProtectionConfig{SiteID: 5, HTMLObfuscationEnabled: true, EncryptionKeyBase: base})
	both := NewProcessor(ProtectionConfig{SiteID: 5, HTMLObfuscationEnabled: true, JSObfuscationEnabled: true, EncryptionKeyBase: base})

	if !bytes.Equal(htmlOnly.cek, both.cek) || !bytes.Equal(htmlOnly.kek, both.kek) {
		t.Fatal("相同基础密钥和站点必须派生出相同密钥")
	}
	if keyCacheLen() != 1 {
		t.Fatalf("缓存条目数 = %d, want 1", keyCacheLen())
	}
}

// TestKeyCacheEvictsAtLimit 验证超过上限后缓存被清空重建而非无界增长。
func TestKeyCacheEvictsAtLimit(t *testing.T) {
	resetKeyCache()
	for i := 0; i < keyCacheMaxEntries+5; i++ {
		NewProcessor(ProtectionConfig{SiteID: uint(i), HTMLObfuscationEnabled: true})
	}
	if n := keyCacheLen(); n > keyCacheMaxEntries {
		t.Fatalf("缓存条目数 = %d, 不得超过上限 %d", n, keyCacheMaxEntries)
	}
}

// TestNewProcessorConcurrent 验证并发构造下缓存无数据竞争，
// 且同一配置始终得到一致的密钥。配合 -race 运行。
func TestNewProcessorConcurrent(t *testing.T) {
	resetKeyCache()
	cfg := ProtectionConfig{SiteID: 11, HTMLObfuscationEnabled: true, JSObfuscationEnabled: true}
	want := NewProcessor(cfg)

	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				p := NewProcessor(cfg)
				if !bytes.Equal(p.cek, want.cek) || !bytes.Equal(p.kek, want.kek) {
					t.Error("并发构造得到了不一致的密钥")
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestProcessHTMLStillEncryptsAfterCaching 端到端确认引入缓存后加密仍然可用，
// 且同一站点两次加密因随机 IV 而输出不同（未退化为确定性加密）。
func TestProcessHTMLStillEncryptsAfterCaching(t *testing.T) {
	resetKeyCache()
	cfg := ProtectionConfig{SiteID: 21, HTMLObfuscationEnabled: true}
	plain := []byte("<html><body>hello</body></html>")

	out1, err := NewProcessor(cfg).ProcessHTML(plain)
	if err != nil {
		t.Fatalf("ProcessHTML: %v", err)
	}
	out2, err := NewProcessor(cfg).ProcessHTML(plain)
	if err != nil {
		t.Fatalf("ProcessHTML: %v", err)
	}

	if bytes.Contains(out1, []byte("hello")) {
		t.Fatal("输出中不应残留明文")
	}
	if bytes.Equal(out1, out2) {
		t.Fatal("随机 IV 应使两次加密输出不同")
	}
}
