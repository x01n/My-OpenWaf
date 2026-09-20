package bot

import (
	"net"
	"testing"

	"My-OpenWaf/internal/core"
)

func TestToUintSetEmpty(t *testing.T) {
	m := toUintSet(nil)
	if len(m) != 0 {
		t.Errorf("toUintSet(nil) len = %d, want 0", len(m))
	}
}

func TestToUintSetValues(t *testing.T) {
	m := toUintSet([]uint{1, 2, 3, 2})
	if len(m) != 3 {
		t.Errorf("toUintSet len = %d, want 3", len(m))
	}
	for _, v := range []uint{1, 2, 3} {
		if _, ok := m[v]; !ok {
			t.Errorf("toUintSet missing key %d", v)
		}
	}
}

func TestToStringSetEmpty(t *testing.T) {
	m := toStringSet(nil)
	if len(m) != 0 {
		t.Errorf("toStringSet(nil) len = %d, want 0", len(m))
	}
}

func TestToStringSetValues(t *testing.T) {
	m := toStringSet([]string{"CN", "RU", "CN"})
	if len(m) != 2 {
		t.Errorf("toStringSet len = %d, want 2", len(m))
	}
	for _, v := range []string{"CN", "RU"} {
		if _, ok := m[v]; !ok {
			t.Errorf("toStringSet missing key %q", v)
		}
	}
}

func TestLookupGeoReturnsEmptyInfoWhenNoDB(t *testing.T) {
	ip := net.ParseIP("8.8.8.8")
	info := LookupGeo(ip)
	if info.Country != "" || info.City != "" || info.ASN != 0 {
		t.Errorf("LookupGeo with no DB should return empty GeoInfo, got %+v", info)
	}
}

func TestLookupGeoNilIPNocrash(t *testing.T) {
	// 不应 panic
	_ = LookupGeo(nil)
}

// TestMaxMindResolverScoreIPNilReturnsZero 验证 nil IP 不 panic 且返回 0。
func TestMaxMindResolverScoreIPNilReturnsZero(t *testing.T) {
	r := NewMaxMindResolver("", "", core.BotConfig{})
	if score := r.ScoreIP(nil); score != 0 {
		t.Errorf("ScoreIP(nil) = %d, want 0", score)
	}
}

// TestMaxMindResolverScoreIPNoDBReturnsZero 验证无数据库时评分为 0。
func TestMaxMindResolverScoreIPNoDBReturnsZero(t *testing.T) {
	r := NewMaxMindResolver("", "", core.BotConfig{})
	ip := net.ParseIP("8.8.8.8")
	if score := r.ScoreIP(ip); score != 0 {
		t.Errorf("ScoreIP with no DB = %d, want 0", score)
	}
}

// TestSetGeoResolverAndLookup 验证 SetGeoResolver 后 LookupGeo 使用新 resolver。
func TestSetGeoResolverAndLookup(t *testing.T) {
	type customResolver struct{ GeoResolver }
	custom := &customResolver{}
	// 先保存原始 resolver，测试结束后恢复
	orig := globalGeo.Load()
	t.Cleanup(func() { globalGeo.Store(orig) })

	var called bool
	customImpl := &funcResolver{fn: func(ip net.IP) GeoInfo {
		called = true
		return GeoInfo{Country: "JP"}
	}}
	var r GeoResolver = customImpl
	globalGeo.Store(&r)

	info := LookupGeo(net.ParseIP("1.2.3.4"))
	if !called {
		t.Error("custom resolver not called")
	}
	if info.Country != "JP" {
		t.Errorf("LookupGeo country = %q, want JP", info.Country)
	}
	_ = custom
}

type funcResolver struct {
	fn func(net.IP) GeoInfo
}

func (f *funcResolver) Lookup(ip net.IP) GeoInfo { return f.fn(ip) }
