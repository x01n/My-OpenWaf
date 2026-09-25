package dataplane

import (
	"net"
	"reflect"
	"testing"
)

// benchH2Conn 模拟 x01n/http2（fork 的 hertz-contrib/http2）的 h2ServerConn 形态：
// {net.Conn 内嵌接口字段, rw *responseWriter}，CloseNotify 实现在 rw 上。
// 用于 BenchmarkStreamCloseNotifyH2 的可重复多流类型。
type benchH2Conn struct {
	net.Conn
	rw *benchH2CloseNotifier
}

type benchH2CloseNotifier struct {
	ch chan bool
}

func (b *benchH2CloseNotifier) CloseNotify() <-chan bool {
	if b == nil || b.ch == nil {
		return nil
	}
	return b.ch
}

// BenchmarkStreamCloseNotifyH2 度量伪 h2 连接（结构同真实 h2ServerConn：
// 内嵌 net.Conn 接口 + 含 CloseNotify 的 rw 指针字段）的每流 CloseNotify
// 探测成本。subscan 用 HEAD 原实现形态，subcached 用本变更后的缓存命中
// 路径（首个请求建缓存，之后全部命中）。两子项共享同一组连接实例，
// 保证对照口径一致。
func BenchmarkStreamCloseNotifyH2(b *testing.B) {
	conns := make([]*benchH2Conn, 0, 1024)
	for i := 0; i < 1024; i++ {
		conns = append(conns, &benchH2Conn{rw: &benchH2CloseNotifier{ch: make(chan bool, 1)}})
	}
	b.Run("scan", func(b *testing.B) {
		i := 0
		for n := 0; n < b.N; n++ {
			if !scanOnlyFind(reflect.ValueOf(conns[i%len(conns)])) {
				b.Fatal("bench conn should surface CloseNotify")
			}
			i++
		}
	})
	b.Run("cached", func(b *testing.B) {
		i := 0
		for n := 0; n < b.N; n++ {
			conn := conns[i%len(conns)]
			got, ok := findCloseNotifyChannel(reflect.ValueOf(conn))
			if !ok || got != conn.rw.ch {
				b.Fatal("bench conn should surface its own CloseNotify")
			}
			i++
		}
	})
}

// scanOnlyFind 是 HEAD 原实现 findCloseNotifyChannel 的等价形式（含
// Value.MethodByName 全程），拆出以避免与当前 findCloseNotifyChannel
// 共享缓存，保证 scan 子项测的是"无缓存全扫"而 cached 子项测的是
// "方法索引缓存命中"。
func scanOnlyFind(v reflect.Value) bool {
	if !v.IsValid() {
		return false
	}
	v = accessibleValue(v)
	if method := v.MethodByName("CloseNotify"); method.IsValid() {
		if _, ok := callCloseNotify(method); ok {
			return true
		}
	}
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return false
		}
		return scanOnlyFind(v.Elem())
	case reflect.Pointer:
		if v.IsNil() {
			return false
		}
		return scanOnlyFind(v.Elem())
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if scanOnlyFind(v.Field(i)) {
				return true
			}
		}
	}
	return false
}

// scanOnlyFindNoCall 与 scanOnlyFind 相同但命中后不调用方法，
// 用于拆解"结构扫描 + MethodByName"与 reflect.Call 各自的占比。
func scanOnlyFindNoCall(v reflect.Value) bool {
	if !v.IsValid() {
		return false
	}
	v = accessibleValue(v)
	if method := v.MethodByName("CloseNotify"); method.IsValid() {
		return true
	}
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return false
		}
		return scanOnlyFindNoCall(v.Elem())
	case reflect.Pointer:
		if v.IsNil() {
			return false
		}
		return scanOnlyFindNoCall(v.Elem())
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if scanOnlyFindNoCall(v.Field(i)) {
				return true
			}
		}
	}
	return false
}

// BenchmarkStreamCloseNotifyH2FindOnly 与 BenchmarkStreamCloseNotifyH2 对照，
// 剥离 reflect.Call 后单独度量结构扫描与 MethodByName 的成本。
func BenchmarkStreamCloseNotifyH2FindOnly(b *testing.B) {
	conns := make([]*benchH2Conn, 0, 1024)
	for i := 0; i < 1024; i++ {
		conns = append(conns, &benchH2Conn{rw: &benchH2CloseNotifier{ch: make(chan bool, 1)}})
	}
	b.Run("scan-find-only", func(b *testing.B) {
		i := 0
		for n := 0; n < b.N; n++ {
			if !scanOnlyFindNoCall(reflect.ValueOf(conns[i%len(conns)])) {
				b.Fatal("bench conn should surface CloseNotify")
			}
			i++
		}
	})
}

// TestFindCloseNotifyChannelCachedHitMatchesDeepScan 缓存命中路径与完整
// 扫描路径对同一连接返回同一个通道，且不同实例结果彼此独立。
func TestFindCloseNotifyChannelCachedHitMatchesDeepScan(t *testing.T) {
	first := &benchH2Conn{rw: &benchH2CloseNotifier{ch: make(chan bool, 1)}}
	second := &benchH2Conn{rw: &benchH2CloseNotifier{ch: make(chan bool, 1)}}

	ch1, ok1 := findCloseNotifyChannel(reflect.ValueOf(first))
	if !ok1 || ch1 == nil {
		t.Fatal("first call failed to locate CloseNotify")
	}
	ch2, ok2 := findCloseNotifyChannel(reflect.ValueOf(second))
	if !ok2 || ch2 == nil {
		t.Fatal("second call (warm cache) failed to locate CloseNotify")
	}
	if ch1 == ch2 {
		t.Fatal("different conn instances must yield different close-notify channels")
	}
	if ch1 != first.rw.ch || ch2 != second.rw.ch {
		t.Fatal("returned channels are not the conns' own channels")
	}

	// 负例：命中的 CloseNotify 持有者为 nil 指针时，两种路径结果一致。
	chNil, okNil := scanOnlyFindChan(reflect.ValueOf(&benchH2Conn{rw: nil}))
	_, okCached := findCloseNotifyChannel(reflect.ValueOf(&benchH2Conn{rw: nil}))
	if okNil || okCached || chNil != nil {
		t.Fatalf("nil-rw divergence deep=%v/%v cached=%v", chNil, okNil, okCached)
	}
}

// scanOnlyFindChan 是 scanOnlyFind 的通道返回版，用于负例比对。
func scanOnlyFindChan(v reflect.Value) (<-chan bool, bool) {
	if !v.IsValid() {
		return nil, false
	}
	v = accessibleValue(v)
	if method := v.MethodByName("CloseNotify"); method.IsValid() {
		if ch, ok := callCloseNotify(method); ok {
			return ch, true
		}
	}
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return nil, false
		}
		return scanOnlyFindChan(v.Elem())
	case reflect.Pointer:
		if v.IsNil() {
			return nil, false
		}
		return scanOnlyFindChan(v.Elem())
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if ch, ok := scanOnlyFindChan(v.Field(i)); ok {
				return ch, true
			}
		}
	}
	return nil, false
}

// typedInnerConn / typedOuterConn 供方法索引缓存命中较深层 conn 场景
// 使用：外层类型无 CloseNotify 方法，内层字段类型有。
type typedInnerConn struct {
	ch chan bool
}

func (i *typedInnerConn) CloseNotify() <-chan bool {
	return i.ch
}

type typedOuterConn struct {
	net.Conn
	inner *typedInnerConn
}

// TestMethodIndexPathHiddenDeeperNode 覆盖"方法索引缓存快路径命中更深
// 层的 conn"场景：外层类型无方法，内层字段类型有方法。
func TestMethodIndexPathHiddenDeeperNode(t *testing.T) {
	ch := make(chan bool, 1)
	got, ok := findCloseNotifyChannel(reflect.ValueOf(&typedOuterConn{inner: &typedInnerConn{ch: ch}}))
	if !ok || got != ch {
		t.Fatal("deep field scan should return inner channel via cached method lookup")
	}
}
