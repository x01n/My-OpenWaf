package dataplane

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
)

type closeNotifyHertzConn struct {
	*testHertzConn
	closeNotify chan bool
}

func (c *closeNotifyHertzConn) CloseNotify() <-chan bool {
	return c.closeNotify
}

func TestBindStreamCloseNotifyContextCancelsOnNestedCloseNotify(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	closeNotify := make(chan bool, 1)
	ctx := app.NewContext(0)
	ctx.SetConn(&loopbackHertzConn{
		Conn: &testHertzConn{Conn: &closeNotifyHertzConn{
			testHertzConn: &testHertzConn{Conn: server},
			closeNotify:   closeNotify,
		}},
	})

	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()

	derivedCtx, cancel := bindStreamCloseNotifyContext(baseCtx, ctx)
	defer cancel()

	select {
	case <-derivedCtx.Done():
		t.Fatal("derived context canceled before CloseNotify")
	default:
	}

	closeNotify <- true

	select {
	case <-derivedCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("derived context was not canceled after CloseNotify")
	}
}

func TestBindStreamCloseNotifyContextNoConnectionKeepsBaseContext(t *testing.T) {
	baseCtx := context.Background()
	derivedCtx, cancel := bindStreamCloseNotifyContext(baseCtx, app.NewContext(0))
	defer cancel()

	if derivedCtx != baseCtx {
		t.Fatal("context without CloseNotify should be returned unchanged")
	}
}

func TestStreamCloseNotifyChannelNilConnReturnsFalse(t *testing.T) {
	if _, ok := streamCloseNotifyChannel(nil); ok {
		t.Fatal("nil conn should return ok=false")
	}
}

func TestStreamCloseNotifyChannelInterfaceWrappingConn(t *testing.T) {
	closeNotify := make(chan bool, 1)
	conn := &closeNotifyHertzConn{
		testHertzConn: &testHertzConn{Conn: &net.TCPConn{}},
		closeNotify:   closeNotify,
	}
	ch, ok := streamCloseNotifyChannel(conn)
	if !ok || ch == nil {
		t.Fatal("interface-wrapped conn should surface CloseNotify")
	}
}

func TestBindStreamCloseNotifyContextBaseContextCancellationPropagates(t *testing.T) {
	closeNotify := make(chan bool, 1)
	ctx := app.NewContext(0)
	ctx.SetConn(&loopbackHertzConn{
		Conn: &testHertzConn{Conn: &closeNotifyHertzConn{
			testHertzConn: &testHertzConn{Conn: &net.TCPConn{}},
			closeNotify:   closeNotify,
		}},
	})

	baseCtx, cancelBase := context.WithCancel(context.Background())
	derivedCtx, cancel := bindStreamCloseNotifyContext(baseCtx, ctx)
	defer cancel()

	cancelBase()
	select {
	case <-derivedCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("derived context was not canceled after base context cancellation")
	}
}

func TestFindCloseNotifyChannelDetectsUnsafeAccessibleFields(t *testing.T) {
	type unsafeFieldHolder struct {
		conn *closeNotifyHertzConn
	}
	notifyCh := make(chan bool, 1)
	holder := &unsafeFieldHolder{conn: &closeNotifyHertzConn{
		testHertzConn: &testHertzConn{Conn: &net.TCPConn{}},
		closeNotify:   notifyCh,
	}}
	ch, ok := findCloseNotifyChannel(reflect.ValueOf(holder))
	if !ok || ch == nil {
		t.Fatal("expected channel via pointer field of unexported struct")
	}
	if ch != notifyCh {
		t.Fatal("unexpected channel returned for unexported-field holder")
	}
}

func TestFindCloseNotifyChannelSkipsStructsWithoutCloseNotify(t *testing.T) {
	type noCloseNotify struct {
		number int
		str    string
	}
	type withCloseNotify struct {
		inner noCloseNotify
		notif *benchH2CloseNotifier
	}
	notifyCh := make(chan bool, 1)
	v := reflect.ValueOf(&withCloseNotify{
		inner: noCloseNotify{number: 1, str: "x"},
		notif: &benchH2CloseNotifier{ch: notifyCh},
	})
	ch, ok := findCloseNotifyChannel(v)
	if !ok || ch != notifyCh {
		t.Fatal("expected channel via nested CloseNotify method scan")
	}

	v = reflect.ValueOf(&noCloseNotify{number: 1, str: "x"})
	if _, ok := findCloseNotifyChannel(v); ok {
		t.Fatal("struct without CloseNotify should not match")
	}

	type unimplementedConn struct {
		net.Conn
	}
	v = reflect.ValueOf(&unimplementedConn{Conn: nil})
	if _, ok := findCloseNotifyChannel(v); ok {
		t.Fatal("interface-embedded struct without close notify should not match")
	}
}

func TestCallCloseNotifyRejectsInvalidMethodPrototype(t *testing.T) {
	type noArgsTwoOuts struct{}
	noArgsTwoOutsType := reflect.TypeOf(&noArgsTwoOuts{})
	fn := reflect.MakeFunc(
		reflect.FuncOf(nil, []reflect.Type{recvOnlyBoolChanType, recvOnlyBoolChanType}, false),
		func([]reflect.Value) []reflect.Value { return nil },
	)
	if _, ok := callCloseNotify(fn); ok {
		t.Fatal("method with wrong arity should be rejected")
	}
	fn = reflect.MakeFunc(
		reflect.FuncOf([]reflect.Type{noArgsTwoOutsType}, []reflect.Type{recvOnlyBoolChanType}, false),
		func([]reflect.Value) []reflect.Value { return nil },
	)
	if _, ok := callCloseNotify(fn); ok {
		t.Fatal("method with receiver should be rejected")
	}
}

// TestCloseNotifyMethodIndexCacheConsistent 断言 method-index 缓存对
// 有/无 CloseNotify 的类型给出与原名探测一致的存在性结论。
func TestCloseNotifyMethodIndexCacheConsistent(t *testing.T) {
	type withoutCN struct {
		ch chan bool
	}
	_ = withoutCN{}

	// 有方法类型：typedInnerConn 的 CloseNotify 方法集含该方法，
	// 索引指向的方法名必须是 CloseNotify。
	withIdx := closeNotifyMethodIndexFor(reflect.TypeOf(&typedInnerConn{}))
	if withIdx < 0 {
		t.Fatal("type with CloseNotify should index non-negative")
	}
	if reflect.TypeOf(&typedInnerConn{}).Method(withIdx).Name != "CloseNotify" {
		t.Fatal("indexed method is not CloseNotify")
	}
	// 无方法类型：负结论入缓存。
	withoutIdx := closeNotifyMethodIndexFor(reflect.TypeOf(&withoutCN{}))
	if withoutIdx != -1 {
		t.Fatal("type without CloseNotify should index -1")
	}
}
