package dataplane

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	forkhttp2 "github.com/x01n/http2"
)

/**
 * TestH2StreamResetterSignatureMatchesForkErrCode 是接口签名锁。
 *
 * Go 的方法签名 identity 规则要求参数类型完全相同：dataplane 本地定义的
 * 命名类型 uint32 与 fork 的 http2.ErrCode 是**两个不同类型**，underlying
 * 相同并不满足。r7.44 曾以本地 http2ErrCode 声明本接口，导致 fork 升到
 * v0.3.0 后断言仍恒 false（实测：fork 签名实现不满足本地签名接口）。
 * 此锁用 fork 自己的命名类型做属性断言，防止缺陷复发。
 */
func TestH2StreamResetterSignatureMatchesForkErrCode(t *testing.T) {
	method, ok := reflect.TypeOf((*h2StreamResetter)(nil)).Elem().MethodByName("ResetStreamHandler")
	if !ok {
		t.Fatal("h2StreamResetter 必须声明 ResetStreamHandler")
	}
	mt := method.Type
	// reflect 的接口方法 Type 不含 receiver：In(0) 即 code 参数。
	if mt.NumIn() != 1 || mt.NumOut() != 1 {
		t.Fatalf("ResetStreamHandler 形状 = %v, want (code) -> bool", mt)
	}
	if got, want := mt.In(0), reflect.TypeOf(forkhttp2.ErrCodeCancel); got != want {
		t.Fatalf("ResetStreamHandler 参数类型 = %v, want %v（必须用 fork 命名类型）", got, want)
	}
	if mt.Out(0).Kind() != reflect.Bool {
		t.Fatalf("ResetStreamHandler 返回类型 = %v, want bool", mt.Out(0))
	}
	if got, want := reflect.TypeOf(h2ErrCodeCancel), reflect.TypeOf(forkhttp2.ErrCodeCancel); got != want {
		t.Fatalf("h2ErrCodeCancel 类型 = %v, want %v", got, want)
	}
}

// h2ResetProbeConn 实现匿名的 h2StreamResetter 接口。
type h2ResetProbeConn struct {
	code   forkhttp2.ErrCode
	called bool
}

func (c *h2ResetProbeConn) ResetStreamHandler(code forkhttp2.ErrCode) bool {
	c.called = true
	c.code = code
	return true
}

/**
 * h2ResetRefuseConn 的 ResetStreamHandler 返回 false，
 * 用于覆盖 drop 路径的兜底顺序（502 在链路中更靠后）。
 */
type h2ResetRefuseConn struct{}

func (c *h2ResetRefuseConn) ResetStreamHandler(code forkhttp2.ErrCode) bool { return false }

/**
 * TestMaybeH2ResetStreamAssertion 验证协议裁决就是类型断言本身：
 * 携带 ResetStreamHandler 的连接走流级重置路径，其他任何连接
 * （包括非 resetter 类型）都返回 false。
 */
func TestMaybeH2ResetStreamAssertion(t *testing.T) {
	t.Run("resetter hits and carries code", func(t *testing.T) {
		guard := &InboundProtocolGuard{conn: &h2ResetProbeConn{}}
		if !maybeH2ResetStream(guard, h2ErrCodeCancel) {
			t.Fatal("reset expected from Resetter conn")
		}
	})
	t.Run("refusing resetter returns false", func(t *testing.T) {
		guard := &InboundProtocolGuard{conn: &h2ResetRefuseConn{}}
		if maybeH2ResetStream(guard, h2ErrCodeCancel) {
			t.Fatal("refusing resetter must report false")
		}
	})
	t.Run("non-resetter conn returns false", func(t *testing.T) {
		guard := &InboundProtocolGuard{conn: &protocolGuardProbeConn{}}
		if maybeH2ResetStream(guard, h2ErrCodeCancel) {
			t.Fatal("non-resetter conn must report false")
		}
	})
	t.Run("nil guard and nil conn return false", func(t *testing.T) {
		if maybeH2ResetStream(nil, h2ErrCodeCancel) {
			t.Fatal("nil guard must report false")
		}
		if maybeH2ResetStream(&InboundProtocolGuard{}, h2ErrCodeCancel) {
			t.Fatal("nil conn must report false")
		}
	})
}

/**
 * protocolGuardProbeConn 是不带任何 resetter 方法的普通 net.Conn，
 * 用来代表 HTTP/1 raw TCP 连接的形态。
 */
type protocolGuardProbeConn struct{}

func (c *protocolGuardProbeConn) Read(p []byte) (int, error)       { return 0, nil }
func (c *protocolGuardProbeConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *protocolGuardProbeConn) Close() error                     { return nil }
func (c *protocolGuardProbeConn) LocalAddr() net.Addr              { return nil }
func (c *protocolGuardProbeConn) RemoteAddr() net.Addr             { return nil }
func (c *protocolGuardProbeConn) SetDeadline(time.Time) error      { return nil }
func (c *protocolGuardProbeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *protocolGuardProbeConn) SetWriteDeadline(time.Time) error { return nil }

/**
 * TestMaybeH3ResetStreamClosure 验证已注册的重置闭包会被 drop 路径
 * 通过 hertz 上下文键恰好执行一次。
 */
func TestMaybeH3ResetStreamClosure(t *testing.T) {
	c := app.NewContext(0)
	if maybeH3ResetStream(c) {
		t.Fatal("no reset closure must report false")
	}
	var executed bool
	c.Set(InternalHTTP3ResetTokenHeader, func() { executed = true })
	if !maybeH3ResetStream(c) {
		t.Fatal("registered reset closure must run through its context key")
	}
	if !executed {
		t.Fatal("reset closure was not executed")
	}
	if maybeH3ResetStream(c) {
		t.Fatal("consumed closure must not fire twice")
	}
}

// TestResetTokenLifecycle 验证重置闭包传递通道的 register/take/unregister 流程。
func TestResetTokenLifecycle(t *testing.T) {
	calls := 0
	token := RegisterInternalHTTP3ResetToken(func() { calls++ })
	if token == "" {
		t.Fatal("register must produce a token")
	}
	reset, ok := takeInternalHTTP3ResetClosure(token)
	if !ok || reset == nil {
		t.Fatal("registered token must be consumable")
	}
	reset()
	if calls != 1 {
		t.Fatalf("consumed closure ran %d times, want 1", calls)
	}
	UnregisterInternalHTTP3ResetToken(token)
	if _, ok := takeInternalHTTP3ResetClosure("missing-token"); ok {
		t.Fatal("unregistered token must not be consumable")
	}
	if RegisterInternalHTTP3ResetToken(nil) != "" {
		t.Fatal("nil closure must not produce a token")
	}
}
