package app

import (
	"net/http"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// h3ResponseWriterShape 复刻 quic-go http3.responseWriter 的字段形状：
// 未导出的 str 字段持有承载该请求的 QUIC 流。用于验证解包链能走到该层。
type h3ResponseWriterShape struct {
	str    *h3ResetStreamMock
	header http.Header
}

func (w *h3ResponseWriterShape) Header() http.Header         { return w.header }
func (w *h3ResponseWriterShape) Write(b []byte) (int, error) { return len(b), nil }
func (w *h3ResponseWriterShape) WriteHeader(int)             {}

// h3UnwrapLoopWriter 的 Unwrap 返回自身，用于验证环/自引用不会死循环。
type h3UnwrapLoopWriter struct{ header http.Header }

func (w *h3UnwrapLoopWriter) Header() http.Header         { return w.header }
func (w *h3UnwrapLoopWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *h3UnwrapLoopWriter) WriteHeader(int)             {}
func (w *h3UnwrapLoopWriter) Unwrap() http.ResponseWriter { return w }

// TestHTTP3ResponseStreamUnwrapsCancelAware 是 h3 流级取消的回归锁：
// 生产传入的是 *http3CancelAwareResponseWriter（嵌入 http.ResponseWriter，
// 无 str 字段），修复前 http3ResponseStream 对它恒返回 nil，导致
// SetStream(nil) → ResetFn()==nil → h3 drop 只能降级为 HTTP 403。
// 解包链必须穿过该包装器，抵达持有 QUIC 流的对象。
func TestHTTP3ResponseStreamUnwrapsCancelAware(t *testing.T) {
	t.Run("cancelAware wrapper reaches the stream", func(t *testing.T) {
		stream := &h3ResetStreamMock{}
		inner := &h3ResponseWriterShape{str: stream}
		wrapped := newHTTP3CancelAwareResponseWriter(inner, func() {}, func() error { return nil })

		got := http3ResponseStream(wrapped)
		if got == nil {
			t.Fatal("解包链必须穿过 cancelAware 包装器解析出 QUIC 流")
		}
		resetter, ok := got.(h3StreamResetter)
		if !ok {
			t.Fatalf("解析结果 %T 不满足 h3StreamResetter", got)
		}
		resetter.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		if !stream.called || stream.code != quic.StreamErrorCode(http3.ErrCodeRequestCanceled) {
			t.Fatalf("流未被取消: called=%v code=0x%x", stream.called, uint64(stream.code))
		}
	})

	t.Run("unwrapped stream is still reachable directly", func(t *testing.T) {
		stream := &h3ResetStreamMock{}
		inner := &h3ResponseWriterShape{str: stream}
		if got := http3ResponseStream(inner); got == nil {
			t.Fatal("已经是流持有者时必须直接解析成功")
		}
	})

	t.Run("nil writer and nil stream", func(t *testing.T) {
		if got := http3ResponseStream(nil); got != nil {
			t.Fatalf("nil writer 必须返回 nil, got %T", got)
		}
		if got := http3ResponseStream(&h3ResponseWriterShape{}); got != nil {
			t.Fatalf("str 为 nil 必须返回 nil, got %T", got)
		}
	})

	t.Run("self-referencing unwrap terminates", func(t *testing.T) {
		loop := &h3UnwrapLoopWriter{}
		if got := http3ResponseStream(loop); got != nil {
			t.Fatalf("自引用 Unwrap 必须安全返回 nil, got %T", got)
		}
	})

	t.Run("shallow shapes return nil", func(t *testing.T) {
		if got := http3ResponseStream(struct{ http.ResponseWriter }{}); got != nil {
			t.Fatalf("非指针值必须返回 nil, got %T", got)
		}
	})
}

// h3ResetStreamMock implements the anonymous h3StreamResetter capability
// (CancelWrite) that ResetFn builds its closure against.
type h3ResetStreamMock struct {
	called bool
	code   quic.StreamErrorCode
}

func (m *h3ResetStreamMock) CancelWrite(code quic.StreamErrorCode) {
	m.called = true
	m.code = code
}

// TestH3LoopbackStateResetFn verifies the drop-side reset closure wiring:
// the closure must cancel the quota-owned stream with
// H3_REQUEST_CANCELED without touching the state's cancel chain.
func TestH3LoopbackStateResetFn(t *testing.T) {
	t.Run("captured stream is reset with request-canceled", func(t *testing.T) {
		state := &http3LoopbackRequestState{}
		if fn := state.ResetFn(); fn != nil {
			t.Fatal("empty state must not produce a reset closure")
		}
		stream := &h3ResetStreamMock{}
		state.SetStream(stream)
		fn := state.ResetFn()
		if fn == nil {
			t.Fatal("captured stream must produce a reset closure")
		}
		fn()
		if !stream.called {
			t.Fatal("reset closure did not reach the stream")
		}
		if stream.code != quic.StreamErrorCode(http3.ErrCodeRequestCanceled) {
			t.Fatalf("reset code = 0x%x, want H3_REQUEST_CANCELED (0x10c)", uint64(stream.code))
		}
	})
	t.Run("nil stream yields nil closure", func(t *testing.T) {
		state := &http3LoopbackRequestState{}
		state.SetStream(nil)
		if fn := state.ResetFn(); fn != nil {
			t.Fatal("nil stream must not produce a reset closure")
		}
	})
	t.Run("non-resetter stream yields nil closure", func(t *testing.T) {
		state := &http3LoopbackRequestState{}
		state.SetStream(struct{}{})
		if fn := state.ResetFn(); fn != nil {
			t.Fatal("non-resetter stream must not produce a reset closure")
		}
	})
}
