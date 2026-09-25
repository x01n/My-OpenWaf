package dataplane

import (
	"context"
	"reflect"
	"sync"
	"unsafe"

	"github.com/cloudwego/hertz/pkg/app"
)

var recvOnlyBoolChanType = reflect.TypeOf((<-chan bool)(nil))

// closeNotifyMethodIndex 按 reflect.Type 缓存 CloseNotify 方法的索引，
// 无该方法的类型缓存为 -1（恒无）。判断口径与
// Value.MethodByName("CloseNotify").IsValid() 一致：命中时只把"按名
// 线性查方法表"替换为"按索引 O(1) 取方法"，方法的存在性、原型检查
// 与调用本身保持原样。表内只存类型级事实，不缓存任何连接/通道值。
var closeNotifyMethodIndex sync.Map // map[reflect.Type]int

// selectStreamCloseNotifyBinding 依据数据面 listener 是否具备 HTTP/2 协议栈
// 选择请求级 CloseNotify 绑定函数。h1/h3 listener 的 conn 永不含 CloseNotify，
// 启用禁选时直接返回 noop，省去每请求一次的全结构体 reflect 扫描。
func selectStreamCloseNotifyBinding(disabled bool) func(context.Context, *app.RequestContext) (context.Context, func()) {
	if disabled {
		return noopStreamCloseNotifyBinding
	}
	return bindStreamCloseNotifyContext
}

// noopStreamCloseNotifyBinding 原样返回请求 context，取消函数为空操作，
// 用于不存在 CloseNotify 源的数据面 listener。
func noopStreamCloseNotifyBinding(ctx context.Context, _ *app.RequestContext) (context.Context, func()) {
	return ctx, func() {}
}

// bindStreamCloseNotifyContext bridges request cancellation to stream closure.
// hertz-contrib/http2 v0.1.8 does not cancel the handler context on RST_STREAM,
// so we additionally bind the request context to the HTTP/2 response writer's
// CloseNotify signal when it is available.
func bindStreamCloseNotifyContext(ctx context.Context, c *app.RequestContext) (context.Context, func()) {
	if c == nil {
		return ctx, func() {}
	}
	closeNotify, ok := streamCloseNotifyChannel(c.GetConn())
	if !ok || closeNotify == nil {
		return ctx, func() {}
	}
	derivedCtx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-derivedCtx.Done():
		case <-closeNotify:
			cancel()
		}
	}()
	return derivedCtx, cancel
}

func streamCloseNotifyChannel(conn any) (<-chan bool, bool) {
	if conn == nil {
		return nil, false
	}
	return findCloseNotifyChannel(reflect.ValueOf(conn))
}

// findCloseNotifyChannel 返回从 v 出发可定位到的第一个 CloseNotify 通道。
// 与原实现的递归 DFS 语义完全一致，唯一差别是每节点的方法探测由
// closeNotifyMethodIndex cache 索引化，不再每请求按名扫方法表。
func findCloseNotifyChannel(v reflect.Value) (<-chan bool, bool) {
	if !v.IsValid() {
		return nil, false
	}
	v = accessibleValue(v)
	if idx := closeNotifyMethodIndexFor(v.Type()); idx >= 0 {
		if ch, ok := callCloseNotifyAt(v, idx); ok {
			return ch, true
		}
	}
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return nil, false
		}
		return findCloseNotifyChannel(v.Elem())
	case reflect.Pointer:
		if v.IsNil() {
			return nil, false
		}
		return findCloseNotifyChannel(v.Elem())
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if ch, ok := findCloseNotifyChannel(v.Field(i)); ok {
				return ch, true
			}
		}
	}
	return nil, false
}

// closeNotifyMethodIndexFor 返回 t 的方法集中 CloseNotify 方法的索引；
// 不存在时返回 -1 并缓存该负结论。索引与
// Value.Method(i) 一一对应，是 MethodByName 的等义快路径。
func closeNotifyMethodIndexFor(t reflect.Type) int {
	if got, ok := closeNotifyMethodIndex.Load(t); ok {
		return got.(int)
	}
	idx := -1
	for i := 0; i < t.NumMethod(); i++ {
		if t.Method(i).Name == "CloseNotify" {
			idx = i
			break
		}
	}
	closeNotifyMethodIndex.Store(t, idx)
	return idx
}

func accessibleValue(v reflect.Value) reflect.Value {
	if !v.IsValid() || v.CanInterface() || !v.CanAddr() {
		return v
	}
	return reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
}

// callCloseNotifyAt 按方法索引从 v 取值后走与原名探测相同的校验与调用；
// recover 边界放在函数体内，与 callCloseNotify 的防护等价。
func callCloseNotifyAt(v reflect.Value, methodIndex int) (ch <-chan bool, ok bool) {
	defer func() {
		if recover() != nil {
			ch, ok = nil, false
		}
	}()
	return callCloseNotify(v.Method(methodIndex))
}

func callCloseNotify(method reflect.Value) (<-chan bool, bool) {
	methodType := method.Type()
	if methodType.NumIn() != 0 || methodType.NumOut() != 1 {
		return nil, false
	}
	channelType := methodType.Out(0)
	if channelType.Kind() != reflect.Chan || channelType.Elem().Kind() != reflect.Bool || channelType.ChanDir() == reflect.SendDir {
		return nil, false
	}
	results := method.Call(nil)
	if len(results) != 1 || results[0].IsNil() {
		return nil, false
	}
	channelValue := results[0]
	if !channelValue.Type().AssignableTo(recvOnlyBoolChanType) {
		if !channelValue.Type().ConvertibleTo(recvOnlyBoolChanType) {
			return nil, false
		}
		channelValue = channelValue.Convert(recvOnlyBoolChanType)
	}
	ch, ok := channelValue.Interface().(<-chan bool)
	return ch, ok
}
