package dataplane

import (
	"context"
	"reflect"
	"unsafe"

	"github.com/cloudwego/hertz/pkg/app"
)

var recvOnlyBoolChanType = reflect.TypeOf((<-chan bool)(nil))

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

func findCloseNotifyChannel(v reflect.Value) (<-chan bool, bool) {
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

func accessibleValue(v reflect.Value) reflect.Value {
	if !v.IsValid() || v.CanInterface() || !v.CanAddr() {
		return v
	}
	return reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
}

func callCloseNotify(method reflect.Value) (<-chan bool, bool) {
	defer func() {
		_ = recover()
	}()
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
