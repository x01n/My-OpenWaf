package dataplane

import (
	"context"
	"net"
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
