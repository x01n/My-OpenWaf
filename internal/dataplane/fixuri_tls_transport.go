package dataplane

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	"github.com/cloudwego/hertz/pkg/network"
)

type fixURITLSTransport struct {
	readBufferSize           int
	network                  string
	addr                     string
	keepAliveTimeout         time.Duration
	readTimeout              time.Duration
	senseClientDisconnection bool
	tls                      *tls.Config
	listenConfig             *net.ListenConfig
	handler                  network.OnData
	OnAccept                 func(net.Conn) context.Context
	OnConnect                func(context.Context, network.Conn) context.Context
	active                   int32
	shuttingDown             int32
	mu                       sync.RWMutex
	ln                       net.Listener
}

func NewFixURITLSTransporter(options *config.Options) network.Transporter {
	return &fixURITLSTransport{
		readBufferSize:           options.ReadBufferSize,
		network:                  options.Network,
		addr:                     options.Addr,
		keepAliveTimeout:         options.KeepAliveTimeout,
		readTimeout:              options.ReadTimeout,
		senseClientDisconnection: options.SenseClientDisconnection,
		tls:                      options.TLS,
		ln:                       options.Listener,
		listenConfig:             options.ListenConfig,
		OnAccept:                 options.OnAccept,
		OnConnect:                options.OnConnect,
	}
}

func (t *fixURITLSTransport) Listener() net.Listener {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.ln
}

func (t *fixURITLSTransport) ListenAndServe(onData network.OnData) error {
	t.handler = onData
	return t.serve()
}

func (t *fixURITLSTransport) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	return t.Shutdown(ctx)
}

func (t *fixURITLSTransport) Shutdown(ctx context.Context) error {
	atomic.StoreInt32(&t.shuttingDown, 1)
	if ln := t.Listener(); ln != nil {
		_ = ln.Close()
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if atomic.LoadInt32(&t.active) <= 0 {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (t *fixURITLSTransport) serve() error {
	t.mu.Lock()
	if t.ln == nil {
		var err error
		if t.listenConfig != nil {
			t.ln, err = t.listenConfig.Listen(context.Background(), t.network, t.addr)
		} else {
			t.ln, err = net.Listen(t.network, t.addr)
		}
		if err != nil {
			t.mu.Unlock()
			return err
		}
	}
	ln := t.ln
	t.mu.Unlock()
	hlog.SystemLogger().Infof("HTTP server listening on address=%s", ln.Addr().String())
	for {
		ctx := context.Background()
		conn, err := ln.Accept()
		if err != nil {
			if atomic.LoadInt32(&t.shuttingDown) > 0 || strings.Contains(err.Error(), "closed") {
				return nil
			}
			hlog.SystemLogger().Errorf("Accept err: %v", err)
			return err
		}
		atomic.AddInt32(&t.active, 1)
		if t.OnAccept != nil {
			ctx = t.OnAccept(conn)
		}

		go func(ctx context.Context, conn net.Conn) {
			defer atomic.AddInt32(&t.active, -1)

			var c network.Conn
			if t.tls != nil {
				tlsConn := tls.Server(conn, t.tls)
				c = newFixURIHertzConn(NewFixURIConn(tlsConn))
				if err := tlsConn.Handshake(); err != nil {
					_ = conn.Close()
					return
				}
			} else {
				c = newFixURIHertzConn(conn)
			}
			if t.OnConnect != nil {
				ctx = t.OnConnect(ctx, c)
			}
			t.handler(ctx, c)
		}(ctx, conn)
	}
}
