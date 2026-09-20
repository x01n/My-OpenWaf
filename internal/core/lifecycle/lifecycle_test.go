package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type testServer struct {
	shutdownErr error
}

func (s testServer) Spin() {}

func (s testServer) Shutdown(ctx context.Context) error {
	return s.shutdownErr
}

func testLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func TestShutdownTreatsStoppedHertzServerAsComplete(t *testing.T) {
	var buf bytes.Buffer
	m := New(testLogger(&buf))
	m.Add("admin:127.0.0.1:19443", testServer{shutdownErr: errors.New(hertzEngineNotRunningError)})

	m.Shutdown(context.Background())

	logs := buf.String()
	if strings.Contains(logs, "shutdown error") {
		t.Fatalf("expected stopped hertz server to avoid shutdown error log, got %s", logs)
	}
	if !strings.Contains(logs, "server shutdown complete") {
		t.Fatalf("expected shutdown complete log, got %s", logs)
	}
}

func TestRemoveTreatsStoppedHertzServerAsRemoved(t *testing.T) {
	var buf bytes.Buffer
	m := New(testLogger(&buf))
	m.Add("admin:127.0.0.1:19443", testServer{shutdownErr: errors.New(hertzEngineNotRunningError)})

	m.Remove("admin:127.0.0.1:19443")

	logs := buf.String()
	if strings.Contains(logs, "remove shutdown error") {
		t.Fatalf("expected stopped hertz server to avoid remove shutdown error log, got %s", logs)
	}
	if !strings.Contains(logs, "server removed") {
		t.Fatalf("expected server removed log, got %s", logs)
	}
}

type blockingShutdownServer struct{}

func (s blockingShutdownServer) Spin() {}

func (s blockingShutdownServer) Shutdown(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestRemoveUsesShortTimeoutForBlockedServer(t *testing.T) {
	var buf bytes.Buffer
	m := New(testLogger(&buf))
	m.Add("site:127.0.0.1:19443", blockingShutdownServer{})

	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		m.Remove("site:127.0.0.1:19443")
		done <- time.Since(start)
	}()

	select {
	case elapsed := <-done:
		if elapsed > 2*time.Second {
			t.Fatalf("Remove blocked for %s, want less than 2s", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Remove did not return within 2s")
	}
}

func TestShutdownUsesBoundedDeadlineForBlockedServer(t *testing.T) {
	var buf bytes.Buffer
	m := New(testLogger(&buf))
	m.Add("site:127.0.0.1:19444", blockingShutdownServer{})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	m.Shutdown(ctx)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Shutdown blocked for %s after context deadline", elapsed)
	}
}

type ignoringContextShutdownServer struct {
	started  chan struct{}
	release  chan struct{}
	finished chan struct{}
	once     sync.Once
}

func (s *ignoringContextShutdownServer) Spin() {}

func (s *ignoringContextShutdownServer) Shutdown(context.Context) error {
	s.once.Do(func() { close(s.started) })
	<-s.release
	close(s.finished)
	return nil
}

func TestShutdownReturnsWhenServerIgnoresContext(t *testing.T) {
	var buf bytes.Buffer
	m := New(testLogger(&buf))
	srv := &ignoringContextShutdownServer{
		started:  make(chan struct{}),
		release:  make(chan struct{}),
		finished: make(chan struct{}),
	}
	m.Add("site:127.0.0.1:19445", srv)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	m.Shutdown(ctx)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Shutdown blocked for %s when server ignored context", elapsed)
	}
	select {
	case <-srv.started:
	default:
		t.Fatal("expected server shutdown to start")
	}
	if !m.Has("site:127.0.0.1:19445") {
		t.Fatal("manager lock remained unavailable after bounded shutdown")
	}

	close(srv.release)
	select {
	case <-srv.finished:
	case <-time.After(time.Second):
		t.Fatal("ignoring server did not finish after release")
	}
}
