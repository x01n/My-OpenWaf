package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
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
