package cache

import (
	context "context"
	"net"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"My-OpenWaf/internal/waf/luaplugin"

	goredis "github.com/redis/go-redis/v9"
)

var _ luaplugin.ContextKVBackend = (*RedisKV)(nil)

func TestRedisKVUnavailableWithoutClient(t *testing.T) {
	kv := NewRedisKV(nil)
	ctx := context.Background()
	if kv.Available() {
		t.Fatal("RedisKV without client must be unavailable")
	}
	if err := kv.Set("key", []byte("value"), time.Minute); err == nil {
		t.Fatal("Set without client must return an error")
	}
	if err := kv.SetContext(ctx, "key", []byte("value"), time.Minute); err == nil {
		t.Fatal("SetContext without client must return an error")
	}
	if _, ok := kv.GetContext(ctx, "key"); ok {
		t.Fatal("GetContext without client must fail open")
	}
	kv.DeleteContext(ctx, "key")
	if _, err := kv.Incr("key", time.Minute); err == nil {
		t.Fatal("Incr without client must return an error")
	}
	if _, err := kv.IncrContext(ctx, "key", time.Minute); err == nil {
		t.Fatal("IncrContext without client must return an error")
	}
}

func TestRedisKVCommandFailureMarksUnavailableAndSetClientRecovers(t *testing.T) {
	client := startRedisServer(t)
	kv := NewRedisKV(client)
	if !kv.Available() {
		t.Fatal("RedisKV with client must be available")
	}

	if err := client.Close(); err != nil {
		t.Fatalf("close Redis client: %v", err)
	}
	if _, ok := kv.Get("after-close"); ok {
		t.Fatal("Get after closing Redis client must fail open")
	}
	if kv.Available() {
		t.Fatal("RedisKV must become unavailable after a Redis command failure")
	}

	recovered := startRedisServer(t)
	kv.SetClient(recovered)
	if !kv.Available() {
		t.Fatal("SetClient must restore RedisKV availability")
	}
	if _, ok := kv.Get("missing"); ok {
		t.Fatal("Get for a missing key must remain a miss")
	}
	if !kv.Available() {
		t.Fatal("redis.Nil must not mark RedisKV unhealthy")
	}
}

func TestRedisKVIncrUsesFixedWindowTTL(t *testing.T) {
	client := startRedisServer(t)
	kv := NewRedisKV(client)
	const key = "fixed-window"
	window := 2 * time.Second

	value, err := kv.Incr(key, window)
	if err != nil {
		t.Fatalf("first increment: %v", err)
	}
	if value != 1 {
		t.Fatalf("first increment = %d, want 1", value)
	}
	firstTTL, err := client.PTTL(context.Background(), redisPrefix+key).Result()
	if err != nil || firstTTL <= 0 {
		t.Fatalf("first TTL = %v, %v; want positive TTL", firstTTL, err)
	}

	time.Sleep(30 * time.Millisecond)
	value, err = kv.IncrContext(context.Background(), key, window)
	if err != nil {
		t.Fatalf("second increment: %v", err)
	}
	if value != 2 {
		t.Fatalf("second increment = %d, want 2", value)
	}
	secondTTL, err := client.PTTL(context.Background(), redisPrefix+key).Result()
	if err != nil || secondTTL <= 0 {
		t.Fatalf("second TTL = %v, %v; want positive TTL", secondTTL, err)
	}
	if secondTTL >= firstTTL {
		t.Fatalf("second TTL = %v, first TTL = %v; fixed-window increment must not refresh TTL", secondTTL, firstTTL)
	}
}

func startRedisServer(t *testing.T) *goredis.Client {
	t.Helper()
	binary, err := exec.LookPath("redis-server")
	if err != nil {
		t.Skip("redis-server is not installed")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve Redis port: %v", err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if closeErr := listener.Close(); closeErr != nil {
		t.Fatalf("release Redis port: %v", closeErr)
	}
	if err != nil {
		t.Fatalf("parse Redis port: %v", err)
	}
	cmd := exec.Command(binary, "--bind", "127.0.0.1", "--port", port, "--save", "", "--appendonly", "no", "--dir", t.TempDir())
	if err := cmd.Start(); err != nil {
		t.Fatalf("start Redis: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})

	client := goredis.NewClient(&goredis.Options{Addr: net.JoinHostPort("127.0.0.1", port)})
	t.Cleanup(func() { _ = client.Close() })
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := client.Ping(context.Background()).Err(); err == nil {
			return client
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Redis did not become ready on port %s", strconv.Quote(port))
	return nil
}
