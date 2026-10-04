package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"My-OpenWaf/internal/waf/luaplugin"

	rueidis "github.com/redis/rueidis"
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

	client.Close()
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

func TestRedisKVFailureBackoffAllowsProbeAndSuccessfulResultsRecover(t *testing.T) {
	client := newKVTestClient(t, "127.0.0.1:1")
	kv := NewRedisKV(client)

	kv.noteCommandResult(client, errors.New("temporary redis failure"))
	if kv.Available() {
		t.Fatal("RedisKV must reject commands during the failure backoff")
	}
	if until := kv.unavailableUntil.Load(); until <= time.Now().UnixNano() {
		t.Fatalf("unavailableUntil = %d, want a future retry time", until)
	}

	kv.unavailableUntil.Store(time.Now().Add(-time.Second).UnixNano())
	if !kv.Available() {
		t.Fatal("RedisKV must become half-open after the failure backoff")
	}
	kv.noteCommandResult(client, nil)
	if !kv.Available() || kv.unavailableUntil.Load() != 0 {
		t.Fatal("a successful probe must fully restore RedisKV health")
	}

	kv.noteCommandResult(client, errors.New("temporary redis failure"))
	kv.unavailableUntil.Store(time.Now().Add(-time.Second).UnixNano())
	kv.noteCommandResult(client, rueidis.Nil)
	if !kv.Available() || kv.unavailableUntil.Load() != 0 {
		t.Fatal("redis.Nil must restore health because it is a successful Redis response")
	}

	kv.noteCommandResult(client, errors.New("temporary redis failure"))
	replacement := newKVTestClient(t, "127.0.0.1:2")
	kv.SetClient(replacement)
	if !kv.Available() || kv.unavailableUntil.Load() != 0 {
		t.Fatal("SetClient must immediately clear the previous client's backoff")
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
	firstTTL, err := kvTestPTTL(client, redisPrefix+key)
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
	secondTTL, err := kvTestPTTL(client, redisPrefix+key)
	if err != nil || secondTTL <= 0 {
		t.Fatalf("second TTL = %v, %v; want positive TTL", secondTTL, err)
	}
	if secondTTL >= firstTTL {
		t.Fatalf("second TTL = %v, first TTL = %v; fixed-window increment must not refresh TTL", secondTTL, firstTTL)
	}
}

// newKVTestClient 为给定地址构造一个 rueidis 测试客户端。
func newKVTestClient(t *testing.T, addr string) rueidis.Client {
	t.Helper()
	client, err := rueidis.NewClient(rueidis.ClientOption{
		InitAddress:       []string{addr},
		DisableRetry:      true,
		DisableCache:      true,
		ForceSingleClient: true,
	})
	if client == nil && err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func startRedisServer(t *testing.T) rueidis.Client {
	t.Helper()
	mock := startKVMiniRedis(t)
	return newKVTestClient(t, mock.ln.Addr().String())
}

// kvTestPTTL 查询键的剩余 TTL（毫秒），rueidis 形态。
func kvTestPTTL(client rueidis.Client, key string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return client.Do(ctx, client.B().Pttl().Key(key).Build()).AsInt64()
}
