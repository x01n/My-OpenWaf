package cache

import (
	"testing"
	"time"
)

func TestRedisKVUnavailableWithoutClient(t *testing.T) {
	kv := NewRedisKV(nil)
	if kv.Available() {
		t.Fatal("RedisKV without client must be unavailable")
	}
	if err := kv.Set("key", []byte("value"), time.Minute); err == nil {
		t.Fatal("Set without client must return an error")
	}
	if _, err := kv.Incr("key", time.Minute); err == nil {
		t.Fatal("Incr without client must return an error")
	}
}
