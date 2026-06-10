package acme

import "testing"

func TestSelfSignedCacheGetOrCreatePtrReusesCachedCertificate(t *testing.T) {
	cache := NewSelfSignedCache()

	first, err := cache.GetOrCreatePtr("127.0.0.1:9443")
	if err != nil {
		t.Fatalf("GetOrCreatePtr() first error: %v", err)
	}
	second, err := cache.GetOrCreatePtr("127.0.0.1:9443")
	if err != nil {
		t.Fatalf("GetOrCreatePtr() second error: %v", err)
	}
	if first != second {
		t.Fatal("GetOrCreatePtr() should return the cached certificate pointer")
	}

	value, err := cache.GetOrCreate("127.0.0.1:9443")
	if err != nil {
		t.Fatalf("GetOrCreate() error: %v", err)
	}
	if len(value.Certificate) == 0 {
		t.Fatal("GetOrCreate() returned an empty certificate chain")
	}
}
