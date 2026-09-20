package dynamic

import "testing"

func BenchmarkNewProcessor(b *testing.B) {
	cfg := ProtectionConfig{
		SiteID:                 42,
		HTMLObfuscationEnabled: true,
		JSObfuscationEnabled:   true,
		JSProtectionMode:       "all",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewProcessor(cfg)
	}
}

func BenchmarkNewProcessorWithKeyBase(b *testing.B) {
	base := make([]byte, 32)
	for i := range base {
		base[i] = byte(i)
	}
	cfg := ProtectionConfig{
		SiteID:                 42,
		HTMLObfuscationEnabled: true,
		EncryptionKeyBase:      base,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewProcessor(cfg)
	}
}
