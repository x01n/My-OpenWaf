package imagery

import "testing"

// TestLoadConfigDefaults 空值必须得到默认配置（关闭状态）。
func TestLoadConfigDefaults(t *testing.T) {
	for _, raw := range []string{"", "   ", "null"} {
		cfg, err := LoadConfig(raw)
		if err != nil {
			t.Fatalf("LoadConfig(%q) err = %v", raw, err)
		}
		if cfg.Enabled {
			t.Fatalf("LoadConfig(%q) enabled by default", raw)
		}
		want := DefaultConfig()
		if cfg.MaxPixels != want.MaxPixels || cfg.MaxSide != want.MaxSide || cfg.MaxBytes != want.MaxBytes {
			t.Fatalf("LoadConfig(%q) limits = %+v, want %+v", raw, cfg, want)
		}
	}
}

// TestLoadConfigMalformedReportsError 坏配置必须报错，不能静默取默认值。
func TestLoadConfigMalformedReportsError(t *testing.T) {
	for _, raw := range []string{"{", "not json", "[1,2", `{"max_pixels": "abc"}`} {
		if _, err := LoadConfig(raw); err == nil {
			t.Fatalf("LoadConfig(%q) succeeded; malformed config must be reported", raw)
		}
	}
}

// TestConfigNormalizeClamps 越界值必须被钳制。
func TestConfigNormalizeClamps(t *testing.T) {
	cases := []struct {
		in   Config
		want func(Config) bool
		desc string
	}{
		{Config{TimeoutMS: 1}, func(c Config) bool { return c.TimeoutMS == MinTimeoutMS }, "timeout below min"},
		{Config{TimeoutMS: 1 << 20}, func(c Config) bool { return c.TimeoutMS == MaxTimeoutMS }, "timeout above max"},
		{Config{TimeoutMS: -5}, func(c Config) bool { return c.TimeoutMS > 0 }, "negative timeout"},
		{Config{Concurrency: -1}, func(c Config) bool { return c.Concurrency == 0 }, "negative concurrency"},
		{Config{Concurrency: 1 << 20}, func(c Config) bool { return c.Concurrency == MaxConcurrencyLimit }, "concurrency above max"},
		{Config{DefaultQuality: 200}, func(c Config) bool { return c.DefaultQuality == MaxQuality }, "quality above max"},
		{Config{DefaultQuality: -3}, func(c Config) bool { return c.DefaultQuality == 0 }, "negative quality"},
		{Config{MaxPixels: -1}, func(c Config) bool { return c.MaxPixels == DefaultDecodeLimits.MaxPixels }, "negative max pixels"},
		{Config{MaxSide: 0}, func(c Config) bool { return c.MaxSide == DefaultDecodeLimits.MaxSide }, "zero max side"},
		{Config{MaxBytes: 0}, func(c Config) bool { return c.MaxBytes == DefaultDecodeLimits.MaxBytes }, "zero max bytes"},
	}
	for _, tc := range cases {
		got := tc.in.Normalize()
		if !tc.want(got) {
			t.Fatalf("%s: Normalize() = %+v", tc.desc, got)
		}
	}
}

// TestConfigProjections 投影出的限额与超时必须与配置一致。
func TestConfigProjections(t *testing.T) {
	cfg := Config{MaxPixels: 1000, MaxSide: 32, MaxBytes: 4096, TimeoutMS: 500}.Normalize()
	limits := cfg.DecodeLimits()
	if limits.MaxPixels != 1000 || limits.MaxSide != 32 || limits.MaxBytes != 4096 {
		t.Fatalf("DecodeLimits = %+v", limits)
	}
	if cfg.Timeout().Milliseconds() != 500 {
		t.Fatalf("Timeout = %v", cfg.Timeout())
	}
}

// TestAcceptsWebP 覆盖 Accept 协商：只有显式 image/webp 才算支持。
func TestAcceptsWebP(t *testing.T) {
	yes := []string{
		"image/webp",
		"image/webp,*/*",
		"text/html,image/webp;q=0.8",
		"IMAGE/WEBP",
		"image/avif, image/webp , image/png",
	}
	for _, a := range yes {
		if !AcceptsWebP(a) {
			t.Fatalf("AcceptsWebP(%q) = false, want true", a)
		}
	}
	no := []string{
		"",
		"*/*",
		"image/*",
		"image/jpeg,image/png",
		"text/html",
		// 子串陷阱：不能因为前缀匹配而误判。
		"image/webpfoo",
		"x-image/webp",
	}
	for _, a := range no {
		if AcceptsWebP(a) {
			t.Fatalf("AcceptsWebP(%q) = true, want false", a)
		}
	}
}
