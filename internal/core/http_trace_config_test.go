package core

import (
	"strings"
	"testing"
)

// TestDefaultHTTPTraceConfig 钉住遥测的默认取值：关闭 + 详细级别。
// 默认开启会让每个部署无条件承担 Tracer 的每请求开销；
// 默认 base 则会把"打开开关"的人降级成只有总耗时，与开关意图相反。
func TestDefaultHTTPTraceConfig(t *testing.T) {
	got := DefaultHTTPTraceConfig()
	if got.Enabled {
		t.Errorf("Enabled = true, want false (telemetry must be opt-in)")
	}
	if got.Level != "detailed" {
		t.Errorf("Level = %q, want %q", got.Level, "detailed")
	}
	if len(got.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none", got.Warnings)
	}
}

// TestLoadConfigFromEnvReadsHTTPTraceValues 校验两个环境变量被读到对应字段且不产生告警。
// 取值刻意与默认值不同，避免"读没读到都一样"的假通过。
func TestLoadConfigFromEnvReadsHTTPTraceValues(t *testing.T) {
	t.Setenv("MY_OPENWAF_TRACE_ENABLED", "true")
	t.Setenv("MY_OPENWAF_TRACE_LEVEL", "base")

	cfg := LoadConfigFromEnv()
	if !cfg.HTTPTrace.Enabled {
		t.Errorf("Enabled = false, want true for MY_OPENWAF_TRACE_ENABLED=true")
	}
	if cfg.HTTPTrace.Level != "base" {
		t.Errorf("Level = %q, want %q", cfg.HTTPTrace.Level, "base")
	}
	if len(cfg.HTTPTrace.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none for valid values", cfg.HTTPTrace.Warnings)
	}
}

// TestLoadConfigFromEnvHTTPTraceDisabledByDefault 断言未设置时保持关闭。
func TestLoadConfigFromEnvHTTPTraceDisabledByDefault(t *testing.T) {
	cfg := LoadConfigFromEnv()
	if cfg.HTTPTrace.Enabled {
		t.Errorf("Enabled = true without MY_OPENWAF_TRACE_ENABLED, want false")
	}
	if cfg.HTTPTrace.Level != "detailed" {
		t.Errorf("Level = %q, want the default %q", cfg.HTTPTrace.Level, "detailed")
	}
}

// TestLoadConfigFromEnvHTTPTraceEnabledIsCaseInsensitiveAndStrict
// 断言开关只认 "true"（大小写不敏感）：其它取值一律保持关闭并不断言为开，
// 避免拼错的 "yes"/"1" 让运维以为已开启。
func TestLoadConfigFromEnvHTTPTraceEnabledIsCaseInsensitiveAndStrict(t *testing.T) {
	tests := map[string]bool{
		"true":  true,
		"TRUE":  true,
		"True":  true,
		"1":     false,
		"yes":   false,
		"on":    false,
		"false": false,
	}
	for raw, want := range tests {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("MY_OPENWAF_TRACE_ENABLED", raw)
			if got := LoadConfigFromEnv().HTTPTrace.Enabled; got != want {
				t.Errorf("Enabled = %v for MY_OPENWAF_TRACE_ENABLED=%q, want %v", got, raw, want)
			}
		})
	}
}

// TestLoadConfigFromEnvHTTPTraceLevelWarnsOnUnknownValue 断言非法级别回退到默认值并告警，
// 与队列参数同口径：静默会让一个拼错的取值伪装成"已生效"。
func TestLoadConfigFromEnvHTTPTraceLevelWarnsOnUnknownValue(t *testing.T) {
	t.Setenv("MY_OPENWAF_TRACE_LEVEL", "verbose")

	cfg := LoadConfigFromEnv()
	if cfg.HTTPTrace.Level != "detailed" {
		t.Errorf("Level = %q, want the kept default %q", cfg.HTTPTrace.Level, "detailed")
	}
	if len(cfg.HTTPTrace.Warnings) == 0 {
		t.Fatalf("Warnings is empty for an unparsable level, want a warning")
	}
	found := false
	for _, w := range cfg.HTTPTrace.Warnings {
		if containsAll(w, "MY_OPENWAF_TRACE_LEVEL", "verbose") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings %v do not mention the variable name and the raw value", cfg.HTTPTrace.Warnings)
	}
}

// containsAll 报告 s 是否同时包含全部子串。
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
