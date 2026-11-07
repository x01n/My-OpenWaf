package configoverride

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// contractKeys 是冻结契约第 3 节的 45 个键及其 group / type，逐字抄录。
//
// 这份表是端点契约的镜像：任何一方漂移（少一个键、改一个组名、把 duration
// 写成 string）都要在这里先变红。
var contractKeys = []struct {
	key   string
	group string
	kind  Kind
}{
	// bootstrap（7，editable=false）
	{"db_driver", GroupBootstrap, KindString},
	{"dsn", GroupBootstrap, KindString},
	{"data_dir", GroupBootstrap, KindString},
	{"admin_bind", GroupBootstrap, KindString},
	{"log_dsn", GroupBootstrap, KindString},
	{"pprof_bind", GroupBootstrap, KindString},
	{"jwt_secret", GroupBootstrap, KindString},

	// network（5，editable=true）
	{"redis_addr", GroupNetwork, KindString},
	{"redis_password", GroupNetwork, KindString},
	{"redis_db", GroupNetwork, KindInt},
	{"admin_static_dir", GroupNetwork, KindString},
	{"captcha_dir", GroupNetwork, KindString},

	// detection（12，editable=true）
	{"cve_enabled", GroupDetection, KindBool},
	{"cve_feed_enabled", GroupDetection, KindBool},
	{"cve_feed_interval", GroupDetection, KindDuration},
	{"nvd_api_key", GroupDetection, KindString},
	{"cve_auto_approve", GroupDetection, KindBool},
	{"geoip_db_path", GroupDetection, KindString},
	{"bot_threshold", GroupDetection, KindInt},
	{"drop_enabled", GroupDetection, KindBool},
	{"drop_bot_threshold", GroupDetection, KindInt},
	{"cve_auto_drop_critical", GroupDetection, KindBool},
	{"cve_auto_drop_high", GroupDetection, KindBool},
	{"bot_enabled", GroupDetection, KindBool},

	// observability（7，editable=true）
	{"trace_enabled", GroupObservability, KindBool},
	{"trace_level", GroupObservability, KindString},
	{"log_level", GroupObservability, KindString},
	{"log_file", GroupObservability, KindString},
	{"log_also_stdout", GroupObservability, KindBool},
	{"log_color", GroupObservability, KindString},
	{"accesslog_sampling", GroupObservability, KindInt},

	// limits（2，editable=true）
	{"request_decompress_limit_bytes", GroupLimits, KindInt},
	{"response_decompress_limit_bytes", GroupLimits, KindInt},

	// cache（2，editable=true）
	{"response_cache_mb", GroupCache, KindInt},
	{"response_cache_ttl_sec", GroupCache, KindInt},

	// queue（7，editable=true）
	{"queue_event_buffer_size", GroupQueue, KindInt},
	{"queue_drop_buffer_size", GroupQueue, KindInt},
	{"queue_batch_size", GroupQueue, KindInt},
	{"queue_flush_interval", GroupQueue, KindDuration},
	{"queue_write_batch_size", GroupQueue, KindInt},
	{"queue_write_capacity", GroupQueue, KindInt},
	{"queue_write_interval", GroupQueue, KindDuration},

	// http3（1，editable=true）
	{"h3_allow_0rtt", GroupHTTP3, KindString},

	// internal（2，editable=false）
	{"h2ws_peeker_off", GroupInternal, KindString},
	{"fingerprint_bench_db", GroupInternal, KindString},
}

// durationKeys 是契约第 5 节钉死的三个时长键。
var durationKeys = []string{"cve_feed_interval", "queue_flush_interval", "queue_write_interval"}

// restartRequiredKeys 是「写进覆盖表 + 需重启才生效」一档的键：值在启动装配期
// 写进结构体并贯穿整个进程生命周期（覆盖表只在 core.NewRuntime 里解析一次，
// reload 不重新应用它），因此写进覆盖表后必须重启进程才会被读到。
//
// 这一档比契约第 6 节「启动固化」一行更宽：契约把检测域的 12 个键列为「随 reload
// 生效」，但实测只有 cve_enabled 有真正的 reload 消费点——它走 snapshot.Build，
// 每次配置重载都会重跑（见 internal/snapshot/config_override_build_test.go）。
// 其余 11 个键（drop_*、bot_*、geoip_db_path 与 CVE 情报源四项）的消费点都读
// 启动期固化的 core.Config，reload 不刷新它，只能如实标成需重启。
var restartRequiredKeys = []string{
	"admin_static_dir",
	"log_color",
	"captcha_dir",
	"bot_enabled",
	"bot_threshold",
	"drop_enabled",
	"drop_bot_threshold",
	"geoip_db_path",
	"cve_feed_enabled",
	"cve_feed_interval",
	"nvd_api_key",
	"cve_auto_approve",
	"request_decompress_limit_bytes",
	"response_decompress_limit_bytes",
	"response_cache_mb",
	"response_cache_ttl_sec",
	"queue_event_buffer_size",
	"queue_drop_buffer_size",
	"queue_batch_size",
	"queue_flush_interval",
	"queue_write_batch_size",
	"queue_write_capacity",
	"queue_write_interval",
	"accesslog_sampling",
	"trace_enabled",
	"trace_level",
}

// hotAppliedKeys 是真正随 reload 生效的键：其消费点是 snapshot.Build，
// 每次配置重载都会重新读取覆盖表。这一档只剩一个键。
var hotAppliedKeys = []string{"cve_enabled", "cve_auto_drop_critical", "cve_auto_drop_high"}

/**
 * TestRegistryMatchesContract 逐条核对 45 个键的键名、域与类型。
 *
 * 三向核对：契约表里的每个键都必须在注册表中且元数据一致；注册表里也不许出现
 * 契约之外的键（多出来的键会让前端渲染出无标签的条目）。
 */
func TestRegistryMatchesContract(t *testing.T) {
	if got := len(All()); got != 45 {
		t.Fatalf("registry size = %d, want 45", got)
	}
	if got := len(contractKeys); got != 45 {
		t.Fatalf("contract table size = %d, want 45", got)
	}

	inContract := make(map[string]struct{}, len(contractKeys))
	for _, want := range contractKeys {
		inContract[want.key] = struct{}{}
		spec, ok := Lookup(want.key)
		if !ok {
			t.Errorf("key %q is missing from the registry", want.key)
			continue
		}
		if spec.Group != want.group {
			t.Errorf("key %q group = %q, want %q", want.key, spec.Group, want.group)
		}
		if spec.Kind != want.kind {
			t.Errorf("key %q kind = %q, want %q", want.key, spec.Kind, want.kind)
		}
	}

	for _, spec := range All() {
		if _, ok := inContract[spec.Key]; !ok {
			t.Errorf("key %q is registered but not part of the contract", spec.Key)
		}
		if spec.LabelKey() != "envOverrides.key."+spec.Key {
			t.Errorf("key %q label key = %q", spec.Key, spec.LabelKey())
		}
		if spec.DescriptionKey() != "envOverrides.key."+spec.Key+".desc" {
			t.Errorf("key %q description key = %q", spec.Key, spec.DescriptionKey())
		}
	}
}

/**
 * TestRegistryGroupsMatchContract 断言 groups[] 的 9 个域与顺序。
 */
func TestRegistryGroupsMatchContract(t *testing.T) {
	want := []string{
		GroupBootstrap, GroupNetwork, GroupDetection, GroupObservability, GroupLimits,
		GroupCache, GroupQueue, GroupHTTP3, GroupInternal,
	}
	got := Groups()
	if len(got) != len(want) {
		t.Fatalf("groups = %d, want %d", len(got), len(want))
	}
	for i, group := range got {
		if group.Key != want[i] {
			t.Errorf("groups[%d] = %q, want %q", i, group.Key, want[i])
		}
		if group.LabelKey != "envOverrides.group."+want[i] {
			t.Errorf("groups[%d] label key = %q", i, group.LabelKey)
		}
	}

	// 每个键的域都必须在 groups[] 里出现，否则界面会丢掉整域。
	known := make(map[string]struct{}, len(want))
	for _, key := range want {
		known[key] = struct{}{}
	}
	for _, spec := range All() {
		if _, ok := known[spec.Group]; !ok {
			t.Errorf("key %q has an unknown group %q", spec.Key, spec.Group)
		}
	}
}

/**
 * TestDurationKeysReportDurationKind 断言三个时长键的类型是 duration，
 * 而不是被字符串类型吞掉（前端据此选择时长校验分支）。
 */
func TestDurationKeysReportDurationKind(t *testing.T) {
	for _, key := range durationKeys {
		spec, ok := Lookup(key)
		if !ok {
			t.Fatalf("duration key %q is not registered", key)
		}
		if spec.Kind != KindDuration {
			t.Errorf("key %q kind = %q, want %q", key, spec.Kind, KindDuration)
		}
		if string(spec.Kind) != "duration" {
			t.Errorf("key %q serialised type = %q, want duration", key, string(spec.Kind))
		}
		// 默认值必须是可解析的 duration 文本。
		text, ok := spec.DefaultValue.(string)
		if !ok || text == "" {
			t.Fatalf("key %q default = %#v, want a duration text", key, spec.DefaultValue)
		}
	}
}

/**
 * TestRestartRequiredMatchesContract 断言「启动固化」一档的键被标记为需重启，
 * 且热生效一档未被误标。
 *
 * 逐键取证见 internal/core/config_override.go 的各 apply*Overrides 段与
 * internal/snapshot/config_override_build_test.go：只有走快照重建的键才是热生效。
 */
func TestRestartRequiredMatchesContract(t *testing.T) {
	want := make(map[string]struct{}, len(restartRequiredKeys))
	for _, key := range restartRequiredKeys {
		want[key] = struct{}{}
	}
	var got []string
	for _, spec := range All() {
		if spec.RestartRequired {
			got = append(got, spec.Key)
		}
	}
	sort.Strings(got)

	gotSet := make(map[string]struct{}, len(got))
	for _, key := range got {
		gotSet[key] = struct{}{}
		if _, ok := want[key]; !ok {
			t.Errorf("key %q is marked restart_required but is not in the startup-fixed set", key)
		}
	}
	for _, key := range restartRequiredKeys {
		if _, ok := gotSet[key]; !ok {
			t.Errorf("key %q must be marked restart_required", key)
		}
	}

	// 热生效一档必须如实是 false：随 reload 生效的键标成需重启会让运维白重启。
	for _, key := range hotAppliedKeys {
		spec, ok := Lookup(key)
		if !ok {
			t.Fatalf("key %q is not registered", key)
		}
		if spec.RestartRequired {
			t.Errorf("key %q is hot-applied and must not be marked restart_required", key)
		}
		if !spec.IsWritable() {
			t.Errorf("key %q must be writable", key)
		}
	}
}

/**
 * TestEveryKeyHasAWritableOrJustifiedReadOnlyScope 断言 45 个键的可写性来源
 * 全部落在四档之内，且没有任何键停留在「只有环境变量载体」的未接管状态。
 *
 * 四档：runtime（可覆盖）/ delegated（专用端点）/ bootstrap（引导参数，不读库）/
 * test_only（测试与基准专用）。这一断言是契约「ScopeEnvOnly 迁空」的落点。
 */
func TestEveryKeyHasAWritableOrJustifiedReadOnlyScope(t *testing.T) {
	known := map[Scope]struct{}{
		ScopeRuntime:   {},
		ScopeDelegated: {},
		ScopeBootstrap: {},
		ScopeTestOnly:  {},
	}
	counts := map[Scope]int{}
	for _, spec := range All() {
		if _, ok := known[spec.Scope]; !ok {
			t.Errorf("key %q has an unrecognised scope %q", spec.Key, spec.Scope)
			continue
		}
		counts[spec.Scope]++
		if spec.Scope == ScopeBootstrap && !spec.RestartRequired {
			// 引导类不进可写清单，不需要 restart_required 语义。
			continue
		}
	}
	want := map[Scope]int{
		ScopeRuntime:   29,
		ScopeDelegated: 7,
		ScopeBootstrap: 7,
	}
	for scope, n := range want {
		if counts[scope] != n {
			t.Errorf("scope %q count = %d, want %d", scope, counts[scope], n)
		}
	}
	if counts[ScopeTestOnly] != 2 {
		t.Errorf("scope test_only count = %d, want 2", counts[ScopeTestOnly])
	}
}

/**
 * TestWritableSetMatchesContract 断言可写键集合：bootstrap 7 键、internal 2 键
 * 与 7 个 delegated 键不可写，其余可写。
 */
func TestWritableSetMatchesContract(t *testing.T) {
	readOnly := map[string]struct{}{}
	for _, spec := range All() {
		switch spec.Group {
		case GroupBootstrap, GroupInternal:
			readOnly[spec.Key] = struct{}{}
		}
	}
	for _, key := range []string{"redis_addr", "redis_password", "redis_db", "log_level", "log_file", "log_also_stdout", "h3_allow_0rtt"} {
		readOnly[key] = struct{}{}
		spec, _ := Lookup(key)
		if spec.Scope != ScopeDelegated {
			t.Errorf("key %q scope = %q, want delegated", key, spec.Scope)
		}
		if spec.DelegatedTo == "" {
			t.Errorf("key %q is delegated but has no delegated_to", key)
		}
	}
	// 专用端点路径逐条核对。
	for key, want := range map[string]string{
		"redis_addr":      "/api/v1/redis-config",
		"redis_password":  "/api/v1/redis-config",
		"redis_db":        "/api/v1/redis-config",
		"log_level":       "/api/v1/log-config",
		"log_file":        "/api/v1/log-config",
		"log_also_stdout": "/api/v1/log-config",
		"h3_allow_0rtt":   "/api/v1/tls-config",
	} {
		spec, _ := Lookup(key)
		if spec.DelegatedTo != want {
			t.Errorf("key %q delegated_to = %q, want %q", key, spec.DelegatedTo, want)
		}
	}

	count := 0
	for _, spec := range All() {
		_, wantReadOnly := readOnly[spec.Key]
		if got := spec.IsWritable(); got == wantReadOnly {
			t.Errorf("key %q IsWritable() = %v, want %v (scope %q)", spec.Key, got, !wantReadOnly, spec.Scope)
		}
		if spec.IsWritable() {
			count++
		}
	}
	if count != 45-len(readOnly) {
		t.Errorf("writable key count = %d, want %d", count, 45-len(readOnly))
	}
}

/**
 * TestResolveThreeStateMatrix 是逐键三态的核心机制断言：
 * 同一个键在「未覆盖 + 环境变量设了」「覆盖了 + 环境变量也设了」「未覆盖 + 环境变量没设」
 * 三种组合下的生效值与来源。
 */
func TestResolveThreeStateMatrix(t *testing.T) {
	spec, ok := Lookup("bot_threshold")
	if !ok {
		t.Fatal("bot_threshold must be registered")
	}

	cases := []struct {
		name         string
		envRaw       string
		envSet       bool
		overrides    Overrides
		wantValue    any
		wantSource   Source
		wantOverride bool
	}{
		{
			name:       "unset override with env set follows env",
			envRaw:     "42",
			envSet:     true,
			overrides:  Overrides{},
			wantValue:  int64(42),
			wantSource: SourceEnv,
		},
		{
			name:         "explicit override wins over env",
			envRaw:       "42",
			envSet:       true,
			overrides:    Overrides{"bot_threshold": int64(7)},
			wantValue:    int64(7),
			wantSource:   SourceDB,
			wantOverride: true,
		},
		{
			name:       "unset override with env unset falls back to default",
			envRaw:     "",
			envSet:     false,
			overrides:  Overrides{},
			wantValue:  int64(80),
			wantSource: SourceDefault,
		},
		{
			name:       "env defined but unusable falls back to default with a warning",
			envRaw:     "not-a-number",
			envSet:     true,
			overrides:  Overrides{},
			wantValue:  int64(80),
			wantSource: SourceDefault,
		},
		{
			// 显式设成默认值必须与「从未保存过」可区分：值相同，来源不同。
			name:         "override equal to the default is still db sourced",
			envRaw:       "42",
			envSet:       true,
			overrides:    Overrides{"bot_threshold": int64(80)},
			wantValue:    int64(80),
			wantSource:   SourceDB,
			wantOverride: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var warns []string
			entry := Resolve(spec, tt.overrides, tt.envRaw, tt.envSet, &warns)
			if entry.Value != tt.wantValue {
				t.Fatalf("value = %#v, want %#v", entry.Value, tt.wantValue)
			}
			if entry.Source != tt.wantSource {
				t.Fatalf("source = %q, want %q", entry.Source, tt.wantSource)
			}
			if entry.Overridden != tt.wantOverride {
				t.Fatalf("overridden = %v, want %v", entry.Overridden, tt.wantOverride)
			}
		})
	}
}

/**
 * TestResolveIncludesKeysWithoutEnvCarrier 断言无环境变量载体的三个键都能被覆盖，
 * 并断言未覆盖时采用内置默认值。
 */
func TestResolveIncludesKeysWithoutEnvCarrier(t *testing.T) {
	for key, want := range map[string]bool{
		"bot_enabled":            true,
		"cve_auto_drop_critical": true,
		"cve_auto_drop_high":     true,
	} {
		spec, ok := Lookup(key)
		if !ok {
			t.Fatalf("key %q must be registered", key)
		}
		if spec.Env != "" {
			t.Fatalf("key %q env = %q, want empty for a key without an environment carrier", key, spec.Env)
		}

		var warns []string
		entry := Resolve(spec, Overrides{key: false}, "", false, &warns)
		if entry.Value != false || entry.Source != SourceDB {
			t.Fatalf("key %q = %+v, want db-sourced false", key, entry)
		}
		entry = Resolve(spec, Overrides{}, "", false, &warns)
		if entry.Value != want || entry.Source != SourceDefault {
			t.Fatalf("key %q = %+v, want default-sourced %v", key, entry, want)
		}
	}
}

/**
 * TestParseStoredOverridesRejectsBrokenTable 断言整表 JSON 损坏时整体回落空覆盖，
 * 且不 panic。
 */
func TestParseStoredOverridesRejectsBrokenTable(t *testing.T) {
	var warns []string
	got := ParseStoredOverrides(`{"bot_threshold":`, &warns)
	if len(got) != 0 {
		t.Fatalf("overrides = %#v, want empty for broken JSON", got)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "not valid JSON") {
		t.Fatalf("warnings = %#v, want one JSON warning", warns)
	}

	if got := ParseStoredOverrides("", &warns); len(got) != 0 {
		t.Fatalf("overrides = %#v, want empty for an empty table", got)
	}
	if got := ParseStoredOverrides("null", &warns); len(got) != 0 {
		t.Fatalf("overrides = %#v, want empty for a null table", got)
	}
}

/**
 * TestParseStoredOverridesIgnoresBadKeys 逐条覆盖坏键的处置：
 * 未知键、类型不匹配、越界、未标 set、不可写的键。
 */
func TestParseStoredOverridesIgnoresBadKeys(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		wantKeys  []string
		wantWarn  string
		wantValue any
	}{
		{
			name:      "unknown key is ignored",
			raw:       `{"totally_unknown":{"value":1,"set":true},"bot_threshold":{"value":55,"set":true}}`,
			wantKeys:  []string{"bot_threshold"},
			wantWarn:  "unknown key",
			wantValue: int64(55),
		},
		{
			name:      "type mismatch is ignored",
			raw:       `{"cve_enabled":{"value":"yes-please","set":true},"bot_threshold":{"value":55,"set":true}}`,
			wantKeys:  []string{"bot_threshold"},
			wantWarn:  "unusable",
			wantValue: int64(55),
		},
		{
			name:      "above the hard limit is ignored",
			raw:       `{"queue_batch_size":{"value":999999,"set":true}}`,
			wantKeys:  nil,
			wantWarn:  "exceeds the maximum",
			wantValue: nil,
		},
		{
			name:      "below the minimum is ignored",
			raw:       `{"queue_batch_size":{"value":0,"set":true}}`,
			wantKeys:  nil,
			wantWarn:  "below the minimum",
			wantValue: nil,
		},
		{
			name:      "entry without the set marker is ignored",
			raw:       `{"bot_threshold":{"value":55,"set":false}}`,
			wantKeys:  nil,
			wantWarn:  "not marked as set",
			wantValue: nil,
		},
		{
			name:      "bootstrap key is not overridable",
			raw:       `{"admin_bind":{"value":":8080","set":true}}`,
			wantKeys:  nil,
			wantWarn:  "non-overridable",
			wantValue: nil,
		},
		{
			name:      "internal key is not overridable",
			raw:       `{"h2ws_peeker_off":{"value":"1","set":true}}`,
			wantKeys:  nil,
			wantWarn:  "non-overridable",
			wantValue: nil,
		},
		{
			name:      "delegated key is not overridable",
			raw:       `{"h3_allow_0rtt":{"value":"on","set":true}}`,
			wantKeys:  nil,
			wantWarn:  "non-overridable",
			wantValue: nil,
		},
		{
			name:      "bool given as a JSON string is accepted",
			raw:       `{"cve_enabled":{"value":"true","set":true}}`,
			wantKeys:  []string{"cve_enabled"},
			wantWarn:  "",
			wantValue: true,
		},
		{
			name:      "duration given as text is normalised",
			raw:       `{"queue_flush_interval":{"value":"1000ms","set":true}}`,
			wantKeys:  []string{"queue_flush_interval"},
			wantWarn:  "",
			wantValue: "1s",
		},
		{
			name:      "unparsable duration is ignored",
			raw:       `{"queue_write_interval":{"value":"soon","set":true}}`,
			wantKeys:  nil,
			wantWarn:  "not a valid duration",
			wantValue: nil,
		},
		{
			name:      "duration above the declared maximum is ignored",
			raw:       `{"queue_flush_interval":{"value":"90s","set":true}}`,
			wantKeys:  nil,
			wantWarn:  "exceeds the maximum",
			wantValue: nil,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var warns []string
			got := ParseStoredOverrides(tt.raw, &warns)
			if len(got) != len(tt.wantKeys) {
				t.Fatalf("overrides = %#v, want keys %#v", got, tt.wantKeys)
			}
			for _, key := range tt.wantKeys {
				value, ok := got[key]
				if !ok {
					t.Fatalf("overrides = %#v, missing key %q", got, key)
				}
				if value != tt.wantValue {
					t.Fatalf("overrides[%q] = %#v, want %#v", key, value, tt.wantValue)
				}
			}
			if tt.wantWarn == "" {
				if len(warns) != 0 {
					t.Fatalf("warnings = %#v, want none", warns)
				}
				return
			}
			if len(warns) == 0 || !strings.Contains(strings.Join(warns, "\n"), tt.wantWarn) {
				t.Fatalf("warnings = %#v, want one containing %q", warns, tt.wantWarn)
			}
		})
	}
}

/**
 * TestParseStoredOverridesNeverPanics 用一组畸形输入钉住「坏数据不会让进程起不来」。
 */
func TestParseStoredOverridesNeverPanics(t *testing.T) {
	inputs := []string{
		"",
		"   ",
		"[]",
		"123",
		`"a string"`,
		`{"bot_threshold":null}`,
		`{"bot_threshold":{}}`,
		`{"bot_threshold":{"value":null,"set":true}}`,
		`{"bot_threshold":{"value":[1,2],"set":true}}`,
		`{"bot_threshold":{"value":1.5,"set":true}}`,
		`{"queue_flush_interval":{"value":"not-a-duration","set":true}}`,
		`{"queue_flush_interval":{"value":3,"set":true}}`,
		`{"log_level":{"value":"nope","set":true}}`,
	}
	for _, input := range inputs {
		var warns []string
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ParseStoredOverrides(%q) panicked: %v", input, r)
				}
			}()
			_ = ParseStoredOverrides(input, &warns)
		}()
	}
}

/**
 * TestEncodeStoredOverridesRoundTrip 断言编码出的存储形态能被解析回同一组取值，
 * 且输出顺序稳定（同一份覆盖表两次编码逐字节一致）。
 */
func TestEncodeStoredOverridesRoundTrip(t *testing.T) {
	values := Overrides{
		"bot_threshold":        int64(55),
		"cve_enabled":          true,
		"geoip_db_path":        "/tmp/GeoLite2-City.mmdb",
		"queue_flush_interval": "3s",
	}
	first, err := EncodeStoredOverrides(values)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	second, err := EncodeStoredOverrides(values)
	if err != nil {
		t.Fatalf("encode again: %v", err)
	}
	if first != second {
		t.Fatalf("encoding is not stable:\n%s\n%s", first, second)
	}
	if !strings.Contains(first, `"set":true`) {
		t.Fatalf("encoded = %s, want the set marker preserved", first)
	}

	var warns []string
	back := ParseStoredOverrides(first, &warns)
	if len(warns) != 0 {
		t.Fatalf("warnings = %#v, want none on a round trip", warns)
	}
	if len(back) != len(values) {
		t.Fatalf("round trip = %#v, want %#v", back, values)
	}
	for key, want := range values {
		if back[key] != want {
			t.Fatalf("round trip[%q] = %#v, want %#v", key, back[key], want)
		}
	}

	empty, err := EncodeStoredOverrides(Overrides{})
	if err != nil || empty != "{}" {
		t.Fatalf("empty encode = %q err %v, want {}", empty, err)
	}
}

/**
 * TestParseSubmitValueAcceptsEveryWritableKind 断言四种类型的写入口径：
 * bool / int / string / duration 各一条，且不可写键被一律拒绝。
 */
func TestParseSubmitValueAcceptsEveryWritableKind(t *testing.T) {
	cases := []struct {
		key  string
		raw  string
		want any
	}{
		{key: "cve_enabled", raw: `true`, want: true},
		{key: "bot_threshold", raw: `55`, want: int64(55)},
		{key: "geoip_db_path", raw: `"/tmp/x.mmdb"`, want: "/tmp/x.mmdb"},
		{key: "queue_write_interval", raw: `"25ms"`, want: "25ms"},
	}
	for _, tt := range cases {
		spec, ok := Lookup(tt.key)
		if !ok {
			t.Fatalf("key %q is not registered", tt.key)
		}
		value, err := ParseSubmitValue(spec, []byte(tt.raw))
		if err != nil {
			t.Errorf("ParseSubmitValue(%q, %s): %v", tt.key, tt.raw, err)
			continue
		}
		if value != tt.want {
			t.Errorf("ParseSubmitValue(%q, %s) = %#v, want %#v", tt.key, tt.raw, value, tt.want)
		}
	}

	for _, key := range []string{"admin_bind", "h2ws_peeker_off", "h3_allow_0rtt", "log_color"} {
		spec, _ := Lookup(key)
		if _, err := ParseSubmitValue(spec, []byte(`"whatever"`)); err == nil {
			t.Errorf("key %q must be rejected by ParseSubmitValue", key)
		}
	}
}

/**
 * TestRegistryCoversEveryProductionEnvVar 断言注册表覆盖了全部生产代码读取的
 * MY_OPENWAF_* 环境变量名，避免新增环境变量时漏登记。
 *
 * 清单来自对 internal/ 与 cmd/ 的环境变量字面量扫描。契约明确不返回的三个
 * 测试专用变量（MY_OPENWAF_TEST_HELPER_PROCESS / MY_OPENWAF_TEST_MYSQL_DSN /
 * MY_OPENWAF_TEST_POSTGRES_DSN）以及两个历史别名（MY_OPENWAF_DB /
 * MY_OPENWAF_LOG_DB）不在注册表内：别名关系写进 dsn / log_dsn 的说明里。
 */
func TestRegistryCoversEveryProductionEnvVar(t *testing.T) {
	want := []string{
		"MY_OPENWAF_ACCESSLOG_SAMPLING",
		"MY_OPENWAF_ADMIN_BIND",
		"MY_OPENWAF_ADMIN_STATIC_DIR",
		"MY_OPENWAF_BOT_THRESHOLD",
		"MY_OPENWAF_CAPTCHA_DIR",
		"MY_OPENWAF_CVE_AUTO_APPROVE",
		"MY_OPENWAF_CVE_ENABLED",
		"MY_OPENWAF_CVE_FEED_ENABLED",
		"MY_OPENWAF_CVE_FEED_INTERVAL",
		"MY_OPENWAF_DATA",
		"MY_OPENWAF_DB_DRIVER",
		"MY_OPENWAF_DROP_BOT_THRESHOLD",
		"MY_OPENWAF_DROP_ENABLED",
		"MY_OPENWAF_DSN",
		"MY_OPENWAF_FINGERPRINT_BENCH_DB",
		"MY_OPENWAF_GEOIP_DB",
		"MY_OPENWAF_H2WS_PEEKER_OFF",
		"MY_OPENWAF_H3_ALLOW_0RTT",
		"MY_OPENWAF_JWT_SECRET",
		"MY_OPENWAF_LOG_ALSO_STDOUT",
		"MY_OPENWAF_LOG_COLOR",
		"MY_OPENWAF_LOG_DSN",
		"MY_OPENWAF_LOG_FILE",
		"MY_OPENWAF_LOG_LEVEL",
		"MY_OPENWAF_NVD_API_KEY",
		"MY_OPENWAF_PPROF_BIND",
		"MY_OPENWAF_QUEUE_BATCH_SIZE",
		"MY_OPENWAF_QUEUE_DROP_BUFFER_SIZE",
		"MY_OPENWAF_QUEUE_EVENT_BUFFER_SIZE",
		"MY_OPENWAF_QUEUE_FLUSH_INTERVAL",
		"MY_OPENWAF_QUEUE_WRITE_BATCH_SIZE",
		"MY_OPENWAF_QUEUE_WRITE_CAPACITY",
		"MY_OPENWAF_QUEUE_WRITE_INTERVAL",
		"MY_OPENWAF_REDIS_ADDR",
		"MY_OPENWAF_REDIS_DB",
		"MY_OPENWAF_REDIS_PASSWORD",
		"MY_OPENWAF_REQUEST_DECOMPRESS_LIMIT_BYTES",
		"MY_OPENWAF_RESPONSE_CACHE_MB",
		"MY_OPENWAF_RESPONSE_CACHE_TTL_SEC",
		"MY_OPENWAF_RESPONSE_DECOMPRESS_LIMIT_BYTES",
		"MY_OPENWAF_TRACE_ENABLED",
		"MY_OPENWAF_TRACE_LEVEL",
	}
	registered := make(map[string]struct{})
	for _, spec := range All() {
		if spec.Env != "" {
			registered[spec.Env] = struct{}{}
		}
	}
	for _, env := range want {
		if _, ok := registered[env]; !ok {
			t.Errorf("environment variable %s is not registered", env)
		}
	}

	// 契约明确排除的键不得出现在注册表里。
	for _, key := range []string{"db", "log_db", "test_helper_process", "test_mysql_dsn", "test_postgres_dsn"} {
		if _, ok := Lookup(key); ok {
			t.Errorf("key %q must not be returned by the registry", key)
		}
	}
}

/**
 * TestRegistryRejectsDuplicateEnvNamesAndKeys 断言注册表没有重复的键名与环境变量名。
 */
func TestRegistryRejectsDuplicateEnvNamesAndKeys(t *testing.T) {
	keys := make(map[string]struct{})
	envs := make(map[string]string)
	for _, spec := range All() {
		if _, ok := keys[spec.Key]; ok {
			t.Fatalf("duplicate key %q", spec.Key)
		}
		keys[spec.Key] = struct{}{}
		if spec.Env == "" {
			continue
		}
		if owner, ok := envs[spec.Env]; ok {
			t.Fatalf("environment variable %s is registered twice: %q and %q", spec.Env, owner, spec.Key)
		}
		envs[spec.Env] = spec.Key
	}
}

/**
 * TestResolveAllUsesInjectedLookup 断言 ResolveAll 只通过注入的查询函数读环境，
 * 不直接摸进程环境，从而让测试可以完全控制三态。
 */
func TestResolveAllUsesInjectedLookup(t *testing.T) {
	lookup := func(name string) (string, bool) {
		if name == "MY_OPENWAF_BOT_THRESHOLD" {
			return "37", true
		}
		return "", false
	}
	var warns []string
	entries := ResolveAll(Overrides{}, lookup, &warns)
	if got := entries["bot_threshold"]; got.Value != int64(37) || got.Source != SourceEnv {
		t.Fatalf("bot_threshold = %+v, want env-sourced 37", got)
	}
	// 环境变量没设的键必须落到内置默认值，而不是零值。
	if got := entries["queue_batch_size"]; got.Value != int64(4096) || got.Source != SourceDefault {
		t.Fatalf("queue_batch_size = %+v, want default-sourced 4096", got)
	}
}

/**
 * TestResolveAllDefaultsToProcessEnv 断言 lookup 传 nil 时使用进程环境。
 */
func TestResolveAllDefaultsToProcessEnv(t *testing.T) {
	t.Setenv("MY_OPENWAF_QUEUE_BATCH_SIZE", "512")
	var warns []string
	entries := ResolveAll(Overrides{}, nil, &warns)
	if got := entries["queue_batch_size"]; got.Value != int64(512) || got.Source != SourceEnv {
		t.Fatalf("queue_batch_size = %+v, want env-sourced 512", got)
	}
}

/**
 * TestEnvParsersMatchLegacySemantics 逐条钉住各环境变量解析器的既有口径：
 * 改动解析口径等于改动「未覆盖时的行为」，属于验收线禁止的范畴。
 */
func TestEnvParsersMatchLegacySemantics(t *testing.T) {
	cases := []struct {
		key    string
		envRaw string
		want   any
	}{
		// 只有字面 true 才开（CVE_ENABLED / TRACE_ENABLED）。
		{key: "cve_enabled", envRaw: "TRUE", want: true},
		{key: "cve_enabled", envRaw: "1", want: false},
		{key: "cve_enabled", envRaw: "yes", want: false},
		{key: "trace_enabled", envRaw: "True", want: true},
		{key: "trace_enabled", envRaw: "on", want: false},
		// 只有字面 false 才关（DROP_ENABLED）。
		{key: "drop_enabled", envRaw: "false", want: false},
		{key: "drop_enabled", envRaw: "FALSE", want: false},
		{key: "drop_enabled", envRaw: "0", want: true},
		// 只有 1 为真（LOG_ALSO_STDOUT）。
		{key: "log_also_stdout", envRaw: "1", want: true},
		{key: "log_also_stdout", envRaw: "true", want: false},
		// 正整数才生效。
		{key: "bot_threshold", envRaw: "0", want: nil},
		{key: "bot_threshold", envRaw: "-5", want: nil},
		{key: "bot_threshold", envRaw: "90", want: int64(90)},
		// 采样率必须 >= 1。
		{key: "accesslog_sampling", envRaw: "0", want: nil},
		{key: "accesslog_sampling", envRaw: "10", want: int64(10)},
		// 时长文本规范化。
		{key: "queue_flush_interval", envRaw: "1s", want: "1s"},
		{key: "queue_flush_interval", envRaw: "500ms", want: "500ms"},
		{key: "queue_flush_interval", envRaw: "3", want: nil},
		{key: "cve_feed_interval", envRaw: "90m", want: "1h30m0s"},
		{key: "cve_feed_interval", envRaw: "six-hours", want: nil},
		// 白名单。
		{key: "trace_level", envRaw: "BASE", want: "base"},
		{key: "trace_level", envRaw: "verbose", want: nil},
		// h3 0-RTT 三态。
		{key: "h3_allow_0rtt", envRaw: "1", want: "on"},
		{key: "h3_allow_0rtt", envRaw: "0", want: "off"},
		{key: "h3_allow_0rtt", envRaw: "anything", want: "auto"},
		// 解压上限必须为正 int64。
		{key: "request_decompress_limit_bytes", envRaw: "0", want: nil},
		{key: "request_decompress_limit_bytes", envRaw: "1048576", want: int64(1048576)},
		// REDIS_DB 解析失败按 0。
		{key: "redis_db", envRaw: "abc", want: int64(0)},
		{key: "redis_db", envRaw: "3", want: int64(3)},
		// 日志着色只认 1 / true。
		{key: "log_color", envRaw: "true", want: "on"},
		{key: "log_color", envRaw: "0", want: "off"},
	}

	for _, tt := range cases {
		t.Run(tt.key+"="+tt.envRaw, func(t *testing.T) {
			spec, ok := Lookup(tt.key)
			if !ok {
				t.Fatalf("key %q is not registered", tt.key)
			}
			var warns []string
			entry := Resolve(spec, Overrides{}, tt.envRaw, true, &warns)
			if tt.want == nil {
				if entry.Source != SourceDefault {
					t.Fatalf("%s=%q resolved to %#v from %q, want the default", tt.key, tt.envRaw, entry.Value, entry.Source)
				}
				return
			}
			if entry.Source != SourceEnv {
				t.Fatalf("%s=%q source = %q, want env", tt.key, tt.envRaw, entry.Source)
			}
			if entry.Value != tt.want {
				t.Fatalf("%s=%q value = %#v, want %#v", tt.key, tt.envRaw, entry.Value, tt.want)
			}
		})
	}
}

/**
 * TestSecretKeysAreMarkedSecret 断言密钥类键被标记为不可回显。
 */
func TestSecretKeysAreMarkedSecret(t *testing.T) {
	for _, key := range []string{"nvd_api_key", "redis_password", "jwt_secret", "dsn", "log_dsn"} {
		spec, ok := Lookup(key)
		if !ok {
			t.Fatalf("key %q is not registered", key)
		}
		if !spec.Secret {
			t.Errorf("key %q must be marked as secret", key)
		}
	}
}

/**
 * TestLookupReturnsCopyOfRegistry 断言 All() 返回副本，调用方改动不会污染注册表。
 */
func TestLookupReturnsCopyOfRegistry(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("registry is empty")
	}
	original := all[0].Key
	all[0].Key = "mutated"
	fresh, _ := Lookup(original)
	if fresh.Key != original {
		t.Fatalf("registry entry was mutated: %q", fresh.Key)
	}
}

/**
 * TestResolveWarnsOnUnusableEnvForCustomValues 断言不可用的环境变量取值一定产生告警，
 * 不静默回落。
 */
func TestResolveWarnsOnUnusableEnvForCustomValues(t *testing.T) {
	spec, _ := Lookup("trace_level")
	var warns []string
	_ = Resolve(spec, Overrides{}, "verbose", true, &warns)
	if len(warns) != 1 || !strings.Contains(warns[0], "MY_OPENWAF_TRACE_LEVEL") {
		t.Fatalf("warnings = %#v, want one naming the environment variable", warns)
	}
}

/**
 * TestPackageDoesNotReadProcessEnvDirectly 是编译期约束的运行时补充：
 * 只有 ResolveAll 的 lookup 为 nil 时才允许访问进程环境。
 */
func TestPackageDoesNotReadProcessEnvDirectly(t *testing.T) {
	// 通过 os.Setenv 设置一个注册键，并确认只有显式传入的 lookup 才会看到它，
	// 直接调用 Resolve（不经过 ResolveAll）同样不读取进程环境。
	if err := os.Setenv("MY_OPENWAF_BOT_THRESHOLD", "12345"); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() { _ = os.Unsetenv("MY_OPENWAF_BOT_THRESHOLD") })

	spec, _ := Lookup("bot_threshold")
	var warns []string
	entry := Resolve(spec, Overrides{}, "", false, &warns)
	if entry.Source != SourceDefault {
		t.Fatalf("source = %q, want default: Resolve must not read the process environment", entry.Source)
	}
}
