package core

import (
	"strings"
	"testing"
	"time"
)

// TestDefaultQueueConfigMatchesLegacyConstants 守护「可配置化不改变既有行为」这一
// 前提：默认值必须逐项等于参数化之前 internal/observability 里的硬编码常量。
// 任何一项漂移都会让未设置环境变量的现网部署静默改变队列容量或事务体积。
func TestDefaultQueueConfigMatchesLegacyConstants(t *testing.T) {
	def := DefaultQueueConfig()

	tests := []struct {
		name string
		got  any
		want any
	}{
		// eventCh / accessCh 原容量。
		{"EventBufferSize", def.EventBufferSize, 16384},
		// dropCh / botScoreCh 原容量。
		{"DropBufferSize", def.DropBufferSize, 8192},
		// 原 unifiedWriterBatchSize。
		{"BatchSize", def.BatchSize, 512},
		// 原 NewUnifiedWriter 内的 flushInterval。
		{"FlushInterval", def.FlushInterval, 3 * time.Second},
		// 原 WriteQueue.maxBatchSize。
		{"WriteQueueBatchSize", def.WriteQueueBatchSize, 64},
		// 原 NewWriteQueue 内的 channel 容量。
		{"WriteQueueCapacity", def.WriteQueueCapacity, 256},
		// 原 WriteQueue.batchInterval。
		{"WriteQueueInterval", def.WriteQueueInterval, 50 * time.Millisecond},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}

// TestDefaultQueueConfigIsAlreadyClamped 保证默认值本身不触发任何钳制告警。
// 若默认值落在钳制范围外，未设置环境变量的部署会在每次启动时刷出无意义的 WARN。
func TestDefaultQueueConfigIsAlreadyClamped(t *testing.T) {
	got, warns := clampQueueConfig(DefaultQueueConfig())

	if len(warns) != 0 {
		t.Errorf("clampQueueConfig(DefaultQueueConfig()) warnings = %v, want none", warns)
	}
	if got != DefaultQueueConfig() {
		t.Errorf("clampQueueConfig(DefaultQueueConfig()) = %+v, want unchanged", got)
	}
}

// TestLoadConfigFromEnvReadsQueueValues 校验七个环境变量都被读取到对应字段，
// 且合法值不产生告警。取值刻意与默认值不同，避免「读没读到都一样」的假通过。
func TestLoadConfigFromEnvReadsQueueValues(t *testing.T) {
	t.Setenv("MY_OPENWAF_QUEUE_EVENT_BUFFER_SIZE", "32768")
	t.Setenv("MY_OPENWAF_QUEUE_DROP_BUFFER_SIZE", "16384")
	t.Setenv("MY_OPENWAF_QUEUE_BATCH_SIZE", "1024")
	t.Setenv("MY_OPENWAF_QUEUE_FLUSH_INTERVAL", "1s")
	t.Setenv("MY_OPENWAF_QUEUE_WRITE_BATCH_SIZE", "128")
	t.Setenv("MY_OPENWAF_QUEUE_WRITE_CAPACITY", "512")
	t.Setenv("MY_OPENWAF_QUEUE_WRITE_INTERVAL", "20ms")

	cfg := LoadConfigFromEnv()

	want := QueueConfig{
		EventBufferSize:     32768,
		DropBufferSize:      16384,
		BatchSize:           1024,
		FlushInterval:       time.Second,
		WriteQueueBatchSize: 128,
		WriteQueueCapacity:  512,
		WriteQueueInterval:  20 * time.Millisecond,
	}
	if cfg.Queue != want {
		t.Errorf("Queue = %+v, want %+v", cfg.Queue, want)
	}
	if len(cfg.QueueWarnings) != 0 {
		t.Errorf("QueueWarnings = %v, want none for valid values", cfg.QueueWarnings)
	}
}

// TestLoadConfigFromEnvUnsetQueueValuesUseDefaults 守护「不设置环境变量等于旧行为」。
func TestLoadConfigFromEnvUnsetQueueValuesUseDefaults(t *testing.T) {
	// t.Setenv 空串等价于「已设置但为空」，而 LoadConfigFromEnv 对空串走 TrimSpace
	// 后跳过分支，与未设置同路径。这里显式置空以隔离宿主环境已有的取值。
	for _, name := range queueEnvNames() {
		t.Setenv(name, "")
	}

	cfg := LoadConfigFromEnv()

	if cfg.Queue != DefaultQueueConfig() {
		t.Errorf("Queue = %+v, want %+v", cfg.Queue, DefaultQueueConfig())
	}
	if len(cfg.QueueWarnings) != 0 {
		t.Errorf("QueueWarnings = %v, want none", cfg.QueueWarnings)
	}
}

// TestLoadConfigFromEnvQueueOutOfRangeFallsBack 覆盖三类越界输入：0、负数、非数字。
// 断言三点：不 panic、回退到默认值、每项都留下告警。
func TestLoadConfigFromEnvQueueOutOfRangeFallsBack(t *testing.T) {
	tests := []struct {
		name string
		env  string
		// 越界写法：0 / 负数 / 非数字 / 超上界。
		value string
		// 该环境变量对应字段的读取器，便于统一断言。
		read func(QueueConfig) any
		want any
	}{
		{"event buffer zero", "MY_OPENWAF_QUEUE_EVENT_BUFFER_SIZE", "0",
			func(q QueueConfig) any { return q.EventBufferSize }, 16384},
		{"event buffer negative", "MY_OPENWAF_QUEUE_EVENT_BUFFER_SIZE", "-1",
			func(q QueueConfig) any { return q.EventBufferSize }, 16384},
		{"event buffer not a number", "MY_OPENWAF_QUEUE_EVENT_BUFFER_SIZE", "abc",
			func(q QueueConfig) any { return q.EventBufferSize }, 16384},
		{"event buffer above hard limit", "MY_OPENWAF_QUEUE_EVENT_BUFFER_SIZE", "9999999",
			func(q QueueConfig) any { return q.EventBufferSize }, queueMaxChannelCapacity},

		{"drop buffer zero", "MY_OPENWAF_QUEUE_DROP_BUFFER_SIZE", "0",
			func(q QueueConfig) any { return q.DropBufferSize }, 8192},
		{"drop buffer negative", "MY_OPENWAF_QUEUE_DROP_BUFFER_SIZE", "-100",
			func(q QueueConfig) any { return q.DropBufferSize }, 8192},
		{"drop buffer not a number", "MY_OPENWAF_QUEUE_DROP_BUFFER_SIZE", "8k",
			func(q QueueConfig) any { return q.DropBufferSize }, 8192},

		{"batch size zero", "MY_OPENWAF_QUEUE_BATCH_SIZE", "0",
			func(q QueueConfig) any { return q.BatchSize }, 512},
		{"batch size negative", "MY_OPENWAF_QUEUE_BATCH_SIZE", "-512",
			func(q QueueConfig) any { return q.BatchSize }, 512},
		{"batch size above hard limit", "MY_OPENWAF_QUEUE_BATCH_SIZE", "50000",
			func(q QueueConfig) any { return q.BatchSize }, queueMaxBatchSize},

		{"flush interval zero", "MY_OPENWAF_QUEUE_FLUSH_INTERVAL", "0s",
			func(q QueueConfig) any { return q.FlushInterval }, 3 * time.Second},
		{"flush interval negative", "MY_OPENWAF_QUEUE_FLUSH_INTERVAL", "-5s",
			func(q QueueConfig) any { return q.FlushInterval }, 3 * time.Second},
		{"flush interval not a duration", "MY_OPENWAF_QUEUE_FLUSH_INTERVAL", "3",
			func(q QueueConfig) any { return q.FlushInterval }, 3 * time.Second},
		{"flush interval above hard limit", "MY_OPENWAF_QUEUE_FLUSH_INTERVAL", "10m",
			func(q QueueConfig) any { return q.FlushInterval }, queueMaxFlushInterval},

		{"write batch zero", "MY_OPENWAF_QUEUE_WRITE_BATCH_SIZE", "0",
			func(q QueueConfig) any { return q.WriteQueueBatchSize }, 64},
		{"write batch not a number", "MY_OPENWAF_QUEUE_WRITE_BATCH_SIZE", "64.5",
			func(q QueueConfig) any { return q.WriteQueueBatchSize }, 64},

		{"write capacity zero", "MY_OPENWAF_QUEUE_WRITE_CAPACITY", "0",
			func(q QueueConfig) any { return q.WriteQueueCapacity }, 256},
		{"write capacity negative", "MY_OPENWAF_QUEUE_WRITE_CAPACITY", "-256",
			func(q QueueConfig) any { return q.WriteQueueCapacity }, 256},

		{"write interval zero", "MY_OPENWAF_QUEUE_WRITE_INTERVAL", "0ms",
			func(q QueueConfig) any { return q.WriteQueueInterval }, 50 * time.Millisecond},
		{"write interval not a duration", "MY_OPENWAF_QUEUE_WRITE_INTERVAL", "fast",
			func(q QueueConfig) any { return q.WriteQueueInterval }, 50 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, name := range queueEnvNames() {
				t.Setenv(name, "")
			}
			t.Setenv(tt.env, tt.value)

			// 越界输入绝不能 panic：容量为负会在 make(chan) 处崩溃，
			// 因此回退必须发生在配置层而不是构造层。
			cfg := LoadConfigFromEnv()

			if got := tt.read(cfg.Queue); got != tt.want {
				t.Errorf("%s=%q → %v, want %v", tt.env, tt.value, got, tt.want)
			}
			if len(cfg.QueueWarnings) == 0 {
				t.Errorf("%s=%q produced no warning, want one", tt.env, tt.value)
			}
			for _, w := range cfg.QueueWarnings {
				if !strings.Contains(w, tt.env) {
					continue
				}
				return
			}
			t.Errorf("warnings %v mention no %s", cfg.QueueWarnings, tt.env)
		})
	}
}

// TestClampQueueConfigZeroValueWarnsEveryField 保证零值结构体（调用方漏了
// DefaultQueueConfig()）会被完整回退且逐项告警，而不是把 0 传到 make(chan)。
func TestClampQueueConfigZeroValueWarnsEveryField(t *testing.T) {
	got, warns := clampQueueConfig(QueueConfig{})

	if got != DefaultQueueConfig() {
		t.Errorf("clampQueueConfig(QueueConfig{}) = %+v, want %+v", got, DefaultQueueConfig())
	}
	// 七个字段全部越界，应产出七条告警。
	if want := len(queueEnvNames()); len(warns) != want {
		t.Errorf("warnings = %d (%v), want %d", len(warns), warns, want)
	}
}

// queueEnvNames 返回全部队列环境变量名，供各用例隔离宿主环境与统计字段数。
func queueEnvNames() []string {
	return []string{
		"MY_OPENWAF_QUEUE_EVENT_BUFFER_SIZE",
		"MY_OPENWAF_QUEUE_DROP_BUFFER_SIZE",
		"MY_OPENWAF_QUEUE_BATCH_SIZE",
		"MY_OPENWAF_QUEUE_FLUSH_INTERVAL",
		"MY_OPENWAF_QUEUE_WRITE_BATCH_SIZE",
		"MY_OPENWAF_QUEUE_WRITE_CAPACITY",
		"MY_OPENWAF_QUEUE_WRITE_INTERVAL",
	}
}
