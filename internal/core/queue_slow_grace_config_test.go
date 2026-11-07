package core

import (
	"strings"
	"testing"
	"time"
)

// SlowLogGraceDuration 的解析与钳制用例。
//
// 该旋钮决定 UnifiedWriter 在队列满时是否等待消费者。默认 30s（开启等待）；
// 环境变量显式设 0 表示关闭、退回参数化前的「满即丢弃」语义。因为它直接决定
// DB 持续跟不上时请求能被拖慢多久，默认值、上界与告警口径都必须被测试锁住。

func TestSlowLogGraceEnvParsing(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		want         time.Duration
		wantDisabled bool
	}{
		{"unset uses enabled default", "", 0, false},
		{"positive duration", "12s", 12 * time.Second, false},
		{"minutes", "2m", 2 * time.Minute, false},
		{"zero is explicit disable", "0s", 0, true},
		{"unparsable keeps default with warning", "not-a-duration", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MY_OPENWAF_QUEUE_SLOW_LOG_GRACE", tc.raw)
			cfg := LoadConfigFromEnv()
			if cfg.Queue.SlowLogGraceDuration != tc.want {
				t.Errorf("SlowLogGraceDuration = %s, want %s", cfg.Queue.SlowLogGraceDuration, tc.want)
			}
			if cfg.Queue.SlowLogGraceDisabled != tc.wantDisabled {
				t.Errorf("SlowLogGraceDisabled = %v, want %v", cfg.Queue.SlowLogGraceDisabled, tc.wantDisabled)
			}
			warned := hasQueueWarning(cfg.QueueWarnings, "MY_OPENWAF_QUEUE_SLOW_LOG_GRACE")
			wantWarn := tc.raw == "not-a-duration"
			if warned != wantWarn {
				t.Errorf("warning present = %v, want %v (warnings: %v)", warned, wantWarn, cfg.QueueWarnings)
			}
		})
	}
}

func TestSlowLogGraceClamp(t *testing.T) {
	tests := []struct {
		name         string
		in           time.Duration
		disabled     bool
		want         time.Duration
		wantDisabled bool
		warns        bool
	}{
		{"unset stays zero (consumed as default)", 0, false, 0, false, false},
		{"in range kept", 30 * time.Second, false, 30 * time.Second, false, false},
		{"at limit kept", queueMaxSlowLogGrace, false, queueMaxSlowLogGrace, false, false},
		{"explicit zero keeps disable", 0, true, 0, true, false},
		{"negative becomes unset", -time.Minute, false, 0, false, true},
		{"over limit clamped", time.Hour, false, queueMaxSlowLogGrace, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultQueueConfig()
			cfg.SlowLogGraceDuration = tc.in
			cfg.SlowLogGraceDisabled = tc.disabled
			got, warns := clampQueueConfig(cfg)
			if got.SlowLogGraceDuration != tc.want {
				t.Errorf("SlowLogGraceDuration = %s, want %s", got.SlowLogGraceDuration, tc.want)
			}
			if got.SlowLogGraceDisabled != tc.wantDisabled {
				t.Errorf("SlowLogGraceDisabled = %v, want %v", got.SlowLogGraceDisabled, tc.wantDisabled)
			}
			if (len(warns) > 0) != tc.warns {
				t.Errorf("warns = %v, want warns=%v", warns, tc.warns)
			}
		})
	}
}

// TestSlowLogGraceEffectiveDefaultIsNonBlocking 守护「不设环境变量即不阻塞请求」：
// QueueConfig 上的 0 是「未配置」，运行时生效值必须是 0，即队列满立即丢弃并计数，
// 绝不能让可观测性背压挂住请求 goroutine。需要等待语义的部署必须显式配置正数。
func TestSlowLogGraceEffectiveDefaultIsNonBlocking(t *testing.T) {
	if defaultSlowLogGraceDuration != 0 {
		t.Fatalf("defaultSlowLogGraceDuration = %s, want 0 (non-blocking request path)", defaultSlowLogGraceDuration)
	}
	cfg := LoadConfigFromEnv()
	if cfg.Queue.SlowLogGraceDisabled {
		t.Fatal("unset MY_OPENWAF_QUEUE_SLOW_LOG_GRACE must not be reported as explicitly disabled")
	}
}

// TestDefaultQueueConfigSlowLogGraceIsNonBlocking 守护默认行为符合用户要求：
// 不设任何环境变量时不得让请求路径等待日志消费者，运行时生效值必须为 0。
//
// QueueConfig 上的 0 是「未配置」而不是「显式关闭」——生效值由 observability 侧
// 折算（observability.defaultSlowLogGrace，本文件的 defaultSlowLogGraceDuration
// 是它的镜像常量），因此这里断言的是「未显式关闭」+「镜像常量为 0」。
func TestDefaultQueueConfigSlowLogGraceIsNonBlocking(t *testing.T) {
	def := DefaultQueueConfig()
	if def.SlowLogGraceDisabled {
		t.Fatal("DefaultQueueConfig().SlowLogGraceDisabled = true, want false (unset is not explicit disable)")
	}
	if defaultSlowLogGraceDuration != 0 {
		t.Fatalf("defaultSlowLogGraceDuration = %s, want 0 so the request path never blocks on log backpressure",
			defaultSlowLogGraceDuration)
	}
	if def.SlowLogGraceDuration != 0 {
		t.Fatalf("DefaultQueueConfig().SlowLogGraceDuration = %s, want 0", def.SlowLogGraceDuration)
	}
}

func hasQueueWarning(warns []string, name string) bool {
	for _, w := range warns {
		if strings.Contains(w, name) {
			return true
		}
	}
	return false
}
