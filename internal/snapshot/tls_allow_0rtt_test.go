package snapshot

import (
	"strings"
	"testing"
)

// TestLoadTLSDefaultsAllow0RTTTriState 钉住 allow_0rtt 的三态加载语义。
//
// 未显式配置必须与「显式 false」可区分：前者 HasExplicitAllow0RTT=false，
// 运行态回落 session_tickets_enabled；后者是明确的关闭决定。
func TestLoadTLSDefaultsAllow0RTTTriState(t *testing.T) {
	cases := []struct {
		name             string
		raw              string
		wantValue        bool
		wantExplicitFlag bool
	}{
		{name: "field_absent_is_not_explicit", raw: `{"session_tickets_enabled":true}`, wantValue: false, wantExplicitFlag: false},
		{name: "empty_object_is_not_explicit", raw: `{}`, wantValue: false, wantExplicitFlag: false},
		{name: "explicit_true", raw: `{"allow_0rtt":true}`, wantValue: true, wantExplicitFlag: true},
		{name: "explicit_false_is_not_absence", raw: `{"allow_0rtt":false}`, wantValue: false, wantExplicitFlag: true},
		{name: "explicit_false_with_tickets_on", raw: `{"allow_0rtt":false,"session_tickets_enabled":true}`, wantValue: false, wantExplicitFlag: true},
		{name: "explicit_true_with_tickets_off", raw: `{"allow_0rtt":true,"session_tickets_enabled":false}`, wantValue: true, wantExplicitFlag: true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := LoadTLSDefaults(tt.raw)
			if got.Allow0RTT != tt.wantValue {
				t.Fatalf("LoadTLSDefaults(%s).Allow0RTT = %v, want %v", tt.raw, got.Allow0RTT, tt.wantValue)
			}
			if got.HasExplicitAllow0RTT != tt.wantExplicitFlag {
				t.Fatalf("LoadTLSDefaults(%s).HasExplicitAllow0RTT = %v, want %v", tt.raw, got.HasExplicitAllow0RTT, tt.wantExplicitFlag)
			}
			// 未显式配置时不得把 Allow0RTT 写成 true，否则「继承」会被误读成「显式开」。
			if !tt.wantExplicitFlag && got.Allow0RTT {
				t.Fatalf("LoadTLSDefaults(%s) must not materialise an inherited allow_0rtt: %+v", tt.raw, got)
			}
		})
	}
}

// TestDefaultTLSDefaultsAllow0RTTIsInherited 确认默认配置不引入显式 0-RTT 决定。
//
// 默认值一旦变成「显式 true」，任何 store 缺省路径都会绕过 session_tickets_enabled。
func TestDefaultTLSDefaultsAllow0RTTIsInherited(t *testing.T) {
	defaults := DefaultTLSDefaults()
	if defaults.HasExplicitAllow0RTT {
		t.Fatalf("DefaultTLSDefaults must not mark allow_0rtt explicit: %+v", defaults)
	}
	if defaults.Allow0RTT {
		t.Fatalf("DefaultTLSDefaults must keep Allow0RTT at the zero value: %+v", defaults)
	}
}

// TestEffectiveAllow0RTT 覆盖三态在运行态折叠后的取值。
func TestEffectiveAllow0RTT(t *testing.T) {
	cases := []struct {
		name     string
		defaults TLSDefaults
		want     bool
	}{
		{
			name:     "unset_inherits_tickets_on",
			defaults: TLSDefaults{SessionTicketsEnabled: true},
			want:     true,
		},
		{
			name:     "unset_inherits_tickets_off",
			defaults: TLSDefaults{SessionTicketsEnabled: false},
			want:     false,
		},
		{
			name:     "explicit_true_ignores_tickets_off",
			defaults: TLSDefaults{SessionTicketsEnabled: false, Allow0RTT: true, HasExplicitAllow0RTT: true},
			want:     true,
		},
		{
			name:     "explicit_false_overrides_tickets_on",
			defaults: TLSDefaults{SessionTicketsEnabled: true, Allow0RTT: false, HasExplicitAllow0RTT: true},
			want:     false,
		},
		{
			name:     "explicit_true_with_tickets_on",
			defaults: TLSDefaults{SessionTicketsEnabled: true, Allow0RTT: true, HasExplicitAllow0RTT: true},
			want:     true,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.defaults.EffectiveAllow0RTT(); got != tt.want {
				t.Fatalf("EffectiveAllow0RTT() = %v, want %v (defaults=%+v)", got, tt.want, tt.defaults)
			}
		})
	}
}

// TestH3Allow0RTTUnsetIsByteEquivalentToSessionTickets 钉住「未显式配置即历史行为」。
//
// allow_0rtt 未显式配置时，H3Allow0RTT 必须与改动前只看 SessionTicketsEnabled
// 的判定逐 case 相同，否则既有部署会在升级后静默改变 0-RTT 暴露面。
func TestH3Allow0RTTUnsetIsByteEquivalentToSessionTickets(t *testing.T) {
	// historical 复刻改动前的判定口径。带空白的取值同样先 TrimSpace：
	// configoverride.parseH3Allow0RTT 会 TrimSpace，两侧口径必须一致，
	// 否则管理界面显示 on 而数据面按透传处理。
	historical := func(envValue string, sessionTicketsEnabled bool) bool {
		switch strings.TrimSpace(envValue) {
		case "1":
			return sessionTicketsEnabled
		case "0":
			return false
		default:
			return sessionTicketsEnabled
		}
	}

	for _, envValue := range []string{"", "1", "0", "true", "yes", "TRUE", " 1 ", " 0 ", "\t1\n"} {
		for _, tickets := range []bool{true, false} {
			name := "env=" + envValue + "/tickets=" + boolName(tickets)
			t.Run(name, func(t *testing.T) {
				defaults := TLSDefaults{SessionTicketsEnabled: tickets}
				if defaults.HasExplicitAllow0RTT {
					t.Fatalf("fixture must not be explicit: %+v", defaults)
				}
				want := historical(envValue, tickets)
				if got := H3Allow0RTT(envValue, defaults); got != want {
					t.Fatalf("H3Allow0RTT(%q, tickets=%v) = %v, want %v (historical behaviour)", envValue, tickets, got, want)
				}
			})
		}
	}
}

// TestH3Allow0RTTExplicitConfigSemantics 覆盖显式配置后的判定。
//
// env 缺省/非法时由 allow_0rtt 决定；"1" 仍受会话票据约束；"0" 恒关。
func TestH3Allow0RTTExplicitConfigSemantics(t *testing.T) {
	explicit := func(allow0RTT bool, tickets bool) TLSDefaults {
		return TLSDefaults{
			SessionTicketsEnabled: tickets,
			Allow0RTT:             allow0RTT,
			HasExplicitAllow0RTT:  true,
		}
	}

	cases := []struct {
		name     string
		envValue string
		defaults TLSDefaults
		want     bool
	}{
		{name: "unset_env_explicit_on_tickets_off", envValue: "", defaults: explicit(true, false), want: true},
		{name: "unset_env_explicit_off_tickets_on", envValue: "", defaults: explicit(false, true), want: false},
		{name: "garbage_env_explicit_on_tickets_off", envValue: "true", defaults: explicit(true, false), want: true},
		{name: "garbage_env_explicit_off_tickets_on", envValue: "true", defaults: explicit(false, true), want: false},
		{name: "env_one_still_bounded_by_tickets_off", envValue: "1", defaults: explicit(true, false), want: false},
		{name: "env_one_with_tickets_on", envValue: "1", defaults: explicit(true, true), want: true},
		{name: "env_zero_forces_off_despite_explicit_on", envValue: "0", defaults: explicit(true, true), want: false},
		{name: "env_zero_with_explicit_off", envValue: "0", defaults: explicit(false, true), want: false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := H3Allow0RTT(tt.envValue, tt.defaults); got != tt.want {
				t.Fatalf("H3Allow0RTT(%q, %+v) = %v, want %v", tt.envValue, tt.defaults, got, tt.want)
			}
		})
	}
}

// TestH3Allow0RTTEnvKeyMatchesDocumentedName 防止常量与文档中的变量名漂移。
func TestH3Allow0RTTEnvKeyMatchesDocumentedName(t *testing.T) {
	if H3Allow0RTTEnvKey != "MY_OPENWAF_H3_ALLOW_0RTT" {
		t.Fatalf("H3Allow0RTTEnvKey = %q, want MY_OPENWAF_H3_ALLOW_0RTT", H3Allow0RTTEnvKey)
	}
}

func boolName(v bool) string {
	if v {
		return "on"
	}
	return "off"
}
