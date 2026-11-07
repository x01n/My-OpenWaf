package system

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	snapshotpkg "My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store/repository"
)

// tlsDefaultsFixture 描述一份 TLS 全局默认配置的三态组合。
type tlsDefaultsFixture struct {
	sessionTickets    bool
	allow0RTT         bool
	explicitAllow0RTT bool
}

// snapshotDefaults 把 fixture 折叠成 snapshot 侧结构。
func (f tlsDefaultsFixture) snapshotDefaults() snapshotpkg.TLSDefaults {
	defaults := snapshotpkg.DefaultTLSDefaults()
	defaults.SessionTicketsEnabled = f.sessionTickets
	defaults.Allow0RTT = f.allow0RTT
	defaults.HasExplicitAllow0RTT = f.explicitAllow0RTT
	return defaults
}

// snapshotNetworkDefaultsFor0RTT 返回启用 HTTP/3 的网络默认配置。
func snapshotNetworkDefaultsFor0RTT() snapshotpkg.NetworkDefaults {
	defaults := snapshotpkg.DefaultNetworkDefaults()
	defaults.HTTP3Enabled = true
	return defaults
}

// tlsDefaultsFromStoredRow 按快照构建的同一路径读取库中的 TLS 默认配置。
func tlsDefaultsFromStoredRow(repo *repository.SystemSettingsRepo) (snapshotpkg.TLSDefaults, error) {
	val, err := repo.Get(settingKeyTLSDefault)
	if err != nil {
		return snapshotpkg.DefaultTLSDefaults(), err
	}
	return snapshotpkg.LoadTLSDefaults(val), nil
}

// seedTLSDefaultsAllow0RTT 写入一份 TLS 默认配置 JSON。
func seedTLSDefaultsAllow0RTT(t *testing.T, repo *repository.SystemSettingsRepo, raw string) {
	t.Helper()
	if err := repo.Set(settingKeyTLSDefault, raw); err != nil {
		t.Fatalf("seed TLS config: %v", err)
	}
}

// storedTLSDefaultsAllow0RTT 读回库中原始 JSON 并解出 allow_0rtt 相关字段。
func storedTLSDefaultsAllow0RTT(t *testing.T, repo *repository.SystemSettingsRepo) (value bool, explicit bool, present bool) {
	t.Helper()
	val, err := repo.Get(settingKeyTLSDefault)
	if err != nil {
		t.Fatalf("load TLS config: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(val), &raw); err != nil {
		t.Fatalf("decode TLS config: %v", err)
	}
	field, ok := raw["allow_0rtt"]
	if !ok {
		return false, false, false
	}
	var parsed bool
	if err := json.Unmarshal(field, &parsed); err != nil {
		t.Fatalf("decode allow_0rtt: %v", err)
	}
	return parsed, true, true
}

// TestUpdateTLSDefaultConfigPersistsAllow0RTT 覆盖 allow_0rtt 的三态写入与读回。
//
// 显式 true/false 落库为布尔值；显式 null 清除该键，回到继承
// session_tickets_enabled；省略字段则保持库中原值不动。
func TestUpdateTLSDefaultConfigPersistsAllow0RTT(t *testing.T) {
	t.Run("explicit_true_is_saved_and_reloaded", func(t *testing.T) {
		repo := newSystemSettingsRepoForTest(t)
		ctx := invokeSystemConfigHandler(t, UpdateTLSDefaultConfig(repo, func() error { return nil }), "POST", "/api/v1/tls-config", []byte(`{"allow_0rtt":true}`))
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		var resp TLSDefaultConfig
		if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if !resp.Allow0RTT || !resp.HasExplicitAllow0RTT {
			t.Fatalf("response = %#v, want allow_0rtt true and explicit", resp)
		}
		value, explicit, present := storedTLSDefaultsAllow0RTT(t, repo)
		if !present || !explicit || !value {
			t.Fatalf("stored allow_0rtt = (value=%v explicit=%v present=%v), want true/explicit/present", value, explicit, present)
		}

		// 重新加载必须读回同一决定。
		reloaded := loadTLSDefaultConfig(repo)
		if !reloaded.Allow0RTT || !reloaded.HasExplicitAllow0RTT {
			t.Fatalf("reloaded config = %#v, want explicit allow_0rtt=true", reloaded)
		}
	})

	t.Run("explicit_false_survives_reload", func(t *testing.T) {
		repo := newSystemSettingsRepoForTest(t)
		ctx := invokeSystemConfigHandler(t, UpdateTLSDefaultConfig(repo, func() error { return nil }), "POST", "/api/v1/tls-config", []byte(`{"allow_0rtt":false}`))
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		var resp TLSDefaultConfig
		if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp.Allow0RTT || !resp.HasExplicitAllow0RTT {
			t.Fatalf("response = %#v, want allow_0rtt false and explicit", resp)
		}
		value, explicit, present := storedTLSDefaultsAllow0RTT(t, repo)
		if !present || !explicit || value {
			t.Fatalf("stored allow_0rtt = (value=%v explicit=%v present=%v), want false/explicit/present", value, explicit, present)
		}
		reloaded := loadTLSDefaultConfig(repo)
		if reloaded.Allow0RTT || !reloaded.HasExplicitAllow0RTT {
			t.Fatalf("reloaded config = %#v, want explicit allow_0rtt=false", reloaded)
		}
	})

	t.Run("explicit_null_clears_back_to_inheritance", func(t *testing.T) {
		repo := newSystemSettingsRepoForTest(t)
		seedTLSDefaultsAllow0RTT(t, repo, `{"min_version":"TLS12","max_version":"TLS13","cipher_suites":"","curve_preferences":"X25519,CurveP256","prefer_server_cipher_suites":true,"session_tickets_enabled":true,"allow_0rtt":false,"self_signed_on_ip":false}`)

		ctx := invokeSystemConfigHandler(t, UpdateTLSDefaultConfig(repo, func() error { return nil }), "POST", "/api/v1/tls-config", []byte(`{"allow_0rtt":null}`))
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		var resp TLSDefaultConfig
		if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp.HasExplicitAllow0RTT || resp.Allow0RTT {
			t.Fatalf("response = %#v, want inheritance restored", resp)
		}
		if _, _, present := storedTLSDefaultsAllow0RTT(t, repo); present {
			val, _ := repo.Get(settingKeyTLSDefault)
			t.Fatalf("explicit null should drop the key, saved JSON: %s", val)
		}
	})

	t.Run("omitted_field_preserves_stored_value", func(t *testing.T) {
		repo := newSystemSettingsRepoForTest(t)
		seedTLSDefaultsAllow0RTT(t, repo, `{"min_version":"TLS12","max_version":"TLS13","cipher_suites":"","curve_preferences":"X25519,CurveP256","prefer_server_cipher_suites":true,"session_tickets_enabled":true,"allow_0rtt":false,"self_signed_on_ip":false}`)

		ctx := invokeSystemConfigHandler(t, UpdateTLSDefaultConfig(repo, func() error { return nil }), "POST", "/api/v1/tls-config", []byte(`{"prefer_server_cipher_suites":false}`))
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		value, explicit, present := storedTLSDefaultsAllow0RTT(t, repo)
		if !present || !explicit || value {
			t.Fatalf("omitted allow_0rtt should preserve explicit false, got (value=%v explicit=%v present=%v)", value, explicit, present)
		}
	})

	t.Run("omitted_field_keeps_history_free_of_explicit_key", func(t *testing.T) {
		repo := newSystemSettingsRepoForTest(t)
		seedTLSDefaultsAllow0RTT(t, repo, `{"min_version":"TLS12","max_version":"TLS13","cipher_suites":"","curve_preferences":"X25519,CurveP256","prefer_server_cipher_suites":true,"session_tickets_enabled":true,"self_signed_on_ip":false}`)

		ctx := invokeSystemConfigHandler(t, UpdateTLSDefaultConfig(repo, func() error { return nil }), "POST", "/api/v1/tls-config", []byte(`{"prefer_server_cipher_suites":true}`))
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		if _, _, present := storedTLSDefaultsAllow0RTT(t, repo); present {
			val, _ := repo.Get(settingKeyTLSDefault)
			t.Fatalf("writing an unrelated field must not introduce allow_0rtt, saved JSON: %s", val)
		}
		var resp TLSDefaultConfig
		if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp.HasExplicitAllow0RTT {
			t.Fatalf("legacy config without allow_0rtt must report inheritance, got %#v", resp)
		}
	})
}

// TestUpdateTLSDefaultConfigRejectsNonBooleanAllow0RTT 确认非法取值被拒且不落库。
func TestUpdateTLSDefaultConfigRejectsNonBooleanAllow0RTT(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	seedTLSDefaultsAllow0RTT(t, repo, `{"min_version":"TLS12","max_version":"TLS13","cipher_suites":"","curve_preferences":"X25519,CurveP256","prefer_server_cipher_suites":true,"session_tickets_enabled":true,"allow_0rtt":true,"self_signed_on_ip":false}`)

	reloaded := 0
	ctx := invokeSystemConfigHandler(t, UpdateTLSDefaultConfig(repo, func() error { reloaded++; return nil }), "POST", "/api/v1/tls-config", []byte(`{"allow_0rtt":"yes"}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("status %d, want 400: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloaded != 0 {
		t.Fatalf("rejected request must not trigger reload, reloaded=%d", reloaded)
	}
	value, explicit, present := storedTLSDefaultsAllow0RTT(t, repo)
	if !present || !explicit || !value {
		t.Fatalf("rejected request must leave stored allow_0rtt untouched, got (value=%v explicit=%v present=%v)", value, explicit, present)
	}
}

// TestLoadTLSDefaultConfigReportsInheritanceForLegacyRows 覆盖老配置行的读回语义。
func TestLoadTLSDefaultConfigReportsInheritanceForLegacyRows(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	seedTLSDefaultsAllow0RTT(t, repo, `{"min_version":"TLS12","max_version":"TLS13","cipher_suites":"","curve_preferences":"X25519,CurveP256","prefer_server_cipher_suites":true,"session_tickets_enabled":false,"self_signed_on_ip":false}`)

	cfg := loadTLSDefaultConfig(repo)
	if cfg.HasExplicitAllow0RTT {
		t.Fatalf("legacy row must report allow_0rtt as inherited, got %#v", cfg)
	}
	if cfg.Allow0RTT {
		t.Fatalf("legacy row must not materialise allow_0rtt=true, got %#v", cfg)
	}
	// 由配置侧数据推出的运行态判定必须回落到 session_tickets_enabled。
	defaults, err := tlsDefaultsFromStoredRow(repo)
	if err != nil {
		t.Fatalf("load snapshot TLS defaults: %v", err)
	}
	if defaults.EffectiveAllow0RTT() {
		t.Fatalf("legacy row with session_tickets_enabled=false must inherit 0-RTT off: %#v", defaults)
	}
}

// TestRuntimeConfigReportsAllow0RTTCapability 覆盖运行态自检条目的存在与语义。
func TestRuntimeConfigReportsAllow0RTTCapability(t *testing.T) {
	cases := []struct {
		name           string
		defaults       tlsDefaultsFixture
		wantStatus     string
		wantDetailText string
	}{
		{
			name:           "inherited_on_from_tickets",
			defaults:       tlsDefaultsFixture{sessionTickets: true},
			wantStatus:     "enabled",
			wantDetailText: "未显式配置",
		},
		{
			name:           "inherited_off_from_tickets",
			defaults:       tlsDefaultsFixture{sessionTickets: false},
			wantStatus:     "disabled",
			wantDetailText: "未显式配置",
		},
		{
			name:           "explicit_off_with_tickets_on",
			defaults:       tlsDefaultsFixture{sessionTickets: true, allow0RTT: false, explicitAllow0RTT: true},
			wantStatus:     "disabled",
			wantDetailText: "已显式配置",
		},
		{
			name:           "explicit_on_with_tickets_off",
			defaults:       tlsDefaultsFixture{sessionTickets: false, allow0RTT: true, explicitAllow0RTT: true},
			wantStatus:     "enabled",
			wantDetailText: "已显式配置",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			status := runtimeAllow0RTTCapability(tt.defaults.snapshotDefaults())
			if status.Key != "0rtt" || status.Label != "0-RTT" {
				t.Fatalf("capability = %#v, want key 0rtt and label 0-RTT", status)
			}
			if status.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q (detail=%q)", status.Status, tt.wantStatus, status.Detail)
			}
			if !strings.Contains(status.Detail, tt.wantDetailText) {
				t.Fatalf("detail = %q, want it to mention %q", status.Detail, tt.wantDetailText)
			}
			if status.Missing {
				t.Fatalf("0-RTT is a runtime-supported capability, must not be missing: %#v", status)
			}
		})
	}
}

// TestRuntimeAllow0RTTCapabilityHonorsEnvOverride 确认 env 覆盖会体现在自检条目里。
func TestRuntimeAllow0RTTCapabilityHonorsEnvOverride(t *testing.T) {
	t.Setenv("MY_OPENWAF_H3_ALLOW_0RTT", "0")
	status := runtimeAllow0RTTCapability(tlsDefaultsFixture{sessionTickets: true, allow0RTT: true, explicitAllow0RTT: true}.snapshotDefaults())
	if status.Status != "disabled" {
		t.Fatalf("env override must force disabled, got %#v", status)
	}
	if !strings.Contains(status.Detail, "MY_OPENWAF_H3_ALLOW_0RTT=0") {
		t.Fatalf("detail = %q, want it to name the overriding env value", status.Detail)
	}
}

// TestRuntimeHTTP3DetailMentions0RTTState 确认 HTTP/3 条目会带出 0-RTT 说明。
func TestRuntimeHTTP3DetailMentions0RTTState(t *testing.T) {
	networkDefaults := snapshotNetworkDefaultsFor0RTT()
	enabled := tlsDefaultsFixture{sessionTickets: true}.snapshotDefaults()
	if detail := runtimeHTTP3Detail(networkDefaults, enabled); !strings.Contains(detail, "接受 0-RTT 早期数据") {
		t.Fatalf("HTTP/3 detail = %q, want it to report accepted 0-RTT", detail)
	}
	disabled := tlsDefaultsFixture{sessionTickets: false}.snapshotDefaults()
	if detail := runtimeHTTP3Detail(networkDefaults, disabled); !strings.Contains(detail, "不接受 0-RTT 早期数据") {
		t.Fatalf("HTTP/3 detail = %q, want it to report rejected 0-RTT", detail)
	}
}
