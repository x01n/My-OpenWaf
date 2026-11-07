package snapshot

import (
	"encoding/json"
	"reflect"
	"testing"

	"My-OpenWaf/internal/store"
)

/**
 * TestCompileProtectionDerivedParsesJSONOnce 验证派生视图与按需解析结果一致，
 * 覆盖 owasp_rules_config 的 Cisco ASA 档位与 skip_path_by_phase 两个大 JSON 字段。
 */
func TestCompileProtectionDerivedParsesJSONOnce(t *testing.T) {
	cfg := store.DefaultProtectionConfig()
	cfg.OWASPRulesConfig = `{"owasp:path:006":{"cisco_asa_mode":"strict"}}`
	cfg.SetSkipPathByPhase(map[string][]string{"owasp_default": {"/phase-skip/*"}})

	derived := CompileProtectionDerived(&cfg)
	if derived == nil {
		t.Fatal("derived view is nil")
	}
	if derived.CiscoASAModeOverride != "strict" {
		t.Fatalf("cisco mode = %q, want strict", derived.CiscoASAModeOverride)
	}
	if got, want := derived.SkipPathByPhase, cfg.GetSkipPathByPhase(); !reflect.DeepEqual(got, want) {
		t.Fatalf("skip map = %#v, want %#v", got, want)
	}

	if empty := CompileProtectionDerived(nil); empty == nil {
		t.Fatal("nil config should still return an empty view")
	} else if empty.CiscoASAModeOverride != "" || empty.SkipPathByPhase != nil {
		t.Fatalf("nil config derived = %#v, want empty", empty)
	}
}

/**
 * TestBuildPopulatesProtectionDerived 验证快照构建期同时填充全局与站点级派生视图，
 * 数据面因此不必在请求路径上反序列化保护配置 JSON。
 */
func TestBuildPopulatesProtectionDerived(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)

	site := store.Site{
		Host:         "derived-build.example.test",
		Bind:         ":80",
		Network:      "tcp",
		UpstreamURLs: "http://127.0.0.1:8080",
		Enabled:      true,
	}
	if err := db.Create(&site).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.SetSkipPathByPhase(map[string][]string{"owasp_default": {"/global/*"}})
	raw, err := json.Marshal(protection)
	if err != nil {
		t.Fatalf("marshal protection: %v", err)
	}
	if err := db.Create(&store.SystemSettings{Key: "protection", Value: string(raw)}).Error; err != nil {
		t.Fatalf("seed protection setting: %v", err)
	}

	sn, err := Build(db, 1, testDynamicKeyBase)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if sn.ProtectionDerived == nil {
		t.Fatal("global ProtectionDerived not populated")
	}
	if got := sn.ProtectionDerived.SkipPathByPhase["owasp_default"]; !reflect.DeepEqual(got, []string{"/global/*"}) {
		t.Fatalf("global derived skip = %#v", got)
	}

	var rt *SiteRuntime
	for _, candidate := range sn.Sites {
		if candidate.Site.ID == site.ID {
			rt = candidate
			break
		}
	}
	if rt == nil {
		t.Fatalf("site %d missing from snapshot", site.ID)
	}
	if rt.EffectiveProtection == nil || rt.ProtectionDerived == nil {
		t.Fatalf("site derived view missing: ep=%v derived=%v", rt.EffectiveProtection, rt.ProtectionDerived)
	}
	if got := rt.ProtectionDerived.SkipPathByPhase["owasp_default"]; !reflect.DeepEqual(got, []string{"/global/*"}) {
		t.Fatalf("site derived skip = %#v", got)
	}
}
