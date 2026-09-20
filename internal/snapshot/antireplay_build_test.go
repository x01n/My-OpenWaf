package snapshot

import (
	"encoding/json"
	"testing"

	"My-OpenWaf/internal/store"
)

/**
 * TestBuildAntiReplayEnabledUsesNullableSiteOverride 验证站点级 AntiReplay 开关的三态
 * 合成：nil 继承全局，非 nil 保留站点显式启用或禁用。
 */
func boolPtr(value bool) *bool {
	return &value
}

func TestBuildAntiReplayEnabledUsesNullableSiteOverride(t *testing.T) {
	cases := []struct {
		name   string
		site   *bool
		global bool
		want   bool
	}{
		{name: "nil inherits disabled global", site: nil, global: false, want: false},
		{name: "nil inherits enabled global", site: nil, global: true, want: true},
		{name: "explicit site enable overrides disabled global", site: boolPtr(true), global: false, want: true},
		{name: "explicit site disable overrides enabled global", site: boolPtr(false), global: true, want: false},
		{name: "explicit site enable overrides enabled global", site: boolPtr(true), global: true, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := newSnapshotBuildDBForTest(t)

			site := store.Site{
				Host:              "antireplay-build.example.test",
				Bind:              ":80",
				Network:           "tcp",
				UpstreamURLs:      "http://127.0.0.1:8080",
				Enabled:           true,
				AntiReplayEnabled: tc.site,
			}
			if err := db.Create(&site).Error; err != nil {
				t.Fatalf("seed site: %v", err)
			}

			protection := store.DefaultProtectionConfig()
			protection.AntiReplayEnabled = tc.global
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
			if sn.Protection.AntiReplayEnabled != tc.global {
				t.Fatalf("global anti-replay = %v, want %v", sn.Protection.AntiReplayEnabled, tc.global)
			}
			rt, ok := sn.MatchSite(":80", site.Host)
			if !ok {
				t.Fatal("site was not matched")
			}
			if rt.AntiReplayEnabled != tc.want {
				t.Fatalf("site=%v global=%v => rt.AntiReplayEnabled = %v, want %v",
					tc.site, tc.global, rt.AntiReplayEnabled, tc.want)
			}
		})
	}
}

/**
 * TestBuildAntiReplayTTLAndActionHaveNoGlobalSource 固化 TTL 与 action 的来源唯一性：
 * 两者**只有站点级**字段，ProtectionConfig 中不存在对应项，因此没有全局兜底。
 *
 *   - TTL：Site.AntiReplayTTL（internal/store/site.go:61，default:300），
 *     经 build.go 原样保留在 rt.Site 上；handler.go:422-425 与
 *     phases.go:1096-1099 都直接读 rt.Site.AntiReplayTTL，
 *     <=0 时回落到 AntiReplayManager 构造入参（antireplay.go:99-101）。
 *   - Action：Site.AntiReplayAction（site.go:62，default:'shield_challenge'），
 *     经 build.go:322 原样进入 SiteRuntime.AntiReplayAction。
 *
 * 断言方式：显式写入站点值后，验证 Build 原样透传（不被全局值改写、不被归一化）。
 * 归一化发生在数据面 normalizeAntiReplayAction（handler.go:2049），不在 Build。
 */
func TestBuildAntiReplayTTLAndActionHaveNoGlobalSource(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)

	site := store.Site{
		Host:              "antireplay-ttl.example.test",
		Bind:              ":80",
		Network:           "tcp",
		UpstreamURLs:      "http://127.0.0.1:8080",
		Enabled:           true,
		AntiReplayEnabled: boolPtr(true),
		AntiReplayTTL:     77,
		AntiReplayAction:  "captcha_challenge",
	}
	if err := db.Create(&site).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}

	sn, err := Build(db, 1, testDynamicKeyBase)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	rt, ok := sn.MatchSite(":80", site.Host)
	if !ok {
		t.Fatal("site was not matched")
	}
	if rt.Site.AntiReplayTTL != 77 {
		t.Fatalf("rt.Site.AntiReplayTTL = %d, want 77（站点值应原样透传）", rt.Site.AntiReplayTTL)
	}
	if rt.AntiReplayAction != "captcha_challenge" {
		t.Fatalf("rt.AntiReplayAction = %q, want %q（Build 不做归一化）", rt.AntiReplayAction, "captcha_challenge")
	}
}
