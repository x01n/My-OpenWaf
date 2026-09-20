package app

import (
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"My-OpenWaf/internal/core"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// newBotGeoSettingsRepo 建一个只含系统设置表的内存库。
func newBotGeoSettingsRepo(t *testing.T) *repository.SystemSettingsRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SystemSettings{}); err != nil {
		t.Fatalf("migrate settings: %v", err)
	}
	return repository.NewSystemSettingsRepo(db)
}

// TestLoadBotGeoConfigAppliesManagedSettings 验证管理界面保存的 GeoIP 配置能被读出来。
//
// 这一环原先是断的：管理端把高风险国家、机房 ASN、VPN ASN 写进 SystemSettings 的
// `bot_settings`，而评分侧的 core.BotConfig 只来自硬编码默认值加两个环境变量，
// 两条线没有交汇——UI 上保存成功，实际评分用的仍是默认值。而默认的
// HighRiskCountries 是 nil，GeoIP 里的判断是 len(hrCountries) > 0，
// 于是高风险国家评分从来没有生效过。
func TestLoadBotGeoConfigAppliesManagedSettings(t *testing.T) {
	repo := newBotGeoSettingsRepo(t)
	if err := repo.Set("bot_settings", `{
		"high_risk_countries":["CN","RU"],
		"datacenter_asns":[16509,14618],
		"vpn_proxy_asns":[9009],
		"geoip_db_path":"/data/GeoLite2-City.mmdb"
	}`); err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}

	got := loadBotGeoConfig(repo, core.DefaultBotConfig())

	if len(got.HighRiskCountries) != 2 ||
		got.HighRiskCountries[0] != "CN" || got.HighRiskCountries[1] != "RU" {
		t.Errorf("HighRiskCountries = %v, want [CN RU]", got.HighRiskCountries)
	}
	// 管理端存的是 uint32，core.BotConfig 用 uint，转换不能丢值。
	if len(got.DataCenterASNs) != 2 || got.DataCenterASNs[0] != 16509 || got.DataCenterASNs[1] != 14618 {
		t.Errorf("DataCenterASNs = %v, want [16509 14618]", got.DataCenterASNs)
	}
	if len(got.VPNProxyASNs) != 1 || got.VPNProxyASNs[0] != 9009 {
		t.Errorf("VPNProxyASNs = %v, want [9009]", got.VPNProxyASNs)
	}
	if got.GeoIPDBPath != "/data/GeoLite2-City.mmdb" {
		t.Errorf("GeoIPDBPath = %q", got.GeoIPDBPath)
	}
}

// TestLoadBotGeoConfigKeepsFallbackForAbsentFields 验证未配置的字段保留启动时的值。
//
// 只覆盖请求里出现过的字段：管理端没配 ASN 列表时，不能把默认的机房 ASN 名单清空。
func TestLoadBotGeoConfigKeepsFallbackForAbsentFields(t *testing.T) {
	repo := newBotGeoSettingsRepo(t)
	if err := repo.Set("bot_settings", `{"high_risk_countries":["JP"]}`); err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}

	fallback := core.DefaultBotConfig()
	fallback.GeoIPDBPath = "/env/configured.mmdb"
	got := loadBotGeoConfig(repo, fallback)

	if len(got.HighRiskCountries) != 1 || got.HighRiskCountries[0] != "JP" {
		t.Errorf("HighRiskCountries = %v, want [JP]", got.HighRiskCountries)
	}
	if len(got.DataCenterASNs) != len(fallback.DataCenterASNs) {
		t.Errorf("未配置的 DataCenterASNs 应保留默认名单，得到 %d 项、期望 %d 项",
			len(got.DataCenterASNs), len(fallback.DataCenterASNs))
	}
	// 路径留空时不能把环境变量配好的库顶掉。
	if got.GeoIPDBPath != "/env/configured.mmdb" {
		t.Errorf("GeoIPDBPath = %q, want /env/configured.mmdb", got.GeoIPDBPath)
	}
}

// TestLoadBotGeoConfigHonorsExplicitEmptyList 验证用户主动清空名单能生效。
//
// nil（没配过）与空数组（配过、清空了）语义不同：前者保留默认，后者如实生效。
// 这和本仓库 Round 109 修的「显式零值被当成未设置」是同一类问题。
func TestLoadBotGeoConfigHonorsExplicitEmptyList(t *testing.T) {
	repo := newBotGeoSettingsRepo(t)
	if err := repo.Set("bot_settings", `{"datacenter_asns":[]}`); err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}

	fallback := core.DefaultBotConfig()
	if len(fallback.DataCenterASNs) == 0 {
		t.Fatal("前提不成立：默认配置本就没有机房 ASN，测不出清空效果")
	}

	got := loadBotGeoConfig(repo, fallback)
	if len(got.DataCenterASNs) != 0 {
		t.Errorf("用户主动清空的名单应生效，得到 %v", got.DataCenterASNs)
	}
}

// TestLoadBotGeoConfigFallsBackOnBadInput 验证坏数据不会打断 reload。
//
// 这个函数在每次配置重载时都会被调用，解析失败必须退回启动配置而不是让整条
// reload 链失败——否则一条写坏的设置会让后续所有配置变更都无法生效。
func TestLoadBotGeoConfigFallsBackOnBadInput(t *testing.T) {
	fallback := core.DefaultBotConfig()

	t.Run("nil repo", func(t *testing.T) {
		if got := loadBotGeoConfig(nil, fallback); len(got.DataCenterASNs) != len(fallback.DataCenterASNs) {
			t.Error("nil repo 应原样返回 fallback")
		}
	})

	t.Run("键不存在", func(t *testing.T) {
		repo := newBotGeoSettingsRepo(t)
		if got := loadBotGeoConfig(repo, fallback); len(got.DataCenterASNs) != len(fallback.DataCenterASNs) {
			t.Error("未保存过设置时应返回 fallback")
		}
	})

	t.Run("非法 JSON", func(t *testing.T) {
		repo := newBotGeoSettingsRepo(t)
		if err := repo.Set("bot_settings", `{not json`); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if got := loadBotGeoConfig(repo, fallback); len(got.DataCenterASNs) != len(fallback.DataCenterASNs) {
			t.Error("解析失败时应返回 fallback，而不是清空配置")
		}
	})
}

// TestUint32SliceToUintPreservesValues 验证 ASN 转换不丢值。
//
// 管理端用 uint32、core.BotConfig 用 uint，真实 ASN 会用到 32 位的高位区间
// （如 4200000000 属私有 ASN 范围），转换出错会让整段名单失配。
func TestUint32SliceToUintPreservesValues(t *testing.T) {
	in := []uint32{0, 1, 16509, 4200000000, 4294967295}
	got := uint32SliceToUint(in)
	if len(got) != len(in) {
		t.Fatalf("长度 = %d, want %d", len(got), len(in))
	}
	for i := range in {
		if got[i] != uint(in[i]) {
			t.Errorf("[%d] = %d, want %d", i, got[i], in[i])
		}
	}
	// 空切片要转成空切片而不是 nil：调用方靠 nil/非 nil 区分「没配过」和「清空了」。
	if empty := uint32SliceToUint([]uint32{}); empty == nil {
		t.Error("空切片不应转成 nil，否则会被误判为「未配置」")
	}
}
